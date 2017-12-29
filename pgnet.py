#!/bin/env python3
# -*- coding: GBK -*-
# 
# 
# 
import sys, os, socket, time
import traceback
import functools
import netutils
import pgprotocol3 as p

# 连接是非阻塞的，除了connect的时候。
class connbase():
    def __init__(self, s):
        self.s = s
        self.s.settimeout(0)
        self.recv_buf = b''
        self.send_buf = b''
        self.readsz = -1 # _read函数每次最多读取多少字节，<=0表示不限。
    def fileno(self):
        return self.s.fileno()
    def close(self):
        self.s.close()
    # 读取数据直到没有数据可读
    def _read(self):
        while True:
            data = netutils.myrecv(self.s, 4096)
            if data is None:
                break
            elif not data:
                raise RuntimeError('the peer(%s) closed connection' % (self.s.getpeername(),))
            self.recv_buf += data
            if len(data) < 4096:
                break
            if self.readsz > 0 and len(self.recv_buf) >= self.readsz:
                break
    def _write(self):
        if self.send_buf:
            sz = self.s.send(self.send_buf)
            self.send_buf = self.send_buf[sz:]
    # 返回解析后的消息列表
    def read_msgs(self, *, fe):
        self._read()
        if not self.recv_buf:
            return []
        idx, msg_list = p.parse_pg_msg(self.recv_buf, fe=fe)
        if msg_list:
            self.recv_buf = self.recv_buf[idx:]
        return msg_list
    # 返回还剩多少个字节没有发送。msg_list为空则会发送上次剩下的数据。
    def write_msgs(self, msg_list=(), *, fe):
        prefix_str = 'BE' if fe else 'FE'
        for msg in msg_list:
            print('%s: %s' % (prefix_str, msg))
            self.send_buf += msg.tobytes()
        self._write()
        return len(self.send_buf)
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
class feconn(connbase):
    # 读取第一个消息，如果还没有收到则返回None。
    def read_startup_msg(self):
        self._read()
        m = None
        if p.startup_msg_is_complete(self.recv_buf):
            m = p.parse_startup_msg(self.recv_buf[4:])
            self.recv_buf = b''
        return m
    def read_msgs(self):
        return super().read_msgs(fe=True)
    def write_msgs(self, msg_list=()):
        return super().write_msgs(msg_list, fe=True)
    def write_msg(self, msg):
        return self.write_msgs((msg,))
class beconn(connbase):
    def __init__(self, addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(addr)
        super().__init__(s)
    def read_msgs(self):
        return super().read_msgs(fe=False)
    def write_msgs(self, msg_list=()):
        return super().write_msgs(msg_list, fe=False)
    def write_msg(self, msg):
        return self.write_msgs((msg,))
class pgconn(beconn):
    def __init__(self, **kwargs):
        host = kwargs.pop('host', '127.0.0.1')
        port = kwargs.pop('port', 5432)
        super().__init__((host, port))
        m = p.StartupMessage.make(**kwargs)
        self.write_msg(m)
    def write_msg(self, msg):
        ret = super().write_msg(msg)
        self.processer = get_processer_for_msg(msg)
        return ret
    # read_msgs_until_done/write_msgs_until_done 现在是循环读写，可能忙等待导致cpu占用，可以用poller来检查是否可读写。
    # 一直读直到有消息为止
    def read_msgs_until_done(self):
        msg_list = None
        while not msg_list:
            msg_list = self.read_msgs()
        return msg_list
    # 一直写直到写完为止
    def write_msgs_until_done(self):
        while self.write_msgs():
            pass
    def flush(self):
        return self.write_msgs((p.Flush(),))
    def sync(self):
        return self.write_msgs((p.Sync(),))
# 表示ErrorResponse消息的异常，其他错误抛出的是RuntimeError异常。
class pgerror(Exception):
    def __init__(self, errmsg):
        super().__init__(errmsg)
        self.errmsg = errmsg
# 
# processer for response msg after sending message
# 
def get_processer_for_msg(msg):
    msgname = type(msg).__name__
    pname = msgname + 'Processer'
    return globals()[pname]
# decorator for process method
def Reset(func):
    @functools.wraps(func)
    def wrapper(cls, cnn, *args, **kwargs):
        try:
            cnn.write_msgs_until_done()
            return func(cls, cnn, *args, **kwargs)
        finally:
            cls.reset()
    return wrapper
class MsgProcesser():
    @classmethod
    def delattrs(cls, attrs):
        for attr in attrs:
            if hasattr(cls, attr):
                delattr(cls, attr)
class StartupMessageProcesser(MsgProcesser):
    UnknownMsgErr = 'unknown response msg for startup message'
    params = {}
    @classmethod
    def reset(cls):
        cls.params = {}
        super().delattrs(['be_keydata'])
    # 返回authtype是Ok/CleartextPasword/MD5Password的Authentication，或者抛出异常。
    @classmethod
    @Reset
    def process(cls, cnn):
        msg_list = cnn.read_msgs_until_done()
        m1 = msg_list[0]
        if m1.msg_type == p.MsgType.MT_Authentication:
            if m1.authtype == p.AuthType.AT_Ok:
                cls._process_msg_list(msg_list[1:], cnn)
                cnn.params = cls.params
                cnn.be_keydata = cls.be_keydata
                return m1
            elif m1.authtype == p.AuthType.AT_CleartextPassword or m1.authtype == p.AuthType.AT_MD5Password:
                return m1
            else:
                raise RuntimeError('unsupported authentication type', m1)
        elif m1.msg_type == p.MsgType.MT_ErrorResponse:
            raise pgerror(m1)
        else:
            raise RuntimeError(cls.UnknownMsgErr, m1)
    @classmethod
    def _process_msg_list(cls, msg_list, cnn):
        got_ready = False
        for m in msg_list:
            if m.msg_type == p.MsgType.MT_ParameterStatus:
                cls.params[bytes(m.name).decode('ascii')] = bytes(m.val).decode('ascii')
            elif m.msg_type == p.MsgType.MT_BackendKeyData:
                cls.be_keydata = (m.pid, m.skey)
            elif m.msg_type == p.MsgType.MT_ReadyForQuery:
                got_ready = True
                break
            elif m.msg_type == p.MsgType.MT_ErrorResponse:
                raise pgerror(m)
            else:
                raise RuntimeError(cls.UnknownMsgErr, m)
        if got_ready:
            return
        msg_list = cnn.read_msgs_until_done()
        cls._process_msg_list(msg_list, cnn)
class PasswordMessageProcesser(StartupMessageProcesser):
    pass
class QueryProcesser(MsgProcesser):
    UnknownMsgErr = 'unknown response msg for Query message'
    ex = None
    @classmethod
    def reset(cls):
        cls.ex = None
        super().delattrs(['cmdstatus', 'rowdesc', 'rows'])
    # 
    @classmethod
    @Reset
    def process(cls, cnn):
        msg_list = cnn.read_msgs_until_done()
        cls._process_msg_list(msg_list, cnn)
        if cls.ex:
            raise cls.ex
        res = (cls.cmdstatus, cls.rowdesc, cls.rows)
        return res
    @classmethod
    def _process_msg_list(cls, msg_list, cnn):
        got_ready = False
        for m in msg_list:
            if m.msg_type == p.MsgType.MT_EmptyQueryResponse:
                cls.ex = RuntimeError('empty query', m)
            elif m.msg_type == p.MsgType.MT_ErrorResponse:
                cls.ex = pgerror(m)
            elif m.msg_type == p.MsgType.MT_RowDescription:
                cls.rowdesc = list(m)
                cls.rows = []
            elif m.msg_type == p.MsgType.MT_DataRow:
                cls.rows.append(list(m))
            elif m.msg_type == p.MsgType.MT_CommandComplete:
                cls.cmdstatus = bytes(m.tag).decode('ascii').split()
            elif m.msg_type == p.MsgType.MT_ReadyForQuery:
                got_ready = True
                break
            else:
                raise RuntimeError(cls.UnknownMsgErr, m)
        if got_ready:
            return
        msg_list = cnn.read_msgs_until_done()
        cls._process_msg_list(msg_list, cnn)
# main
if __name__ == '__main__':
    if len(sys.argv) > 3:
        print('usage: %s [be_addr [listen_addr]]' % sys.argv[0])
        sys.exit(1)
    be_addr = ('10.10.77.150', 5432)
    listen_addr = ('0.0.0.0', 9999)
    if len(sys.argv) >= 2:
        host, port = sys.argv[1].split(':')
        be_addr = (host, int(port))
    if len(sys.argv) >= 3:
        host, port = sys.argv[2].split(':')
        listen_addr = (host, int(port))
    print(be_addr, listen_addr)
        
    listen_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_s.bind(listen_addr)
    listen_s.listen()
    poll = netutils.spoller()
    while True:
        s, peer = listen_s.accept()
        print('accept connection from %s' % (peer,))
        poll.clear()
        try:
            with feconn(s) as fe_c, beconn(be_addr) as be_c:
                while True:
                    m = fe_c.read_startup_msg()
                    if m:
                        be_c.write_msgs([m])
                        break
                    time.sleep(0.01)
                poll.register(fe_c, poll.POLLIN)
                poll.register(be_c, poll.POLLIN)
                while True:
                    poll.poll(timeout=0.1)
                    if be_c.write_msgs(fe_c.read_msgs()):
                        poll.register(be_c, poll.POLLIN|poll.POLLOUT)
                    else:
                        poll.register(be_c, poll.POLLIN)
                    if fe_c.write_msgs(be_c.read_msgs()):
                        poll.register(fe_c, poll.POLLIN|poll.POLLOUT)
                    else:
                        poll.register(fe_c, poll.POLLIN)
        except Exception as ex:
            print('%s: %s' % (ex.__class__.__name__, ex))
            #traceback.print_tb(sys.exc_info()[2])
