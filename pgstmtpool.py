#!/bin/env python3
# -*- coding: GBK -*-
# 
# 语句级别的连接池。当前只支持simple query，不支持extended query和copy。
# 
import sys, os
import collections, socket
import threading, queue
import pgnet
import pgprotocol3 as p
import pghba
import netutils
import pseudodb

class fepgfatal(Exception):
    def __init__(self, fatal_ex):
        self.fatal_ex = fatal_ex
class pgworker():
    nextid = 0
    @classmethod
    def get_nextid(cls):
        cls.nextid += 1
        return cls.nextid
    def __init__(self, max_msg=0):
        self.msg_queue = queue.Queue(maxsize=max_msg)
        self.id = self.get_nextid()
        self.auth_ok_msgs = []
        self.startup_msg = None
        self.num_processed_msg = 0
    def _process_auth(self, be_addr, fecnn, main_queue):
        self.startup_msg = fecnn.startup_msg
        self.becnn = pgnet.beconn(be_addr)
        self.becnn.write_msgs_until_done((fecnn.startup_msg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            fecnn.write_msgs_until_done(msg_list)
            self.auth_ok_msgs.extend(msg_list)
            msg = msg_list[-1]
            if msg.msg_type == p.MsgType.MT_ReadyForQuery:
                break
            elif msg.msg_type == p.MsgType.MT_ErrorResponse:
                main_queue.put(('fail', fecnn))
                return False
            elif msg.msg_type == p.MsgType.MT_Authentication:
                if msg.authtype not in (p.AuthType.AT_Ok, p.AuthType.AT_SASLFinal):
                    self.becnn.write_msgs_until_done(fecnn.read_msgs_until_avail())
        # auth ok
        for idx, msg in enumerate(self.auth_ok_msgs):
            if msg.msg_type == p.MsgType.MT_Authentication and msg.authtype == p.AuthType.AT_Ok:
                self.auth_ok_msgs = self.auth_ok_msgs[idx:]
                break
        main_queue.put(('ok', fecnn, self))
        return True
    def run(self, be_addr, fecnn, main_queue):
        if not self._process_auth(be_addr, fecnn, main_queue):
            return
        # process Query msg from queue
        while True:
            self.fe_fatal = None
            try:
                fecnn, msg = self.msg_queue.get()
                self._process_one(fecnn, msg)
            except pgnet.pgfatal as ex:
                fecnn.close()
                print('<thread %d> BE%s: %s' % (self.id, self.becnn.getpeername(), ex))
                break
            else:
                main_queue.put(('done', fecnn))
        main_queue.put(('exit', self))
    def _process_one(self, fecnn, msg):
        if msg.msg_type == p.MsgType.MT_Terminate:
            print('<trhead %d> recved Terminate from %s' % (self.id, fecnn.getpeername()))
        elif msg.msg_type == p.MsgType.MT_Query:
            self._process_query(fecnn, msg)
        elif msg.msg_type == p.MsgType.MT_Parse:
            self._process_parse(fecnn, msg)
        else:
            self._process_unsupported(fecnn,  msg)
        self.num_processed_msg += 1
    def _process_query(self, fecnn, femsg):
        self.becnn.write_msgs_until_done((femsg,))
        m = self.becnn.read_msgs_until_avail(max_msg=1)[0]
        if m.msg_type == p.MsgType.MT_CopyInResponse:
            self._process_copyin(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyOutResponse:
            self._process_copyout(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyBothResponse:
            raise pgnet.pgfatal(None, 'do not support CopyBothResponse')
        else:
            self._process_query2(fecnn, m)
    def _process_query2(self, fecnn, bemsg):
        msg_list = (bemsg,)
        while True:
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
            msg_list = self.becnn.read_msgs_until_avail()
    def _process_copyin(self, fecnn, bemsg):
        self._write_msgs_to_fe(fecnn, (bemsg,))
        while True:
            netutils.poll2in(fecnn, self.becnn)
            try:
                msg_list = fecnn.read_msgs()
            except pgnet.pgfatal as ex:
                err_msg = str(ex).encode('utf8')
                self.becnn.write_msgs_until_done((p.CopyFail(err_msg=err_msg),))
                self._skip_be_msgs()
                break
            self.becnn.write_msgs_until_done(msg_list)
            msg_list = self.becnn.read_msgs()
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list and msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
    def _process_copyout(self, fecnn, bemsg):
        self._write_msgs_to_fe(fecnn, (bemsg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
    def _process_parse(self, fecnn, femsg):
        pass
    def _process_unsupported(self, fecnn, femsg):
        errmsg = p.ErrorResponse.make_error(b'unsupported msg type:%s' % femsg.msg_type)
        try:
            fecnn.write_msgs_until_done((errmsg, p.ReadyForQuery.Idle))
        except pgnet.pgfatal as ex:
            pass # 不需要处理，主线程在下次read的时候会报错
    def _write_msgs_to_fe(self, fecnn, msg_list):
        if self.fe_fatal:
            return False
        try:
            fecnn.write_msgs_until_done(msg_list)
        except pgnet.pgfatal as ex:
            self.fe_fatal = ex
            return False
        return True
    def _skip_be_msgs(self, msg_list=()):
        if not msg_list:
            msg_list = self.becnn.read_msgs_until_avail()
        while True:
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                return
            msg_list = self.becnn.read_msgs_until_avail()
    def put(self, fecnn, msg):
        self.msg_queue.put_nowait((fecnn, msg))
# 记录所有pgworker，按startup_msg分组。
class pgworkerpool():
    def __init__(self):
        self.workers_map = collections.defaultdict(list) # startup_msg -> worker_list
        self.nextidx_map = collections.defaultdict(int)  # startup_msg -> nextidx for accessing worker_list
    # 启动一个新的worker，此时该worker还没有添加到pool里面，
    # 主线程从main_queue接收到auth成功之后才会把worker加到pool。
    def new_worker(self, be_addr, fecnn, main_queue):
        w = pgworker()
        thr = threading.Thread(target=w.run, args=(be_addr, fecnn, main_queue))
        thr.start()
    def add(self, w):
        worker_list = self.workers_map[w.startup_msg]
        worker_list.append(w)
        self.nextidx_map[w.startup_msg] = len(worker_list)-1
    def remove(self, w):
        worker_list = self.workers_map[w.startup_msg]
        worker_list.remove(w)
    # 参数startup_msg可以是fecnn或者worker
    def get(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return self.workers_map[startup_msg]
    def count(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return len(self.workers_map[startup_msg])
    def __iter__(self):
        for msg, worker_list in self.workers_map.items():
            for w in worker_list:
                yield msg, w
    # 把来自前端cnn的消息msg分发给相应的worker
    def dispatch_fe_msg(self, poll, cnn, msg):
        worker_list = self.workers_map[cnn.startup_msg]
        nextidx = self.nextidx_map[cnn.startup_msg] % len(worker_list)
        if not worker_list: # 没有可用的worker则断开连接
            cnn.close()
        else:
            worker_list[nextidx].put(cnn, msg)
            self.nextidx_map[cnn.startup_msg] = (nextidx + 1) % len(worker_list)
    # 当worker异常退出时需要把剩下的消息分发到其他worker上。在调用之前必须先remove worker。
    def dispatch_worker_remain_msg(self, poll, w):
        while True:
            try:
                cnn, msg = w.msg_queue.get_nowait()
            except queue.Empty:
                break
            self.dispatch_fe_msg(poll, cnn, msg)
# 记录所有auth成功的fe连接，按startup_msg分组。
# 有2种auth成功的情况: new_worker成功的时候和pgauth成功的时候。
class feconnpool():
    def __init__(self):
        self.fecnns_map = collections.defaultdict(set)
    def add(self, fecnn):
        self.fecnns_map[fecnn.startup_msg].add(fecnn)
    def remove(self, fecnn):
        x = self.fecnns_map[fecnn.startup_msg]
        if fecnn in x:
            x.remove(fecnn)
    # 返回有多少个和startup msg对应的fecnn。参数startup_msg可以是fecnn。
    def count(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return len(self.fecnns_map[startup_msg])
    def __contains__(self, fecnn):
        return fecnn in self.fecnns_map[fecnn.startup_msg]
    def __iter__(self):
        for msg, fecnns in self.fecnns_map.items():
            for cnn in fecnns:
                yield msg, cnn
# pseudo db
class pooldb(pseudodb.pseudodb):
    def __init__(self, cnn, wpool, fepool):
        super().__init__(cnn)
        self.wpool = wpool
        self.fepool = fepool
    def process_query(self, query):
        query = query.strip().strip(';').lower()
        cmd, *args = query.split()
        if cmd not in self.cmd_map:
            return self.write_msgs((p.ErrorResponse.make_error(b'unknown cmd:%s' % cmd.encode('utf8')), p.ReadyForQuery.Idle))
        return self.cmd_map[cmd](self, args)
    # 各种命令实现
    cmd_map = {}
    def _process_fe(self, args):
        msg_list = []
        msg_list.append(p.RowDescription.make({'name':b'host'}, {'name':b'port'}, {'name':b'database'}, {'name':b'user'}))
        for m, fecnn in self.fepool:
            host, port = fecnn.getpeername()
            host = host.encode('utf8')
            port = b'%d' % port
            msg_list.append(p.DataRow.make(host, port, m['database'], m['user']))
        cnt = len(msg_list) - 1
        msg_list.append(p.CommandComplete(tag=b'SELECT %d' % cnt))
        msg_list.append(p.ReadyForQuery.Idle)
        return self.write_msgs(msg_list)
    def _process_be(self, args):
        msg_list = []
        msg_list.append(p.RowDescription.make(
                                      {'name':b'id'}, {'name':b'host'}, {'name':b'port'}, 
                                      {'name':b'database'}, {'name':b'user'}, {'name':b'processed'}))
        for m, w in self.wpool:
            id = b'%d' % w.id
            processed = b'%d' % w.num_processed_msg
            host, port = w.becnn.getpeername()
            host = host.encode('utf8')
            port = b'%d' % port
            msg_list.append(p.DataRow.make(id, host, port, m['database'], m['user'], processed))
        cnt = len(msg_list) - 1
        msg_list.append(p.CommandComplete(tag=b'SELECT %d' % cnt))
        msg_list.append(p.ReadyForQuery.Idle)
        return self.write_msgs(msg_list)
    cmd_map['fe'] = _process_fe
    cmd_map['be'] = _process_be
    del _process_fe, _process_be
# main
def need_new_worker(startup_msg):
    wcnt = wpool.count(startup_msg)
    if wcnt == 0:
        return True
    fecnt = fepool.count(startup_msg)
    return fecnt/wcnt >= 10
if __name__ == '__main__':
    be_addr = ('127.0.0.1', 5432)
    if len(sys.argv) >= 2:
        host, port = sys.argv[1].split(':')
        be_addr = (host, int(port))
    
    auth_cnn = pgnet.pgconn(host=be_addr[0], port=be_addr[1])
    hba = pghba.pghba.from_database(auth_cnn)
    shadows = pghba.pgshadow.from_database(auth_cnn)
    auth_cnn.close()
    
    wpool = pgworkerpool()
    fepool = feconnpool()
    main_queue = queue.Queue()
    
    listen = netutils.listener(('', 7777), async=True)
    poll = netutils.spoller()
    poll.register(listen, poll.POLLIN)
    while True:
        x = poll.poll(0.001)
        for fobj, event in x:
            try:
                if fobj is listen:
                    cs, addr = fobj.accept()
                    print('accept connection from %s' % (addr,))
                    poll.register(pgnet.feconn4startup(pgnet.feconn(cs)), poll.POLLIN)
                elif type(fobj) is pgnet.feconn4startup:
                    m = fobj.read_startup_msg()
                    if not m:
                        continue
                    poll.unregister(fobj)
                    is_pseudo = (m['database'] == b'pseudo')
                    if not is_pseudo and need_new_worker(m):
                        wpool.new_worker(be_addr, fobj.cnn, main_queue)
                        continue
                    
                    auth_ok_msgs = pooldb.auth_ok_msgs if is_pseudo else wpool.get(m)[0].auth_ok_msgs
                    cnn = pooldb(fobj.cnn, wpool, fepool) if is_pseudo else fobj.cnn
                    auth = pghba.get_auth(hba, shadows, cnn, m, auth_ok_msgs)
                    if auth.handle_event(poll, event):
                        if not isinstance(auth.cnn, pseudodb.pseudodb):
                            fepool.add(auth.cnn)
                elif isinstance(fobj, pghba.pgauth):
                    poll.unregister(fobj)
                    if fobj.handle_event(poll, event):
                        if not isinstance(auth.cnn, pseudodb.pseudodb):
                            fepool.add(fobj.cnn)
                elif type(fobj) is pgnet.feconn:
                    if event & poll.POLLOUT:
                        if not fobj.write_msgs():
                            poll.register(fobj, poll.POLLIN)
                        continue
                    m = fobj.read_msgs(max_msg=1)
                    if not m:
                        continue
                    poll.unregister(fobj) # 主线程停止检测，把控制权交给worker
                    wpool.dispatch_fe_msg(poll, fobj, m[0])
                elif isinstance(fobj, pseudodb.pseudodb):
                    fobj.handle_event(poll, event)
            except pgnet.pgfatal as ex:
                print('%s: %s' % (ex.__class__.__name__, ex))
                poll.clear((fobj,))
                if type(fobj) is pgnet.feconn:
                    fepool.remove(fobj)
        # process main_queue
        while True:
            try:
                x = main_queue.get_nowait()
            except queue.Empty:
                break
            print(x)
            if x[0] == 'ok': # ('ok', fecnn, worker)
                poll.register(x[1], poll.POLLIN)
                fepool.add(x[1])
                wpool.add(x[2])
            elif x[0] == 'fail': # ('fail', fecnn)
                x[1].close()
            elif x[0] == 'exit': # ('exit', worker)
                wpool.remove(x[1])
                wpool.dispatch_worker_remain_msg(poll, x[1])
            elif x[0] == 'done': # ('done', fecnn)
                poll.register(x[1], poll.POLLIN)
            else:
                raise RuntimeError('unknow x from main_queue:%s' % (x,))
