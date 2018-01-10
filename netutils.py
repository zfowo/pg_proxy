#!/bin/env python3
# -*- coding: GBK -*-
# 
# poller classes
# 
import sys, os, errno, struct
import socket, select
import collections
import logging

if 'PyPy' in sys.version:
    NONBLOCK_SEND_RECV_OK = (errno.EAGAIN, 10035)
    NONBLOCK_CONNECT_EX_OK = (10036, 0)
elif os.name == 'posix':
    NONBLOCK_SEND_RECV_OK = (errno.EAGAIN, errno.EWOULDBLOCK)
    NONBLOCK_CONNECT_EX_OK = (errno.EINPROGRESS, 0)
else:
    NONBLOCK_SEND_RECV_OK = (errno.EAGAIN, errno.EWOULDBLOCK, errno.WSAEWOULDBLOCK)
    NONBLOCK_CONNECT_EX_OK = (errno.WSAEINPROGRESS, 0)

# 检查1个/2个fobj
POLLIN = 0x01
POLLOUT = 0x02
POLLERR = 0x04
POLLINOUT = POLLIN|POLLOUT
POLLINERR = POLLIN|POLLERR
POLLOUTERR = POLLOUT|POLLERR
POLLINOUTERR = POLLIN|POLLOUT|POLLERR
def poll(fobj, event, timeout=None):
    if timeout != None and timeout < 0: # 负值表示block，这和poll/epoll相同。
        timeout = None
    fd = fobj.fileno() if type(fobj) is not int else fobj
    r_list, w_list, e_list = [], [], []
    r_list.append(fd) if event & POLLIN else None
    w_list.append(fd) if event & POLLOUT else None
    e_list.append(fd) if event & POLLERR else None
    r_list, w_list, e_list = select.select(r_list, w_list, e_list, timeout)
    return bool(r_list), bool(w_list), bool(e_list)
def pollin(fobj, timeout=None):
    return poll(fobj, POLLIN, timeout)[0]
def pollout(fobj, timeout=None):
    return poll(fobj, POLLOUT, timeout)[1]
# 往类cls增加pollin/pollout/pollerr函数。
def pollize(cls):
    def mypoll(self, event, timeout=None): return poll(self, event, timeout)
    def mypollin(self, timeout=None): return pollin(self, timeout)
    def mypollout(self, timeout=None): return pollout(self, timeout)
    setattr(cls, 'poll', mypoll)
    setattr(cls, 'pollin', mypollin)
    setattr(cls, 'pollout', mypollout)
    return cls
def poll2(fobj1, event1, fobj2, event2, timeout=None):
    if timeout != None and timeout < 0:
        timeout = None
    fd1 = fobj1.fileno() if type(fobj1) is not int else fobj1
    fd2 = fobj2.fileno() if type(fobj2) is not int else fobj2
    r_list, w_list, e_list = [], [], []
    for fd, event in ((fd1, event1), (fd2, event2)):
        r_list.append(fd) if event & POLLIN else None
        w_list.append(fd) if event & POLLOUT else None
        e_list.append(fd) if event & POLLERR else None
    r_list, w_list, e_list = select.select(r_list, w_list, e_list, timeout)
    return tuple((fd in r_list, fd in w_list, fd in e_list) for fd in (fd1, fd2))
def poll2in(fobj1, fobj2, timeout=None):
    x = poll2(fobj1, POLLIN, fobj2, POLLIN, timeout)
    return x[0][0], x[1][0]
def poll2out(fobj1, fobj2, timeout=None):
    x = poll2(fobj1, POLLOUT, fobj2, POLLOUT, timeout)
    return x[0][1], x[1][1]
# 当poll到POLLERR的时候调用该函数获得错误代码/错误信息。
# 在异步建立连接(connect_ex)的时候，一般需要检测POLLOUT|POLLERR，有POLLERR表示连接失败，POLLOUT表示连接成功。
# 而在连接建立完成后可以不检测POLLERR，因为在读写的时候会出错。
def get_socket_error(s):
    errcode = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if hasattr(socket, 'errorTab'):
        errmsg = socket.errorTab[errcode]
    else:
        errmsg = os.strerror(errcode)
    return (errcode, errmsg)

class poller_base(object):
    def __init__(self):
        self.fd2objs = {}
    def register(self, fobj, eventmask):
        fd = fobj
        if type(fobj) != int:
            fd = fobj.fileno()
        
        objs = self.fd2objs.get(fd, None)
        if objs and objs[0] is not fobj:
            logging.warning('register with same fd(%d) but with two different obj(%s %s)', fd, objs, fobj)
        
        exist = objs is not None
        self.fd2objs[fd] = (fobj, eventmask)
        return (fd, exist)
    def modify(self, fobj, eventmask):
        fd = fobj
        if type(fobj) != int:
            fd = fobj.fileno()
        if fd not in self.fd2objs:
            ex = OSError()
            ex.errno = errno.ENOENT
            raise ex
        self.fd2objs[fd] = (fobj, eventmask)
        return (fd, )
    def unregister(self, fobj):
        fd = fobj
        if type(fobj) != int:
            fd = fobj.fileno()
        self.fd2objs.pop(fd)
        return (fd, )
    # 派生类需要定义_poll
    def _poll(self, *args, **kwargs):
        raise SystemError('BUG: the derived class(%s) should implement _poll' % (type(self), ))
    def poll(self, timeout = None, *args, **kwargs):
        while True:
            try:
                ret = self._poll(timeout, *args, **kwargs)
            except OSError as ex:
                if ex.errno == errno.EINTR:
                    continue
                raise
            return ret
    def clear(self, fobj_list=None):
        if fobj_list is None:
            fobj_list = list(self.fd2objs.keys())
        for fobj in fobj_list:
            if self._has_fobj(fobj):
                self.unregister(fobj)
    def _has_fobj(self, fobj):
        fd = fobj
        if type(fobj) != int:
            fd = fobj.fileno()
        return fd in self.fd2objs
    def close(self):
        self.clear()
# 
# 基于select.select
# 
class spoller(poller_base):
    POLLIN =  0x01
    POLLOUT = 0x02
    POLLERR = 0x04
    POLLINOUT = POLLIN|POLLOUT
    POLLINERR = POLLIN|POLLERR
    POLLOUTERR = POLLOUT|POLLERR
    POLLINOUTERR = POLLIN|POLLOUT|POLLERR
    def __init__(self):
        super().__init__()
    def _poll(self, timeout = None):
        if timeout != None and timeout < 0: # 负值表示block，这和poll/epoll相同。
            timeout = None
        
        r_list, w_list, e_list = [], [], []
        for fd, (_, m) in self.fd2objs.items():
            r_list.append(fd) if m & self.POLLIN else None
            w_list.append(fd) if m & self.POLLOUT else None
            e_list.append(fd) if m & self.POLLERR else None
        #logging.debug('select: %s %s %s %s', r_list, w_list, e_list, timeout)
        x = select.select(r_list, w_list, e_list, timeout)
        
        res = collections.defaultdict(int)
        masks = [self.POLLIN, self.POLLOUT, self.POLLERR]
        for idx, fdlist in enumerate(x):
            for fd in fdlist:
                fobj = self.fd2objs[fd][0]
                res[fobj] |= masks[idx]
        return list(res.items())

if os.name == 'posix':
    # 
    # 基于select.poll
    # 
    class poller(poller_base):
        POLLIN  = select.POLLIN
        POLLOUT = select.POLLOUT
        POLLERR = select.POLLERR
        POLLINOUT = POLLIN|POLLOUT
        POLLINERR = POLLIN|POLLERR
        POLLOUTERR = POLLOUT|POLLERR
        POLLINOUTERR = POLLIN|POLLOUT|POLLERR
        def __init__(self):
            super().__init__()
            self.p = select.poll()
        def register(self, fobj, eventmask):
            ret = super().register(fobj, eventmask)
            self.p.register(ret[0], eventmask)
        def modify(self, fobj, eventmask):
            ret = super().modify(fobj, eventmask)
            self.p.modify(ret[0], eventmask)
        def unregister(self, fobj):
            ret = super().unregister(fobj)
            self.p.unregister(ret[0])
        def _poll(self, timeout = None):
            res = self.p.poll(timeout)
            res_list = []
            for fd, event in res:
                res_list.append((self.fd2objs[fd][0], event))
            return res_list
    # 
    # 基于select.epoll
    # 
    class epoller(poller_base):
        POLLIN  = select.EPOLLIN
        POLLOUT = select.EPOLLOUT
        POLLERR = select.EPOLLERR
        POLLINOUT = POLLIN|POLLOUT
        POLLINERR = POLLIN|POLLERR
        POLLOUTERR = POLLOUT|POLLERR
        POLLINOUTERR = POLLIN|POLLOUT|POLLERR
        def __init__(self):
            super().__init__()
            self.p = select.epoll()
        def register(self, fobj, eventmask):
            ret = super().register(fobj, eventmask)
            if ret[1]:
                self.p.unregister(ret[0])
            self.p.register(ret[0], eventmask)
        def modify(self, fobj, eventmask):
            ret = super().modify(fobj, eventmask)
            self.p.modify(ret[0], eventmask)
        def unregister(self, fobj):
            ret = super().unregister(fobj)
            self.p.unregister(ret[0])
        def _poll(self, timeout = None, maxevents = -1):
            if timeout == None:
                timeout = -1
            res = self.p.poll(timeout = timeout, maxevents = maxevents)
            res_list = []
            for fd, event in res:
                res_list.append((self.fd2objs[fd][0], event))
            return res_list
        def close(self):
            super().close()
            self.p.close()
else:
    poller = spoller
    epoller = spoller
# 
# 如果s是非阻塞的，即使通过poll检测到可读，也可能返回None，
# 这是因为poll可能返回假的可读信号或者可读的数据checksum失败，需要对方重传。
# 所以需要检查返回值是否为None。
# 
# 如果s是阻塞的，则不会返回None。
# 
# 有些情况下即使有数据可接收也会抛出ConnectionResetError异常。比如: 
#     client发送了100个字节，而服务器端只接收了50个字节，然后发给client数据后就close了。
#     如果服务器端没有正常close socket，而是进程异常退出，比如通过os._exit(1)。
#     linux下面没有这个问题，因为close就能把socket正常关闭，而windows下面必须用closesocket来关闭。
# 
def myrecv(s, bufsize=4096):
    try:
        data = s.recv(bufsize)
    except OSError as ex:
        if ex.errno in NONBLOCK_SEND_RECV_OK:
            return None
        raise
    return data
# 
# 接收sz个字节。调用之前应该把s设为阻塞，也就是s.settimeout(None)。
# 如果对端已经close则抛出异常。
# 
def recv_size(s, sz):
    ret = b'';
    while sz > 0:
        tmp = s.recv(sz)
        if not tmp:
            raise RuntimeError('the peer(%s) closed the connection. last recved:[%s]' % (s.getpeername(), ret))
        ret += tmp
        sz -= len(tmp)
    return ret
class listener():
    def __init__(self, addr, *, async=False, family=socket.AF_INET):
        self.s = socket.socket(family, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(addr)
        self.s.listen()
        if async:
            self.s.settimeout(0)
    def __getattr__(self, name):
        return getattr(self.s, name)
# 
# 通过unix domain socket进行通信，可以传递具体的消息以及文件描述符。
# 消息格式：一字节的消息类型 + 四个字节的消息长度(包括本四个字节) + 消息数据。
# 'f'类型的消息后面跟有文件描述符。
# 
class uds_ep(object):
    FDSIZE = 4
    MAXFD = 100
    def __init__(self, x):
        if type(x) == socket.socket:
            self.s = x
        else:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(x)
        self.s.settimeout(0)
        
        self.recv_msg_header = b''
        self.recv_msg_data = b''
        self.recv_msg_fdlist = []
        
        self.send_msg_list = [] # 待发送消息列表。list of (idx, data, fdlist)
    def fileno(self):
        return self.s.fileno()
    def close(self):
        self.s.close()
    # 
    # 在调用该函数前必须确保socket可读。
    # 返回值 (len, msg)。抛出异常表示出问题了，可以close掉了。
    # .) len=-1表示整个消息已经接收完，此时msg为(msg_type, msg_data, fdlist)。
    # .) len>0表示本次接收了多少数据，但整个消息还没有接收完。
    # .) len=0表示虽然poll返回可读事件，但是还是没有数据可读。
    # 
    def recv(self):
        n = 5 - len(self.recv_msg_header)
        if n > 0:
            data = myrecv(self.s, n)
            if data == None:
                return (0, None)
            if not data:
                raise RuntimeError('the peer(%s) closed the connection' % (self.s.getpeername(), ))
            self.recv_msg_header += data
            return (len(data), None)
        
        msg_type = self.recv_msg_header[:1]
        msg_len = struct.unpack('>i', self.recv_msg_header[1:])[0]
        n = msg_len - 4 - len(self.recv_msg_data)
        if n > 0:
            data = myrecv(self.s, n)
            if data == None:
                return (0, None)
            if not data:
                raise RuntimeError('the peer(%s) closed the connection' % (self.s.getpeername(), ))
            self.recv_msg_data += data
            if len(data) == n and msg_type != b'f':
                ret = (-1, (msg_type, self.recv_msg_data, self.recv_msg_fdlist))
                self.recv_msg_header = b''
                self.recv_msg_data = b''
                self.recv_msg_fdlist = []
                return ret
            else:
                return (len(data), None)
        
        if msg_type == b'f':
            data, ancdata, flags, addr = self.s.recvmsg(1, socket.CMSG_LEN(self.MAXFD*self.FDSIZE))
            for cmsg in ancdata:
                fddata = cmsg[2]
                tail_len = len(fddata) % self.FDSIZE
                if tail_len:
                    logging.warning('found truncated fd:%s %d', fddata, tail_len)
                fdcnt = len(fddata) // self.FDSIZE
                fds = struct.unpack('%di'%fdcnt, fddata[:len(fddata)-tail_len])
                self.recv_msg_fdlist.extend(fds)
        
        ret = (-1, (msg_type, self.recv_msg_data, self.recv_msg_fdlist))
        self.recv_msg_header = b''
        self.recv_msg_data = b''
        self.recv_msg_fdlist = []
        return ret
    # 
    # 在需要发送消息的时候，先调用put_msg把消息放到待发送队列，然后用select/poll/epoll检测是否可写，当可写的时候再调用send函数。
    # 注意：如果发送描述符，那么不要在调用put_msg之后立刻close描述符。而是在调用send函数之后检查是否已发送，发送之后才可以close。
    # 
    def put_msg(self, msg_type, msg_data, fdlist = None):
        if (msg_type != b'f' and fdlist) or (msg_type == b'f' and not fdlist):
            raise SystemError("BUG: fdlist should be empty while msg_type is not b'f', and fdlist should not be empty while msg_type is b'f'. (%s %s %s)" % (msg_type, msg_data, fdlist))
        data = msg_type + struct.pack('>i', len(msg_data)+4) + msg_data
        self.send_msg_list.append([0, data, fdlist])
    # 
    # 返回None表示不需要再检测是否可写。也就是都发送完了。
    # 如果抛出OSError，那就说明出问题了，可以close掉了。
    # 
    def send(self):
        if not self.send_msg_list:
            return None
        msg = self.send_msg_list[0]
        if msg[0] < len(msg[1]):
            n = self.s.send(msg[1][msg[0]:])
            msg[0] += n
            if msg[0] < len(msg[1]) or msg[2]:
                return 'w'
            # msg已发送完并且它的fdlist为空
            self.send_msg_list.remove(msg)
            if self.send_msg_list:
                return 'w'
            else:
                return None
        # 发送fdlist
        fdlist = msg[2]
        fddata = struct.pack('%di'%len(fdlist), *fdlist)
        self.s.sendmsg([b'z'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fddata)])
        self.send_msg_list.remove(msg)
        if self.send_msg_list:
            return 'w'
        else:
            return None
    # 
    # 检查文件描述符是否已经发送。只有发送之后才可以close文件描述符。
    # 
    def fd_is_sent(self, fd):
        for msg in self.send_msg_list:
            if fd in msg[2]:
                return False
        return True
    # 
    # 生成一个消息
    # 
    @staticmethod
    def make_msg(msg_type, msg_data):
        msg = b'' + msg_type
        if type(msg_data) == str:
            msg_data = msg_data.encode('utf8')
        msg += struct.pack('>i', len(msg_data)+4)
        msg += msg_data
        return msg
# main
if __name__ == '__main__':
    pass

