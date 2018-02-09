#!/bin/env python3
# -*- coding: GBK -*-
# 
# misc utils
# 
import sys, os
import datetime, socket, struct
import collections
from netutils import uds_ep

# 连接到主进程的uds，然后发送b's'消息。
def connect_to_main_process(ipc_uds_path, subprocess_name):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(ipc_uds_path)
    pid = os.getpid()
    msg_data = '%s:%s' % (subprocess_name, str(pid))
    s.sendall(uds_ep.make_msg(b's' + msg_data))
    return uds_ep(s)

def read_conf_file(conf_file, conf_name):
    f = open(conf_file, encoding='gbk')
    data = f.read()
    f.close()
    this_path = os.path.dirname(conf_file)
    this_path = os.path.abspath(this_path)
    local_dict = {'this_path' : this_path}
    exec(data, None, local_dict)
    return local_dict.pop(conf_name)
# 如果没有指定配置文件那么就在thist_path目录找缺省的配置文件。
def read_conf(this_path=''):
    if len(sys.argv) == 1:
        fn = os.path.basename(sys.argv[0])[:-3] + '.conf.py'
        conf_file = os.path.join(this_path, fn)
    elif len(sys.argv) == 2:
        conf_file = sys.argv[1]
    else:
        print('usage: %s [conf_file]' % (sys.argv[0], ))
        sys.exit(1)
    x = read_conf_file(conf_file, 'all')
    return x

def close_fobjs(x_list):
    for x in x_list:
        if type(x) == list:
            for fobj in x:
                fobj.close()
            x.clear()
        else:
            x.close()

def get_max_len(s_list):
    max_len = 0
    for s in s_list:
        if len(s) > max_len:
            max_len = len(s)
    return max_len

try:
    import setproctitle
except ImportError:
    setproctitle = None
def set_process_title(title):
    if not setproctitle:
        return
    setproctitle.setproctitle(title)

def get_now_time():
    d = datetime.datetime.now()
    return '%.4d-%.2d-%.2d %.2d:%.2d:%.2d' % (d.year, d.month, d.day, d.hour, d.minute, d.second)

def parse_args(args, sep='=', **kwargs):
    res = collections.defaultdict(list)
    for kv in args:
        kv = kv.strip()
        k, v = kv.split(sep, maxsplit=1)
        k, v = k.strip(), v.strip()
        x = mysplit(v, kwargs.get(k))
        if type(x) is str:
            res[k].append(x)
        else:
            res[k] += x
    return res
def mysplit(s, seps):
    if not seps:
        return s
    res = s.split(seps[0])
    return [mysplit(x, seps[1:]) for x in res]
# 固定大小的列表，老的数据将被丢弃。
class SizedList():
    def __init__(self, maxsz):
        self.maxsz = maxsz
        self.modsz = self.maxsz + 1
        self.L = [None] * self.modsz
        self.start = self.end = 0
    def clear(self):
        for idx, _ in enumerate(self.L):
            self.L[idx] = None
        self.start = self.end = 0
    def append(self, v):
        self.L[self.end] = v
        self.end = (self.end + 1) % self.modsz
        if self.end == self.start:
            self.start = (self.start + 1) % self.modsz
    def __iter__(self):
        idx = self.start
        while idx != self.end:
            yield self.L[idx]
            idx = (idx + 1) % self.modsz
    def __len__(self):
        if self.end >= self.start:
            return self.end - self.start
        return self.modsz + (self.end - self.start)
# 分析pg协议用到的一些函数。
try:
    import cutils
except ImportError:
    cutils = None
# 获得\x00结尾的字节串，返回字节串和下一个sidx。
# nullbyte表示返回值是否保留结尾的\x00字节。
def get_cstr(buf, sidx, nullbyte=False):
    idx = sidx
    while buf[sidx] != 0:
        sidx += 1
    sidx += 1
    if nullbyte:
        d = buf[idx:sidx]
    else:
        d = buf[idx:sidx-1]
    return d, sidx

def get_byte(buf, sidx):
    return struct.unpack('>b', buf[sidx:sidx+1])[0]
def get_short(buf, sidx):
    return struct.unpack('>h', buf[sidx:sidx+2])[0]
def get_nshort(buf, sidx, cnt):
    return struct.unpack('>%dh'%cnt, buf[sidx:sidx+2*cnt])
def get_int(buf, sidx):
    return struct.unpack('>i', buf[sidx:sidx+4])[0]
def get_nint(buf, sidx, cnt):
    return struct.unpack('>%di'%cnt, buf[sidx:sidx+4*cnt])

def put_byte(n):
    return struct.pack('>b', n)
def put_short(n):
    return struct.pack('>h', n)
def put_nshort(n_list):
    return struct.pack('>%dh'%len(n_list), *n_list)
def put_int(n):
    return struct.pack('>i', n)
def put_nint(n_list):
    return struct.pack('>%di'%len(n_list), *n_list)

def get_24X(buf, sidx):
    old_sidx = sidx
    res = []
    if cutils:
        cnt = cutils.lib.get_short(buf, sidx)
    else:
        cnt = struct.unpack('>h', buf[sidx:sidx+2])[0]
    sidx += 2
    # 当cnt很小时(比如<=5)，while好像比for要快。
    for i in range(cnt):
        if cutils:
            n = cutils.lib.get_int(buf, sidx)
        else:
            n = struct.unpack('>i', buf[sidx:sidx+4])[0]
        sidx += 4
        if n < 0:
            res.append(None)
        else:
            res.append(buf[sidx:sidx+n])
            sidx += n
    return tuple(res), sidx-old_sidx
def put_24X(v_list):
    data = struct.pack('>h', len(v_list))
    for v in v_list:
        if v is None:
            data += struct.pack('>i', -1)
        else:
            data += struct.pack('>i', len(v)) + v
    return data
def get_X(buf, sidx):
    res = []
    while buf[sidx] != 0:
        s, sidx = get_cstr(buf, sidx)
        res.append(s)
    return res
def put_X(v_list):
    res = b''
    for v in v_list:
        res += v + b'\x00'
    res += b'\x00'
    return res
# main
if __name__ == '__main__':
    pass

