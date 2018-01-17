#!/bin/env python3
# -*- coding: GBK -*-
# 
# misc utils
# 
import sys, os
import datetime, socket
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
# main
if __name__ == '__main__':
    pass

