#!/bin/env python3
# -*- coding: GBK -*-
# 
# misc utils
# 
import sys, os
import datetime

def read_conf_file(conf_file, conf_name):
    f = open(conf_file, encoding='gbk')
    data = f.read()
    f.close()
    this_path = os.path.dirname(conf_file)
    local_dict = {'this_path' : this_path}
    exec(data, None, local_dict)
    return local_dict.pop(conf_name)

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

# main
if __name__ == '__main__':
    pass

