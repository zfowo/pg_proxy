#!/bin/env python3
# -*- coding: GBK -*-
# 
# pseudo db worker进程，用于处理伪数据库pg_proxy。
# 伪数据库的信息来自proxy worker和pgmonitor worker的共享内存。
# 
import sys, os
import logging
from pgprotocol import *
from netutils import *
from miscutils import *
from myshm import *

def pseudodb_worker(ipc_uds_path):
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    # 先建立到主进程的连接
    ipc_ep = connect_to_main_process(ipc_uds_path, 'pseudodb')
    
    poll = spoller()
    poll.register(ipc_ep, poll.POLLIN)
    while True:
        x = poll.poll()
        for fobj, event in x:
            pass
    os._exit(0)

# main
g_conf = None
if __name__ == '__main__':
    pass

