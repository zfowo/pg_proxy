#!/bin/env python3
# -*- coding: GBK -*-
# 
# pgmonitor worker进程，用于监控主库和从库。
# 
import sys, os
import logging, signal
from pgmonitor import *
from netutils import *
from miscutils import *
from myshm import *

def pgmonitor_worker(ipc_uds_path):
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    # 先建立到主进程的连接
    ipc_ep = connect_to_main_process(ipc_uds_path, 'pgmonitor')
    
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

