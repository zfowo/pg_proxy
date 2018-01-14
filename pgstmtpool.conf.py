#!/bin/env python3
# -*- coding: GBK -*-
# 
import sys, os

# admin_cnn, master必须指定。
# conn_params是个列表，列表中的元素是连接参数(不包括host和port)，当前端和其中一个匹配的时候才会启动slaver worker。
all = {
    'listen' : ('', 7777), 
    # admin_cnn用于获得hba/shadows，以及切换时连接到从库时用的，需要超级用户权限。
    # pg_hba.conf中不要对连接池所在的host设置trust，因为前端第一次连接的时候是由后端auth的，此时后端看到的host是连接池的host。
    'admin_cnn' : {'user':'zhb', 'password':''}, 
    'lo_oid' : 9999, 
    'trigger_file' : 'trigger', 
    'enable_ha' : True, 
    # 主从库信息
    # worker_min_cnt中第idx个值表示当有idx+1个前端连接时需要的worker数，worker_cnt_per表示每多少个前端连接需要一个后端连接。
    'worker_min_cnt' : [1]*2 + [2]*4 + [3]*4, 
    'worker_cnt_per' : 10, 
    'master' : ('127.0.0.1', 5432), 
    'slaver' : [('127.0.0.1', 5433),], 
    'conn_params' : [
        {'database':'postgres', 'user':'zhb'}, 
        {'database':'postgres', 'user':'zhb', 'client_encoding':'GBK', 'application_name':'psql'}, 
        {'database':'postgres', 'user':'user1', 'client_encoding':'GBK', 'application_name':'psql', 'password':'123456'}, 
    ], 
}
if 'host' not in all['admin_cnn']:
    all['admin_cnn']['host'] = all['master'][0]
    all['admin_cnn']['port'] = all['master'][1]
