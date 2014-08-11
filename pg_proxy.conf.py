#!/bin/env python3
# -*- coding: GBK -*-
# exec(s, None, local_dict) local_dict中应该有'this_path'，其值为本文件所在的目录。
import sys, os, logging

pg_proxy_conf = {
    # 输出顺序
    '_print_order' : ('listen', 'ipc_uds_path', 'master', 'promote', 'conninfo', 'slaver_list', 
                      'idle_cnn_timeout', 'active_cnn_timeout', 'disable_conds_list', 'recv_sz_per_poll', 'pg_proxy_pw', 'proxy_worker_num', 'log', 'pid_file'), 
    # 
    'listen' : ('', 9999), 
    'ipc_uds_path' : None, 
    'master' : ('127.0.0.1', 5400), 
    'promote' : None, 
    'conninfo' : {'user':'zhb', 'db':'postgres', 'pw':'', 'conn_retry_num':5, 'conn_retry_interval':6, 'query_interval':30, 'lo_oid':9999}, 
    'slaver_list' : [], 
    'idle_cnn_timeout' : 5*60, 
    'active_cnn_timeout' : 5*60, 
    'disable_conds_list' : [], 
    'recv_sz_per_poll' : 4, 
    'pg_proxy_pw' : 'pg2pg', 
    'proxy_worker_num' : 1, 
    'log' : {'filename':None, 'level':logging.INFO, 'format':'[%(asctime)s]%(levelname)s:%(message)s', 'datefmt':'%Y-%m-%d %H:%M:%S'}, 
    'pid_file' : None, 
}

c = pg_proxy_conf
if not c['ipc_uds_path']:
    c['ipc_uds_path'] = '/tmp/pg_proxy.%d' % (c['listen'][1]+1, )
if not c['master']:
    raise RuntimeError('should provide master in pg_proxy_conf')
if not c['conninfo']['user']:
    raise RuntimeError('should provide user in conninfo in pg_proxy_conf')
if c['log']['filename']:
    c['log']['filename'] = os.path.join(this_path, c['log']['filename'])
if not c['pid_file']:
    c['pid_file'] = 'pg_proxy.pid'
c['pid_file'] = os.path.join(this_path, c['pid_file'])

