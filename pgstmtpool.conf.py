#!/bin/env python3
# -*- coding: GBK -*-
# 
import sys, os

all = {
    'listen' : ('', 7777), 
    # admin_cnn用于获得hba/shadows，以及切换时连接到从库时用的，需要超级用户权限。
    # pg_hba.conf中不要对连接池所在的host设置trust，因为前端第一次连接的时候是由后端auth的，此时后端看到的host是连接池的host。
    'admin_cnn' : {'user':'zhb', 'password':''}, 
    'lo_oid' : 9999, 
    # 主从库信息
    'master' : ('127.0.0.1', 5432), 
    'slaver' : [('10.10.77.100', 5432), ], 
    'conn_params' : [
        {'database':'postgres', 'user':'zhb', 'client_encoding':'GBK', 'application_name':'psql'}, 
        {'database':'postgres', 'user':'user1', 'password':'123456', 'client_encoding':'GBK', 'application_name':'psql'}, 
    ], 
}
if 'host' not in all['admin_cnn']:
    all['admin_cnn']['host'] = all['master'][0]
    all['admin_cnn']['port'] = all['master'][1]
