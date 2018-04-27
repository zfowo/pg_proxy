#!/bin/env python3
# -*- coding: GBK -*-
# 
import sys, os

# admin_cnn, master必须指定。
# 对于pseudo_cnn/user_pwds参数，如果用户的auth方法是md5，那么不需要指定密码。
# admin_cnn必须指定密码，如果用户的auth方法是md5，那么可以用pg_shadow中的md5开头的那个密码，否则必须是明文密码。
all = {
    'listen' : ('', 7777), 
    # pseudo_cnn是主从连接池之间通信时用的连接参数(无需指定host/port/database)，如果没有指定则使用admin_cnn。
    'pseudo_cnn' : {'user':'zhb', 'password':''}, 
    # admin_cnn用于获得hba/shadows，以及切换时连接到从库时用的，需要超级用户权限。
    # pg_hba.conf中不要对连接池所在的host设置trust，因为前端第一次连接的时候是由后端auth的，此时后端看到的host是连接池的host。
    'admin_cnn' : {'user':'zhb', 'password':''}, 
    'enable_ha' : True, 
    'ha_after_fail_cnt' : 10, 
    'ha_check_interval' : 3, 
    'lo_oid' : 9999, 
    'trigger_file' : 'trigger', 
    # cache
    'cache_threshold_to_file' : 10*1024, 
    'cache_root_dir' : 'querycache', 
    # 主从库信息
    # worker_min_cnt中第idx个值表示当有idx+1个前端连接时需要的worker数，worker_per_fe_cnt表示每多少个前端连接需要一个后端连接。
    'worker_min_cnt' : [1]*2 + [2]*4 + [3]*4, 
    'worker_per_fe_cnt' : 10, 
    'idle_timeout' : 60*60*24, 
    'master' : ('127.0.0.1', 5432), 
    'slaver' : [('127.0.0.1', 5433),], 
    # user_pwds包含用户密码，从库worker用这些密码连接到从库。如果用户的auth方法是md5则不需要指定，
    # 如果auth方法是password/scram-sha256则必须指定密码，如果是trust则可以指定任意值。
    # 如果不指定也不是md5 auth，那么不会启动从库worker。
    'user_pwds' : {
        'user2' : '123456', 
    }, 
}
