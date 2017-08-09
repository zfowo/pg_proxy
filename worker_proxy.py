#!/bin/env python3
# -*- coding: GBK -*-
# 
# proxy worker进程。用于连接池。
# 
# 主进程会为每个proxy worker创建一块共享内存，名字是<proxy_shm_name>.<n>，其中proxy_shm_name可以在配置文件中设置，缺省是端口号。
# 每块共享内存分为3部分：
#   1) 开头的16个字节包含proxy worker的pid。后面用\x00填充。用part_idx=-1去访问。
#   2) 哈希表，用于记录和startup_msg_raw+be_addr对应的空闲fe_be_pair，哈希表中的项值是md5(startup_msg_raw+be_addr)+<2字节的空闲连接数>，
#      项值的大小是18个字节。分配1*PAGE_SIZE，不包括开头的16个字节，可以保存226项。用part_idx=0去访问。
#   3) 
# 
import sys, os

def proxy_worker(ipc_uds_path):
    pass

# main
g_conf = None
if __name__ == '__main__':
    pass

