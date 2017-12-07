#!/bin/env python3
# -*- coding: GBK -*-
# 
# Forker : 用于fork worker进程。
# 主进程在调用Forker之前，需要初始化各种共享结构，用于和Forker以及worker通信。
# 主进程
#   |-> Forker
#         |-> Worker1
#         |-> Worker2
#         |-> Workern
# 
import sys, os
import mysem

class Forker(object):
    pass 

