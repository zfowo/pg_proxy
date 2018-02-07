#!/bin/env python3
# -*- coding: GBK -*-
# 
# run this script to generate cutils module.
# 性能关键的python函数用c函数代替。
# 
import sys, os
import cffi

ffibuilder = cffi.FFI()
ffibuilder.cdef('''
int has_msg(const char * data, int data_len, int sidx);
''')
ffibuilder.set_source('cutils', 
'''
#include <stdlib.h>
#include <string.h>
int has_msg(const char * data, int data_len, int sidx)
{
    if (data_len - sidx < 5)
        return 0;
    int msg_len = 0;
    char * p = (char *)&msg_len;
    p[0] = data[sidx+1+3];
    p[1] = data[sidx+1+2];
    p[2] = data[sidx+1+1];
    p[3] = data[sidx+1];
    if (data_len - sidx < msg_len + 1)
        return 0;
    return msg_len + 1;
}
''')
ffibuilder.compile()
