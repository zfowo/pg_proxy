#!/bin/env python3
# -*- coding: GBK -*-
# 
# run this script to generate cutils module.
# 性能关键的python函数用c函数代替。
# API比ABI模式要快，分析单个/多个整数，c代码比struct差不多快10%左右。
# 
import sys, os
import cffi

ffibuilder = cffi.FFI()
ffibuilder.cdef('''
int get_short(const char * data, int sidx);
int get_int(const char * data, int sidx);
void get_nshort(const char * data, int sidx, int num, short * res);
void get_nint(const char * data, int sidx, int num, int * res);

int has_msg(const char * data, int data_len, int sidx);
''')
ffibuilder.set_source('cutils', 
'''
#include <stdlib.h>
#include <string.h>
#define GET_SHORT(n, data, sidx) do {char * pc=(char *)&(n); pc[0]=(data)[(sidx)+1]; pc[1]=(data)[(sidx)];} while (0)
#define GET_INT(n, data, sidx) do {char * pc=(char *)&(n); pc[0]=(data)[(sidx)+3]; pc[1]=(data)[(sidx)+2]; pc[2]=(data)[(sidx)+1]; pc[3]=(data)[(sidx)];} while (0)
int get_short(const char * data, int sidx)
{
    short n = 0;
    GET_SHORT(n, data, sidx);
    return n;
}
int get_int(const char * data, int sidx)
{
    int n = 0;
    GET_INT(n, data, sidx);
    return n;
}
void get_nshort(const char * data, int sidx, int num, short * res)
{
    short n = 0;
    for (int i = 0; i < num; ++i)
    {
        GET_SHORT(n, data, sidx);
        res[i] = n;
        sidx += 2;
    }
}
void get_nint(const char * data, int sidx, int num, int * res)
{
    int n = 0;
    for (int i = 0; i < num; ++i)
    {
        GET_INT(n, data, sidx);
        res[i] = n;
        sidx += 4;
    }
}

int has_msg(const char * data, int data_len, int sidx)
{
    if (data_len - sidx < 5)
        return 0;
    int msg_len = 0;
    GET_INT(msg_len, data, sidx+1);
    if (data_len - sidx < msg_len + 1)
        return 0;
    return msg_len + 1;
}
''')
ffibuilder.compile()
