#!/bin/env pypy
# -*- coding: GBK -*-
# 
# 由于现在pypy的socket还不支持sendmsg/recvmsg，所以用CFFI实现它。
# 
import sys, os
import cffi

source = r'''
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

int sendmsg(int sockfd, const char *data, int dlen, const char *cdata, int cdlen, int flags)
{
}
int sendfds(int sockfd, int *fds, int fdnum, int flags)
{
    return sendmsg(sockfd, "z", 1, fds, fdnum*sizeof(int), flags)
}
'''
cdef = r'''
int sendmsg(int sockfd, const char *data, int dlen, const char *cdata, int cdlen, int flags);
int sendfds(int sockfd, int *fds, int fdnum, int flags);
extern int errno;
'''

ffi = cffi.FFI()
ffi.cdef(cdef)
x = ffi.verify(source)

def sendfds(s, fds, flags=0):
    ret = x.sendfds(s.fileno(), fds, len(fds), flags)
    if ret < 0:
        ex = OSError()
        ex.errno = x.errno
        ex.strerror = os.strerror(x.errno)
        raise ex
    return ret

