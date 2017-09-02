#!/bin/env python3
# -*- coding: GBK -*-
#
# 由于posix_ipc没有提供无名信号量，所以通过cffi实现。
# 
import sys, os, errno
import contextlib
import cffi

PROCESS_SHARED = 1
THREAD_SHARED = 0

ffi = cffi.FFI()
ffi.cdef('''
#define SEM_T_SZ ...
int init(char *sem, int pshared, unsigned int value);
int destroy(char *sem);
int getvalue(char *sem, int *sval);
int post(char *sem);
// timeout指定超时值，单位是秒。
//   <  0.0 : sem_wait
//   == 0.0 : sem_trywait
//   >  0.0 : sem_timedwait
// errno可能值: EINTR / EAGAIN / ETIMEOUT
int wait(char *sem, double timeout);
''')

lib = ffi.verify('''
#include <time.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>

#define SEM_T_SZ sizeof(sem_t)
int init(char *sem, int pshared, unsigned int value)
{
    return sem_init((sem_t *)sem, pshared, value);
}
int destroy(char *sem)
{
    return sem_destroy((sem_t *)sem);
}
int getvalue(char *sem, int *sval)
{
    return sem_getvalue((sem_t *)sem, sval);
}
int post(char *sem)
{
    return sem_post((sem_t *)sem);
}
#define NSEC_PER_SEC (1000000000)
int wait(char *sem, double timeout)
{
    if (timeout < 0.0)
        return sem_wait((sem_t *)sem);
    else if (timeout == 0.0)
        return sem_trywait((sem_t *)sem);
    else
    {
        struct timespec ts;
        long sec, nsec;
        int ret = clock_gettime(CLOCK_REALTIME, &ts);
        if (ret != 0)
            return ret;
        sec = (long)timeout;
        nsec = (long)((timeout - sec) * NSEC_PER_SEC);
        ts.tv_sec += sec;
        ts.tv_nsec += nsec;
        ts.tv_sec += ts.tv_nsec / NSEC_PER_SEC;
        ts.tv_nsec = ts.tv_nsec % NSEC_PER_SEC;
        return sem_timedwait((sem_t *)sem, &ts);
    }
}
''')
# 
# python wrapper for lib.*
# 
# decorator to check errno and raise OSError
def check_errno(f):
    def wrapper(*args, **kwargs):
        retval = f(*args, **kwargs)
        if type(retval) == tuple:
            if retval[0] == 0:
                return
        elif retval == 0:
            return
        ex = OSError()
        ex.errno = ffi.errno
        ex.strerror = os.strerror(ex.errno)
        raise ex
    return wrapper
# 初始化位于mmap中的semaphore
@check_errno
def init(mm, idx, value):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.init(sem, PROCESS_SHARED, value)
@check_errno
def destroy(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.destroy(sem)
@check_errno
def _getvalue(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    v = ffi.new('int *')
    ret = lib.getvalue(sem, v)
    return (ret, v[0])
def getvalue(mm, idx):
    return _getvalue(mm, idx)[1]
@check_errno
def post(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.post(sem)
@check_errno
def wait(mm, idx, timeout):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.wait(sem, timeout)

# main
if __name__ == '__main__':
    pass
