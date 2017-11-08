#!/bin/env python3
# -*- coding: GBK -*-
#
# 由于posix_ipc没有提供无名信号量，所以通过cffi实现。
# 
import sys, os, errno, struct
import contextlib
import cffi

PROCESS_SHARED = 1
THREAD_SHARED = 0

ffi = cffi.FFI()
ffi.cdef('''
int semsize();
int seminit(char *sem, int pshared, unsigned int value);
int semdestroy(char *sem);
int semgetvalue(char *sem, int *sval);
int sempost(char *sem);
// timeout指定超时值，单位是秒。
//   <  0.0 : sem_wait
//   == 0.0 : sem_trywait
//   >  0.0 : sem_timedwait
// errno可能值: EINTR / EAGAIN / ETIMEOUT
int semwait(char *sem, double timeout);
''')
so = os.path.join(os.path.dirname(__file__), 'libmysem.so')
lib = ffi.dlopen(so)
# 
# python wrapper for lib.*
# 
# decorator to check errno and raise OSError
def check_errno(f):
    def wrapper(*args, **kwargs):
        retval = f(*args, **kwargs)
        if type(retval) == tuple:
            if retval[0] == 0:
                return retval
        elif retval == 0:
            return retval
        ex = OSError()
        ex.errno = ffi.errno
        ex.strerror = os.strerror(ex.errno)
        raise ex
    return wrapper
def semsize():
    return lib.semsize()
# 初始化位于mmap中的semaphore
@check_errno
def init(mm, idx, value):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.seminit(sem, PROCESS_SHARED, value)
@check_errno
def destroy(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.semdestroy(sem)
@check_errno
def _getvalue(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    v = ffi.new('int *')
    ret = lib.semgetvalue(sem, v)
    return (ret, v[0])
def getvalue(mm, idx):
    return _getvalue(mm, idx)[1]
@check_errno
def post(mm, idx):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.sempost(sem)
@check_errno
def wait(mm, idx, timeout):
    buf = ffi.from_buffer(mm)
    sem = buf + idx
    return lib.semwait(sem, timeout)
# 
# sobj = sem(mm, 0)
# with sobj.wait():
#    ....
# 
class Sem(object):
    SIZE = semsize()
    def __len__(self):
        return self.SIZE
    def __init__(self, mm, idx, value=1):
        self.mm = mm
        self.idx = idx
        self.init_value = value
        if self.init_value != None:
            init(self.mm, self.idx, value)
    def destroy(self):
        if self.init_value != None:
            destroy(self.mm, self.idx)
    def getvalue(self):
        return getvalue(self.mm, self.idx)
    def post(self):
        post(self.mm, self.idx)
    def wait(self, timeout = -1):
        wait(self.mm, self.idx, timeout)
        return self
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self.post()
#========================================================================================================
# 下面是一些位于匿名共享内存中的数据结构
# 
# Stack : 共享内存中包含：sem + top +        <data>
#                               |->top_idx   |->data_idx
# 
class Stack(object):
    @staticmethod
    def mmsize(itemnum, itemsz):
        return Sem.SIZE + 4 + itemnum * itemsz
    # value=None 表示不初始化sem和topvalue
    def __init__(self, itemsz, mm, start=0, end=0, value=1, fin=None, fout=None):
        self.itemsz = itemsz
        self.fin = fin
        self.fout = fout
        
        self.mm = mm
        self.mm_start = start
        self.mm_end = end
        if self.end <= 0:
            self.end = len(mm)
        
        self.sem = Sem(mm, start, value)
        self.top_idx = self.mm_start + Sem.SIZE
        self.data_idx = self.mm_start + Sem.SIZE + 4
        if value != None:
            self._topvalue(0)
    def _topvalue(self, *args):
        if args:
            v = args[0]
            self.mm[self.top_idx:self.top_idx+4] = struct.pack('=i', v)
        else:
            return struct.unpack('=i', self.mm[self.top_idx:self.top_idx+4])[0]
    def count(self, timeout=-1):
        with self.sem.wait(timeout):
            return self._topvalue()
    def push(self, item, timeout=-1):
        if self.fin:
            item = self.fin(item)
        if type(item) != bytes or len(item) != self.itemsz:
            raise RuntimeError('wrong item: %s %s' % (item, type(item)))
        with self.sem.wait(timeout):
            topv = self._topvalue()
            if self.data_idx + (topv + 1) * self.itemsz >= self.mm_end:
                return None
            item_idx = self.data_idx + topv * self.itemsz
            self.mm[item_idx:item_idx+self.itemsz] = item
            self._topvalue(topv + 1)
            return item
    def pop(self, timeout=-1):
        with self.sem.wait(timeout):
            topv, item = self._top()
            if topv > 0:
                self._topvalue(topv - 1)
            return item
    def top(self, timeout=-1):
        with self.sem.wait(timeout):
            return self._top()[1]
    def _top(self):
        topv = self._topvalue()
        if topv <= 0:
            return (topv, None)
        item_idx = self.data_idx + (topv - 1) * self.itemsz
        item = self.mm[item_idx:item_idx+self.itemsz]
        if self.fout:
            item = self.fout(item)
        return (topv, item)
# main
if __name__ == '__main__':
    pass
