#!/bin/env python3
# -*- coding: GBK -*-
#
# 由于posix_ipc没有提供无名信号量，所以通过cffi实现。
# 
import sys, os, errno, struct
import contextlib
import cffi
from structview import *

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
    # value=None 表示不初始化sem
    def __init__(self, mm, idx, value=1):
        self.mm = mm
        self.idx = idx
        self.init_value = value
        self.init()
    def init(self):
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
# 共享对象 : 在共享内存中的布局: sem + <具体类型的管理数据> + <data>
# 
class ShmObjectBase(object):
    def __init__(self, itemsz, mm, start=0, end=0, semvalue=1, fin=None, fout=None):
        self.itemsz = itemsz
        self.fin = fin
        self.fout = fout
        
        self.mm = mm
        self.mm_start = start
        self.mm_end = end
        if self.mm_end <= 0:
            self.mm_end = len(mm)
        
        self.sem = Sem(mm, start, semvalue)
    def _misc_init(self):
        self.itemnum = (self.mm_end - self.data_idx) // self.itemsz
    def _apply_fin(self, item):
        if self.fin:
            item = self.fin(item)
        if type(item) != bytes or len(item) != self.itemsz:
            raise RuntimeError('wrong item: %s %s' % (item, type(item)))
        return item
    def _apply_fout(self, item):
        if self.fout and item != None: # None表示stack/queue为空
            item = self.fout(item)
        return item
# 
# Stack : 共享内存中包含: sem + top +        <data>
#                               |->top_idx   |->data_idx
# 
class Stack(ShmObjectBase):
    @classmethod
    def mmsize(cls, itemnum, itemsz):
        return Sem.SIZE + struct.calcsize('=i'), + itemnum * itemsz
    # semvalue=None 表示不初始化sem和top
    def __init__(self, itemsz, mm, start=0, end=-1, semvalue=1, fin=None, fout=None):
        super().__init__(itemsz, mm, start, end, semvalue, fin, fout)
        self.top_idx = self.mm_start + Sem.SIZE
        self.top_ = structview('=', 'i', self.mm, self.top_idx)
        self.data_idx = self.top_.nextpos()
        self.data = mvfrombuf(self.mm, self.data_idx)
        if semvalue != None:
            self.top_[0] = 0
        self._misc_init()
    def count(self, timeout=-1):
        with self.sem.wait(timeout):
            return self.top_[0]
    def push(self, item, timeout=-1):
        old_item = item
        item = self._apply_fin(item)
        with self.sem.wait(timeout):
            topv = self.top_[0]
            if topv >= self.itemnum: # stack is full
                return None
            item_idx = topv * self.itemsz
            self.data[item_idx:item_idx+self.itemsz] = item
            self.top_[0] = topv + 1
            return old_item
    def pop(self, timeout=-1):
        with self.sem.wait(timeout):
            topv, item = self._top()
            if topv > 0:
                self.top_[0] = topv - 1
            return item
    def top(self, timeout=-1):
        with self.sem.wait(timeout):
            return self._top()[1]
    def _top(self):
        topv = self.top_[0]
        if topv <= 0: # stack is empty
            return (topv, None)
        item_idx = (topv - 1) * self.itemsz
        item = self.data[item_idx:item_idx+self.itemsz]
        item = self._apply_fout(item)
        return (topv, item)
# 
# Queue : 共享内存中包含: sem + head + tail + <data>
# 当head/tail到达结尾的时候，则从头开始。如果tail在head前面，那么tail和head之间至少留一个item空间，
# 这个空闲item空间用于表示队列已满。所以如果要保存最多n个item，那么需要分配n+1个item的空间。
# 
class Queue(ShmObjectBase):
    @classmethod
    def mmsize(cls, itemnum, itemsz):
        return Sem.SIZE + struct.calcsize('=ii') + itemnum * itemsz
    # semvalue=None 表示不初始化sem和head/tail
    def __init__(self, itemsz, mm, start=0, end=-1, semvalue=1, fin=None, fout=None):
        super().__init__(itemsz, mm, start, end, semvalue, fin, fout)
        self.pointer_idx = self.mm_start + Sem.SIZE
        self.pointer = structview('=', 'ii', self.mm, self.pointer_idx, fields='head tail')
        self.data_idx = self.pointer.nextpos()
        self.data = mvfrombuf(self.mm, self.data_idx)
        if semvalue != None:
            self.pointer.head = 0
            self.pointer.tail = 0
        self._misc_init()
    def count(self, timeout=-1):
        with self.sem.wait(timeout):
            headv = self.pointer.head
            tailv = self.pointer.tail
            v = tailv - headv
            v = (v + self.itemnum) % self.itemnum
            return v
    def _isempty(self):
        headv = self.pointer.head
        tailv = self.pointer.tail
        if headv == tailv:
            return (True, headv, tailv)
        else:
            return (False, headv, tailv)
    def _isfull(self):
        headv = self.pointer.head
        tailv = self.pointer.tail
        if (tailv + 1) % self.itemnum == headv:
            return (True, headv, tailv)
        else:
            return (False, headv, tailv)
    def push(self, item, timeout=-1):
        old_item = item
        item = self._apply_fin(item)
        with self.sem.wait(timeout):
            isfull, headv, tailv = self._isfull()
            if isfull:
                return None
            item_idx = tailv * self.itemsz
            self.data[item_idx:item_idx+self.itemsz] = item
            tailv = (tailv + 1) % self.itemnum
            self.pointer.tail = tailv
            return old_item
    def _itemat(self, head=True):
        isempty, headv, tailv = self._isempty()
        if isempty:
            return (None, headv, tailv)
        if head:
            item_idx = headv * self.itemsz
        else:
            item_idx = ((tailv - 1 + self.itemnum) % self.itemnum) * self.itemsz
        item = self.data[item_idx:item_idx+self.itemsz]
        item = self._apply_fout(item)
        return (item, headv, tailv)
    def pop(self, timeout=-1):
        with self.sem.wait(timeout):
            item, headv, tailv = self._itemat()
            if headv != tailv:
                headv = (headv + 1) % self.itemnum
                self.pointer.head = headv
            return item
    def head(self, timeout=-1):
        with self.sem.wait(timeout):
            return self._itemat()[0]
    def tail(self, timeout=-1):
        with self.sem.wait(timeout):
            return self._itemat(False)[0]
# 
# 用于和worker通信，向worker发送task，然后接收结果，如果结果太大，则需要多次接收。
# 共享内存中包含3个sem和task/result区域。
# 3个sem为：
#   发送task: 主进程把task写到共享内存之后，把channel状态设为RUNNING，然后post该信号量通知worker有新的task。
#   接收结果: 主进程wait该信号量，然后读取结果，如果结果没接收完，则post第3个信号量。
#   下一个结果: 如果结果太大需要多次发送的话，主进程需要post该信号量通知worker发送下一个结果。
# 
class WorkerChannel(object):
    IDLE = 0
    RUNNING = 1
    # 派生类可以提供下面这4个函数
    def task_in(self, task):
        return task.encode('UTF-8')
    def task_out(self, task):
        return task.decode('UTF-8')
    def result_in(self, res):
        return res.encode('UTF-8')
    def result_out(self, res):
        return res.decode('UTF-8')
    # init表示是否初始化信号量。一般由主进程初始化。
    # tasksz/resultsz表示任务和结果区域的大小。
    def __init__(self, mm, start, tasksz, resultsz, init=True): 
        sz = sem.SIZE * 3 + tasksz + resultsz
        if start + sz > len(mm):
            raise RuntimeError("mm has not enough space. need %d after idx:%d" % (sz, start))
        
        self.mm = mm
        self.mm_start = start
        self.tasksz = tasksz
        self.task_idx = self.mm_start + sem.SIZE * 3
        self.task_header = structview('=', 'i', self.mm, self.task_idx)
        self.task_data = mvfrombuf(self.mm, self.task_header.nextpos(), self.tasksz - self.task_header.size)
        self.resultsz = resultsz
        self.result_idx = self.task_idx + self.tasksz
        self.result_header = structview('=', 'bi', self.mm, self.result_idx)
        self.result_data = mvfrombuf(self.mm, self.result_header.nextpos(), self.resultsz - self.result_header.size)
        self.status = self.__class__.IDLE
        
        init_value = (0 if init else None)
        self.task_sem = sem(self.mm, self.mm_start, init_value)
        self.res_sem = sem(self.mm, self.mm_start + sem.SIZE, init_value)
        self.next_res_sem = sem(self.mm, self.mm_start + sem.SIZE * 2, init_value)
    # 把任务数据写到task区域，开头4个字节是任务数据的大小。
    # 主进程在调用该函数之前，需要检查status是否是IDLE。
    def put_task(self, task):
        if self.status != self.__class__.IDLE:
            raise RuntimeError("can not put task while status is not IDLE")
        taskdata = self.task_in(task)
        sz = len(taskdata)
        if sz + self.task_header.size > self.tasksz:
            raise RuntimeError("task data is too large")
        
        self.task_header[0] = sz
        self.task_data[:sz] = taskdata
        self.status = self.__class__.RUNNING
        self.task_sem.post()
        self.next_res_sem.post()
    # worker调用该函数
    def get_task(self):
        self.task_sem.wait()
        sz = self.task_header[0]
        d = self.task_data[:sz]
        return self.task_out(d)
    # worker调用该函数
    def put_result(self, result, last=True):
        resultdata = self.result_in(result)
        sz = len(resultdata)
        if sz + self.result_header.size > self.resultsz:
            raise RuntimeError("result data is too large")
        
        self.next_res_sem.wait()
        hasnext_flag = (0 if last else 1)
        self.result_header[0] = hasnext_flag
        self.result_header[1] = sz
        self.result_data[:sz] = resultdata
        self.res_sem.post()
    # 主进程调用该函数。可能会抛出OSError异常。
    def get_result(self, timeout=0):
        self.res_sem.wait(timeout)
        hasnext_flag = self.result_header[0]
        sz = self.result_header[1]
        d = self.result_data[:sz]
        if hasnext_flag: 
            self.next_res_sem.post()
        else:
            self.status = self.__class__.IDLE
        return self.result_out(d)
# 
# HashTable : 共享内存中包含: 
#             sem : 信号量
#             <bucket count> : 桶的数量。
#             <data block size> : 数据块大小。
#             <idle item header pointer> : 指向空闲ItemHeader列表，如果没有空闲，则为0。
#             <idle data block pointer> : 指向空闲DataBlock列表，如果没有空闲，则为0。
#             <total item count> : 哈希表中item的数量。
#             <bucket header list> : 固定大小的BucketHeader列表。
#             <data block list> : DataBlock列表。
# DataBlock的大小是ItemHeader大小的倍数，初始化的时候先从开头的n块DataBlock初始化空闲ItemHeader列表。
# 如果没有空闲ItemHeader了，则再从空闲DataBlock分配一批，如果没有空闲DataBlock，那么表示哈希表已满。
# ItemHeader大小为16个字节，包含: 
#     <next item header pointer> : 4个字节
#     <key size> : 2个字节
#     <value size> : 2个字节
#     <key hash value> : 4个字节，key的哈希值
#     <data block pointer> : 指向保存key/value的第一个DataBlock，数据块的最后4个字节指向下一个数据块，但最后一个数据块的最后4个字节不是指针。
# BucketHeader的大小为8个字节，包含: 
#     <item header pointer> : 4个字节，指向第一个ItemHeader
#     <item count> : 4个字节，本桶中的item数量
# 
class HashTable(object):
    pass
# main
if __name__ == '__main__':
    pass
