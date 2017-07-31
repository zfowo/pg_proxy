#!/bin/env python3
# -*- coding: GBK -*-
# 
# 信号量保护的共享内存
# 
import sys, os
import posix_ipc as ipc
import mmap
import contextlib

@contextlib.contextmanager
def timed_acquire(sem_obj, timeout=None):
    sem_obj.acquire(timeout)
    try:
        yield sem_obj
    finally:
        sem_obj.release()

class shm(object):
    PAGE_SIZE = ipc.PAGE_SIZE
    def __init__(self, prefix, name, size=0, part_spec=None, open_only=False, read_only=False):
        self.prefix = prefix
        self.name = name
        self.open_only = open_only
        self.read_only = read_only
        self.shm_obj = None
        self.sem_obj = None
        self.part_sem_obj_list = [] # list of (upper_bound, sem_obj)
        self.mm = None
        
        flags = 0
        prot = mmap.PROT_READ
        if not open_only:
            flags = ipc.O_CREAT | ipc.O_EXCL
            if size <= 0:
                raise RuntimeError('size should be greater than 0 while open_only=False')
        if not read_only:
            prot = prot | mmap.PROT_WRITE
        self.shm_obj = ipc.SharedMemory('%s.%s' % (prefix, name), flags=flags, size=size, read_only=read_only)
        self.sem_obj = ipc.Semaphore('%s.%s' % (prefix, name), flags=flags, initial_value=1)
        if part_spec:
            self._init_part_sems(part_spec, flags)
        self.mm = mmap.mmap(self.shm_obj.fd, 0, prot=prot)
    def _init_part_sems(self, part_spec, flags):
        prev_ub = 0
        for ub in part_spec:
            if ub <= prev_ub:
                raise RuntimeError('upper_bound(%d) <= prev upper_bound(%d)' % (ub, prev_ub))
            if ub > self.shm_obj.size:
                raise RuntimeError('upper_bound(%d) > shm_size(%d)' % (ub, self.shm_obj.size))
            prev_ub = ub
        for upper_bound in part_spec:
            sem_obj = ipc.Semaphore('%s.%s.%d' % (self.prefix, self.name, upper_bound), flags=flags, initial_value=1)
            self.part_sem_obj_list.append((upper_bound, sem_obj))
    def close(self):
        if self.mm:
            self.mm.close()
        if self.shm_obj:
            self.shm_obj.close_fd()
        if self.sem_obj:
            self.sem_obj.close()
        if self.part_sem_obj_list:
            for x in self.part_sem_obj_list:
                x[1].close()
    # 对于创建者，要先unlink再close
    def unlink(self):
        if self.shm_obj:
            self.shm_obj.unlink()
        if self.sem_obj:
            self.sem_obj.unlink()
        if self.part_sem_obj_list:
            for x in self.part_sem_obj_list:
                x[1].unlink()
        return self
    # sidx是相对于part的起始位置
    # sz=-1表示一直读取到part结尾
    # pf(mm, sidx, sz, (start ,end))
    def get(self, sidx=0, sz=-1, part_idx=-1, pf=None, timeout=None):
        ret = None
        if part_idx < 0:
            with timed_acquire(self.sem_obj, timeout):
                if pf:
                    ret = pf(self.mm, sidx, sz, (0, self.shm_obj.size))
                else:
                    if sz < 0:
                        ret = self.mm[sidx:self.shm_obj.size]
                    else:
                        ret = self.mm[sidx:sidx+sz]
            return ret

        if part_idx >= len(self.part_sem_obj_list):
            raise RuntimeError('part_idx(%d) out of index' % (part_idx, ))
        x = self.part_sem_obj_list[part_idx]
        if part_idx > 0:
            prev_x = self.part_sem_obj_list[part_idx-1]
        else:
            prev_x = (0, None)
        with timed_acquire(x[1], timeout):
            if pf:
                ret = pf(self.mm, sidx, sz, (prev_x[0], x[0]))
            else:
                if sz < 0:
                    ret = self.mm[prev_x[0]+sidx:x[0]]
                else:
                    ret = self.mm[prev_x[0]+sidx:prev_x[0]+sidx+sz]
        return ret
    # sidx是相对于part的起始位置
    # pf(mm, data, sidx, (start, end))
    def put(self, data, sidx=0, part_idx=-1, pf=None, timeout=None):
        d_len = len(data)
        if part_idx < 0:
            with timed_acquire(self.sem_obj, timeout):
                if pf:
                    pf(self.mm, data, sidx, (0, self.shm_obj.size))
                else:
                    self.mm[sidx:sidx+d_len] = data
            return self
        
        if part_idx >= len(self.part_sem_obj_list):
            raise RuntimeError('part_idx(%d) out of index' % (part_idx, ))
        x = self.part_sem_obj_list[part_idx]
        if part_idx > 0:
            prev_x = self.part_sem_obj_list[part_idx-1]
        else:
            prev_x = (0, None)
        with timed_acquire(x[1], timeout):
            if pf:
                pf(self.mm, data, sidx, (prev_x[0], x[0]))
            else:
                self.mm[prev_x[0]+sidx:prev_x[0]+sidx+d_len] = data
        return self
# main
if __name__ == '__main__':
    pass

