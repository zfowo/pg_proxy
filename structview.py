#!/bin/env python3
# -*- coding: GBK -*-
# 
# structview : 用于简化读写struct。对于读写很长一段字节，可以用memoryview，比如：
#   mv = mvfrombuf(mm, 100, 100)
#   mv[:] = .....
# 
import sys, os
import struct

__all__ = ['mvfrombuf', 'structview']

def mvfrombuf(buf, start, sz = -1):
    mv = memoryview(buf)
    if sz == -1:
        return mv[start:]
    else:
        return mv[start:start + sz]

class structview(object):
    flag_list = tuple('@=<>!')
    format_list = tuple('bBhHiIlLqQfd')
    # 下面4个函数分别对应 "native order native size" "native order std size" "little order std size" "big order std size"
    @classmethod
    def nat_nat(cls, *args, **kwargs):
        return cls('@', *args, **kwargs)
    @classmethod
    def nat_std(cls, *args, **kwargs):
        return cls('=', *args, **kwargs)
    @classmethod
    def little_std(cls, *args, **kwargs):
        return cls('<', *args, **kwargs)
    @classmethod
    def big_std(cls, *args, **kwargs):
        return cls('>', *args, **kwargs)
    # buf可以是bytes,bytearray,mmap,以及format='B'的memoryview。
    def __init__(self, flag, format, buf, start = 0, fields = None):
        if flag not in self.__class__.flag_list:
            raise ValueError("Wrong flag:%s" % flag)
        for f in format:
            if f not in self.__class__.format_list:
                raise ValueError("Wrong format:%s" % f)
        self.flag = flag
        self.format = format
        self.size = struct.calcsize(self.flag + self.format)
        self.buf = buf
        self.buf_start = start
        if self.buf_start + self.size > len(buf):
            raise ValueError("buf has not enouth space after idx %d. need %d" % (start, sz))
        # build index. list of (idx, sz)
        self.index = []
        sidx = self.buf_start
        for f in format:
            sz = struct.calcsize(self.flag + f)
            self.index.append((sidx, sz))
            sidx += sz
        self.index = tuple(self.index)
        # fields放在最后处理，因为需要检查fields里是否有self本身有的属性。
        if not fields:
            fields = ()
        elif type(fields) == str:
            fields = fields.split()
        for fld in fields:
            if fld in self.__dict__:
                raise ValueError("fields can not contain %s" % fld)
        self.fields = tuple(fields)
    def nextpos(self):
        return self.buf_start + self.size
    def __len__(self):
        return len(self.format)
    def _get_ffii(self, idx):
        try:
            return self.format[idx], self.index[idx]
        except IndexError:
            raise IndexError("structview index out of range") from None
        except TypeError:
            raise TypeError("strutview indices must be integer or slice") from None
    def __getitem__(self, idx):
        ff, ii = self._get_ffii(idx)
        t = type(idx)
        if t == int:
            fmt = self.flag + ff
            i = ii
            return struct.unpack(fmt, self.buf[i[0]:i[0]+i[1]])[0]
        elif t == slice:
            res = []
            for f, i in zip(ff, ii):
                fmt = self.flag + f
                v = struct.unpack(fmt, self.buf[i[0]:i[0]+i[1]])[0]
                res.append(v)
            return res
        else:
            raise TypeError("strutview indices must be integer or slice")
    def __setitem__(self, idx, value):
        ff, ii = self._get_ffii(idx)
        t = type(idx)
        if t == int:
            fmt = self.flag + ff
            i = ii
            self.buf[i[0]:i[0]+i[1]] = struct.pack(fmt, value)
        elif t == slice:
            if len(ff) != len(value):
                raise ValueError("wrong len in value")
            for f, i, v in zip(ff, ii, value):
                fmt = self.flag + f
                self.buf[i[0]:i[0]+i[1]] = struct.pack(fmt, v)
        else:
            raise TypeError("strutview indices must be integer or slice")
    def _field2idx(self, field):
        # 在__init__里面可能在初始化self.fields之前就访问不存在的属性
        if 'fields' not in self.__dict__:
            return -1
        try:
            idx = self.fields.index(field)
        except ValueError:
            idx = -1
        return idx
    def __getattr__(self, name):
        idx = self._field2idx(name)
        if idx == -1:
            raise AttributeError("no attribute:%s" % name)
        return self[idx]
    def __setattr__(self, name, value):
        idx = self._field2idx(name)
        if idx == -1:
            return super().__setattr__(name, value)
        self[idx] = value
# main
if __name__ == '__main__':
    sv = structview('=', 'iii', bytearray(12), fields = 'a b c')
    sv.a = 1; sv.b = 2; sv.c = 3
    print(list(sv))
    x, y, z = sv
    sv[0] += 1
    sv[1] += 1
    sv[2] += 1
    print(list(sv))
