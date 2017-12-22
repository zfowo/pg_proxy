#!/bin/env python3
# -*- coding: GBK -*-
# 
# structview : 用于简化读写struct。对于读写很长一段字节，可以用memoryview，比如：
#   mv = mvfrombuf(mm, 100, 100)
#   mv[:] = .....
# 
import sys, os, re
import struct
import itertools
import collections

__all__ = ['mvfrombuf', 'structview', 'struct_base', 'xval']

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

# 获得\x00结尾的字节串，返回字节串和下一个sidx。
# nullbyte表示返回值是否保留结尾的\x00字节。
def get_cstr(buf, sidx, nullbyte=False):
    idx = sidx
    while buf[sidx] != 0:
        sidx += 1
    sidx += 1
    if nullbyte:
        d = buf[idx:sidx]
    else:
        d = buf[idx:sidx-1]
    return d, sidx
# xval表示单个字节串
class xval(object):
    _c2fmt = [None, 'B', 'H', None, 'I']
    def __init__(self, data, c, flag):
        self.data = bytes(data)
        self.c = c
        if self.c not in (0, 1, 2, 4):
            raise ValueError('c should be 0|1|2|4')
        if self.c == 0:
            if b'\x00' in self.data:
                raise ValueError(r'xval(format 0) can not contain \x00')
        self.flag = flag
        if self.flag not in structview.flag_list:
            raise ValueError('unknown flag:%s' % self.flag)
    def __str__(self):
        return '<xval data:{0} c:{1} flag:{2}>'.format(self.data, self.c, self.flag)
    def __repr__(self):
        return 'xval({0!r}, {1!r}, {2!r})'.format(self.data, self.c, self.flag)
    def __bytes__(self):
        return self.data
    def __len__(self):
        return len(self.data)
    def tobuf(self):
        if self.c == 0:
            return self.data + b'\x00'
        else:
            fmt = self.flag + self._c2fmt[self.c]
            return struct.pack(fmt, len(self.data)) + self.data
    @classmethod
    def frombuf(cls, c, flag, buf, sidx):
        if c == 0:
            data, sidx = get_cstr(buf, sidx)
        else:
            fmt = flag + cls._c2fmt[c]
            sz = struct.unpack(fmt, buf[sidx:sidx+c])[0]
            sidx += c
            data = buf[sidx:sidx+sz]
            sidx += sz
        return cls(data, c, flag), sidx
# Xval表示多个字节串
# c=0时不支持空字节串
class Xval(object):
    def __init__(self, data_list, c, flag):
        self.xval_list = [xval(d, c, flag) for d in data_list]
        self.c = c
        self.flag = flag
        if self.c == 0 and any(len(xv)==0 for xv in self.xval_list):
            raise ValueError('Xval does not support empty byte string while c=0')
    def __iter__(self):
        yield from self.xval_list
    def tobuf(self):
        res = b''
        if self.c > 0:
            fmt = self.flag + xval._c2fmt[self.c]
            res += struct.pack(fmt, len(self.xval_list))
        for v in self.xval_list:
            res += v.tobuf()
        if self.c == 0:
            res += b'\x00'
        return res
    @classmethod
    def frombuf(cls, c, flag, buf, sidx):
        data_list = []
        if c == 0:
            while buf[sidx] != 0:
                d, sidx = get_cstr(buf, sidx)
                data_list.append(d)
            sidx += 1
        else:
            fmt = flag + xval._c2fmt[c]
            cnt = struct.unpack(fmt, buf[sidx:sidx+c])[0]
            sidx += c
            for i in range(cnt):
                sz = struct.unpack(fmt, buf[sidx:sidx+c])[0]
                sidx += c
                data_list.append(buf[sidx:sidx+sz])
                sidx += sz
        return cls(data_list, c, flag), sidx
# meta class for struct_base
class struct_meta(type):
    def __new__(cls, name, bases, ns):
        if '_formats' not in ns or '_fields' not in ns:
            raise ValueError('class %s should has _formats and _fields' % name)
        
        _fields = ns['_fields']
        if type(_fields) == str:
            _fields = _fields.split()
        if set(_fields) & set(ns):
            raise ValueError('_fields can not contain class attribute')
        ns['_fields'] = tuple(_fields)
        
        _formats = ns['_formats']
        if type(_formats) == str:
            _formats = _formats.split()
        _formats_res = []
        for fmt in _formats:
            _formats_res.append(__class__._parse_format(fmt))
        ns['_formats'] = tuple(_formats_res)
        
        if len(ns['_formats']) != len(ns['_fields']):
            raise ValueError('_formats should be equal with _fields')
        return super().__new__(cls, name, bases, ns)
    @staticmethod
    def _parse_format(fmt):
        n = ''.join(itertools.takewhile(lambda c: c in '-0123456789', fmt))
        fmt = fmt[len(n):]
        n = int(n) if n else 0
        
        flag = fmt[0]
        if flag not in structview.flag_list:
            raise ValueError('unknown flag:%s' % fmt[0])
        
        fmt = fmt[1:]
        pitem = '%s[%s%s]' % (r'\d*', '|'.join(structview.format_list), r'|s|x|X')
        p = r'^(%s)+$' % pitem
        if not re.match(p, fmt):
            raise ValueError('wrong format:%s' % fmt)
        fmt_list = tuple(re.findall(pitem, fmt))
        return (n, flag, fmt_list)
    
# 
# _formats : 指定格式
#     [n]<flag>ff...  : n指定后面的模式重复读取几次，0/1都表示读取一次，不过1是返回长度为1的列表；
#                       如果n<0，则表示从第-n-1个属性读取n值。
# flag必须指定，有效值是structview.flag_list里面的值。
# f是单个字符，必须是structview.format_list里面的字符，或者下面这些自定义的字符: 
#     [0|n]x : 单个串。0表示字节串以\x00结尾；n(1|2|4)表示开头n个字节为字节串的大小。
#     [0|n]X : 多个串。0表示多个字节串以\x00结尾，单个字节串也以\x00结尾，也就是最后会有2个\x00；
#                      n(1|2|4)表示开头n个字节表示字节串数量，每个字节串前面也有表示字节串大小的n个字节。
# 
# _fields : _formats中对应项的属性名。不能包含buf以及类已有的属性。
# 
class struct_base(metaclass=struct_meta):
    _formats = ('>b', '2>i', '-1>i')
    _fields = 'v1 v2 v3'
    # 
    def __init__(self, buf=None, **kwargs):
        if buf is not None and kwargs:
            raise ValueError('kwargs can not contain buf')
        if buf:
            self._init_from_buf(buf)
        else:
            self._init_from_kwargs(kwargs)
    def _init_from_buf(self, buf):
        sidx = 0
        for fmt_spec, field in zip(self._formats, self._fields):
            sidx = self._read(fmt_spec, field, buf, sidx)
        self._sidx = sidx
    def _init_from_kwargs(self, kwargs):
        if set(self._fields) != set(kwargs):
            raise ValueError('wrong kwargs, should contain %s' % self._fields)
        # 这里不检查参数值的有效性，在tobytes函数里会抛出异常。
        for k, v in kwargs.items():
            setattr(self, k, v)
    def _field_ref(self, n):
        fn = self._fields[(-n)-1]
        n = getattr(self, fn, None)
        if not isinstance(n, int):
            raise ValueError('field(%s) value should be int' % fe)
        return n
    def _read(self, fmt_spec, field, buf, sidx):
        n, flag, fmt_list = fmt_spec
        if n == 0:
            v, sidx = self._read_one(flag, fmt_list, buf, sidx)
        else:
            if n < 0:
                n = self._field_ref(n)
            v = []
            for i in range(n):
                x, sidx =self._read_one(flag, fmt_list, buf, sidx) 
                v.append(x)
        setattr(self, field, v)
        return sidx
    # 返回(val, next_sidx)
    def _read_one(self, flag, fmt_list, buf, sidx):
        res = []
        for fmt in fmt_list:
            f = fmt[-1]
            v, sidx = self._read_map[f](flag, fmt, buf, sidx)
            res.extend(v)
        if len(res) == 1:
            return res[0], sidx
        return res, sidx
    def tobytes(self):
        res = b''
        for fmt_spec, field in zip(self._formats, self._fields):
            res += self._write(fmt_spec, field)
        return res
    def _write(self, fmt_spec, field):
        n, flag, fmt_list = fmt_spec
        fval = getattr(self, field)
        if n == 0: # fval可以是单值或者序列。
            res, leftval = self._write_one(flag, fmt_list, fval)
        else: # fval必须是序列，fval中的元素可以是单值或者序列。
            if n < 0:
                n = self._field_ref(n)
            res = b''
            for i in range(n):
                d, leftval = self._write_one(flag, fmt_list, fval[i])
                if leftval:
                    break
                res += d
        if leftval:
            raise ValueError('attribute(%s) has too many values:%s' % (field, leftval))
        return res
    def _write_one(self, flag, fmt_list, val):
        if type(val) in (str, bytes, bytearray, Xval) or not isinstance(val, collections.Sequence):
            val = [val]
        res = b''
        for fmt in fmt_list:
            f = fmt[-1]
            d, val = self._write_map[f](flag, fmt, val)
            res += d
        return res, val
    # read map
    # 下面这些函数没有self，也不能是staticmethod或者classmethod，因为是通过字典_read_map来访问它们，
    # 所以不会通过描述符协议。
    # _read_xxx函数返回值列表和下一个sidx
    def _read_std(flag, fmt, buf, sidx):
        sz = struct.calcsize(flag+fmt)
        res = struct.unpack(flag+fmt, buf[sidx:sidx+sz])
        return res, sidx+sz
    def _read_x(flag, fmt, buf, sidx):
        c = fmt[:-1]
        c = int(c) if c else 0
        v, sidx = xval.frombuf(c, flag, buf, sidx)
        return [v], sidx
    def _read_X(flag, fmt, buf, sidx):
        c = fmt[:-1]
        c = int(c) if c else 0
        v, sidx = Xval.frombuf(c, flag, buf, sidx)
        raise [v], sidx
    _read_map = dict(zip(structview.format_list, itertools.repeat(_read_std)))
    _read_map['x'] = _read_x
    _read_map['X'] = _read_X
    # write map
    # _write_xxx函数返回结果字节串和剩余的值列表
    def _write_s(flag, fmt, val):
        res = struct.pack(flag+fmt, val[0])
        return res, val[1:]
    def _write_std(flag, fmt, val):
        c = fmt[:-1]
        c = int(c) if c else 1
        res = struct.pack(flag+fmt, *val[:c])
        return res, val[c:]
    def _write_x(flag, fmt, val):
        c = fmt[:-1]
        c = int(c) if c else 0
        # xval支持__bytes__,所以不需要检查val[0]是否是xval类型。
        d = bytes(val[0])
        res = xval(d, c, flag).tobuf()
        return res, val[1:]
    def _write_X(flag, fmt, val):
        c = fmt[:-1]
        c = int(c) if c else 0
        # val[0]必须是个iterable，Xval支持iterable协议
        res = Xval(val[0], c, flag).tobuf()
        raise res, val[1:]
    _write_map = dict(zip(structview.format_list, itertools.repeat(_write_std)))
    _write_map['s'] = _write_s
    _write_map['x'] = _write_x
    _write_map['X'] = _write_X

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
