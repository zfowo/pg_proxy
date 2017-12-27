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

# struct_base etc.
__all__ += ['struct_meta', 'struct_base', 'xval', 'Xval', 'def_struct']
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
# xval表示单个字节串。在创建xval对象后不要修改它的属性值。
# c=0表示字节串以\x00结尾，这时字节串中不能包含\x00。
# c>0表示字节串前面有c个字节表示字节串的大小，这时字节串可以包含\x00。
# c>0时，大小前缀支持负数，负数表示后面没有字节串，不过这个负值对某些应用可能有特别的意义。
class xval(object):
    _c2fmt = [None, 'b', 'h', None, 'i']
    # c=0时后面的flags和sz参数无意义
    # sz不能大于0，sz<0时表示是个负值串
    # 如果data是xval对象，那么将会丢失负值串信息。可以用make来从一个xval创建新的xval，这样可以保留负值串信息。
    def __init__(self, data, c=1, flag='>', sz=0):
        self.data = bytes(data)
        self.c = c
        if self.c not in (0, 1, 2, 4):
            raise ValueError('c should be 0|1|2|4')
        if self.c == 0:
            if b'\x00' in self.data:
                raise ValueError(r'xval(format 0) can not contain \x00')
        self.flag = flag
        if self.flag not in struct_meta.flag_list:
            raise ValueError('unknown flag:%s' % self.flag)
        
        self.sz = sz
        if self.sz > 0:
            raise ValueError('sz can not be greater than 0')
        if self.c == 0 and self.sz < 0:
            raise ValueError('sz can not be less than 0 while c is 0')
        if self.c > 0 and self.sz < 0:
            self.data = b''
    def __repr__(self):
        if self.sz < 0:
            return "<xval data:-1>"
        else:
            return "<xval data:{}>".format(self.data,)
    def _info(self):
        return "<xval data:{} c:{} flag:'{}' sz:{}>".format(self.data, self.c, self.flag, self.sz)
    def __bytes__(self):
        return self.data
    def __len__(self):
        return len(self.data)
    def __getitem__(self, idx):
        return self.data[idx]
    def make(self, c, flag):
        if c == self.c and flag == self.flag:
            return self
        if c == 0:
            return xval(self.data, c, flag)
        else:
            return xval(self.data, c, flag, self.sz)
    def tobuf(self):
        if self.c == 0:
            return self.data + b'\x00'
        else:
            fmt = self.flag + self._c2fmt[self.c]
            if self.sz < 0:
                return struct.pack(fmt, self.sz)
            else:
                return struct.pack(fmt, len(self.data)) + self.data
    @classmethod
    def frombuf(cls, c, flag, buf, sidx):
        if c == 0:
            data, sidx = get_cstr(buf, sidx)
            sz = 0
        else:
            fmt = flag + cls._c2fmt[c]
            sz = struct.unpack(fmt, buf[sidx:sidx+c])[0]
            sidx += c
            data = b''
            if sz > 0:
                data = buf[sidx:sidx+sz]
                sidx += sz
                sz = 0
        return cls(data, c, flag, sz), sidx
# Xval表示多个字节串。
# c1=0时，单个字节串以\x00结尾，整个Xval也以\x00结尾，所以单个字节串不允许是空串。
# c1>0时，开头有c1个字节表示有多少个串，c2表示单个串的格式，即使c2=0也支持空串。
# **需要特别注意的是**：
#   如果data_list里面有c2>0的xval，那么用c2=0构造Xval的时候会导致负值串信息丢失，负值串会变成空串。
#   所以最好用属性对应的c1/c2来初始化Xval(可以调用struct_base.fmt函数来获得c1/c2)，
#   或者初始化Xval的时候不用c2=0，所以把c1/c2的缺省值改为非0。
class Xval(object):
    _c2fmt = [None, 'b', 'h', None, 'i']
    def __init__(self, data_list, c1=1, c2=1, flag='>'):
        if c1 not in (0, 1, 2, 4):
            raise ValueError('wrong c1 for Xval')
        if c1 == 0 and c2 != 0:
            raise ValueError('c2 should be 0 while c1 is 0')
        self.c = c1
        
        self.xval_list = []
        for d in data_list:
            if isinstance(d, xval):
                d = d.make(c2, flag)
            else:
                d = xval(d, c2, flag)
            self.xval_list.append(d)
        self.flag = flag
        if c1 == 0 and any(len(xv)==0 for xv in self.xval_list):
            raise ValueError('Xval does not support empty byte string while c1=0')
    def __repr__(self):
        return "<Xval xval_list:{}>".format(self.xval_list)
    def _info(self):
        return "<Xval xval_list:{} c:{} flag:'{}'>".format(len(self.xval_list), self.c, self.flag)
    def __len__(self):
        return len(self.xval_list)
    def __getitem__(self, idx):
        return self.xval_list[idx]
    def __iter__(self):
        yield from self.xval_list
    def tobuf(self):
        res = b''
        if self.c > 0:
            fmt = self.flag + self._c2fmt[self.c]
            res += struct.pack(fmt, len(self.xval_list))
        for v in self.xval_list:
            res += v.tobuf()
        if self.c == 0:
            res += b'\x00'
        return res
    @classmethod
    def frombuf(cls, c1, c2, flag, buf, sidx):
        data_list = []
        if c1 == 0:
            while buf[sidx] != 0:
                d, sidx = xval.frombuf(c2, flag, buf, sidx)
                data_list.append(d)
            sidx += 1
        else:
            fmt = flag + cls._c2fmt[c1]
            cnt = struct.unpack(fmt, buf[sidx:sidx+c1])[0]
            sidx += c1
            for i in range(cnt):
                d, sidx = xval.frombuf(c2, flag, buf, sidx)
                data_list.append(d)
        return cls(data_list, c1, c2, flag), sidx
# struct attribute descriptor
# 不用实现__get__，这样通过类访问会返回描述符本身，通过instance访问的话会返回instance字典里的同名属性。
class struct_attr_descriptor(object):
    def __init__(self, name, fmt_spec):
        self.name = name
        self.fmt_spec = fmt_spec
    # 目前只检查是否是序列以及序列的长度，
    # 不检查值是否有效，如果值无效那么tobytes函数会抛出异常。
    def __set__(self, instance, val):
        if getattr(instance, '_check_assign', True):
            n, flag, fmt_list, fmt_str, fmt_info = self.fmt_spec
            sz = len(fmt_str)
            if n == 0:
                if sz > 1:
                    self._check_sequence(val, sz)
            else:
                if n < 0:
                    n = instance._field_ref(n)
                self._check_sequence(val, n)
                if sz > 1:
                    for item in val:
                        self._check_sequence(item, sz)
            self._apply_instance_check(instance, val)
        instance.__dict__[self.name] = val
    # sz <  0 只检查是否是序列
    # sz >= 0 检查是否是序列，并且大小是否是sz
    def _check_sequence(self, v, sz = -1):
        if not isinstance(v, collections.Sequence):
            raise ValueError('val(%s) is not sequence' % v)
        if sz >= 0 and len(v) != sz:
            raise ValueError('len of val(%s) is not equal %s' % (v, sz))
    # 检查instance是否提供了相关的检查函数，如果有就调用它。
    def _apply_instance_check(self, instance, val):
        m = getattr(instance, '_check_'+self.name, None)
        if not m:
            return
        m(val)
# meta class for struct_base
# _formats和_fields必须同时指定，或者都不指定，如果都不指定，那么继承基类。
class struct_meta(type):
    flag_list = structview.flag_list
    format_list = structview.format_list + tuple('sxX')
    def __repr__(self):
        return "<class '%s.%s' _formats='%s' _fields='%s'>" % (self.__module__, self.__name__, self._formats_original, self._fields_original)
    def __new__(cls, name, bases, ns):
        if '_formats' not in ns and '_fields' not in ns:
            return super().__new__(cls, name, bases, ns)
        if '_formats' not in ns or '_fields' not in ns:
            raise ValueError('class %s should has _formats and _fields' % name)
        if '_field2idx' in ns:
            raise ValueError('class %s should not define _field2idx' % name)
        ns['_formats_original'] = ns['_formats']
        ns['_fields_original'] = ns['_fields']
        
        _fields = ns['_fields']
        if type(_fields) == str:
            _fields = _fields.split()
        if set(_fields) & set(ns):
            raise ValueError('_fields can not contain class attribute')
        for fn in _fields:
            if fn[0] == '_':
                raise ValueError('fieldname in _fields can not starts with undercore')
        ns['_fields'] = tuple(_fields)
        field2idx = {}
        for idx, fn in enumerate(ns['_fields']):
            field2idx[fn] = idx
        ns['_field2idx'] = field2idx
        
        _formats = ns['_formats']
        if type(_formats) == str:
            _formats = _formats.split()
        _formats_res = []
        for idx, fmt in enumerate(_formats):
            _formats_res.append(cls._parse_format(fmt, idx))
        ns['_formats'] = tuple(_formats_res)
        
        if len(ns['_formats']) != len(ns['_fields']):
            raise ValueError('_formats should be equal with _fields')
        # add descriptor
        for fn, fmt_spec in zip(ns['_fields'], ns['_formats']):
            ns[fn] = struct_attr_descriptor(fn, fmt_spec)
        return super().__new__(cls, name, bases, ns)
    # 处理数字串n; idx当前处理的fmt是第几个; emptyval是n为空串时对应的值
    @classmethod
    def _process_n(cls, n, fmt, idx, emptyval):
        if n == '-0':
            if idx == 0:
                raise ValueError('first fmt(%s) can not contain -0' % fmt)
            else:
                n = -idx
        else:
            n = int(n) if n else emptyval
            if n < 0 and -n > idx:
                raise ValueError('fmt(%s) reference attribute behind it' % fmt)
        return n
    @classmethod
    def _parse_format(cls, fmt, idx):
        p_split = '([%s])' % ''.join(cls.flag_list)
        split_res = re.split(p_split, fmt)
        if len(split_res) != 3:
            raise ValueError('wrong format:%s' % fmt)
        n, flag, fmt = split_res
        n = cls._process_n(n, ''.join(split_res), idx, 0)
                
        pitem = '%s[%s]' % (r'-?\d*', ''.join(cls.format_list))
        p = r'^(%s)+$' % pitem
        if not re.match(p, fmt):
            raise ValueError('wrong format:%s' % fmt)
        fmt_list = re.findall(pitem, fmt)
        fmt_list_new = []
        fmt_str = ''
        fmt_info = []
        for fi in fmt_list:
            c, f = fi[:-1], fi[-1:]
            if f == 's':
                c = cls._process_n(c, fmt, idx, 1)
                fmt_str += f
                fmt_info.append(c)
                if c < 0: # 原始c可能是-0，所以需要修改fi
                    fi = '%s%s' % (c, f)
            elif f == 'x':
                c = int(c) if c else 0
                if c not in (0, 1, 2, 4):
                    raise ValueError('the prefix n of x in %s should be 0|1|2|4' % fmt)
                fmt_str += f
                fmt_info.append(c)
                fi = '%s%s' % (c, f)
            elif f == 'X':
                if not c:
                    c = '00'
                elif len(c) == 1:
                    c = c*2
                elif len(c) > 2:
                    raise ValueError('wrong prefix n(%s) for X in %s' % (c, fmt))
                c1, c2 = int(c[0]), int(c[1])
                if c1 not in (0, 1, 2, 4) or c2 not in (0, 1, 2, 4):
                    raise ValueError('the prefix n of X in %s should be 0|1|2|4' % fmt)
                if c1 == 0 and c2 != 0:
                    raise ValueError('the prefix n can not be 0(1|2|4) in %s' % fmt)
                fmt_str += f
                fmt_info.append(c)
                fi = '%s%s%s' % (c1, c2, f)
            else:
                c = int(c) if c else 1
                if c <= 0:
                    raise ValueError('the prefix n of %s in %s should not be less than 0' % (f,fmt))
                fmt_str += f*c
                fmt_info.extend([c]*c)
            fmt_list_new.append(fi)
        return (n, flag, tuple(fmt_list_new), fmt_str, tuple(fmt_info))
    
# 
# _formats : 指定格式
#     [n]<flag>ff...  : n指定后面的模式重复读取几次，0/1都表示读取一次，不过1是返回长度为1的列表；
#                       如果n<0，则表示从第-n-1个属性读取n值；如果n=-0，则表示从前一个属性读取n值。
# flag必须指定，有效值是struct_meta.flag_list里面的值。
# f是单个字符，必须是struct_meta.format_list里面的字符，f前面可以有数字前缀n，对于s，n<0的含义同前面一样
# f也可以是下面这些自定义的字符: 
#     [n]x : 单个串。0表示字节串以\x00结尾；(1|2|4)表示开头n个字节为字节串的大小。
#     [n]X : 多个串。n(c1c2)包含2个数字，如果第一个数字c1为0则第二个数字c2也必须为0。
#                    00表示多个字节串以\x00结尾，单个字节串也以\x00结尾，也就是最后会有2个\x00，不支持空串；
#                    c1>0则表示开头c1个字节表示字节串的数目，c2=0表示字节串以\x00结尾，c2>0表示字节串的前面c2个字节表示字节串的大小。
#                    除了00，其他格式其实可以用x来代替，比如'>11X'和'>b -0>1x'可以达到同样的效果。
# struct_meta会把_formats转换成fmt_spec的列表，fmt_spec包含5部分：
#     n, flag, fmt_list : fmt_list是单个fmt的序列
#     fmt_str : 不包含数字前缀的格式字符组成的串。对于非s/x/X格式字符，会根据前缀数字扩展。比如3i -> iii
#     fmt_info : 记录fmt_str中对应格式字符前面的数字
# 例子:
#   '>i' : 返回单个整数
#   '1>i' : 返回包含一个整数的列表
#   '>ii' : 返回包含两个整数的列表
#   '2>i' : 同上
#   '2>ii' : 返回列表的列表，列表中包含两个长度为2的整数列表，比如[[1,2],[3,4]]
# 
# _fields : _formats中对应项的属性名。不能包含buf以及类已有的属性。
# 
class struct_base(metaclass=struct_meta):
    _check_assign = True # 如果为True或者不定义，那么在描述符里将检查属性值
    _formats = ''
    _fields = ''
    # 获得field对应的format spec中的第idx个子format
    @classmethod
    def fmt(cls, field, idx=0):
        i = cls._field2idx[field]
        fmt_list = cls._formats[i][2]
        fi = fmt_list[idx]
        n, f = fi[:-1], fi[-1:]
        if f == 'X':
            return int(n[0]), int(n[1]), f
        elif f == 'x':
            return int(n), f
        n = int(n) if n else 1
        return n, f
    # 
    def __init__(self, buf=None, **kwargs):
        if buf is not None and kwargs:
            raise ValueError('buf and kwargs can not be given meanwhile')
        # 允许buf和kwargs都不指定，在创建一个空对象之后对属性逐个赋值，但是必须按照_fields里面的顺序赋值。
        #if buf is None and not kwargs:
        #    raise ValueError('buf or kwargs should be given')
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
        if set(kwargs) - set(self._fields):
            raise ValueError('kwargs contains keys which are not in %s' % self._fields)
        # 按_fields里面的顺序赋值
        for k in self._fields:
            if k in kwargs:
                setattr(self, k, kwargs[k])
    def _field_ref(self, n):
        fn = self._fields[(-n)-1]
        n = getattr(self, fn, None)
        if not isinstance(n, int):
            raise ValueError('field(%s) value should be int' % fe)
        return n
    def _read(self, fmt_spec, field, buf, sidx):
        n, flag, fmt_list, fmt_str, fmt_info = fmt_spec
        if n == 0:
            v, sidx = self._read_one(flag, fmt_list, buf, sidx)
        else:
            if n < 0: # 这个不能放在n==0前面，因为_field_ref可能返回0
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
            v, sidx = self._read_map[f](self, flag, fmt, buf, sidx)
            res.extend(v)
        if len(res) == 1:
            return res[0], sidx
        return res, sidx
    def __bytes__(self):
        return self.tobytes()
    def tobytes(self):
        res = b''
        for fmt_spec, field in zip(self._formats, self._fields):
            res += self._write(fmt_spec, field)
        return res
    def _write(self, fmt_spec, field):
        n, flag, fmt_list, fmt_str, fmt_info = fmt_spec
        fval = getattr(self, field)
        if isinstance(fval, struct_attr_descriptor):
            raise ValueError('attribute(%s) is not assigned' % field)
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
        if type(val) in (str, bytes, bytearray, xval, Xval) or not isinstance(val, collections.Sequence):
            val = [val]
        res = b''
        for fmt in fmt_list:
            f = fmt[-1]
            d, val = self._write_map[f](self, flag, fmt, val)
            res += d
        return res, val
    # 
    # read map & write map
    # 因为是通过字典_read_map来访问这些函数，所以不会通过描述符协议。
    # 因此在调用的时候需要提供self参数。
    # 
    # 处理数字串n，如果n为负则读取相应属性的值，如果为空串则返回emptyval
    def _process_n(self, n, emptyval):
        n = int(n) if n else emptyval
        if n < 0:
            n = self._field_ref(n)
        return n
    # _read_xxx函数返回值列表和下一个sidx
    def _read_s(self, flag, fmt, buf, sidx):
        n = self._process_n(fmt[:-1], 1)
        fmt = '%s%s%s' % (flag, n, fmt[-1])
        sz = struct.calcsize(fmt)
        res = struct.unpack(fmt, buf[sidx:sidx+sz])
        return res, sidx+sz
    def _read_std(self, flag, fmt, buf, sidx):
        fmt = flag + fmt
        sz = struct.calcsize(fmt)
        res = struct.unpack(fmt, buf[sidx:sidx+sz])
        return res, sidx+sz
    def _read_x(self, flag, fmt, buf, sidx):
        c = int(fmt[0])
        v, sidx = xval.frombuf(c, flag, buf, sidx)
        return [v], sidx
    def _read_X(self, flag, fmt, buf, sidx):
        c1, c2 = int(fmt[0]), int(fmt[1])
        v, sidx = Xval.frombuf(c1, c2, flag, buf, sidx)
        return [v], sidx
    _read_map = dict(zip(structview.format_list, itertools.repeat(_read_std)))
    _read_map['s'] = _read_s
    _read_map['x'] = _read_x
    _read_map['X'] = _read_X
    del _read_std, _read_x, _read_X
    # _write_xxx函数返回结果字节串和剩余的值列表
    # 对于s格式，strut.pack的时候，如果给定的字节串太长则会截断，如果太短则会用\x00填补。
    # 而struct.unpack的时候，必须给定相同长度的字节串。
    def _write_s(self, flag, fmt, val):
        n = self._process_n(fmt[:-1], 1)
        fmt = '%s%s%s' % (flag, n, fmt[-1])
        d = bytes(val[0])
        res = struct.pack(fmt, d)
        return res, val[1:]
    def _write_std(self, flag, fmt, val):
        n = self._process_n(fmt[:-1], 1)
        res = struct.pack(flag+fmt, *val[:n])
        return res, val[n:]
    def _write_x(self, flag, fmt, val):
        c = int(fmt[0])
        d = val[0]
        if isinstance(d, xval):
            d = d.make(c, flag)
        else:
            d = xval(d, c, flag)
        res = d.tobuf()
        return res, val[1:]
    def _write_X(self, flag, fmt, val):
        c1, c2 = int(fmt[0]), int(fmt[1])
        # val[0]必须是个iterable，Xval支持iterable协议
        res = Xval(val[0], c1, c2, flag).tobuf()
        return res, val[1:]
    _write_map = dict(zip(structview.format_list, itertools.repeat(_write_std)))
    _write_map['s'] = _write_s
    _write_map['x'] = _write_x
    _write_map['X'] = _write_X
    del _write_s, _write_std, _write_x, _write_X
# utility func to define struct_base derived class
def def_struct(name, formats, fields):
    return struct_meta(name, (struct_base,), {'_formats':formats, '_fields':fields})
# examples for testing
__all__ += ['S1', 'S2']
class S1(struct_base):
    _formats = '>i -0>xi'
    _fields = 'num name_age_list'
class S2(struct_base):
    _formats = '>i 1>i >ii 2>ii'
    _fields = 'v1 v2 v3 v4'
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
