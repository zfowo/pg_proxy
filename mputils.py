#!/bin/env python3
# -*- coding: GBK -*-
# 
# meta programming相关的一些比较通用的代码
# 
import functools
import collections

# 不能重复赋值的dict
class NoRepeatAssignMap(dict):
    def __setitem__(self, key, val):
        if key in self:
            raise ValueError('key(%s) already in dict. val is %s' % (key, val))
        super().__setitem__(key, val)

def assert_no_attr(obj, *attnames):
    for an in attnames:
        if hasattr(obj, an):
            raise ValueError('%s already has attribute %s' % (obj, an))
# 如果iterfn/getfn为None，那么就用__iter__/__getitem__，如果getfn是None，那么还要增加__len__函数。
# 如果iterfn/getfn为空串，则函数名为get_<restype>s和get_<restype>，如果restype=None则报错。
# 如果restype为None，那么iterfn/getfn不能为空串，此时不会创建namedtuple类型。
# f对属性中的每个数据先做处理一下再传给restype或者直接返回。
def SeqAccess(cls=None, *, attname, iterfn=None, getfn=None, restype=None, resfields='', f=lambda x:x):
    if cls is None:
        return functools.partial(SeqAccess, attname=attname, iterfn=iterfn, getfn=getfn, restype=restype, resfields=resfields, f=f)
    
    t = None
    if restype:
        assert_no_attr(cls, restype)
        t = collections.namedtuple(restype, resfields)
        setattr(cls, restype, t)
    
    if iterfn is None:
        iterfn = '__iter__'
    elif iterfn == '':
        if restype:
            iterfn = 'get_%ss' % restype
        else:
            raise ValueError('iterfn can not be empty while restype is None')
    if getfn is None:
        getfn = '__getitem__'
    elif getfn == '':
        if restype:
            getfn = 'get_%s' % restype
        else:
            raise ValueError('getfn can not be empty while restype is None')
    assert_no_attr(cls, iterfn, getfn)
    
    def MyIter(self):
        for x in getattr(self, attname):
            v = f(x)
            yield t(*v) if restype else v
    MyIter.__name__ = iterfn
    MyIter.__qualname__ = '%s.%s' % (cls.__name__, iterfn)
    setattr(cls, iterfn, MyIter)
    
    def MyGet(self, idx):
        v = getattr(self, attname)
        v = f(v[idx])
        return t(*v) if restype else v
    MyGet.__name__ = getfn
    MyGet.__qualname__ = '%s.%s' % (cls.__name__, getfn)
    setattr(cls, getfn, MyGet)
    
    def MyLen(self):
        v = getattr(self, attname)
        return len(v)
    MyLen.__name__ = '__len__'
    MyLen.__qualname__ = '%s.%s' % (cls.__name__, '__len__')
    if getfn == '__getitem__':
        assert_no_attr(cls, '__len__')
        setattr(cls, '__len__', MyLen)
    return cls

# 往类cls里添加check函数
def Check(cls=None, *, attname, attvals, fnfmt='_check_%s'):
    if cls is None:
        return functools.partial(Check, attname=attname, attvals=attvals)
    def MyCheck(self, v):
        if v not in attvals:
            raise ValueError('val(%s) not in %s' % (v, attvals))
    fn = fnfmt % attname
    MyCheck.__name__ = fn
    MyCheck.__qualname__ = '%s.%s' % (cls.__name__, fn)
    assert_no_attr(cls, fn)
    setattr(cls, fn, MyCheck)
    return cls
# 有时需要定义一些常量值，而又希望从常量值获得对应的符号名，这就需要定义个从常量值到符号名的映射表。
# 本元类的作用就是创建这个映射表。
class V2SMapMeta(type):
    def __init__(self, name, bases, ns, **kwargs):
        super().__init__(name, bases, ns)
    # v2s_attname指定要创建的属性的名字；skip指定那些常量值不保存；strip指定从符号名开头去掉几个字符。
    def __new__(cls, name, bases, ns, v2s_attname='v2smap', skip=(), strip=0):
        if v2s_attname in ns:
            raise ValueError('class %s should not define attribute %s' % v2s_attname)
        v2smap = NoRepeatAssignMap()
        for s, v in ns.items():
            if s[0] == '_' or callable(v):
                continue
            if v not in skip:
                s = s[strip:]
                v2smap[v] = s
        ns[v2s_attname] = v2smap
        return super().__new__(cls, name, bases, ns)

