#!/bin/env python3
# -*- coding: GBK -*-
# 
# meta programming��ص�һЩ�Ƚ�ͨ�õĴ���
# 
import functools
import collections

# �����ظ���ֵ��dict
class NoRepeatAssignMap(dict):
    def __setitem__(self, key, val):
        if key in self:
            raise ValueError('key(%s) already in dict. val is %s' % (key, val))
        super().__setitem__(key, val)

def assert_no_attr(obj, *attnames):
    for an in attnames:
        if hasattr(obj, an):
            raise ValueError('%s already has attribute %s' % (obj, an))
# 
# ���iterfn/getfnΪNone����ô����__iter__/__getitem__�����getfn��None����ô��Ҫ����__len__������
# ���iterfn/getfnΪ�մ���������Ϊget_<restype>s��get_<restype>�����restype=None�򱨴�
# ���restypeΪNone����ôiterfn/getfn����Ϊ�մ�����ʱ���ᴴ��namedtuple���͡�
# f�������е�ÿ��������������һ���ٴ���restype����ֱ�ӷ��ء�
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

# ����cls�����check����
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
# ��ʱ��Ҫ����һЩ����ֵ������ϣ���ӳ���ֵ��ö�Ӧ�ķ������������Ҫ������ӳ���ֵ����������ӳ���
# ��Ԫ������þ��Ǵ������ӳ���
class V2SMapMeta(type):
    def __init__(self, name, bases, ns, **kwargs):
        super().__init__(name, bases, ns)
    # v2s_attnameָ��Ҫ���������Ե����֣�skipָ����Щ����ֵ�����棻stripָ���ӷ�������ͷȥ�������ַ���
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
# Ϊ��cls��ÿ��ʵ����������һ��id
# ���������û��generateid����ô�������һ�������id�ӻ����е����һ��id��ʼ
def generateid(cls):
    cls._nextid = 0
    old_new = cls.__dict__.get('__new__')
    @staticmethod
    def mynew(cls2, *args, **kwargs):
        if old_new:
            obj = old_new(cls2, *args, **kwargs)
        else:
            obj = super(cls, cls2).__new__(cls2)
        cls2._nextid += 1
        obj.id = cls2._nextid
        return obj
    cls.__new__ = mynew
    return cls
# cmd_map����cmd_name -> (cmd_process_func, sub_cmd_map)
class mycmd():
    def __init__(self, name, cmd_map):
        self.name = name
        self.cmd_map = cmd_map
    def __call__(self, func):
        oldname = func.__name__
        func.__name__ = '%s_%s' % ('_cmd', self.name)
        func.__qualname__ = func.__qualname__.replace(oldname, func.__name__)
        self.cmd_map[self.name] = (func, {})
        return self
    def sub_cmd(self, func=None, *, name):
        if func is None:
            return functools.partial(self.sub_cmd, name=name)
        oldname = func.__name__
        func.__name__ = '%s_%s_%s' % ('_cmd', self.name, name)
        func.__qualname__ = func.__qualname__.replace(oldname, func.__name__)
        self.cmd_map[self.name][1][name] = func
        return self
# �Ժ����Զ���/����
def AutoLock(f):
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return wrapper
# main
if __name__ == '__main__':
    class A:
      cmd_map = {}
      @mycmd('cmd1', cmd_map)
      def cmd(self): pass
      @cmd.sub_cmd(name='cmd11')
      def cmd(self): pass
      @mycmd('cmd2', cmd_map)
      def cmd(self): pass
      del cmd
    print(A.cmd_map)
