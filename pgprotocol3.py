#!/bin/env python3
# -*- coding: GBK -*-
# 
# 解析postgresql c/s version 3协议，不包括复制相关的协议。
# postgresql消息格式: type + len + data。type是一个字节，len是4个字节表示大小，包括len本身的4个字节。
# FE的第一个消息不包含type部分。
# 传给Msg派生类的buf包含开头的5个字节(或者4个字节)。
# 
# ** 所有消息类的对象在创建之后都不要修改已经赋值的属性 **
# ** 如果要保留从MsgChunk/RawMsgChunk获得的单个消息留作以后用，则需要保存copy的返回值，而不是直接保存消息 **
# 
# 现在对于不能识别的消息类型直接抛出异常，这样做可能不是很合适，因为pg新版本可能增加新的消息类型。
# TODO: 有些消息类型的所有对象其实都是相同的，所以可以预先创建这些对象及其bytes。类似于NoneType类型只有None这一个对象。
# 
import sys, os
import struct
import hashlib
import collections
import copy
import mputils
from pgparse import *

# 输入输出都是bytes类型
def md5(bs):
    m = hashlib.md5()
    m.update(bs)
    return m.hexdigest().encode('ascii')

class FeMsgType(metaclass=mputils.V2SMapMeta, skip=(b'',), strip=3):
    # FE msg type
    MT_StartupMessage = b''        #
    MT_CancelRequest = b''         #
    MT_SSLRequest = b''            #

    MT_Msg = b''                   # 
    MT_Query = b'Q'                # Query
    MT_Parse = b'P'                # Parse (大写P)
    MT_Bind = b'B'                 # Bind
    MT_Execute = b'E'              # Execute
    MT_DescribeClose = b''         # placeholder for Describe/Close base class
    MT_Describe = b'D'             # Describe
    MT_Close = b'C'                # Close
    MT_Sync = b'S'                 # Sync
    MT_Flush = b'H'                # Flush
    MT_CopyData = b'd'             # CopyData (和be共用)
    MT_CopyDone = b'c'             # CopyDone (和be共用)
    MT_CopyFail = b'f'             # CopyFail
    MT_FunctionCall = b'F'         # FunctionCall
    MT_Terminate = b'X'            # Terminate
    # 'p'类型的消息是对Authentication的响应。类似于Authentication，包括多个具体类型，不过只能从上下文中判断。
    MT_AuthResponse = b'p'         # (小写p)具体类型包括: PasswordMessage,SASLInitialResponse,SASLResponse,GSSResponse。
class BeMsgType(metaclass=mputils.V2SMapMeta, skip=(b'',), strip=3):
    # BE msg type
    MT_Authentication = b'R'       # AuthenticationXXX
    MT_BackendKeyData = b'K'       # BackendKeyData
    MT_BindComplete = b'2'         # BindComplete
    MT_CloseComplete = b'3'        # CloseComplete
    MT_CommandComplete = b'C'      # CommandComplete
    MT_CopyData = b'd'             # CopyData
    MT_CopyDone = b'c'             # CopyDone
    MT_CopyResponse = b''          # placeholder for Copy[In|Out|Both]Response base class
    MT_CopyInResponse = b'G'       # CopyInResponse
    MT_CopyOutResponse = b'H'      # CopyOutResponse
    MT_CopyBothResponse = b'W'     # CopyBothResponse (only for Streaming Replication)
    MT_DataRow = b'D'              # DataRow
    MT_EmptyQueryResponse = b'I'   # EmptyQueryResponse
    MT_ErrorNoticeResponse = b''   # placeholder for ErrorResponse/NoticeResponse base class
    MT_ErrorResponse = b'E'        # ErrorResponse
    MT_NoticeResponse = b'N'       # NoticeResponse (async message)
    MT_FunctionCallResponse = b'V' # FunctionCallResponse (大写V)
    MT_NoData = b'n'               # NoData
    MT_NotificationResponse = b'A' # NotificationResponse (async message)
    MT_ParameterDescription = b't' # ParameterDescription
    MT_ParameterStatus = b'S'      # ParameterStatus (async message while reloading configure file)
    MT_ParseComplete = b'1'        # ParseComplete
    MT_PortalSuspended = b's'      # PortalSuspended
    MT_ReadyForQuery = b'Z'        # ReadyForQuery
    MT_RowDescription = b'T'       # RowDescription
    @classmethod
    def is_async_msg(cls, msgtype):
        return msgtype in (cls.MT_NoticeResponse, cls.MT_NotificationResponse, cls.MT_ParameterStatus)
class MsgType(FeMsgType, BeMsgType):
    pass

# 对象类型：prepared statement, portal
class ObjType(metaclass=mputils.V2SMapMeta, strip=4):
    OBJ_PreparedStmt = b'S'
    OBJ_Portal = b'P'

# 事务状态
class TransStatus(metaclass=mputils.V2SMapMeta, strip=3):
    TS_Idle = b'I'
    TS_InBlock = b'T'
    TS_Fail = b'E'

# ErrorResponse/NoticeResponse中的field type
class FieldType(metaclass=mputils.V2SMapMeta, strip=3):
    FT_Severity = b'S'
    FT_Severity2 = b'V'      # same to b'S', but never localized
    FT_Code = b'C'
    FT_Message = b'M'
    FT_Detail = b'D'
    FT_Hint = b'H'
    FT_Position = b'P'
    FT_InternalPos = b'p'
    FT_InternalQuery = b'q'
    FT_Where = b'W'
    FT_SchemaName = b's'
    FT_TableName = b't'
    FT_ColumnName = b'c'
    FT_DataType = b'd'
    FT_ConstraintName = b'n'
    FT_File = b'F'
    FT_Line = b'L'
    FT_Routine = b'R'
    # 把fieldtype字节串转成列表
    @classmethod
    def ftstr2list(cls, ftstr):
        return [ftstr[i:i+1] for i in range(len(ftstr))]

# auth type。Authentication消息类型
class AuthType(metaclass=mputils.V2SMapMeta, strip=3):
    AT_Ok = 0
    AT_KerberosV5 = 2
    AT_CleartextPassword = 3
    AT_MD5Password = 5
    AT_SCMCredential = 6
    AT_GSS = 7
    AT_GSSContinue = 8
    AT_SSPI = 9
    AT_SASL = 10
    AT_SASLContinue = 11
    AT_SASLFinal = 12
    _HasData = (AT_MD5Password, AT_GSSContinue, AT_SASL, AT_SASLContinue, AT_SASLFinal)

class MsgMeta(type):
    _fe_msg_map = mputils.NoRepeatAssignMap()
    fe_msg_map = [None] * (ord('z') + 1)
    _be_msg_map = mputils.NoRepeatAssignMap()
    be_msg_map = [None] * (ord('z') + 1)
    def __init__(self, name, bases, ns):
        if self.msg_type: # 跳过msg_type=b''
            mt_symbol = 'MT_' + name
            if hasattr(FeMsgType, mt_symbol):
                type(self)._fe_msg_map[self.msg_type] = self
                type(self).fe_msg_map[self.msg_type[0]] = self
            if hasattr(BeMsgType, mt_symbol):
                type(self)._be_msg_map[self.msg_type] = self
                type(self).be_msg_map[self.msg_type[0]] = self
        super().__init__(name, bases, ns)
    def __new__(cls, name, bases, ns):
        if 'msg_type' in ns:
            raise ValueError('class %s should not define msg_type' % name)
        ns['msg_type'] = getattr(MsgType, 'MT_' + name)
        if '_fields' in ns:
            _fields = ns['_fields']
            if type(_fields) == str:
                _fields = _fields.split()
            if set(_fields) & set(ns):
                raise ValueError('_fields can not contain class attribute')
            if set(_fields) & {'buf', 'sidx', 'eidx'}:
                raise ValueError('_fields can not contain buf/sidx/eidx')
            for fn in _fields:
                if fn[0] == '_':
                    raise ValueError('fieldname in _fields can not starts with undercore')
            ns['_fields'] = tuple(_fields)
        return super().__new__(cls, name, bases, ns)
    @classmethod
    def check_msg_type(cls, msg_type, *, fe):
        if fe:
            if msg_type not in cls._fe_msg_map:
                raise ValueError('unknown fe msg type:[%s]' % msg_type)
        else:
            if msg_type not in cls._be_msg_map:
                raise ValueError('unknown be msg type:[%s]' % msg_type)
# 消息基类。
# 派生类需要实现_parse和_tobytes函数。
class Msg(metaclass=MsgMeta):
    _fields = ''
    def __init__(self, buf=None, sidx=0, eidx=None, **kwargs):
        if buf is not None and kwargs:
            raise ValueError('buf and kwargs can not be given meanwhile')
        if buf:
            self.buf = buf
            self.sidx, self.eidx = sidx, eidx
            self._parse()
        else:
            self.buf = None
            self.sidx, self.eidx = 0, None
            self._init_from_kwargs(kwargs)
    def _init_from_kwargs(self, kwargs):
        for k, v in kwargs.items():
            if k not in self._fields:
                raise ValueError('unknown kwarg(%s), valid kwargs is %s' % (k, self._fields))
            setattr(self, k, v)
    def tobytes(self):
        if self.buf:
            return self.buf[self.sidx:self.eidx]
        data = self._tobytes()
        header = self.msg_type + struct.pack('>i', len(data)+4)
        self.buf = header + data
        return self.buf
    def __bytes__(self):
        return self.tobytes()
    def _parse(self):
        pass
    def _tobytes(self):
        return b''
    def __repr__(self):
        res = '<%s' % type(self).__name__
        for field in self._fields:
            fval = getattr(self, field)
            res += ' %s=%s' % (field, fval)
        res += '>'
        return res
    def to_msg(self, *, fe):
        return self
    def to_rawmsg(self):
        return RawMsg(self.tobytes())
    def copy(self, nobuf=False):
        m = object.__new__(type(self))
        if nobuf:
            m.buf = None
        elif self.buf:
            m.buf = bytes(self)
        else:
            m.buf = None
        m.sidx, m.eidx = 0, None
        for f in m._fields:
            setattr(m, f, getattr(self, f))
        return m
# 
# FE msg
# 
# simple query。允许分号分隔的多条语句。
# 如果query包含分号分隔的多条语句，那么会返回每条语句的结果消息直到出错的语句(出错语句后面的语句不会执行)，最后是一个ReadyForQuery消息。
# 而且这多条语句是在一个事务里执行的。如果多条语句是用begin/end包起来的话也是一样的，除了有错误语句的时候，最后的ReadyForQuery的trans_status不一样，
# 对于没有begin/end的多条语句，trans_status为TS_Idle，而有begin/end的话，trans_status为TS_Fail。
class Query(Msg):
    _formats = '>x'
    _fields = 'query'
    def _parse(self):
        self.query, _ = get_cstr(self.buf, self.sidx + 5)
    def _tobytes(self):
        return self.query + b'\x00'
    @classmethod
    def make(cls, sql):
        return cls(query=sql)
# extended query。不允许多条语句。
# 一般顺序为: Parse->Bind->Describe->Execute->Close->Sync。
# 如果想立刻收到消息的结果的话则需要后面发送Flush(Sync后面不需要Flush)，如果有错误则服务器端会立刻发回ErrorResponse(不需要Flush)。
# 如果有错则服务器端会忽略后面的所有消息直到Sync，所以每个消息后面可以先检查是否收到ErrorResponse，如果没收到再发送后续的消息。
# Sync会关闭事务(提交或回滚)，然后返回ReadyForQuery。每个Sync都会有一个ReadyForQuery对应。
# 
# Parse -> ParseComplete
# Bind -> BindComplete
# Describe (portal) -> NoData or RowDescription  如果不发送Describe那么就不会有NoData或者RowDescription
# Execute -> CommandComplete or [DataRow... + CommandComplete], 也可能ErrorResponse
# Close -> CloseComplete
# Sync -> ReadyForQuery
#
# 如果是copy语句:
#   对于Describe消息服务器会发回NoData而不是RowDescription。
#   对于Execute消息:
#     CopyIn  : 
#       服务器发送CopyInResponse
#       客户端发送CopyData... + CopyDone/CopyFail。服务器在接收CopyData时可能会发送ErrorResponse，然后就会忽略所有后面的消息直到Sync。
#       服务器发送CommandComplete/ErrorResponse (分别对应于CopyDone和CopyFail)
#     CopyOut : 
#       服务器发送CopyOutResponse + CopyData... + CopyDone。同样服务器可能会发送ErrorResponse，然后就会忽略所有后面的消息直到Sync。
#       服务器发送CommandComplete/ErrorResponse。
#   前面是针对扩展查询协议，对于simple查询协议，服务器发送ErrorResponse后不需要客户端再发送Sync后才会发送ReadyForQuery。
# 
# param_cnt/param_oids指定参数的数据类型的oid，如果oid=0则系统会自己推导出类型。
# 这里指定的参数个数可以小于查询语句中实际的参数个数，没有指定的参数由系统自己推导出类型。
class Parse(Msg):
    _formats = '>x >x >h -0>i'
    _fields = 'stmt query param_cnt param_oids'
    def _parse(self):
        sidx = self.sidx + 5
        self.stmt, sidx = get_cstr(self.buf, sidx)
        self.query, sidx = get_cstr(self.buf, sidx)
        self.param_cnt = get_short(self.buf, sidx); sidx += 2
        self.params = get_nint(self.buf, sidx, self.param_cnt)
    def _tobytes(self):
        return b''.join((self.stmt, b'\x00', self.query, b'\x00', put_short(self.param_cnt), put_nint(self.param_oids)))
    # query/stmt必须是格式为client_encoding的字节串。其他地方也一样。
    # query是sql语句，其中参数用$n表示；stmt是prepared statement名字。
    @classmethod
    def make(cls, query, stmt=b'', param_oids=()):
        return cls(stmt=stmt, query=query, param_cnt=len(param_oids), param_oids=param_oids)
@mputils.SeqAccess(attname='params')
class Bind(Msg):
    _check_assign = False
    _formats = '>x >x >h -0>h >24X >h -0>h'
    _fields = 'portal stmt fc_cnt fc_list params res_fc_cnt res_fc_list'
    def _parse(self):
        sidx = self.sidx + 5
        self.portal, sidx = get_cstr(self.buf, sidx)
        self.stmt, sidx = get_cstr(self.buf, sidx)
        self.fc_cnt = get_short(self.buf, sidx); sidx += 2
        self.fc_list = get_nshort(self.buf, sidx, self.fc_cnt); sidx += 2*self.fc_cnt
        self.params, sz = get_24X(self.buf, sidx); sidx += sz
        self.res_fc_cnt = get_short(self.buf, sidx); sidx += 2
        self.res_fc_list = get_nshort(self.buf, sidx)
    def _tobytes(self):
        return b''.join((self.portal, b'\x00', self.stmt, b'\x00', put_short(self.fc_cnt), put_nshort(self.fc_list), 
                        put_24X(self.params), put_short(self.res_fc_cnt), put_nshort(self.res_fc_list)))
    # fc_list指定params中参数值的格式代码(fc)，0是文本格式1是二进制格式。如果为空则表示都是文本格式，
    # 如果只有一个fc则指定所有参数的格式为fc，否则fc_list的大小和params的大小一样，指定每个参数的fc。
    # res_fc_list指定返回结果中各列的格式代码，意义和fc_list一样。
    @classmethod
    def make(cls, params, portal=b'', stmt=b'', fc_list=(), res_fc_list=()):
        return cls(portal=portal, stmt=stmt, fc_cnt=len(fc_list), fc_list=fc_list, 
                   params=params, res_fc_cnt=len(res_fc_list), res_fc_list=res_fc_list)
# 当需要创建大量Bind消息然后发送出去的话，用该类可以提高性能。
class SimpleBind():
    def __init__(self, params):
        self.params = params
    def tobytes(self):
        data = b'\x00\x00\x00\x00' + put_24X(self.params) + b'\x00\x00'
        header = MsgType.MT_Bind + struct.pack('>i', len(data)+4)
        return header + data
class Execute(Msg):
    _formats = '>x >i'
    _fields = 'portal max_num'
    def _parse(self):
        sidx = self.sidx + 5
        self.portal, sidx = get_cstr(self.buf, sidx)
        self.max_num = get_int(self.buf, sidx)
    def _tobytes(self):
        return b''.join((self.portal, b'\x00', put_nint(self.max_num)))
    @classmethod
    def make(cls, portal=b'', max_num=0):
        return cls(portal=portal, max_num=max_num)
Execute.Default = Execute.make()
@mputils.Check(attname='obj_type', attvals=ObjType.v2smap)
class DescribeClose(Msg):
    _formats = '>s >x'
    _fields = 'obj_type obj_name'
    def _parse(self):
        sidx = self.sidx + 5
        self.obj_type = self.buf[sidx:sidx+1]; sidx += 1
        self.obj_name, _ = get_cstr(self.buf, sidx)
    def _tobytes(self):
        return b''.join((self.obj_type, self.obj_name, b'\x00'))
    # 注意:不能通过DescribeClose调用下面这2个方法，应该通过Describe和Close调用。
    @classmethod
    def stmt(cls, name=b''):
        return cls(obj_type=ObjType.OBJ_PreparedStmt, obj_name=name)
    @classmethod
    def portal(cls, name=b''):
        return cls(obj_type=ObjType.OBJ_Portal, obj_name=name)
class Describe(DescribeClose):
    pass
Describe.DefaultStmt = Describe.stmt()
Describe.DefaultPortal = Describe.portal()
class Close(DescribeClose):
    pass
class Sync(Msg):
    pass
class Flush(Msg):
    pass
# CopyData/CopyDone和BE共用，在下面定义。
class CopyFail(Msg):
    _formats = '>x'
    _fields = 'err_msg'
    def _parse(self):
        self.err_msg, _ = get_cstr(self.buf, self.sidx + 5)
    def _tobytes(self):
        return self.err_msg + b'\x00'
@mputils.SeqAccess(attname='args')
class FunctionCall(Msg):
    _formats = '>i >h -0>h >24X >h'
    _fields = 'foid fc_cnt fc_list args res_fc'
    def _parse(self):
        sidx = self.sidx + 5
        self.foid = get_int(self.buf, sidx); sidx += 4
        self.fc_cnt = get_short(self.buf, sidx); sidx += 2
        self.fc_list = get_nshort(self.buf, sidx, self.fc_cnt); sidx += 2*self.fc_cnt
        self.args, sz = get_24X(self.buf, sidx); sidx += sz
        self.res_fc = get_short(self.buf, sidx)
    def _tobytes(self):
        return b''.join((put_int(self.foid), put_short(self.fc_cnt), put_nshort(self.fc_list), 
                        put_24X(self.args), put_short(self.res_fc)))
    # fc_list的意思和Bind.make一样。
    @classmethod
    def make(cls, foid, args, fc_list=(), res_fc=0):
        return cls(foid=foid, fc_cnt=len(fc_list), fc_list=fc_list, args=args, res_fc=res_fc)
class Terminate(Msg):
    pass
# 'p'消息类型是对Authentication的回应，包括多个具体的类型，需要根据上下文判断需要那个具体类型。
# AuthResponse包含data，这data由具体的类型解析；反过来具体类型的tobytes结果要赋值给AuthResponse的data。
# 比如：
#     r = SASLInitialResponse(name=b'xxxx', response=xval(b'yyyy'))
#     ar = AuthResponse(data=bytes(r))
#     r2 = SASLInitialResponse(ar.data)   不能用ar.tobytes()或者bytes(ar)
class AuthResponse(Msg):
    _formats = '>a'
    _fields = 'data'
    def _parse(self):
        self.data = self.buf[self.sidx+5:self.eidx]
    def _tobytes(self):
        return self.data
# 具体AuthResponse类型的buf不包括开头的5个字节。
class PasswordMessage():
    _formats = '>x'
    _fields = 'password'
    def __init__(self, buf=None, *, password=None):
        if buf:
            self.password, _ = get_cstr(buf, 0)
        else:
            self.password = password
    def tobytes(self):
        return self.password + b'\x00'
    def __bytes__(self):
        return self.tobytes()
    # 参数必须是字节串。如果password是md5开头那说明已经经过一次md5了.
    @classmethod
    def make(cls, password, user=None, md5salt=None):
        if md5salt:
            if not user:
                raise SystemError('BUG: should provide user for md5 authentication')
            if password[:3] == b'md5' and len(password) == 35:
                password = b'md5' + md5(password[3:] + md5salt)
            else:
                password = b'md5' + md5(md5(password + user) + md5salt)
        return cls(password=password)
class SASLInitialResponse():
    _formats = '>x >4x'
    _fields = 'name response'
    def __init__(self, buf=None, *, name=None, response=None):
        if buf:
            sidx = 0
            self.name, sidx = get_cstr(buf, sidx)
            n = get_int(buf, sidx); sidx += 4
            if n < 0:
                self.response = None
            else:
                self.response = buf[sidx:sidx+n]
        else:
            self.name = name
            self.response = response
    def tobytes(self):
        return b''.join((self.name, b'\x00', put_int(len(self.response)), self.response))
    def __bytes__(self):
        return self.tobytes()
class SASLResponse():
    _formats = '>a'
    _fields = 'msgdata'
    def __init__(self, buf=None, *, msgdata=None):
        if buf:
            self.msgdata = buf
        else:
            self.msgdata = msgdata
    def tobytes(self):
        return self.msgdata
    def __bytes__(self):
        return self.tobytes()
class GSSResponse(SASLResponse):
    pass
# 
# BE msg
# 
# 某些authtype即使是没有data值的，也要把b''赋值给data。
@mputils.Check(attname='authtype', attvals=AuthType.v2smap)
class Authentication(Msg):
    _formats = '>i >a'
    _fields = 'authtype data'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._check()
    def _parse(self):
        sidx = self.sidx + 5
        self.authtype = get_int(self.buf, sidx); sidx += 4
        self.data = self.buf[sidx:self.eidx]
    def _tobytes(self):
        return put_int(self.authtype) + self.data
    # 检查val是否是有效的data，在给data赋值前必须先给authtype赋值。
    def _check(self):
        if not hasattr(self, 'authtype') or not hasattr(self, 'data'):
            raise ValueError('authtype or data is not set')
        if self.authtype not in AuthType._HasData and self.data:
            raise ValueError('authtype(%s) should has empty data(%s)' % (AuthType.v2smap[self.authtype], self.data))
        if self.authtype in AuthType._HasData and not self.data:
            raise ValueError('authtype(%s) should has data which is not empty' % (AuthType.v2smap[self.authtype],))
        # 检查具体auth类型的data的有效性
        if self.authtype == AuthType.AT_MD5Password and len(self.data) != 4:
            raise ValueError('the data size for authtype(MD5Password) should be 4:%s' % self.data)
    def __repr__(self):
        return '<%s authtype=%s data=%s>' % (type(self).__name__, AuthType.v2smap[self.authtype], self.data)
    # 根据本消息的类型创建相应的AuthResponse消息
    def make_ar(self, **kwargs):
        if self.authtype in (AuthType.AT_CleartextPassword, AuthType.AT_MD5Password):
            return AuthResponse(data=PasswordMessage.make(md5salt=self.data, **kwargs).tobytes())
        elif self.authtype == AuthType.AT_SASL:
            sasl = SASL(self.data)
            mechs = list(sasl)
            if 'SCRAM-SHA-256' not in mechs:
                raise RuntimeError('only support SCRAM-SHA-256. server support %s' % mechs)
            return AuthResponse(data=kwargs['sasl_init_resp_msg'].tobytes())
        elif self.authtype == AuthType.AT_SASLContinue:
            return AuthResponse(data=kwargs['sasl_resp_msg'].tobytes())
        else:
            raise ValueError('do not support authentication:%s' % AuthType.v2smap[self.authtype])
Authentication.Ok = Authentication(authtype=AuthType.AT_Ok, data=b'')
# mech_name_list是服务器端支持的authentication mechanisms
# postgresql 10支持SCRAM-SHA-256和SCRAM-SHA-256-PLUS(if SSL enabled)
# 要想支持scram，在设置用户密码的时候必须把password_encryption设为'scram-sha-256'
# SASL: Simple Authentication and Security Layer
@mputils.SeqAccess(attname='mech_name_list', f=lambda x:bytes(x).decode('ascii'))
class SASL():
    _formats = '>X'
    _fields = 'mech_name_list'
    def __init__(self, buf=None, *, mech_name_list=None):
        if buf:
            self.mech_name_list = get_X(buf, 0)
        else:
            self.mech_name_list = mech_name_list
    def tobytes(self):
        return put_X(self.mech_name_list)
    def __bytes__(self):
        return self.tobytes()
    @classmethod
    def make(cls, *names):
        mech_name_list = [name.encode('ascii') if type(name)==str else name for name in names]
        return cls(mech_name_list=mech_name_list)

class BackendKeyData(Msg):
    _formats = '>i >i'
    _fields = 'pid skey'
    def _parse(self):
        self.pid, self.skey = get_nint(self.buf, self.sidx + 5, 2)
    def _tobytes(self):
        return put_nint((self.pid, self.skey))
class BindComplete(Msg):
    pass
class CloseComplete(Msg):
    pass
class CommandComplete(Msg):
    _formats = '>x'
    _fields = 'tag'
    def _parse(self):
        self.tag, _ = get_cstr(self.buf, self.sidx + 5)
    def _tobytes(self):
        return self.tag + b'\x00'
class CopyData(Msg):
    _formats = '>a'
    _fields = 'data'
    def _parse(self):
        self.data = self.buf[self.sidx+5:self.eidx]
    def _tobytes(self):
        return self.data
class CopyDone(Msg):
    pass
# just base class for Copy In/Out/Both Response
# col_cnt必须等于CopyData中的列数。
# 如果overall_fmt=0也就是文本格式，那么col_fc_list中必须都是0。
class CopyResponse(Msg):
    _formats = '>b >h -0>h'
    _fields = 'overall_fmt col_cnt col_fc_list'
    def _parse(self):
        sidx = self.sidx + 5
        self.overall_fmt = get_byte(self.buf, sidx); sidx += 1
        self.col_cnt = get_short(self.buf, sidx); sidx += 2
        self.col_fc_list = get_nshort(self.buf, sidx, self.col_cnt)
    def _tobytes(self):
        return b''.join((put_byte(self.overall_fmt), put_short(self.col_cnt), put_nshort(self.col_fc_list)))
    @classmethod
    def make(cls, overall_fmt, col_fc_list):
        return cls(overall_fmt=overall_fmt, col_cnt=len(col_fc_list), col_fc_list=col_fc_list)
class CopyInResponse(CopyResponse):
    pass
class CopyOutResponse(CopyResponse):
    pass
class CopyBothResponse(CopyResponse):
    pass
@mputils.SeqAccess(attname='col_vals')
class DataRow(Msg):
    _formats = '>24X'
    _fields = 'col_vals'
    def _parse(self):
        colcnt = get_short(self.buf, self.idx + 5)
        if (colcnt < 0): # is unsaferow
            self.col_vals = self.buf[self.sidx:self.eidx]
        else:
            self.col_vals, sz = get_24X(self.buf, self.sidx + 5)
    def _tobytes(self):
        return put_24X(self.col_vals)
    # 参数必须是字节串或者None
    @classmethod
    def make(cls, *vals):
        return cls(col_vals=vals)
class EmptyQueryResponse(Msg):
    pass
# field_list是字节串列表，字节串中第一个字节是fieldtype, 剩下的是fieldval
@mputils.SeqAccess(attname='field_list', restype='Field', resfields='t v', f=lambda x:(x[:1],x[1:]))
class ErrorNoticeResponse(Msg):
    _formats = '>X'
    _fields = 'field_list'
    def __init__(self, *args, **kwargs):
        self._cached_fields = None
        super().__init__(*args, **kwargs)
        self._cached_fields = collections.OrderedDict(self.get())
    def _parse(self):
        self.field_list = get_X(self.buf, self.sidx + 5)
    def _tobytes(self):
        return put_X(self.field_list)
    def __getattr__(self, name):
        if self._cached_fields is None:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))
        if name not in self._cached_fields:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))
        return self._cached_fields[name]
    # 返回(field_name, field_val)列表，其中field_name是str，field_val是bytes。
    def get(self, fields=(), decode=lambda x:x):
        res = []
        if type(fields) == bytes:
            fields = FieldType.ftstr2list(fields)
        if not (set(fields) <= FieldType.v2smap.keys()):
            raise ValueError('fields(%s) have unknown field type' % (fields,))
        for t, v in self:
            if fields and t not in fields:
                continue
            res.append((FieldType.v2smap[t], decode(v)))
        return res
    def __repr__(self):
        res = '<%s' % type(self).__name__
        for t, v in self:
            res += ' %s:%s' % (t, v)
        return res + '>'
    def copy(self, nobuf=False):
        m = super().copy(nobuf)
        m._cached_fields = self._cached_fields
        return m
    # fields是(t,v)或者Field列表
    @classmethod
    def make(cls, *fields):
        field_list = []
        for t, v in fields:
            if t not in FieldType.v2smap:
                raise ValueError('unknown field type:%s' % t)
            field_list.append(t + v)
        return cls(field_list=field_list)
    @classmethod
    def make_error(cls, message, detail=None, hint=None):
        fields = []
        fields.append((FieldType.FT_Severity, b'ERROR'))
        fields.append((FieldType.FT_Severity2, b'ERROR'))
        fields.append((FieldType.FT_Message, message))
        if detail:
            fields.append((FieldType.FT_Detail, detail))
        if hint:
            fields.append((FieldType.FT_Hint, hint))
        return cls.make(*fields)
class ErrorResponse(ErrorNoticeResponse):
    pass
class NoticeResponse(ErrorNoticeResponse):
    pass
class FunctionCallResponse(Msg):
    _formats = '>4x'
    _fields = 'res_val'
    def _parse(self):
        sidx = self.sidx + 5
        n = get_int(self.buf, sidx); sidx += 4
        if n < 0:
            self.res_val = None
        else:
            self.res_val = self.buf[sidx:sidx+n]
    def _tobytes(self):
        if self.res_val is None:
            return struct.pack('>i', -1)
        else:
            return struct.pack('>i', len(self.res_val)) + self.res_val
class NoData(Msg):
    pass
class NotificationResponse(Msg):
    _formats = '>i >x >x'
    _fields = 'pid channel payload'
    def _parse(self):
        sidx = self.sidx + 5
        self.pid = get_int(self.buf, sidx); sidx += 5
        self.channel, sidx = get_cstr(self.buf, sidx)
        self.payload, sidx = get_cstr(self.buf, sidx)
    def _tobytes(self):
        return b''.join((put_int(self.pid), self.channel, b'\x00', self.payload, b'\x00'))
class ParameterDescription(Msg):
    _formats = '>h -0>i'
    _fields = 'count oid_list'
    def _parse(self):
        sidx = self.sidx + 5
        self.count = get_short(self.buf, sidx); sidx += 2
        self.oid_list = get_nint(self.buf, sidx, self.count)
    def _tobytes(self):
        return put_short(self.count) + put_nint(self.oid_list)
class ParameterStatus(Msg):
    _formats = '>x >x'
    _fields = 'name val'
    def _parse(self):
        sidx = self.sidx + 5
        self.name, sidx = get_cstr(self.buf, sidx)
        self.val, sidx = get_cstr(self.buf, sidx)
    def _tobytes(self):
        return b''.join((self.name, b'\x00', self.val, b'\x00'))
    @classmethod
    def make(cls, name, val):
        name = name.encode('ascii') if type(name) is str else name
        val = val.encode('ascii') if type(val) is str else val
        return cls(name=name, val=val)
class ParseComplete(Msg):
    pass
class PortalSuspended(Msg):
    pass
@mputils.Check(attname='trans_status', attvals=TransStatus.v2smap)
class ReadyForQuery(Msg):
    _formats = '>s'
    _fields = 'trans_status'
    def _parse(self):
        self.trans_status = self.buf[self.sidx+5:self.sidx+6]
    def _tobytes(self):
        return self.trans_status
ReadyForQuery.Idle = ReadyForQuery(trans_status=TransStatus.TS_Idle)
ReadyForQuery.InBlock = ReadyForQuery(trans_status=TransStatus.TS_InBlock)
ReadyForQuery.Fail = ReadyForQuery(trans_status=TransStatus.TS_Fail)
# field_list包含(name, tableoid, attnum, typoid, typlen, typmod, fmtcode)
@mputils.SeqAccess(attname='field_list', restype='Field', resfields='name tableoid attnum typoid typlen typmod fmtcode')
class RowDescription(Msg):
    _formats = '>h -0>xihihih'
    _fields = 'field_cnt field_list'
    def _parse(self):
        sidx = self.sidx + 5
        self.field_cnt = get_short(self.buf, sidx); sidx += 2
        self.field_list = []
        for i in range(self.field_cnt):
            name, sidx = get_cstr(self.buf, sidx)
            tableoid, attnum, typoid, typlen, typmod, fmtcode = struct.unpack('>ihihih', self.buf[sidx:sidx+18]); sidx += 18
            self.field_list.append((name, tableoid, attnum, typoid, typlen, typmod, fmtcode))
    def _tobytes(self):
        data = put_short(self.field_cnt)
        for f in self.field_list:
            data += f.name + b'\x00' + struct.pack('>ihihih', f.tableoid, f.attnum, f.typoid, f.typlen, f.typmod, f.fmtcode)
        return data
    # 参数可以是序列也可以是字典
    @classmethod
    def make(cls, *fields):
        flist = []
        for idx, field in enumerate(fields):
            if isinstance(field, collections.Sequence):
                flist.append(cls.Field(*field))
            else:
                flist.append(cls.make_field(idx, **field))
        return cls(field_cnt=len(flist), field_list=flist)
    @classmethod
    def make_field(cls, idx, **kwargs):
        kwargs.setdefault('name', b'col%d' % (idx+1))
        kwargs.setdefault('tableoid', 99999)
        kwargs.setdefault('attnum', idx+1)
        kwargs.setdefault('typoid', 25)
        kwargs.setdefault('typlen', -1)
        kwargs.setdefault('typmod', -1)
        kwargs.setdefault('fmtcode', 0)
        return cls.Field(**kwargs)

# 
# FE->BE的第一个消息
# 
PG_PROTO_VERSION2_NUM = 131072
PG_PROTO_VERSION3_NUM = 196608
PG_CANCELREQUEST_CODE = 80877102
PG_SSLREQUEST_CODE    = 80877103

# 
# V3 StartupMessage的详情参见postmaster.c中的ProcessStartupPacket函数。
# 可以包含下面这些：
#   database
#   user
#   options       命令行选项
#   replication   有效值true/false/1/0/database，database表示连接到database选项指定的数据库，一般用于逻辑复制。
#   <guc option>  其他guc选项。比如: client_encoding/application_name
# 
class StartupMessage(Msg):
    _formats = '>i >X'
    _fields = 'code params'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_PROTO_VERSION3_NUM
        # cached value
        self._params_dict = None
        self._hv = None
    def _parse(self):
        sidx = self.sidx + 4
        self.code = get_int(self.buf, sidx); sidx += 4
        self.params = get_X(self.buf, sidx)
    def _tobytes(self):
        return put_int(self.code) + put_X(self.params)
    def get_params(self):
        # 把params转成dict，dict的key转成str，value是字节串
        if not self._params_dict:
            f = lambda x: (bytes(x[0]).decode('ascii'), bytes(x[1]))
            it = iter(self.params)
            self._params_dict = dict(map(f, zip(it, it)))
        return self._params_dict
    def __getitem__(self, key):
        return self.get_params()[key]
    def __eq__(self, other):
        return self.get_params() == other.get_params()
    def __hash__(self):
        if self._hv is not None:
            return self._hv
        self._hv = 0
        for k, v in self.get_params().items():
            self._hv += hash(k) + hash(v)
        return self._hv
    # other是字典
    def match(self, other, skip=('host','port','password')):
        def xf(x):
            x = copy.copy(x)
            for k in skip:
                x.pop(k, None)
            return self.make(**x)
        m1 = xf(self.get_params())
        m2 = xf(other)
        return m1 == m2
    def md5(self):
        data = b''
        keys = list(self.get_params().keys())
        keys.sort()
        for k in keys:
            data += self.get_params()[k]
        return md5(data)
    @classmethod
    def make(cls, **kwargs):
        params = []
        for k, v in kwargs.items():
            params.append(k.encode('ascii'))
            if type(v) is str:
                v = v.encode('ascii')
            params.append(v)
        return cls(params = params)
class CancelRequest(Msg):
    _formats = '>i >i >i'
    _fields = 'code pid skey'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_CANCELREQUEST_CODE
    def _parse(self):
        self.code, self.pid, self.skey = get_nint(self.buf, self.sidx + 4, 3)
    def _tobytes(self):
        return put_nint((self.code, self.pid, self.skey))
class SSLRequest(Msg):
    _formats = '>i'
    _fields = 'code'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_SSLREQUEST_CODE
    def _parse(self):
        self.code = get_int(self.buf, self.sidx + 4)
    def _tobytes(self):
        return put_int(self.code)

#============================================================================================
# 和协议解析不直接相关的
# 
# 检查startup消息是否已完整，如果data太长则抛出异常，data包含开头表示长度的4个字节。
def startup_msg_is_complete(data):
    data_len = len(data)
    if data_len <= 4:
        return False
    msg_len = struct.unpack('>i', data[:4])[0]
    if data_len > msg_len:
        raise RuntimeError('startup msg is invalid. msg_len:%s data_len:%s data:%s' % (msg_len, data_len, data))
    return data_len == msg_len
# 分析FE的第一个消息，返回相应的消息类的对象或者抛出异常。data包括开头表示大小的4个字节。
def parse_startup_msg(data):
    code = struct.unpack('>i', data[4:8])[0]
    if code == PG_PROTO_VERSION2_NUM:
        raise RuntimeError('do not support version 2 protocol')
    elif code == PG_PROTO_VERSION3_NUM:
        return StartupMessage(data)
    elif code == PG_CANCELREQUEST_CODE:
        return CancelRequest(data)
    elif code == PG_SSLREQUEST_CODE:
        return SSLRequest(data)
    else:
        raise RuntimeError('unknown code(%s) in startup msg:%s' % (code, data))
# 判断data中从idx开始是否有完整的消息，返回消息包的长度(包括开头5个字节)。如果没有完整消息则返回0。
def has_msg(data, idx, *, fe=True):
    data_len = len(data)
    if data_len - idx < 5:
        return 0
    #msg_type = data[idx:idx+1]
    #MsgMeta.check_msg_type(msg_type, fe=fe)
    msg_len = struct.unpack('>i', data[idx+1:idx+5])[0]
    if data_len -idx < msg_len + 1:
        return 0
    return msg_len + 1
# 返回下一个idx和msg_idxs((idx,sz)的列表)
def _parse_pg_msg(data, max_msg=0, stop=None):
    msg_idxs = []
    idx, cnt = 0, 0
    while True:
        if cutils:
            msg_len = cutils.lib.has_msg(data, len(data), idx)
        else:
            msg_len = has_msg(data, idx)
        if msg_len <= 0:
            break
        msg_idxs.append((idx, msg_len))
        idx += msg_len

        if stop:
            x = msg_idxs[-1]
            raw_msg = RawMsg(data, x[0], x[0]+x[1])
            if callable(stop):
                if stop(raw_msg): break
            else:
                if raw_msg.msg_type in stop: break        
        cnt += 1
        if max_msg > 0 and cnt >= max_msg:
            break
    return idx, msg_idxs
# 多个不同的MsgChunk之间不共享data，但是MsgChunk和从它获得的Msg共享data。
# 调用Msg.copy返回的msg将脱离MsgChunk。
class MsgChunk():
    def __init__(self, data, msg_idxs, msg_map):
        self.data = data
        self.msg_list = tuple(msg_map[self.data[mi[0]]](self.data, mi[0], mi[0] + mi[1]) for mi in msg_idxs)
    @classmethod
    def make(cls, data, msg_list):
        chunk = object.__new__(cls)
        chunk.data = data
        chunk.msg_list = tuple(msg_list)
        return chunk
    def __len__(self):
        return len(self.msg_list)
    def __getitem__(self, idx):
        if type(idx) is slice:
            if idx.step is not None:
                raise ValueError('MsgChunk do not support extended slice')
            if (idx.start is None or idx.start == 0) and (idx.stop is None or idx.stop >= len(self)):
                return self
            x_list = self.msg_list[idx]
            if not x_list:
                return MsgChunk.Empty
            data = self.data[x_list[0].sidx:x_list[-1].eidx]
            idx_offset = -(x_list[0].sidx)
            msg_list = self._copy_msg_list(x_list, data, idx_offset)
            return self.make(data, msg_list)
        else:
            return self.msg_list[idx]
    def __iter__(self):
        yield from self.msg_list
    def __bytes__(self):
        return self.data
    def __add__(self, other):
        if type(other) is not MsgChunk:
            raise TypeError("unsupported operand type for +: 'MsgChunk' and '%s'" % type(other).__name__)
        if not self:
            return other
        if not other:
            return self
        data = self.data + other.data
        msg_list = self._copy_msg_list(self.msg_list, data, 0)
        idx_offset = self[-1].eidx
        msg_list.extend(self._copy_msg_list(other.msg_list, data, idx_offset))
        return self.make(data, msg_list)
    def _copy_msg_list(self, msg_list, data, idx_offset):
        res = []
        for x in msg_list:
            m = x.copy(nobuf=True)
            m.buf = data
            m.sidx = x.sidx + idx_offset
            m.eidx = x.eidx + idx_offset
            res.append(m)
        return res
MsgChunk.Empty = MsgChunk.make(b'', ())
# 
# 从data中提取多个消息包，返回下一个idx和消息对象列表。该函数不能用于parse从FE发给BE的第一个消息。
#   data : 原始数据。
#   max_msg : 最多提取多少个消息包。如果为0表示提取所有。
#   stop : 指定提取停止的条件。可以指定消息类型，包含多个消息类型(多个MsgType的+或者序列)；也可以是函数，函数返回True表示停止提取。
#   fe : 是否是来自FE的消息。
# 
def parse_pg_msg(data, max_msg=0, stop=None, *, fe=True):
    msg_map = MsgMeta.fe_msg_map if fe else MsgMeta.be_msg_map
    idx, msg_idxs = _parse_pg_msg(data, max_msg, stop)
    if not msg_idxs:
        return idx, MsgChunk.Empty
    else:
        return idx, MsgChunk(data[:idx], msg_idxs, msg_map)
# 没有parse过的raw消息
class RawMsg():
    def __init__(self, data, sidx=0, eidx=None):
        self.data = data
        self.sidx, self.eidx = sidx, eidx
        if self.sidx is None:
            self.sidx = 0
        if self.eidx is None:
            self.eidx = len(self.data)
    @property
    def msg_type(self):
        return self.data[self.sidx:self.sidx+1]
    def __len__(self):
        return self.eidx - self.sidx
    def __bytes__(self):
        return self.data[self.sidx:self.eidx]
    def to_msg(self, *, fe):
        msg_map = MsgMeta.fe_msg_map if fe else MsgMeta.be_msg_map
        return msg_map[self.msg_type[0]](self.data[self.sidx:self.eidx])
    def to_rawmsg(self):
        return self
    # 返回的消息对象是独立的，不和任何RawMsgChunk共享data。
    def copy(self):
        return RawMsg(bytes(self))
# 多个不同的RawMsgChunk之间不共享data，但是RawMsgChunk和从它获得的RawMsg共享data。
class RawMsgChunk():
    def __init__(self, data, msg_idxs):
        self.data = data
        self.msg_idxs = msg_idxs # list of (sidx, msg_len)
        if self.msg_idxs:
            eidx = self.msg_idxs[-1][0] + self.msg_idxs[-1][1]
            if eidx != len(self.data):
                raise ValueError('data len(%s) != eidx(%s)' % (len(self.data), eidx))
    def __len__(self):
        return len(self.msg_idxs)
    def __getitem__(self, idx):
        if type(idx) is slice:
            if idx.step is not None:
                raise ValueError('RawMsgChunk do not support extended slice')
            if (idx.start is None or idx.start == 0) and (idx.stop is None or idx.stop >= len(self.msg_idxs)):
                return self
            x_list = self.msg_idxs[idx]
            if not x_list:
                return RawMsgChunk.Empty
            total_sz = x_list[-1][0] + x_list[-1][1] - x_list[0][0]
            sidx = x_list[0][0]
            x_list = [(idx-sidx, sz) for idx, sz in x_list]
            return RawMsgChunk(self.data[sidx:sidx+total_sz], x_list)
        else:
            x = self.msg_idxs[idx]
            return RawMsg(self.data, x[0], x[0]+x[1])
    def __iter__(self):
        for x in self.msg_idxs:
            yield RawMsg(self.data, x[0], x[0]+x[1])
    def __bytes__(self):
        return self.data
    def __add__(self, other):
        if type(other) is not RawMsgChunk:
            raise TypeError("unsupported operand type for +: 'RawMsgChunk' and '%s'" % type(other).__name__)
        if not self:
            return other
        if not other:
            return self
        other_sidx = len(self.data)
        res_msg_idxs = copy.copy(self.msg_idxs)
        res_msg_idxs.extend((other_sidx+idx, sz) for idx, sz in other.msg_idxs)
        return RawMsgChunk(self.data+other.data, res_msg_idxs)
    # 返回一个不包含异步消息的chunk，如果没有异步消息则返回self。
    def remove_async_msg(self):
        if not self:
            return self
        chunk_list = []
        sidx = 0
        for idx, mi in enumerate(self.msg_idxs):
            msg_type = self.data[mi[0]:mi[0]+1]
            if not MsgType.is_async_msg(msg_type):
                continue
            chun_list.append(self[sidx:idx])
            sidx += 1
        chunk_list.append(self[sidx:])
        if len(chunk_list) == 1:
            return chunk_list[0]
        chunk = RawMsgChunk.Empty
        for c in chunk_list:
            chunk = chunk + c
        return chunk
    # raw_msg_list是RawMsg列表
    @classmethod
    def join(cls, raw_msg_list):
        data = b''.join(bytes(m) for m in raw_msg_list)
        msg_idxs = []
        sidx = 0
        for m in raw_msg_list:
            sz = len(m)
            msg_idxs.append((sidx, sz))
            sidx += sz
        return cls(data, msg_idxs)
RawMsgChunk.Empty = RawMsgChunk(b'', [])
# 从data中提取多个raw消息，返回下一个idx和RawMsgChunk。该函数不能用于parse从FE发给BE的第一个消息。
def parse_raw_pg_msg(data, max_msg=0, stop=None):
    idx, msg_idxs = _parse_pg_msg(data, max_msg, stop)
    if not msg_idxs:
        return idx, RawMsgChunk.Empty
    else:
        return idx, RawMsgChunk(data[:idx], msg_idxs)
# other utility
def make_auth_ok_msgs(params, be_keydata):
    msg_list = []
    msg_list.append(Authentication.Ok)
    for k, v in params.items():
        msg_list.append(ParameterStatus.make(k, v))
    msg_list.append(BackendKeyData(pid=be_keydata[0], skey=be_keydata[1]))
    msg_list.append(ReadyForQuery.Idle)
    return msg_list
def parse_auth_ok_msgs(msg_list):
    params = {}
    be_keydata = None
    for msg in msg_list:
        if msg.msg_type == MsgType.MT_ParameterStatus:
            params[bytes(msg.name).decode('ascii')] = bytes(msg.val).decode('ascii')
        elif msg.msg_type == MsgType.MT_BackendKeyData:
            be_keydata = (msg.pid,  msg.skey)
    return params, be_keydata
# main
if __name__ == '__main__':
    pass
