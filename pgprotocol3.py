#!/bin/env python3
# -*- coding: GBK -*-
# 
# 解析postgresql c/s version 3协议，不包括复制相关的协议。
# postgresql消息格式: type + len + data。type是一个字节，len是4个字节表示大小，包括len本身的4个字节。
# FE的第一个消息不包含type部分。
# 传给Msg派生类的buf不包含开头的5个字节(或者4个字节)。
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
from structview import *
import scram

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
        return msgtype in (cls.MT_NoticeResponse, cls.MT_NotificationResponse, cls.MT_ParameterDescription)
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

class MsgMeta(struct_meta):
    fe_msg_map = mputils.NoRepeatAssignMap()
    be_msg_map = mputils.NoRepeatAssignMap()
    def __init__(self, name, bases, ns):
        if self.msg_type: # 跳过msg_type=b''
            mt_symbol = 'MT_' + name
            if hasattr(FeMsgType, mt_symbol):
                type(self).fe_msg_map[self.msg_type] = self
            if hasattr(BeMsgType, mt_symbol):
                type(self).be_msg_map[self.msg_type] = self
        super().__init__(name, bases, ns)
    def __new__(cls, name, bases, ns):
        if 'msg_type' in ns:
            raise ValueError('class %s should not define msg_type' % name)
        ns['msg_type'] = getattr(MsgType, 'MT_' + name)
        return super().__new__(cls, name, bases, ns)
    @classmethod
    def check_msg_type(cls, msg_type, *, fe):
        if fe:
            if msg_type not in cls.fe_msg_map:
                raise ValueError('unknown fe msg type:[%s]' % msg_type)
        else:
            if msg_type not in cls.be_msg_map:
                raise ValueError('unknown be msg type:[%s]' % msg_type)
# 消息基类。
class Msg(struct_base, metaclass=MsgMeta):
    def tobytes(self):
        data = super().tobytes()
        header = self.msg_type + struct.pack('>i', len(data)+4)
        return header + data
    def __repr__(self):
        res = '<%s' % type(self).__name__
        for field in self._fields:
            fval = getattr(self, field)
            res += ' %s=%s' % (field, fval)
        res += '>'
        return res
# 对于那些不是从Msg派生的消息类，用下面这两个decorator把它们加进来。
def FE(cls):
    MsgMeta.fe_msg_map[cls.msg_type] = cls
    return cls
def BE(cls):
    MsgMeta.be_msg_map[cls.msg_type] = cls
    return cls

# 
# FE msg
# 
# simple query
# 如果query包含分号分隔的多条语句，那么会返回每条语句的结果消息直到出错的语句(出错语句后面的语句不会执行)，最后是一个ReadyForQuery消息。
# 而且这多条语句是在一个事务里执行的。如果多条语句是用begin/end包起来的话也是一样的，除了有错误语句的时候，最后的ReadyForQuery的trans_status不一样，
# 对于没有begin/end的多条语句，trans_status为TS_Idle，而有begin/end的话，trans_status为TS_Fail。
class Query(Msg):
    _formats = '>x'
    _fields = 'query'
# extended query。
# 一般顺序为: Parse->Bind->Describe->Execute->Close->Sync。
# 如果想立刻收到消息的结果的话则需要后面发送Flush(Sync后面不需要Flush)，如果有错误则服务器端会立刻发回ErrorResponse(不需要Flush)。
# 如果有错则服务器端会忽略后面的所有消息直到Sync，所以每个消息后面可以先检查是否收到ErrorResponse，如果没收到再发送后续的消息。
# Sync会关闭事务(提交或回滚)，然后返回ReadyForQuery。每个Sync都会有一个ReadyForQuery对应。
# 
# param_cnt/param_oids指定参数的数据类型的oid，如果oid=0则系统会自己推导出类型。
# 这里指定的参数个数可以小于查询语句中实际的参数个数，没有指定的参数由系统自己推导出类型。
class Parse(Msg):
    _formats = '>x >x >h -0>i'
    _fields = 'stmt query param_cnt param_oids'
    # query/stmt必须是格式为client_encoding的字节串。其他地方也一样。
    # query是sql语句，其中参数用$n表示；stmt是prepared statement名字。
    @classmethod
    def make(cls, query, stmt=b'', param_oids=()):
        return cls(stmt=stmt, query=query, param_cnt=len(param_oids), param_oids=param_oids)
@mputils.SeqAccess(attname='params', f=lambda x:(None if x.sz < 0 else x.data))
class Bind(Msg):
    _formats = '>x >x >h -0>h >24X >h -0>h'
    _fields = 'portal stmt fc_cnt fc_list params res_fc_cnt res_fc_list'
    # fc_list指定params中参数值的格式代码(fc)，0是文本格式1是二进制格式。如果为空则表示都是文本格式，
    # 如果只有一个fc则指定所有参数的格式为fc，否则fc_list的大小和params的大小一样，指定每个参数的fc。
    # res_fc_list指定返回结果中各列的格式代码，意义和fc_list一样。
    @classmethod
    def make(cls, params, portal=b'', stmt=b'', fc_list=(), res_fc_list=()):
        params = List2Xval(params)
        return cls(portal=portal, stmt=stmt, fc_cnt=len(fc_list), fc_list=fc_list, 
                   params=params, res_fc_cnt=len(res_fc_list), res_fc_list=res_fc_list)
class Execute(Msg):
    _formats = '>x >i'
    _fields = 'portal max_num'
    @classmethod
    def make(cls, portal=b'', max_num=0):
        return cls(portal=portal, max_num=max_num)
@mputils.Check(attname='obj_type', attvals=ObjType.v2smap)
class DescribeClose(Msg):
    _formats = '>s >x'
    _fields = 'obj_type obj_name'
    # 注意:不能通过DescribeClose调用下面这2个方法，应该通过Describe和Close调用。
    @classmethod
    def stmt(cls, name=b''):
        return cls(obj_type=ObjType.OBJ_PreparedStmt, obj_name=name)
    @classmethod
    def portal(cls, name=b''):
        return cls(obj_type=ObjType.OBJ_Portal, obj_name=name)
class Describe(DescribeClose):
    pass
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
@mputils.SeqAccess(attname='args', f=lambda x:(None if x.sz < 0 else x.data))
class FunctionCall(Msg):
    _formats = '>i >h -0>h >24X >h'
    _fields = 'foid fc_cnt fc_list args res_fc'
    # fc_list的意思和Bind.make一样。
    @classmethod
    def make(cls, foid, args, fc_list=(), res_fc=0):
        args = List2Xval(args)
        return cls(foid=foid, fc_cnt=len(fc_list), fc_list=fc_list, args=args, res_fc=res_fc)
class Terminate(Msg):
    pass
# 'p'消息类型是对Authentication的回应，包括多个具体的类型，需要根据上下文判断需要那个具体类型。
# AuthResponse包含data，这data由具体的类型解析；反过来具体类型的tobytes结果要赋值给AuthResponse的data。
# 比如：
#     r = SASLInitialResponse(name=b'xxxx', response=xval(b'yyyy'))
#     ar = AuthResponse(data=bytes(r))  or  ar = AuthResponse(r)
#     r2 = SASLInitialResponse(ar.data)   不能用ar.tobytes()或者bytes(ar)
class AuthResponse(Msg):
    _formats = '>a'
    _fields = 'data'
class PasswordMessage(struct_base):
    _formats = '>x'
    _fields = 'password'
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
class SASLInitialResponse(struct_base):
    _formats = '>x >4x'
    _fields = 'name response'
class SASLResponse(struct_base):
    _formats = '>a'
    _fields = 'msgdata'
class GSSResponse(struct_base):
    _formats = '>a'
    _fields = 'msgdata'

# 
# BE msg
# 
# 某些authtype即使是没有data值的，也要把b''赋值给data。
@mputils.Check(attname='authtype', attvals=AuthType.v2smap)
class Authentication(Msg):
    _formats = '>i >a'
    _fields = 'authtype data'
    # 检查val是否是有效的data，在给data赋值前必须先给authtype赋值。
    def _check_data(self, val):
        if not self.field_assigned('authtype'):
            raise ValueError('authtype should be assigned before data')
        if self.authtype not in AuthType._HasData and val:
            raise ValueError('authtype(%s) should has empty data(%s)' % (AuthType.v2smap[self.authtype], val))
        if self.authtype in AuthType._HasData and not val:
            raise ValueError('authtype(%s) should has data which is not empty' % (AuthType.v2smap[self.authtype],))
        # 检查具体auth类型的data的有效性
        if self.authtype == AuthType.AT_MD5Password and len(val) != 4:
            raise ValueError('the data size for authtype(MD5Password) should be 4:%s' % val)
    def __repr__(self):
        return '<%s authtype=%s data=%s>' % (type(self).__name__, AuthType.v2smap[self.authtype], self.data)
    # 根据本消息的类型创建相应的AuthResponse消息
    def make_ar(self, **kwargs):
        if self.authtype in (AuthType.AT_CleartextPassword, AuthType.AT_MD5Password):
            return AuthResponse(PasswordMessage.make(md5salt=self.data, **kwargs))
        elif self.authtype == AuthType.AT_SASL:
            sasl = SASL(self.data)
            mechs = list(sasl)
            if 'SCRAM-SHA-256' not in mechs:
                raise RuntimeError('only support SCRAM-SHA-256. server support %s' % mechs)
            return AuthResponse(kwargs['sasl_init_resp_msg'])
        elif self.authtype == AuthType.AT_SASLContinue:
            return AuthResponse(kwargs['sasl_resp_msg'])
        else:
            raise ValueError('do not support authentication:%s' % AuthType.v2smap[self.authtype])
Authentication.Ok = Authentication(authtype=AuthType.AT_Ok, data=b'')
# mech_name_list是服务器端支持的authentication mechanisms
# postgresql 10支持SCRAM-SHA-256和SCRAM-SHA-256-PLUS(if SSL enabled)
# 要想支持scram，在设置用户密码的时候必须把password_encryption设为'scram-sha-256'
# SASL: Simple Authentication and Security Layer
@mputils.SeqAccess(attname='mech_name_list', f=lambda x:bytes(x).decode('ascii'))
class SASL(struct_base):
    _formats = '>X'
    _fields = 'mech_name_list'
    @classmethod
    def make(cls, *names):
        names = (name.encode('ascii') if type(name)==str else name for name in names)
        mech_name_list = Xval(names)
        return cls(mech_name_list=mech_name_list)

class BackendKeyData(Msg):
    _formats = '>i >i'
    _fields = 'pid skey'
class BindComplete(Msg):
    pass
class CloseComplete(Msg):
    pass
class CommandComplete(Msg):
    _formats = '>x'
    _fields = 'tag'
class CopyData(Msg):
    _formats = '>a'
    _fields = 'data'
class CopyDone(Msg):
    pass
# just base class for Copy In/Out/Both Response
class CopyResponse(Msg):
    _formats = '>b >h -0>h'
    _fields = 'overall_fmt col_cnt col_fc_list'
    @classmethod
    def make(cls, overall_fmt, col_fc_list):
        return cls(overall_fmt=overall_fmt, col_cnt=len(col_fc_list), col_fc_list=col_fc_list)
class CopyInResponse(CopyResponse):
    pass
class CopyOutResponse(CopyResponse):
    pass
class CopyBothResponse(CopyResponse):
    pass
@mputils.SeqAccess(attname='col_vals', f=lambda x:(None if x.sz < 0 else x.data))
class DataRow(Msg):
    _formats = '>24X'
    _fields = 'col_vals'
    # 参数必须是字节串或者None
    @classmethod
    def make(cls, *vals):
        return cls(col_vals=List2Xval(vals))
class EmptyQueryResponse(Msg):
    pass
# field_list是字节串列表，字节串中第一个字节是fieldtype, 剩下的是fieldval
@mputils.SeqAccess(attname='field_list', restype='Field', resfields='t v', f=lambda x:(x[:1],x[1:]))
class ErrorNoticeResponse(Msg):
    _formats = '>X'
    _fields = 'field_list'
    def get(self, fields):
        res = []
        if type(fields) == bytes:
            fields = FieldType.ftstr2list(fields)
        if not (set(fields) <= FieldType.v2smap.keys()):
            raise ValueError('fields(%s) have unknown field type' % (fields,))
        for t, v in self:
            if t not in fields:
                continue
            res.append((FieldType.v2smap[t], v))
        return res
    # fields是(t,v)或者Field列表
    @classmethod
    def make(cls, *fields):
        field_list = []
        for t, v in fields:
            if t not in FieldType.v2smap:
                raise ValueError('unknown field type:%s' % t)
            field_list.append(t + v)
        return cls(field_list=Xval(field_list))
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
    def value(self):
        return (None if self.res_val.sz < 0 else bytes(self.res_val))
class NoData(Msg):
    pass
class NotificationResponse(Msg):
    _formats = '>i >x >x'
    _fields = 'pid channel payload'
class ParameterDescription(Msg):
    _formats = '>h -0>i'
    _fields = 'count oid_list'
class ParameterStatus(Msg):
    _formats = '>x >x'
    _fields = 'name val'
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
ReadyForQuery.Idle = ReadyForQuery(trans_status=TransStatus.TS_Idle)
ReadyForQuery.InBlock = ReadyForQuery(trans_status=TransStatus.TS_InBlock)
ReadyForQuery.Fail = ReadyForQuery(trans_status=TransStatus.TS_Fail)
# field_list包含(name, tableoid, attnum, typoid, typlen, typmod, fmtcode)
@mputils.SeqAccess(attname='field_list', restype='Field', resfields='name tableoid attnum typoid typlen typmod fmtcode')
class RowDescription(Msg):
    _formats = '>h -0>xihihih'
    _fields = 'field_cnt field_list'
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
    def get_params(self):
        # 把params转成dict，dict的key转成str，value是字节串
        if not self._params_dict:
            it = iter(self.params)
            f = lambda x: (bytes(x[0]).decode('ascii'), bytes(x[1]))
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
    def match(self, other, skip=('host','port','password')):
        def xf(x):
            x = copy.copy(x)
            for k in skip:
                x.pop(k, None)
            return self.make(**x)
        m1 = xf(self.get_params())
        m2 = xf(other)
        return m1 == m2
    @classmethod
    def make(cls, **kwargs):
        params = []
        for k, v in kwargs.items():
            params.append(k.encode('ascii'))
            if type(v) is str:
                v = v.encode('ascii')
            params.append(v)
        return cls(params = Xval(params))
class CancelRequest(Msg):
    _formats = '>i >i >i'
    _fields = 'code pid skey'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_CANCELREQUEST_CODE
class SSLRequest(Msg):
    _formats = '>i'
    _fields = 'code'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_SSLREQUEST_CODE
# 用于处理nnX(非00X/X)，负值串和None相互转换。
def Xval2List(v):
    return [None if x.sz < 0 else x.data for x in v]
def List2Xval(vlist):
    xlist = (xval(b'', sz=-1) if v is None else v for v in vlist)
    return Xval(xlist)

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
        raise RuntimeError('startup msg is invalid. msg_len:%s data_len:%s' % (msg_len, data_len))
    return data_len == msg_len
# 分析FE的第一个消息，返回相应的消息类的对象或者抛出异常。data不包括开头表示大小的4个字节。
def parse_startup_msg(data):
    code = struct.unpack('>i', data[:4])[0]
    if code == PG_PROTO_VERSION2_NUM:
        raise RuntimeError('do not support version 2 protocol')
    elif code == PG_PROTO_VERSION3_NUM:
        return StartupMessage(data)
    elif code == PG_CANCELREQUEST_CODE:
        return CancelRequest(data)
    elif code == PG_SSLREQUEST_CODE:
        return SSLRequest(data)
    else:
        raise RuntimeError('unknown code(%s) in startup msg' % code)
# 判断data中从idx开始是否有完整的消息，返回消息包的长度(包括开头5个字节)。如果没有完整消息则返回0。
def has_msg(data, idx, *, fe=True):
    data_len = len(data)
    if data_len - idx < 5:
        return 0
    msg_type = data[idx:idx+1]
    MsgMeta.check_msg_type(msg_type, fe=fe)
    msg_len = struct.unpack('>i', data[idx+1:idx+5])[0]
    if data_len -idx < msg_len + 1:
        return 0
    return msg_len + 1
# 
# 从data中提取多个消息包，返回下一个idx和消息对象列表。该函数不能用于parse从FE发给BE的第一个消息。
#   data : 原始数据。
#   max_msg : 最多提取多少个消息包。如果为0表示提取所有。
#   stop : 指定提取停止的条件。可以指定消息类型，包含多个消息类型(多个MsgType的+或者序列)；也可以是函数，函数返回True表示停止提取。
#   fe : 是否是来自FE的消息。
# 
def parse_pg_msg(data, max_msg=0, stop=None, *, fe=True):
    msg_list = []
    idx, cnt = 0, 0
    msg_map = MsgMeta.fe_msg_map if fe else MsgMeta.be_msg_map
    while True:
        msg_len = has_msg(data, idx, fe=fe)
        if msg_len <= 0:
            break
        msg_type = data[idx:idx+1]
        msg_data = data[idx+5:idx+msg_len]
        idx += msg_len
        
        msg = msg_map[msg_type](msg_data)
        msg_list.append(msg)
        if stop:
            if callable(stop):
                if stop(msg): break
            else:
                if msg_type in stop: break
        cnt += 1
        if max_msg > 0 and cnt >= max_msg:
            break
    return (idx, msg_list)
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
