#!/bin/env python3
# -*- coding: GBK -*-
# 
# 解析postgresql c/s version 3协议，不包括复制相关的协议。
# postgresql消息格式: type + len + data。type是一个字节，len是4个字节表示大小，包括len本身的4个字节。
# FE的第一个消息不包含type部分。
# 传给Msg派生类的buf不包含开头的5个字节(或者4个字节)。
# 
import sys, os
import struct
import hashlib
import collections
import mputils
from structview import *

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
    MT_Bind = b'B'                 # Bind
    MT_Close = b'C'                # Close
    MT_CopyData = b'd'             # CopyData (和be共用)
    MT_CopyDone = b'c'             # CopyDone (和be共用)
    MT_CopyFail = b'f'             # CopyFail
    MT_Describe = b'D'             # Describe
    MT_Execute = b'E'              # Execute
    MT_Flush = b'H'                # Flush
    MT_FunctionCall = b'F'         # FunctionCall
    MT_Parse = b'P'                # Parse (大写的P)
    MT_PasswordMessage = b'p'      # PasswordMessage (小写的p)
    MT_Query = b'Q'                # Query
    MT_Sync = b'S'                 # Sync
    MT_Terminate = b'X'            # Terminate
class BeMsgType(metaclass=mputils.V2SMapMeta, skip=(b'',), strip=3):
    # BE msg type
    MT_Authentication = b'R'       # AuthenticationXXX
    MT_BackendKeyData = b'K'       # BackendKeyData
    MT_BindComplete = b'2'         # BindComplete
    MT_CloseComplete = b'3'        # CloseComplete
    MT_CommandComplete = b'C'      # CommandComplete
    MT_CopyData = b'd'             # CopyData
    MT_CopyDone = b'c'             # CopyDone
    MT_CopyResponse = b''          # placeholder for CopyResponse base class
    MT_CopyInResponse = b'G'       # CopyInResponse
    MT_CopyOutResponse = b'H'      # CopyOutResponse
    MT_CopyBothResponse = b'W'     # CopyBothResponse
    MT_DataRow = b'D'              # DataRow
    MT_EmptyQueryResponse = b'I'   # EmptyQueryResponse
    MT_ErrorResponse = b'E'        # ErrorResponse
    MT_FunctionCallResponse = b'V' # FunctionCallResponse
    MT_NoData = b'n'               # NoData
    MT_NoticeResponse = b'N'       # NoticeResponse
    MT_NotificationResponse = b'A' # NotificationResponse (async message)
    MT_ParameterDescription = b't' # ParameterDescription
    MT_ParameterStatus = b'S'      # ParameterStatus (async message while reloading configure file)
    MT_ParseComplete = b'1'        # ParseComplete
    MT_PortalSuspended = b's'      # PortalSuspended
    MT_ReadyForQuery = b'Z'        # ReadyForQuery
    MT_RowDescription = b'T'       # RowDescription
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
        if self.msg_type:
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
# 消息基类。有些不能用struct_base实现的消息类不从Msg派生，包括Authentication/CopyData。
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

# FE msg
class Bind(Msg):
    _formats = '>x >x >h -0>h >24X >h -0>h'
    _fields = 'portal pstmt fc_cnt fc_list params res_fc_cnt res_fc_list'
@mputils.Check(attname='obj_type', attvals=ObjType.v2smap)
class Close(Msg):
    _formats = '>s >x'
    _fields = 'obj_type obj_name'
class CopyFail(Msg):
    _formats = '>x'
    _fields = 'err_msg'
@mputils.Check(attname='obj_type', attvals=ObjType.v2smap)
class Describe(Msg):
    _formats = '>s >x'
    _fields = 'obj_type obj_name'
class Execute(Msg):
    _formats = '>x >i'
    _fields = 'portal max_num'
class Flush(Msg):
    pass
class FunctionCall(Msg):
    _formats = '>i >h -0>h >24X >h'
    _fields = 'foid fc_cnt fc_list arguments res_fc'
class Parse(Msg):
    _formats = '>x >x >h -0>i'
    _fields = 'portal query param_cnt oid_list'
class PasswordMessage(Msg):
    _formats = '>x'
    _fields = 'password'
    # 参数必须是字节串
    @classmethod
    def md5pw(cls, password, username=None, md5salt = None):
        if md5salt:
            if not username:
                raise SystemError('BUG: should provide username for md5 authentication')
            password = b'md5' + md5(md5(password + username) + md5salt)
        return cls(password=password)
class Query(Msg):
    _formats = '>x'
    _fields = 'query'
class Sync(Msg):
    pass
class Terminate(Msg):
    pass

# BE msg
# Authentication特殊，不从Msg派生。
@BE
class Authentication():
    msg_type = MsgType.MT_Authentication
    # buf和关键字参数互斥
    def __init__(self, buf=None, *, authtype=None, data=b''):
        if buf:
            self.authtype = struct.unpack('>i', buf[:4])[0]
            self.data = buf[4:]
        else:
            self.authtype = authtype
            self.data = data
        self._check()
    def _check(self):
        if self.authtype not in AuthType.v2smap:
            raise ValueError('unknown authtype %s' % self.authtype)
        if self.authtype not in AuthType._HasData and self.data:
            raise ValueError('authtype(%s) should not has data(%s)' % (AuthType.v2smap[self.authtype], self.data))
        if self.authtype in AuthType._HasData and not self.data:
            raise ValueError('authtype(%s) should has data' % (AuthType.v2smap[self.authtype],))
        # 检查具体auth类型的data的有效性
        if self.authtype == AuthType.AT_MD5Password and len(self.data) != 4:
            raise ValueError('the data size for authtype(MD5Password) should be 4:%s' % self.data)
    def tobytes(self):
        d = struct.pack('>i', self.authtype) + self.data
        return self.msg_type + struct.pack('>i', len(d)+4) + d
    def __repr__(self):
        return '<%s authtype=%s data=%s>' % (type(self).__name__, AuthType.v2smap[self.authtype], self.data)
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
# CopyData特殊，单独实现，不从Msg派生。
@FE
@BE
class CopyData():
    msg_type = MsgType.MT_CopyData
    def __init__(self, buf):
        self.data = buf
    def tobytes(self):
        return self.msg_type + struct.pack('>i', len(self.data)+4) + self.data
    def __repr__(self):
        return '<%s data=%s>' % (type(self).__name__, self.data)
class CopyDone(Msg):
    pass
# just base class for Copy In/Out/Both Response
class CopyResponse(Msg):
    _formats = '>b >h -0>h'
    _fields = 'overall_fmt col_cnt col_fc_list'
class CopyInResponse(CopyResponse):
    pass
class CopyOutResponse(CopyResponse):
    pass
class CopyBothResponse(CopyResponse):
    pass
class DataRow(Msg):
    _formats = '>24X'
    _fields = 'col_vals'
class EmptyQueryResponse(Msg):
    pass
# err_list是字节串列表，字节串中第一个字节是fieldtype, 剩下的是fieldval
@mputils.SeqAccess(attname='err_list', restype='Field', resfields='t v', f=lambda x:(x[:1],x[1:]))
class ErrorResponse(Msg):
    _formats = '>X'
    _fields = 'err_list'
class FunctionCallResponse(Msg):
    _formats = '>4x'
    _fields = 'res_val'
class NoData(Msg):
    pass
# notice_list是字节串列表，字节串中第一个字节是fieldtype, 剩下的是fieldval
@mputils.SeqAccess(attname='notice_list', restype='Field', resfields='t v', f=lambda x:(x[:1],x[1:]))
class NoticeResponse(Msg):
    _formats = '>X'
    _fields = 'notice_list'
class NotificationResponse(Msg):
    _formats = '>i >x >x'
    _fields = 'pid channel payload'
class ParameterDescription(Msg):
    _formats = '>h -0>i'
    _fields = 'param_cnt oid_list'
class ParameterStatus(Msg):
    _formats = '>x >x'
    _fields = 'param_name param_val'
class ParseComplete(Msg):
    pass
class PortalSuspended(Msg):
    pass
@mputils.Check(attname='trans_status', attvals=TransStatus.v2smap)
class ReadyForQuery(Msg):
    _formats = '>s'
    _fields = 'trans_status'
# field_list包含(name, tableoid, attnum, typoid, typlen, typmod, fmtcode)
@mputils.SeqAccess(attname='field_list', restype='Field', resfields='name tableoid attnum typoid typlen typmod fmtcode')
class RowDescription(Msg):
    _formats = '>h -0>xihihih'
    _fields = 'field_cnt field_list'

# FE->BE的第一个消息
PG_PROTO_VERSION2_NUM = 131072
PG_PROTO_VERSION3_NUM = 196608
PG_CANCELREQUEST_CODE = 80877102
PG_SSLREQUEST_CODE    = 80877103

class StartupMessage(Msg):
    _formats = '>i >X'
    _fields = 'code params'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code = PG_PROTO_VERSION3_NUM
        self._params_dict = None
    def get_params(self):
        # 把params转成dict，dict的key转成str，value是字节串
        if not self._params_dict:
            it = iter(self.params)
            f = lambda x: (bytes(x[0]).decode('ascii'), bytes(x[1]))
            self._params_dict = dict(map(f, zip(it, it)))
        return self._params_dict
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
#============================================================================================
# 和协议解析不直接相关的
# 
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
#   fe : 是否是来自FE的消息。
# 
def parse_pg_msg(data, max_msg = 0, *, fe=True):
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
        
        msg_list.append(msg_map[msg_type](msg_data))
        cnt += 1
        if max_msg > 0 and cnt >= max_msg:
            break
    return (idx, msg_list)

# main
if __name__ == '__main__':
    pass
