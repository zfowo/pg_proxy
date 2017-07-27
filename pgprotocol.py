#!/bin/env python3
# -*- coding: GBK -*-
# 
# 分析PostgreSQL version 3 protocol
# 
# process_XXX : 解析消息，返回类型是tuple，该tuple中的第一个元素是消息名，第二个元素是消息类型字符，后面是与消息类型对应的值。
# make_XXX1 : 从process_XXX的返回结果构造一个消息。该函数一般调用make_XXX2。
# make_XXX2 : 从具体的参数构造一个消息。
# make_Msg0 : 从原始数据(msg_type, msg_data)构造一个消息。
# make_Msg1 : 从process_XXX的返回结果构造一个消息。
# 注: 不能通过make_Msg0/make_Msg1来构造那三个没有消息类型的消息。必须直接通过make_XXX1/make_XXX2来构造。
#     make函数中的串类型的参数的值必须是bytes。
#
# 
# 
import sys, os
import struct, socket, hashlib

from netutils import NONBLOCK_SEND_RECV_OK

# 
# utility functions
# 
# 输入输出都是bytes类型
def md5(bs):
    m = hashlib.md5()
    m.update(bs)
    return m.hexdigest().encode('latin1')
# 获得data中从idx开始的C串，C串以\x00结尾。
def get_cstr(data, idx):
    end = idx
    while (data[end] != 0):
        end += 1
    return data[idx:end+1]
# make一个C串。s的类型必须是bytes。
def make_cstr(s):
    s_len = len(s)
    if s_len == 0 or s[len(s)-1] != 0:
        s += b'\x00'
    return s
# 
# 
# 
def make_Msg0(msg_type, msg_data):
    return msg_type + struct.pack('>i', len(msg_data)+4) + msg_data
def make_Msg1(msg_res, is_from_be = True):
    if is_from_be:
        return be_msg_type_info[msg_res[1]][1](msg_res)
    else:
        return fe_msg_type_info[msg_res[1]][1](msg_res)
# msg_type : 消息类型
# msg_data : 消息内容，不包括表示长度的那4个字节
def process_AuthenticationXXX(msg_type, msg_data):
    v = struct.unpack('>i', msg_data[:4])[0]
    if v == 0: 
        return ('AuthenticationOk', msg_type)
    elif v == 2:
        return ('AuthenticationKerberosV5', msg_type)
    elif v == 3:
        return ('AuthenticationCleartextPassword', msg_type)
    elif v == 5:
        return ('AuthenticationMD5Password', msg_type, msg_data[4:])
    elif v == 6:
        return ('AuthenticationSCMCredential', msg_type)
    elif v == 7:
        return ('AuthenticationGSS', msg_type)
    elif v == 9:
        return ('AuthenticationSSPI', msg_type)
    elif v == 8:
        return ('AuthenticationGSSContinue', msg_type, msg_data[4:])
    else:
        raise RuntimeError('Unknown Authentication message:(%s,%s,%s)' % (msg_type, v, msg_data))
def make_AuthenticationXXX1(msg_res):
    return make_AuthenticationXXX2(msg_res[0], *msg_res[2:])
def make_AuthenticationXXX2(auth_name, *auth_params):
    msg_data = b''
    if auth_name == 'AuthenticationOk' or auth_name == b'AuthenticationOk':
        msg_data = struct.pack('>i', 0)
    elif auth_name == 'AuthenticationCleartextPassword' or auth_name == b'AuthenticationCleartextPassword':
        msg_data = struct.pack('>i', 3)
    elif auth_name == 'AuthenticationMD5Password' or auth_name == b'AuthenticationMD5Password':
        msg_data = struct.pack('>i', 5) + auth_params[0] # auth_params[0]是md5 salt
    else:
        raise RuntimeError('do not support authentication type:%s' % auth_name)
    return make_Msg0(b'R', msg_data)

def process_BackendKeyData(msg_type, msg_data):
    pid, skey = struct.unpack('>ii', msg_data)
    return ('BackendKeyData', msg_type, pid, skey)
def make_BackendKeyData1(msg_res):
    return make_BackendKeyData2(msg_res[2], msg_res[3])
def make_BackendKeyData2(pid, skey):
    msg_data = struct.pack('>ii', pid, skey)
    return make_Msg0(b'K', msg_data)

def process_BindComplete(msg_type, msg_data):
    return ('BindComplete', msg_type)
def make_BindComplete1(msg_res):
    return make_BindComplete2()
def make_BindComplete2():
    return make_Msg0(b'2', b'')

def process_CloseComplete(msg_type, msg_data):
    return ('CloseComplete', msg_type)
def make_CloseComplete1(msg_res):
    return make_CloseComplete2()
def make_CloseComplete2():
    return make_Msg0(b'3', b'')

def process_CommandComplete(msg_type, msg_data):
    return ('CommandComplete', msg_type, msg_data)
def make_CommandComplete1(msg_res):
    return make_CommandComplete2(msg_res[2])
def make_CommandComplete2(cmd_tag):
    return make_Msg0(b'C', make_cstr(cmd_tag))

def process_CopyData(msg_type, msg_data):
    return ('CopyData', msg_type, msg_data)
def make_CopyData1(msg_res):
    return make_CopyData2(msg_res[2])
def make_CopyData2(data):
    return make_Msg0(b'd', data)

def process_CopyDone(msg_type, msg_data):
    return ('CopyDone', msg_type)
def make_CopyDone1(msg_res):
    return make_CopyDone2()
def make_CopyDone2():
    return make_Msg0(b'c', b'')

def process_CopyInResponse(msg_type, msg_data):
    overall_fmt, col_cnt = struct.unpack('>bh', msg_data[:3])
    col_fmts = struct.unpack('>%dh'%col_cnt, msg_data[3:])
    return ('CopyInResponse', msg_type, overall_fmt, col_cnt, col_fmts)
def make_CopyInResponse1(msg_res):
    return make_CopyInResponse2(msg_res[2], msg_res[4])
def make_CopyInResponse2(overall_fmt, col_fmts):
    '''
    overall_fmt : 总的格式代码。0是text格式；1是binary格式。
    col_fmts : 指定每个列的格式代码。如果overall_fmt为0，那么必须全为0。
    '''
    cnt = len(col_fmts)
    msg_data = struct.pack('>bh%dh'%cnt, overall_fmt, cnt, *col_fmts)
    return make_Msg0(b'G', msg_data)

def process_CopyOutResponse(msg_type, msg_data):
    overall_fmt, col_cnt = struct.unpack('>bh', msg_data[:3])
    cols_fmt = struct.unpack('>%dh'%col_cnt, msg_data[3:])
    return ('CopyOutResponse', msg_type, overall_fmt, col_cnt, cols_fmt)
def make_CopyOutResponse1(msg_res):
    return make_CopyOutResponse2(msg_res[2], msg_res[4])
def make_CopyOutResponse2(overall_fmt, col_fmts):
    '''
    overall_fmt : 总的格式代码。0是text格式；1是binary格式。
    col_fmts : 指定每个列的格式代码。如果overall_fmt为0，那么必须全为0。
    '''
    cnt = len(col_fmts)
    msg_data = struct.pack('>bh%dh'%cnt, overall_fmt, cnt, *col_fmts)
    return make_Msg0(b'H', msg_data)

def process_CopyBothResponse(msg_type, msg_data):
    overall_fmt, col_cnt = struct.unpack('>bh', msg_data[:3])
    cols_fmt = struct.unpack('>%dh'%col_cnt, msg_data[3:])
    return ('CopyBothResponse', msg_type, overall_fmt, col_cnt, cols_fmt)
def make_CopyBothResponse1(msg_res):
    return make_CopyBothResponse2(msg_res[2], msg_res[4])
def make_CopyBothResponse2(overall_fmt, col_fmts):
    '''
    overall_fmt : 总的格式代码。0是text格式；1是binary格式。
    col_fmts : 指定每个列的格式代码。如果overall_fmt为0，那么必须全为0。
    '''
    cnt = len(col_fmts)
    msg_data = struct.pack('>bh%dh'%cnt, overall_fmt, cnt, *col_fmts)
    return make_Msg0(b'W', msg_data)

def process_DataRow(msg_type, msg_data):
    col_cnt = struct.unpack('>h', msg_data[:2])[0]
    idx = 2
    res = ('DataRow', msg_type, col_cnt, [])
    col_list = res[3]
    for i in range(col_cnt):
        col_len = struct.unpack('>i', msg_data[idx:idx+4])[0]
        idx += 4
        col_val = b''
        if col_len > 0:
            col_val = msg_data[idx:idx+col_len]
        idx += (col_len if col_len > 0 else 0)
        col_list.append((col_len, col_val))
    return res
def make_DataRow1(msg_res):
    return make_DataRow2(msg_res[3])
def make_DataRow2(col_list):
    '''
    col_list : 列值的列表。列表中的元素是个tuple，该tuple中的第一个元素指定了列值的长度，-1表示列的值为NULL；
               tuple中的第二个元素是列值(如果第一个元素的值为0或者-1，那么列值必须为空字节串)。
    '''
    cnt = len(col_list)
    msg_data = struct.pack('>h', cnt)
    for col in col_list:
        msg_data += struct.pack('>i', col[0]) + col[1]
    return make_Msg0(b'D', msg_data)

def process_EmptyQueryResponse(msg_type, msg_data):
    return ('EmptyQueryResponse', msg_type)
def make_EmptyQueryResponse1(msg_res):
    return make_EmptyQueryRespone2()
def make_EmptyQueryResponse2():
    return make_Msg0(b'I', b'')

def p_ErrorNoticeField(msg_data, idx, res):
    while True:
        field_type = msg_data[idx:idx+1]
        if field_type == b'\x00':
            break
        field_val = get_cstr(msg_data, idx + 1)
        idx += 1 + len(field_val)
        res.append((field_type, field_val))
def process_ErrorResponse(msg_type, msg_data):
    res = ('ErrorResponse', msg_type, [])
    p_ErrorNoticeField(msg_data, 0, res[2])
    return res
def make_ErrorResponse1(msg_res):
    return make_ErrorResponse2(msg_res[2])
def make_ErrorResponse2(err_field_list):
    '''
    err_field_list : 指定错误field列表。列表中的元素类型是tuple，tuple中的第一个元素是field类型，第二个元素是与field类型对应的串值。支持的field类型有：
                     .) b'S' : Severity: the field contents are ERROR, FATAL, or PANIC (in an error message), or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message), 
                               or a localized translation of one of these. Always present.
                     .) b'C' : Code: the SQLSTATE code for the error (see Appendix A). Not localizable. Always present.
                     .) b'M' : Message: the primary human-readable error message. This should be accurate but terse (typically one line). Always present.
                     .) b'D' : Detail: an optional secondary error message carrying more detail about the problem. Might run to multiple lines.
                     .) b'H' : Hint: an optional suggestion what to do about the problem. This is intended to differ from Detail in that 
                               it offers advice (potentially inappropriate) rather than hard facts. Might run to multiple lines.
                     .) ... 其他具体看文档
    '''
    msg_data = b''
    for err_field in err_field_list:
        msg_data += err_field[0] + make_cstr(err_field[1])
    msg_data += b'\x00'
    return make_Msg0(b'E', msg_data)

def process_FunctionCallResponse(msg_type, msg_data):
    v_len = struct.unpack('>i', msg_data[:4])[0]
    val = b''
    if v_len > 0:
        val = msg_data[4:4+v_len]
    return ('FunctionCallResponse', msg_type, v_len, val)
def make_FunctionCallResponse1(msg_res):
    return make_FunctionCallResponse2(msg_res[2], msg_res[3])
def make_FunctionCallResponse2(res_len, res_val):
    '''
    res_len : 函数调用结果值的长度。为-1表示函数返回值为NULL。
    res_val : 函数调用的结果值。如果res_len为0或者-1，那么该值必须为b''。
    '''
    msg_data = struct.pack('>i', res_len) + res_val
    return make_Msg0(b'V', msg_data)

def process_NoData(msg_type, msg_data):
    return ('NoData', msg_type)
def make_NoData1(msg_res):
    return make_NoData2()
def make_NoData2():
    return make_Msg0(b'n', b'')

def process_NoticeResponse(msg_type, msg_data):
    res = ('NoticeResponse', msg_type, [])
    p_ErrorNoticeField(msg_data, 0, res[2])
    return res
def make_NoticeResponse1(msg_res):
    return make_NoticeResponse2(msg_res[2])
def make_NoticeResponse2(notice_field_list):
    '''
    notice_field_list : 和make_ErrorResponse2类似。
    '''
    msg_data = b''
    for notice_field in notice_field_list:
        msg_data += notice_field[0] + make_cstr(notice_field[1])
    msg_data += b'\x00'
    return make_Msg0(b'N', msg_data)

def process_NotificationResponse(msg_type, msg_data):
    pid = struct.unpack('>i', msg_data[:4])[0]
    channel = get_cstr(msg_data, 4)
    payload = get_cstr(msg_data, 4+len(channel))
    return ('NotificationResponse', msg_type, pid, channel, payload)
def make_NotificationResponse1(msg_res):
    return make_NotificationResponse2(msg_res[2], msg_res[3], msg_res[4])
def make_NotificationResponse2(pid, channel, payload):
    '''
    pid : 发送notification的进程ID。
    channel : channel名字。
    payload : payload串。
    '''
    msg_data = struct.pack('>i', pid) + make_cstr(channel) + make_cstr(payload)
    return make_Msg0(b'A', msg_data)

def process_ParameterDescription(msg_type, msg_data):
    param_cnt = struct.unpack('>h', msg_data[:2])[0]
    param_type_oids = struct.unpack('>%di'%param_cnt, msg_data[2:])
    return ('ParameterDescription', msg_type, param_cnt, param_type_oids)
def make_ParameterDescription1(msg_res):
    return make_ParameterDescription2(msg_res[3])
def make_ParameterDescription2(param_type_oids):
    '''
    param_type_oids : 参数类型的oid列表。
    '''
    cnt = len(param_type_oids)
    msg_data = struct.pack('>h%di', cnt, *param_type_oids)
    return make_Msg0(b't', msg_data)

def process_ParameterStatus(msg_type, msg_data):
    param_name = get_cstr(msg_data, 0)
    param_val = get_cstr(msg_data, len(param_name))
    return ('ParameterStatus', msg_type, param_name, param_val)
def make_ParameterStatus1(msg_res):
    return make_ParameterStatus2(msg_res[2], msg_res[3])
def make_ParameterStatus2(param_name, param_val):
    msg_data = make_cstr(param_name) + make_cstr(param_val)
    return make_Msg0(b'S', msg_data)

def process_ParseComplete(msg_type, msg_data):
    return ('ParseComplete', msg_type)
def make_ParseComplete1(msg_res):
    return make_ParseComplete2()
def make_ParseComplete2():
    return make_Msg0(b'1', b'')

def process_PortalSuspended(msg_type, msg_data):
    return ('PortalSuspended', msg_type)
def make_PortalSuspended1(msg_res):
    return make_PortalSuspended2()
def make_PortalSuspended2():
    return make_Msg0(b's', b'')

def process_ReadyForQuery(msg_type, msg_data):
    return ('ReadyForQuery', msg_type, msg_data[:1])
def make_ReadyForQuery1(msg_res):
    return make_ReadyForQuery2(msg_res[2])
def make_ReadyForQuery2(trans_status):
    '''
    trans_status : 事务状态。b'I'表示空闲(不在事务内)；b'T'表示在事务块内；b'E'表示一个失败的事务块内(后续的语句将拒绝执行)。
    '''
    return make_Msg0(b'Z', trans_status)

def process_RowDescription(msg_type, msg_data):
    field_cnt = struct.unpack('>h', msg_data[:2])[0]
    res = ('RowDescription', msg_type, field_cnt, [])
    field_list = res[3]
    idx = 2
    for i in range(field_cnt):
        f_name = get_cstr(msg_data, idx)
        idx += len(f_name)
        f_table_oid, f_attr_num, f_type_oid, f_typlen, f_typmod, f_fmtcode = struct.unpack('>ihihih', msg_data[idx:idx+18])
        idx += 18
        field_list.append((f_name, f_table_oid, f_attr_num, f_type_oid, f_typlen, f_typmod, f_fmtcode))
    return res
def make_RowDescription1(msg_res):
    return make_RowDescription2(msg_res[3])
def make_RowDescription2(field_list):
    '''
    field_list : 指定field描述列表。列表中的元素类型是tuple，该tuple包含：
                 .) f_name : field名字。
                 .) f_table_oid : 如果该field属于某个表，那么就是表的oid，否则为0。
                 .) f_attr_num : 如果该field属于某个表，那么就是该列在表中的属性号，否则为0。
                 .) f_type_oid : field的数据类型的oid。
                 .) f_typlen : field的数据类型的长度，如果是可变长度类型，那么为-1。
                 .) f_typmod : field的数据类型的修饰符。
                 .) f_fmtcode : field的值的格式代码。0表示text；1表示binary。
    '''
    cnt = len(field_list)
    msg_data = struct.pack('>h', cnt)
    for f in field_list:
        msg_data += make_cstr(f[0]) + struct.pack('>ihihih', *f[1:])
    return make_Msg0(b'T', msg_data)

#
be_msg_type_info = {
    b'R' : (process_AuthenticationXXX, make_AuthenticationXXX1),       # AuthenticationXXX
    b'K' : (process_BackendKeyData, make_BackendKeyData1),             # BackendKeyData
    b'2' : (process_BindComplete, make_BindComplete1),                 # BindComplete
    b'3' : (process_CloseComplete, make_CloseComplete1),               # CloseComplete
    b'C' : (process_CommandComplete, make_CommandComplete1),           # CommandComplete
    b'd' : (process_CopyData, make_CopyData1),                         # CopyData
    b'c' : (process_CopyDone, make_CopyDone1),                         # CopyDone
    b'G' : (process_CopyInResponse, make_CopyInResponse1),             # CopyInResponse
    b'H' : (process_CopyOutResponse, make_CopyOutResponse1),           # CopyOutResponse
    b'W' : (process_CopyBothResponse, make_CopyBothResponse1),         # CopyBothResponse
    b'D' : (process_DataRow, make_DataRow1),                           # DataRow
    b'I' : (process_EmptyQueryResponse, make_EmptyQueryResponse1),     # EmptyQueryResponse
    b'E' : (process_ErrorResponse, make_ErrorResponse1),               # ErrorResponse
    b'V' : (process_FunctionCallResponse, make_FunctionCallResponse1), # FunctionCallResponse
    b'n' : (process_NoData, make_NoData1),                             # NoData
    b'N' : (process_NoticeResponse, make_NoticeResponse1),             # NoticeResponse
    b'A' : (process_NotificationResponse, make_NotificationResponse1), # NotificationResponse (async message)
    b't' : (process_ParameterDescription, make_ParameterDescription1), # ParameterDescription
    b'S' : (process_ParameterStatus, make_ParameterStatus1),           # ParameterStatus (async message while reloading configure file)
    b'1' : (process_ParseComplete, make_ParseComplete1),               # ParseComplete
    b's' : (process_PortalSuspended, make_PortalSuspended1),           # PortalSuspended
    b'Z' : (process_ReadyForQuery, make_ReadyForQuery1),               # ReadyForQuery
    b'T' : (process_RowDescription, make_RowDescription1),             # RowDescription
}
# 
# 分析来自frontend的消息
# 
def process_Bind(msg_type, msg_data):
    idx = 0
    portal_name = get_cstr(msg_data, idx)
    idx += len(portal_name)
    stmt_name = get_cstr(msg_data, idx)
    idx += len(stmt_name)
    
    fmt_code_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    fmt_code_list = struct.unpack('>%dh'%fmt_code_cnt, msg_data[idx:idx+fmt_code_cnt*2])
    idx += fmt_code_cnt*2
    
    param_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    param_list = []
    for i in range(param_cnt):
        v_len = struct.unpack('>i', msg_data[idx:idx+4])[0]
        idx += 4
        val = b''
        if v_len > 0:
            val = msg_data[idx:idx+v_len]
        idx += (v_len if v_len > 0 else 0)
        param_list.append((v_len, val))
    
    res_fmt_code_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    res_fmt_code_list = struct.unpack('>%dh'%res_fmt_code_cnt, msg_data[idx:idx+res_fmt_code_cnt*2])
    
    return ('Bind', msg_type, portal_name, stmt_name, fmt_code_cnt, fmt_code_list, param_cnt, param_list, res_fmt_code_cnt, res_fmt_code_list)
def make_Bind1(msg_res):
    return make_Bind2(msg_res[2], msg_res[3], msg_res[5], msg_res[7], msg_res[9])
def make_Bind2(portal_name, stmt_name, param_fmt_codes, param_list, res_fmt_codes):
    '''
    portal_name : portal名字。
    stmt_name : prepared语句的名字。
    param_fmt_codes : 指定参数值的格式代码。
                      .) 如果为空列表，那就表示没有参数或者所有参数值的格式代码为0；
                      .) 如果只有一个元素，那么该元素值指定了所有参数的格式代码；
                      .) 否则元素个数等于参数个数，每个元素指定了对应参数值的格式代码。
    param_list : 参数值的列表。列表中的元素是个tuple，该tuple中的第一个元素指定了参数值的长度，-1表示参数的值为NULL；
                 tuple中的第二个元素是参数值(如果第一个元素的值为0或者-1，那么参数值必须为空字节串)。
    res_fmt_codes : 指定结果列的格式代码。和param_fmt_codes意识相同。
    '''
    msg_data = make_cstr(portal_name) + make_cstr(stmt_name)
    
    cnt = len(param_fmt_codes)
    msg_data += struct.pack('>h%dh'%cnt, cnt, *param_fmt_codes)
    
    cnt = len(param_list)
    msg_data += struct.pack('>h', cnt)
    for param in param_list:
        msg_data += struct.pack('>i', param[0]) + param[1]
    
    cnt = len(res_fmt_codes)
    msg_data += struct.pack('>h%dh'%cnt, cnt, *res_fmt_codes)
    return make_Msg0(b'B', msg_data)

def process_Close(msg_type, msg_data):
    obj_type = msg_data[:1]
    obj_name = get_cstr(msg_data, 1)
    return ('Close', msg_type, obj_type, obj_name)
def make_Close1(msg_res):
    return make_Close2(msg_res[2], msg_res[3])
def make_Close2(obj_type, obj_name):
    '''
    obj_type : 对象类型。为b'S'表示是prepared语句；为b'P'表示是portal。
    obj_name : prepared语句或者portal的名字。
    '''
    msg_data = obj_type + make_cstr(obj_name)
    return make_Msg0(b'C', msg_data)

def process_CopyFail(msg_type, msg_data):
    return ('CopyFail', msg_type, msg_data)
def make_CopyFail1(msg_res):
    return make_Fail2(msg_res[2])
def make_CopyFail2(errmsg):
    '''
    errmsg : 错误信息。
    '''
    msg_data = make_cstr(errmsg)
    return make_Msg0(b'f', msg_data)

def process_Describe(msg_type, msg_data):
    obj_type = msg_data[:1]
    obj_name = get_cstr(msg_data, 1)
    return ('Close', msg_type, obj_type, obj_name)
def make_Describe1(msg_res):
    return make_Describe2(msg_res[2], msg_res[3])
def make_Describe2(obj_type, obj_name):
    '''
    obj_type : 对象类型。为b'S'表示是prepared语句；为b'P'表示是portal。
    obj_name : prepared语句或者portal的名字。
    '''
    msg_data = obj_type + make_cstr(obj_name)
    return make_Msg0(b'D', msg_data)

def process_Execute(msg_type, msg_data):
    idx = 0
    portal_name = get_cstr(msg_data, idx)
    idx += len(portal_name)
    return_row_cnt = struct.unpack('>i', msg_data[idx:idx+4])[0]
    return ('Execute', msg_type, portal_name, return_row_cnt)
def make_Execute1(msg_res):
    return make_Execute2(msg_res[2], msg_res[3])
def make_Execute2(portal_name, return_row_cnt = 0):
    '''
    portal_name : portal名字
    return_row_cnt : 最多返回多少条，0表示返回所有。
    '''
    msg_data = make_cstr(portal_name) + struct.pack('>i', return_row_cnt)
    return make_Msg0(b'E', msg_data)

def process_Flush(msg_type, msg_data):
    return ('Flush', msg_type)
def make_Flush1(msg_res):
    return make_Flush2()
def make_Flush2():
    return make_Msg0(b'H', b'')

def process_FunctionCall(msg_type, msg_data):
    idx = 0
    func_oid = struct.unpack('>i', msg_data[idx:idx+4])[0]
    idx += 4
    
    arg_fmt_code_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    arg_fmt_code_list = struct.unpack('>%dh'%arg_fmt_code_cnt, msg_data[idx:idx+arg_fmt_code_cnt*2])
    idx += arg_fmt_code_cnt*2
    
    arg_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    arg_list = []
    for i in range(arg_cnt):
        v_len = struct.unpack('>i', msg_data[idx:idx+2])[0]
        idx += 4
        val = b''
        if v_len > 0:
            val = msg[idx:idx+v_len]
        idx += (v_len if v_len > 0 else 0)
        arg_list.append((v_len, val))
    
    res_fmt_code = struct.unpack('>h', msg_data[idx:idx+2])[0]
    
    return ('FunctionCall', msg_type, func_oid, arg_fmt_code_cnt, arg_fmt_code_list, arg_cnt, arg_list, res_fmt_code)
def make_FunctionCall1(msg_res):
    return make_FunctionCall2(msg_res[2], msg_res[4], msg_res[6], msg_res[7])
def make_FunctionCall2(func_oid, arg_fmt_codes, arg_list, res_fmt_code):
    '''
    func_oid : 要调用的函数的oid。
    arg_fmt_codes : 指定函数参数值的格式代码。
                    .) 如果为空列表，那就表示函数没有参数或者所有参数值的格式代码为0；
                    .) 如果只有一个元素，那么该元素值指定了所有参数的格式代码；
                    .) 否则元素个数等于函数参数个数，每个元素指定了对应参数值的格式代码。
    arg_list : 函数参数值列表。列表中的元素是个tuple，该tuple中的第一个元素指定了函数参数值的长度，-1表示函数参数的值为NULL；
               tuple中的第二个元素是函数参数值(如果第一个元素的值为0或者-1，那么函数参数值必须为空字节串)。
    res_fmt_code : 函数返回值的格式代码。
    '''
    msg_data = struct.pack('>i', func_oid)
    
    cnt = len(arg_fmt_codes)
    msg_data += struct.pack('>h%dh'%cnt, cnt, *arg_fmt_codes)
    
    cnt = len(arg_list)
    msg_data += struct.pack('>h', cnt)
    for arg in arg_list:
        msg_data += struct.pack('>i', arg[0]) + arg[1]
    
    msg_data += struct.pack('>h', res_fmt_code)
    return make_Msg0(b'F', msg_data)

def process_Parse(msg_type, msg_data):
    idx = 0
    stmt_name = get_cstr(msg_data, idx)
    idx += len(stmt_name)
    query = get_cstr(msg_data, idx)
    idx += len(query)
    
    param_type_cnt = struct.unpack('>h', msg_data[idx:idx+2])[0]
    idx += 2
    param_type_oid_list = struct.unpack('>%di'%param_type_cnt, msg_data[idx:idx+param_type_cnt*4])
    
    return ('Parse', msg_type, stmt_name, query, param_type_cnt, param_type_oid_list)
def make_Parse1(msg_res):
    return make_Parse2(msg_res[2], msg_res[3], msg_res[5])
def make_Parse2(stmt_name, query, param_type_oids):
    '''
    stmt_name : prepared语句的名字。
    query : 查询语句。
    param_type_oids : 参数类型的oid列表。如果oid的值为0，那么系统会自己推导出类型；
                      这里指定的个数可以小于查询语句中实际的参数个数，没有指定的参数由系统自己推导出类型。
    '''
    param_cnt = len(param_type_oids)
    msg_data = make_cstr(stmt_name) + make_cstr(query) + struct.pack('>h', param_cnt)
    msg_data += struct.pack('>%di'%param_cnt, *param_type_oids)
    return make_Msg0(b'P', msg_data)

def process_PasswordMessage(msg_type, msg_data):
    return ('PasswordMessage', msg_type, msg_data)
def make_PasswordMessage1(msg_res):
    return make_Msg0(msg_res[1], msg_res[2])
def make_PasswordMessage2(password, user_name = None, md5_salt = None):
    if md5_salt:
        if not user_name:
            raise SystemError('BUG: should provide user_name for md5 authentication')
        password = b'md5' + md5(md5(password + user_name) + md5_salt)
    return make_Msg0(b'p', make_cstr(password)) # 消息类型是小写的p

def process_Query(msg_type, msg_data):
    return ('Query', msg_type, msg_data)
def make_Query1(msg_res):
    return make_Query2(msg_res[2])
def make_Query2(sql):
    return make_Msg0(b'Q', make_cstr(sql))

def process_Sync(msg_type, msg_data):
    return ('Sync', msg_type)
def make_Sync1(msg_res):
    return make_Sync2()
def make_Sync2():
    return make_Msg0(b'S', b'')

def process_Terminate(msg_type, msg_data):
    return ('Terminate', msg_type)
def make_Terminate1(msg_res):
    return make_Terminate2()
def make_Terminate2():
    return make_Msg0(b'X', b'')

fe_msg_type_info = {
    b'B' : (process_Bind, make_Bind1),                       # Bind
    b'C' : (process_Close, make_Close1),                     # Close
    b'd' : (process_CopyData, make_CopyData1),               # CopyData (和be共用)
    b'c' : (process_CopyDone, make_CopyDone1),               # CopyDone (和be共用)
    b'f' : (process_CopyFail, make_CopyFail1),               # CopyFail
    b'D' : (process_Describe, make_Describe1),               # Describe
    b'E' : (process_Execute, make_Execute1),                 # Execute
    b'H' : (process_Flush, make_Flush1),                     # Flush
    b'F' : (process_FunctionCall, make_FunctionCall1),       # FunctionCall
    b'P' : (process_Parse, make_Parse1),                     # Parse  (大写的P)
    b'p' : (process_PasswordMessage, make_PasswordMessage1), # PasswordMessage  (小写的p)
    b'Q' : (process_Query, make_Query1),                     # Query
    b'S' : (process_Sync, make_Sync1),                       # Sync
    b'X' : (process_Terminate, make_Terminate1),             # Terminate
    # 下面这3个消息没有消息类型字符，它们是在连接后从FE发送给BE的第一个消息。
    # CancelRequest
    # SSLRequest
    # StartupMessage
}
PG_PROTO_VERSION2_NUM = 131072
PG_PROTO_VERSION3_NUM = 196608
PG_CANCELREQUEST_CODE = 80877102
PG_SSLREQUEST_CODE    = 80877103
# 
# 分析从FE->BE的第一个消息。这三种消息没有消息类型。
# 由于没有对应的消息类型，返回结果中用b'\x00'来代替消息类型。
# msg_data不包含表示消息长度的那4个字节。
# 
# V3 StartupMsg的详情参见postmaster.c中的ProcessStartupPacket函数。
# 可以包含下面这些：
#   database
#   user
#   options       命令行选项
#   replication   有效值true/false/1/0/database，database表示连接到database选项指定的数据库，一般用于逻辑复制。
#   <guc option>  其他guc选项。比如: client_encoding/application_name
# 
def process_Startup(msg_data):
    idx = 0
    code = struct.unpack('>i', msg_data[idx:idx+4])[0]
    idx += 4
    if code == PG_PROTO_VERSION3_NUM: # StartupMessage for version 3
        res = ('StartupMessage', b'\x00', code, [])
        param_list = res[3]
        while msg_data[idx] != 0:
            param_name = get_cstr(msg_data, idx)
            idx += len(param_name)
            param_val = get_cstr(msg_data, idx)
            idx += len(param_val)
            param_list.append((param_name, param_val))
        return res
    elif code == PG_PROTO_VERSION2_NUM: # StartupMessage for version 2
        return ('StartupMessage', b'\x00', code, msg_data[idx:])
    elif code == PG_CANCELREQUEST_CODE: # CancelRequest
        pid, skey = struct.unpack('>ii', msg_data[idx:idx+8])
        return ('CancelRequest', b'\x00', pid, skey)
    elif code == PG_SSLREQUEST_CODE: # SSLRequest
        return ('SSLRequest', b'\x00')
    else:
        raise RuntimeError('unknown startup message:(%d, %s)' % (code, msg_data))

def make_Startup1(msg_res):
    if msg_res[0] == 'StartupMessage':
        return make_StartupMessage1(msg_res)
    elif msg_res[0] == 'CancelRequest':
        return make_CancelRequest1(msg_res)
    elif msg_res[0] == 'SSLRequest':
        return make_SSLRequest1(msg_res)
    else:
        raise RuntimeError('unknown startup message: %s' % (msg_res, ))

def make_StartupMessage1(msg_res):
    version = msg_res[2]
    if version == PG_PROTO_VERSION3_NUM:
        param_list = msg_res[3]
        param_dict = {kv[0].decode('latin1'):kv[1] for kv in param_list}
        return make_StartupMessage2(**param_dict)
    elif version == PG_PROTO_VERSION2_NUM:
        msg_data = struct.pack('>i', version) + msg_res[3]
        return struct.pack('>i', len(msg_data)+4) + msg_data
# 按param name顺序来组装，因为其结果会用作dict的key。
def make_StartupMessage2(**param_dict):
    res = b''
    res += struct.pack('>i', PG_PROTO_VERSION3_NUM)
    param_name_list = list(param_dict.keys())
    param_name_list.sort()
    for k in param_name_list:
        res += make_cstr(k.encode('latin1')) + make_cstr(param_dict[k])
    res += b'\0'
    res = struct.pack('>i', len(res)+4) + res
    return res

def make_CancelRequest1(msg_res):
    return make_CancelRequest2(msg_res[2], msg_res[3])
def make_CancelRequest2(pid, skey):
    res = struct.pack('>i', 16)
    res += struct.pack('>i', PG_CANCELREQUEST_CODE)
    res += struct.pack('>i', pid)
    res += struct.pack('>i', skey)
    return res

def make_SSLRequest1(msg_res):
    return make_SSLRequest2()
def make_SSLRequest2():
    res = struct.pack('>i', 8)
    res += struct.pack('>i', PG_SSLREQUEST_CODE)
    return res
# 
# 接收消息函数
# 
def recv_size(s, sz):
    ret = b'';
    while sz > 0:
        tmp = s.recv(sz)
        if not tmp:
            raise RuntimeError('the peer(%s) closed the connection. last recved:[%s]' % (s.getpeername(), ret));
        ret += tmp
        sz -= len(tmp)
    return ret
# 接收FE->BE的第一个消息。
def recv_fe_startup_msg(s):
    msg_len = recv_size(s, 4)
    msg_len = struct.unpack('>i', msg_len)[0]
    msg_len -= 4
    msg_data = b''
    if msg_len > 0:
        msg_data = recv_size(s, msg_len)
    return msg_data
# 检查startup消息是否已完整，data包含开头表示长度的4个字节。
def startup_msg_is_complete(data):
    data_len = len(data)
    if data_len <= 4:
        return False
    msg_len = struct.unpack('>i', data[:4])[0]
    return data_len == msg_len
# 接收下一个消息。
# 注意：本函数的性能不好但使用方便。如果要考虑性能，那么就批量接收数据，然后用parse_pg_msg等函数。
def recv_pg_msg(s, process, msg_type_info = None, timeout = 0):
    s.settimeout(timeout)
    try:
        msg_type = recv_size(s, 1)
    except socket.timeout:
        return None
    except OSError as err:
        if err.errno in NONBLOCK_SEND_RECV_OK:
            return None
        else:
            raise
    finally:
        s.settimeout(None)
    msg_len = recv_size(s, 4)
    msg_len = struct.unpack('>i', msg_len)[0]
    msg_len -= 4
    msg_data = b''
    if msg_len:
        msg_data = recv_size(s, msg_len)
    if process:
        return msg_type_info[msg_type][0](msg_type, msg_data)
    else:
        return (msg_type, msg_data)
def recv_be_msg(s, process = True, timeout = 0):
    return recv_pg_msg(s, process, be_msg_type_info, timeout)
def recv_fe_msg(s, process = True, timeout = 0):
    return recv_pg_msg(s, process, fe_msg_type_info, timeout)
# 
# 从data中提取多个消息包。该函数不能用于parse从FE发给BE的第一个消息。
# data : 原始数据。
# max_msg : 最多提取多少个消息包。如果为0表示提取所有。
# process : 是否返回处理过的消息。
# msg_type_info : 字典对象，包含各消息类型对应的处理函数。
# 
def parse_pg_msg(data, max_msg = 0, process = False, msg_type_info = None):
    idx = 0
    data_len = len(data)
    msg_list = []
    cnt = 0
    while True:
        if data_len - idx < 5:
            break
        msg_type = data[idx:idx+1]
        msg_len = struct.unpack('>i', data[idx+1:idx+1+4])[0]
        if data_len - idx < msg_len + 1:
            break
        msg_data = data[idx+5:idx+msg_len+1]
        idx += msg_len + 1
        
        if process:
            msg_list.append(msg_type_info[msg_type][0](msg_type, msg_data))
        else:
            msg_list.append((msg_type, msg_data))
        cnt += 1
        if max_msg > 0 and cnt >= max_msg:
            break
    return (idx, msg_list)
def parse_fe_msg(data, max_msg = 0, process = True):
    return parse_pg_msg(data, max_msg, process, fe_msg_type_info)
def parse_be_msg(data, max_msg = 0, process = True):
    return parse_pg_msg(data, max_msg, process, be_msg_type_info)
# startup_msg中的参数值的类型必须是bytes。startup_msg中必须有user
def make_pg_connection(host, port, **startup_msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(make_StartupMessage2(**startup_msg))
    return s
# 建立到pg的连接，完成登陆过程，直到接收到ReadyForQuery或者ErrorResponse，如果接收到ErrorResponse那就抛出异常。
# 如果登陆成功，那么返回(socket, parameter_dict, (pid, cancelkey))
def make_pg_login(host, port, password = b'', **startup_msg):
    param_dict = {}
    key_data = None
    s = make_pg_connection(host, port, **startup_msg)
    msg_res = recv_be_msg(s, timeout=None)
    if msg_res[0] == 'AuthenticationOk':
        None
    elif msg_res[0] == 'AuthenticationCleartextPassword' or msg_res[0] == 'AuthenticationMD5Password':
        # 发送PasswordMessage
        if msg_res[0] == 'AuthenticationCleartextPassword':
            s.sendall(make_PasswordMessage2(password))
        else:
            s.sendall(make_PasswordMessage2(password, startup_msg['user'], msg_res[2]))
        # 接收AuthentictionOk或者ErrorResponse
        msg_res = recv_be_msg(s, timeout=None)
        if msg_res[0] == 'ErrorResponse':
            raise RuntimeError('authentication fail:%s' % (msg_res, ))
    elif msg_res[0] == 'ErrorResponse':
        raise RuntimeError('got ErrorResponse from be while authentication:%s' % (msg_res, ))
    else:
        raise RuntimeError('do not support this authentication type:%s' % (msg_res, ))
    # 接收消息直到ReadyForQuery或者ErrorResponse
    while True:
        msg_res = recv_be_msg(s, timeout=None)
        if msg_res[0] == 'ErrorResponse':
            raise RuntimeError('got ErrorResponse from be after authentication:%s' % (msg_res, ))
        elif msg_res[0] == 'ParameterStatus':
            k = msg_res[2].rstrip(b'\x00').decode('latin1')
            v = msg_res[3].rstrip(b'\x00')
            param_dict[k] = v
        elif msg_res[0] == 'BackendKeyData':
            key_data = (msg_res[2], msg_res[3])
        elif msg_res[0] == 'ReadyForQuery':
            break
    # 根据client_encoding把字节串decode成unicode串
    enc = param_dict['client_encoding'].decode('latin1')
    for k in param_dict:
        param_dict[k] = param_dict[k].decode(enc)
    return (s, param_dict, key_data)
# 执行一条语句，如果失败则抛出异常OSError/RuntimeError。
# 如果成功，则返回(cmd_status, row_desc, row_list)
def execute(s, sql):
    cmd_status = None
    row_desc = None
    row_list = []
    ex = None
    s.sendall(make_Query2(sql))
    while True:
        msg_res = recv_be_msg(s, timeout=None)
        if msg_res[0] == 'EmptyQueryResponse':
            ex = RuntimeError('got EmptyQueryResponse')
        elif msg_res[0] == 'ErrorResponse':
            # 某种情况下服务器端在发送ErrorResponse之后就退出了，不会再发送ReadyForQuery。这种情况下在下一次调用recv_be_msg的时候会抛出异常。
            # 另外当语句执行过程中也可能发送ErrorResponse，也即是说在发送DataRow之后也有可能发送ErrorResponse。
            ex = RuntimeError('got ErrorResponse:%s' % (msg_res, ))
        elif msg_res[0] == 'RowDescription':
            row_desc = msg_res[3]
        elif msg_res[0] == 'DataRow':
            row = []
            for col in msg_res[3]:
                if col[0] == -1:
                    row.append(None)
                else:
                    row.append(col[1])
            row_list.append(row)
        elif msg_res[0] == 'CommandComplete':
            cmd_status = msg_res[2].rstrip(b'\x00').decode('latin1')
            cmd_status = cmd_status.split()
        elif msg_res[0] == 'ReadyForQuery':
            break
    if ex:
        raise ex
    return (cmd_status, row_desc, row_list)

# main
if __name__ == '__main__':
    pass

