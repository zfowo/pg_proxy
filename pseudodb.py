#!/bin/env python3
# -*- coding: GBK -*-
# 
# 伪数据库
# 
import sys, os
import copy
import pgnet
import pgprotocol3 as p
import netutils

default_auth_ok_msgs = [
    p.Authentication(authtype=p.AuthType.AT_Ok, data=b''), 
    p.ParameterStatus(name=b'application_name', val=b'pseudo'), 
    p.ParameterStatus(name=b'client_encoding', val=b'UTF8'), 
    p.ParameterStatus(name=b'DateStyle', val=b'ISO, MDY'), 
    p.ParameterStatus(name=b'integer_datetimes', val=b'on'), 
    p.ParameterStatus(name=b'IntervalStyle', val=b'postgres'), 
    p.ParameterStatus(name=b'is_superuser', val=b'on'), 
    p.ParameterStatus(name=b'server_encoding', val=b'UTF8'), 
    p.ParameterStatus(name=b'server_version', val=b'11devel'), 
    p.ParameterStatus(name=b'session_authorization', val=b'pseudo'), 
    p.ParameterStatus(name=b'standard_conforming_strings', val=b'on'), 
    p.ParameterStatus(name=b'TimeZone', val=b'Asia/Hong_Kong'), 
    p.BackendKeyData(pid=1234, skey=1234), 
    p.ReadyForQuery(trans_status=b'I'), 
]
# 本类不处理auth过程，由pgauth处理，用户名/密码用的是数据库中的，不单独设置。
class pseudodb():
    auth_ok_msgs = copy.copy(default_auth_ok_msgs)
    def __init__(self, fecnn):
        self.fecnn = fecnn
    def __getattr__(self, name):
        return getattr(self.fecnn, name)
    def handle_event(self, poll, event):
        if event & poll.POLLOUT:
            self._process_write(poll)
        elif event & poll.POLLIN:
            self._process_read(poll)
    def _process_write(self, poll):
        if not self.write_msgs():
            poll.register(self, poll.POLLIN)
    def _process_read(self, poll):
        msg_list = self.read_msgs(max_msg=1)
        if not msg_list:
            return
        m = msg_list[0]
        if m.msg_type not in (p.MsgType.MT_Query, p.MsgType.MT_Terminate):
            if self._write_error('only support Query/Terminate msg'):
                poll.register(self, poll.POLLOUT)
            return
        # Query/Terminate msg
        if m.msg_type == p.MsgType.MT_Terminate:
            print('recved Terminate msg from peer:%s' % (self.getpeername(),))
            poll.unregister(self)
            self.close()
            return
        try:
            query = bytes(m.query).decode('utf8')
            if self.process_query(query):
                poll.register(self, poll.POLLOUT)
        except pgnet.pgfatal as ex:
            raise
        except Exception as ex:
            if self._write_error('%s' % ex):
                poll.register(self, poll.POLLOUT)
    # 派生类需要实现process_query，往前端写消息，返回write_msgs的返回值。
    # 如果成功则发送: RowDescription + DataRow + CommandComplete + ReadyForQuery
    # 如果失败则发送: ErrorResponse + ReadyForQuery
    def process_query(self, query):
        raise RuntimeError('derived class should implement process_query')
    # 写错误信息
    def _write_error(self, err):
        err = err.encode('utf8') if type(err) is str else err
        return self.write_msgs((p.ErrorResponse.make_error(err), p.ReadyForQuery.Idle))
    def _write_result(self, col_names, rows):
        msg_list = []
        x = []
        for cn in col_names:
            cn = cn.encode('utf8') if type(cn) is str else cn
            x.append({'name':cn})
        msg_list.append(p.RowDescription.make(*x))
        for r in rows:
            y = (str(c).encode('utf8') if type(c) is not bytes else c for c in r)
            msg_list.append(p.DataRow.make(*y))
        cnt = len(msg_list) - 1
        msg_list.append(p.CommandComplete(tag=b'SELECT %d'%cnt))
        msg_list.append(p.ReadyForQuery.Idle)
        return self.write_msgs(msg_list)
# for test
class testdb(pseudodb):
    def process_query(self, query):
        query = query.upper()
        return self.write_msgs((
            p.RowDescription.make({'name':b'response'}), 
            p.DataRow.make(query.encode('utf8')), 
            p.CommandComplete(tag=b'SELECT 1'), 
            p.ReadyForQuery.Idle, 
            ))
# main
if __name__ == '__main__':
    pass
