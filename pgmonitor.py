#!/bin/env python3
# -*- coding: GBK -*-
# 
# 监控pg是否可用
# 
import sys, os, time
import socket
import logging

from netutils import myrecv, NONBLOCK_CONNECT_EX_OK
from pgprotocol import *

# 
# 监控pg是否可用，可用于监控主库和从库。
# 需要在两种情况下调用try_go:
#   .) 在poller中检测到可读写。此时返回None表示已检测完或者已断开连接，需要等一段时间后再开始下一次检测。
#      这时需要从poller unregister pg_monitor，同时在poller的下一次poll时需要设置一个小的timeout。
#   .) 在poller之外需要调用。
# 
class pg_monitor(object):
    # addr : 主库/从库地址
    # conninfo : 用户名/数据库/密码等等信息
    def __init__(self, addr, conninfo):
        self.addr = addr
        self.username = conninfo['user'].encode('latin1')
        self.dbname = conninfo.get('db', 'postgres').encode('latin1')
        self.password = conninfo.get('pw', '').encode('latin1')
        self.conn_retry_num = conninfo.get('conn_retry_num', 5)
        self.conn_retry_interval = conninfo.get('conn_retry_interval', 2)
        self.query_interval = conninfo.get('query_interval', 5)
        self.lo_oid = conninfo.get('lo_oid', 9999)
        self.query_sql = b'select 1'
        
        self.s = None
        self.param_dict = None
        self.key_data = None
        self.status = 'disconnected' # disconnected -> connect_sending -> connect_recving -> connected -> query_sending -> query_recving
        
        self.last_query_time = time.time() # 记录最近一次成功query的时间。
        self.query_sending_data = b''
        self.query_recving_data = b''
        self.ready_for_query_recved = False
        self.error_response_recved = False
        
        self.disconnected_list = [] # 记录连接失败的时间，后面的记录是最近的连接失败记录。连接成功的时候会清空该列表。
        self.connect_sending_data = b''
        self.connect_recving_data = b''
    # 连接成功后调用该函数
    def connection_done(self):
        self.status = 'connected'
        
        self.last_query_time = time.time()
        self.query_sending_data = b''
        self.query_recving_data = b''
        self.ready_for_query_recved = False
        self.error_response_recved = False
        
        self.disconnected_list.clear()
        self.connect_sending_data = b''
        self.connect_recving_data = b''
    # 连接失败的时候调用该函数。is_down表示数据库是否已经down掉。
    def close(self, is_down):
        if self.s:
            self.s.close()
            self.s = None
            self.param_dict = None
            self.key_data = None
        self.status = 'disconnected'
        
        self.last_query_time = time.time()
        self.query_sending_data = b''
        self.query_recving_data = b''
        self.ready_for_query_recved = False
        self.error_response_recved = False
        
        if not is_down:
            self.disconnected_list.clear()
        self.disconnected_list.append(time.time())
        self.connect_sending_data = b''
        self.connect_recving_data = b''
    def fileno(self):
        return self.s.fileno()
    # 在程序启动时，必须同步建立连接，以确保数据库可用。
    def connect_first(self):
        self.s, self.param_dict, self.key_data = make_pg_login(self.addr[0], self.addr[1], password=self.password, 
                                                               user=self.username, database=self.dbname, application_name=b'pg_proxy monitor')
        # 检查大对象是否存在
        sql = ("select oid from pg_largeobject_metadata where oid=%d"%self.lo_oid).encode('latin1')
        try:
            res = execute(self.s, sql)
        except (OSError, RuntimeError) as ex:
            raise RuntimeError('execute(%s) fail:%s' % (sql, str(ex)))
        if len(res[2]) != 1:
            raise RuntimeError('large object(%d) does not exist' % (self.lo_oid, ))
        
        self.last_query_time = time.time()
        self.status = 'connected'
        self.s.settimeout(0)
    # 检查数据库是否已经down掉。
    def check_down(self):
        if len(self.disconnected_list) >= self.conn_retry_num:
            return True
        return False
    # 调用go并捕获相关的异常。
    # called表示是否在poll循环里面调用的，也就是说是否在poll里面。
    def try_go(self, poll, called):
        try:
            return self.go(poll, called)
        except (OSError, RuntimeError) as ex:
            logging.warning('[pg_monitor %s %s %s] Exception: %s', self.addr, self.dbname, self.username, str(ex))
            if called:
                poll.unregister(self)
            self.close(is_down=True)
            return None
    # 注意：如果go函数抛出异常，那就说明数据库已经down了，所以在该函数内必须捕获不表示数据库已经down掉的异常。
    # 返回None表示不需要检测是否可读写，此时poller需要设置一个超时。
    def go(self, poll, called):
        if self.status == 'disconnected':
            # 在本状态的时候，disconnected_list里面肯定至少有一条记录。
            if not self.disconnected_list:
                raise SystemError('BUG: disconnected_list should not be empty')
            t = time.time()
            prev_t = self.disconnected_list[len(self.disconnected_list)-1]
            if t - prev_t < self.conn_retry_interval:
                return None
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.settimeout(0)
            ret = self.s.connect_ex(self.addr)
            if ret not in NONBLOCK_CONNECT_EX_OK:
                raise RuntimeError('connect_ex fail:%s' % (os.strerror(ret), ))
            self.connect_sending_data = make_StartupMessage2(user=self.username, database=self.dbname, application_name=b'pg_proxy monitor')
            self.connect_recving_data = b''
            self.status = 'connect_sending'
            poll.register(self, poll.POLLOUT)
            return 'w'
        elif self.status == 'connect_sending':
            # 如果无法连接，那么下面的send将会抛出OSError异常。但有一种情况数据库没有down掉，但是连接失败。出现这种情况的原因是：服务器端
            # 文件描述符已经用光导致accept失败。如何从OSError判断这种情况？
            n = self.s.send(self.connect_sending_data)
            self.connect_sending_data = self.connect_sending_data[n:]
            if not self.connect_sending_data:
                self.status = 'connect_recving'
                poll.register(self, poll.POLLIN)
                return 'r'
            poll.register(self, poll.POLLOUT)
            return 'w'
        elif self.status == 'connect_recving':
            data = myrecv(self.s, 1024*4)
            if data == None:
                return 'r'
            if not data:
                raise RuntimeError('the peer(%s) closed the connection' % (self.s.getpeername(), ))
            self.connect_recving_data += data
            # 检查连接相关的消息包
            ret = parse_be_msg(self.connect_recving_data)
            self.connect_recving_data = self.connect_recving_data[ret[0]:]
            for msg in ret[1]:
                logging.debug('[pg_monitor %s %s %s] %s', self.addr, self.dbname, self.username, msg)
                if msg[1] == b'R': # AuthenticationXXX消息
                    if msg[0] == 'AuthenticationOk':
                        None
                    elif msg[0] == 'AuthenticationCleartextPassword' or msg[0] == 'AuthenticationMD5Password':
                        if msg[0] == 'AuthenticationCleartextPassword':
                            self.connect_sending_data = make_PasswordMessage2(self.password)
                        else:
                            self.connect_sending_data = make_PasswordMessage2(self.password, self.username, msg[2])
                        self.connect_recving_data = b''
                        self.status = 'connect_sending'
                        poll.register(self, poll.POLLOUT)
                        return 'w'
                    else:
                        # 对于不支持的authentication，只发送报警，但是不能认为数据库已经down掉。
                        if called: # 必须在close之前unregister
                            poll.unregister(self)
                        self.report_error(b'unsupported authentication:%s' % (msg, ))
                        self.close(is_down=False)
                        return None
                elif msg[0] == 'ErrorResponse':
                    if called:
                        poll.unregister(self)
                    self.error_response_recved = True
                    self.report_error(msg)
                    self.close(is_down=False)
                    return None
                elif msg[0] == 'ReadyForQuery':
                    self.ready_for_query_recved = True
            if self.ready_for_query_recved:
                if called:
                    poll.unregister(self)
                self.connection_done()
                return None
            poll.register(self, poll.POLLIN)
            return 'r'
        elif self.status == 'connected':
            t = time.time()
            if t - self.last_query_time < self.query_interval:
                return None
            self.query_sending_data = make_Query2(self.query_sql)
            self.query_recving_data = b''
            self.status = 'query_sending'
            logging.debug('[pg_monitor %s %s %s] sending query: %s', self.addr, self.dbname, self.username, self.query_sending_data.decode('latin1'))
            poll.register(self, poll.POLLOUT)
            return 'w'
        elif self.status == 'query_sending':
            n = self.s.send(self.query_sending_data)
            self.query_sending_data = self.query_sending_data[n:]
            if not self.query_sending_data:
                poll.register(self, poll.POLLIN)
                self.status = 'query_recving'
                return 'r'
            poll.register(self, poll.POLLOUT)
            return 'w'
        elif self.status == 'query_recving':
            data = myrecv(self.s, 1024*4)
            if data == None:
                return 'r'
            if not data:
                raise RuntimeError('the peer(%s) closed the connection' % (self.s.getpeername(), ))
            self.query_recving_data += data
            # 检查消息包，直到接收到ReadyForQuery，中间可能会接收到ErrorResponse消息。
            ret = parse_be_msg(self.query_recving_data)
            self.query_recving_data = self.query_recving_data[ret[0]:]
            for msg in ret[1]:
                logging.debug('[pg_monitor %s %s %s] %s', self.addr, self.dbname, self.username, msg)
                if msg[0] == 'ErrorResponse': # 接收ErrorResponse不表示数据库已经down掉，但是需要发送报警邮件之类的，通知管理员。
                    self.error_response_recved = True
                    self.report_error(msg)
                elif msg[0] == 'ReadyForQuery':
                    self.ready_for_query_recved = True
            if self.ready_for_query_recved and not self.query_recving_data: # 以防ReadyForQuery之后还有其他异步消息。比如ParameterStatus，NotificationResponse。
                if called:
                    poll.unregister(self)
                self.status = 'connected'
                self.last_query_time = time.time()
                self.query_sending_data = b''
                self.query_recving_data = b''
                self.error_response_recved = False
                self.ready_for_query_recved = False
                return None
            poll.register(self, poll.POLLIN)
            return 'r'
        else:
            raise SystemError('BUG: unknown status:%s' % (self.status, ))
    # 在连接或者执行语句出错时，会调用该函数。
    def report_error(self, msg):
        logging.error('[pg_monitor %s %s %s] report error:%s', self.addr, self.dbname, self.username, msg)

# main
if __name__ == '__main__':
    pass

