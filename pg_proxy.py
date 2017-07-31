#!/bin/evn python3
# -*- coding: GBK -*-
# 
# pg_proxy.py [conf_file]
#   配置文件conf_file是个python文件，里面有一个dict对象pg_proxy_conf，该字典包含下面这些项：
# 
#   'listen' : (host, port)                               指定监听的ip和端口。
#   'master' : (host, port)                               指定主库地址。
#   'conninfo' : {'name':value, ...}                      指定用于连接到master和promote的用户名/数据库/密码等，必须是超级用户。
#                                                         可以指定的name有：user/pw/db/conn_retry_num/conn_retry_interval/query_interval/lo_oid。user必须指定。
#   'promote' : (host, port)                              指定用于提升为主库的从库的地址。
#   'slaver_list' : [(host, port), ...]                   指定用于只读连接的从库列表。
#   'idle_cnn_timeout' : 300                              指定空闲连接的lifetime，单位是秒。
#   'active_cnn_timeout' : 300                            指定活动连接空闲时间限制，如果空闲时间超时，那么就断开fe的连接。如果为0那就不限制空闲时间。(目前不支持扩展查询协议)
#   'recv_sz_per_poll' : 4                                每次poll一个连接上最多接收多少数据，单位是K。
#   'disable_conds_list' : [[(name, value), ...], ...]    当active_cnn_timeout>0，可以用该参数指定不限制空闲时间的连接。可以指定的name有user/database以及其他可以出现在startup消息包中的项名。
#   'pg_proxy_pw' : 'pg2pg'                               指定连接到伪数据库pg_proxy的时候需要的密码。
#   'log' : {'name' : value, ...}                         指定logging相关的配置，可以指定的项有：filename, level。level可以设为logging.DEBUG/INFO/WARNING/ERROR。
#                                                         不指定filename则往stderr输出。
#   注：master/promote/slaver_list不支持unix domain socket。listen也不支持unix domain socket。
# 
# pg_proxy根据用户名把连接转发到主库或者从库，用户名后面添加'@ro'的连接都转发到从库，用roundrobin方式来选择从库。
# 
# 当主库down掉后，如果指定了promote配置，那么就会把它提升为主库。如果指定了promote，那么slaver_list中的
# 从库必须连接到promote这个从库，而不是直接连接到master。此外在主库中必须创建一个OID为9999的内容为空的大对象。
# 大对象的OID可以用lo_oid来设置，缺省值为9999，该大对象用于在promote上生成trigger文件。
# 另外从库上的recovery.conf中的trigger_file需要设为'trigger_file'。
#
# 可以用psql连接到伪数据库pg_proxy查看当前状态，缺省密码是pg2pg，用户名任意。共有4个表: connection/process/server/startupmsg。
# 只支持单表的select查询，其中process/server表不支持查询条件和列选择。
# .) connection : 包含每个fe/be连接对的信息，包括活动连接和空闲连接。
# .) process    : 包含每个池子进程的连接信息。
# .) server     : 包含每个数据库server的连接信息。
# .) startupmsg : 包含每个连接的startup消息包，以及连接是否空闲。
#
# pg_proxy.py只支持postgres version 3协议，不支持SSL连接，认证方法可能只支持trust/password/md5，其他认证方法没有测试。
# 在配置pg_hba.conf的时候需要注意的是ADDRESS部分是针对pg_proxy.py所在的服务器的IP地址，
# 所以最好不要配置成trust方法，否则知道用户名/数据库名后谁都可以登录数据库。
#
# pg_proxy.py需要python 3.3及以上版本，不支持windows。只支持session级别的连接池，不支持事务/语句级别的连接池。
# 不支持复制连接，修改几行代码就能支持，不过复制连接不能支持池功能，也就是说当复制客户端断开连接后，到be端的连接也应该断开。
# 
# pg_proxy.py的结构如下：
# .) 主进程启动时创建AF_UNIX socket(用于在主进程和子进程之间通信)以及AF_INET socket(接收来自pg客户端的连接)。
# .) 然后创建n个连接池进程(P)，以及一个工作进程(W)用于处理来自主进程(M)的任务请求，比如发送CancelRequest，发送切换结果等等。
# .) M和P之间通过UDS(unix domain socket)通信，他们之间的消息有：
#    .) M->P 如果pending_fe_connection已经接收到StartupMessage，那么M把它的文件描述符以及StartupMessage发送给P，P的选择规则是：P中的空闲的BE连接
#       的StartupMessage与pending_fe_connection匹配；如果所有P中没有匹配的连接，那么就选活动连接最少的P。从库的选择则是roundrobin方式。
#    .) P->M 当连接建立或者断开的时候P会把连接信息发给M。
# .) M和W之间主要是M向W发送工作任务消息。当前的工作任务消息有：发送CancelRequest；发送切换结果。
# 
import sys, os, struct, socket, time, errno
import traceback
import signal
import sqlite3
import re, logging

from netutils import *
from miscutils import *
from pgprotocol import *
from pgmonitor import *

# 
# 
# 主进程和子进程之间通信的消息类型：
# 'f'类型的消息是主进程发给proxy子进程的，后面跟有文件描述符。
# 's'类型的消息是子进程在启动的时候把自己的进程号发给主进程。
# 'c'类型的消息是主进程把CancelRequest发给工作进程。
# 'C'类型的消息是proxy子进程发给主进程的，包含连接成功信息。
# 'D'类型的消息是proxy子进程发给主进程的，包含连接断开信息。
# 'P'类型的消息是主进程发给子进程的，包含主从库切换结果。
# 
# 表示proxy进程中的fe_be_pair
class proxy_conn_info(object):  
    def __init__(self, pair_id, fe_ip, fe_port, be_ip, be_port, startup_msg_raw, status_time, use_num):
        self.pair_id = pair_id
        
        self.fe_ip = fe_ip
        self.fe_port = fe_port
        self.be_ip = be_ip
        self.be_port = be_port
        
        self.startup_msg_raw = startup_msg_raw
        self.startup_msg = process_Startup(startup_msg_raw[4:])
        self.status_time = status_time
        self.use_num = use_num
    def fe_disconnected(self, status_time):
        self.fe_ip = ''
        self.fe_port = 0
        self.status_time = status_time
    def update(self, fe_ip, fe_port, status_time, use_num):
        self.fe_ip = fe_ip
        self.fe_port = fe_port
        self.status_time = status_time
        self.use_num = use_num
    
class worker_process_base(object):
    def __init__(self, pid, idx):
        self.pid = pid
        self.idx = idx
        self.ep = None # 到子进程的socket连接。子进程在启动时会连接到主进程的UDS(unix domain socket)。
    def fileno(self):
        return self.ep.fileno()
    def close(self):
        if self.ep:
            self.ep.close()
            self.ep = None
    def is_connected(self):
        return self.ep != None
    def put_msg(self, msg_type, msg_data, fdlist = None):
        logging.debug('[%d]put_msg: %s %s %s', self.pid, msg_type, msg_data, fdlist)
        self.ep.put_msg(msg_type, msg_data, fdlist)
    def fd_is_sent(self, fd):
        return self.ep.fd_is_sent(fd)
class proxy_worker_process(worker_process_base):
    def __init__(self, pid, idx):
        super().__init__(pid, idx)
        self.proxy_conn_info_map = {} # pair_id -> proxy_conn_info  所有连接
        self.startup_msg_raw_to_conn_map = {} # startup_msg_raw -> idle_cnn_num   空闲连接数
        self.pending_cnn_num = 0 # 已经发送给proxy进程但还没有回应'C'/'D'消息的连接请求数，
        self.closing_fe_cnn_list = []
    def close(self):
        super().close()
        for cnn in self.closing_fe_cnn_list:
            cnn.close()
        self.closing_fe_cnn_list.clear()
    def add_closing_fe_cnn(self, fe_cnn):
        self.closing_fe_cnn_list.append(fe_cnn)
    def close_fe_cnn(self):
        del_cnns = []
        for cnn in self.closing_fe_cnn_list:
            if self.fd_is_sent(cnn.fileno()):
                cnn.close()
                del_cnns.append(cnn)
        for cnn in del_cnns:
            self.closing_fe_cnn_list.remove(cnn)
        del_cnns.clear()
    def has_matched_idle_conn(self, startup_msg_raw, be_addr):
        if (startup_msg_raw not in self.startup_msg_raw_to_conn_map) or \
           (self.startup_msg_raw_to_conn_map[startup_msg_raw] <= 0):
            return False
        for id in self.proxy_conn_info_map:
            ci = self.proxy_conn_info_map[id]
            if ci.startup_msg_raw == startup_msg_raw and be_addr == (ci.be_ip, ci.be_port):
                return True
        return False
    def remove_idle_conn(self, startup_msg_raw):
        self.startup_msg_raw_to_conn_map[startup_msg_raw] -= 1
    def get_active_cnn_num(self):
        return self.get_total_cnn_num() - self.get_idle_cnn_num() + (self.pending_cnn_num if self.pending_cnn_num > 0 else 0)
    def get_total_cnn_num(self):
        return len(self.proxy_conn_info_map)
    def get_idle_cnn_num(self):
        num = 0
        for k in self.startup_msg_raw_to_conn_map:
            num += self.startup_msg_raw_to_conn_map[k]
        return num
    def get_pending_cnn_num(self):
        return self.pending_cnn_num
    # 
    def handle_event(self, poll, event):
        if event & poll.POLLOUT:
            x = self.ep.send()
            if x == None:
                logging.debug('[proxy_worker_process][%d]send done', self.pid)
                poll.register(self, poll.POLLIN)
        if event & poll.POLLIN:
            x = self.ep.recv()
            if x[0] != -1:
                return
            logging.debug('[proxy_worker_process][%d]recv: %s', self.pid, x[1])
            msg = x[1]
            msg_data = msg[1]
            msg_len = struct.unpack('>i', msg_data[:4])[0]
            sub_data = msg_data[4:msg_len]
            if msg[0] == b'C': # b'C'消息数据格式：len + pair_id;ip,port;ip,port;time;use_num;main_use_idle_cnn;proxy_use_idle_cnn + startup_msg_raw。len不包括startup_msg_raw。
                sub_data = sub_data.decode('latin1')
                startup_msg_raw = msg_data[msg_len:]
                pair_id, fe_addr, be_addr, status_time, use_num, main_use_idle_cnn, proxy_use_idle_cnn = sub_data.split(';')
                pair_id = int(pair_id)
                fe_ip, fe_port = fe_addr.split(',')
                fe_port = int(fe_port)
                be_ip, be_port = be_addr.split(',')
                be_port = int(be_port)
                status_time = int(status_time)
                use_num = int(use_num)
                main_use_idle_cnn = int(main_use_idle_cnn)
                proxy_use_idle_cnn = int(proxy_use_idle_cnn)
                
                logging.debug('(main_use_idle_cnn, proxy_use_idle_cnn) = (%d, %d)', main_use_idle_cnn, proxy_use_idle_cnn)
                conn_info = self.proxy_conn_info_map.get(pair_id, None)
                if not conn_info: # 全新的fe_be_pair
                    conn_info = proxy_conn_info(pair_id, fe_ip, fe_port, be_ip, be_port, startup_msg_raw, status_time, use_num)
                    self.proxy_conn_info_map[pair_id] = conn_info
                else: # 复用的fe_be_pair
                    # TODO: 检查conn_info中的信息是否与消息中的一致
                    # 只需要更新3项，其他项都不变的。
                    conn_info.update(fe_ip, fe_port, status_time, use_num)
                
                if main_use_idle_cnn == 0:
                    self.pending_cnn_num -= 1
                if startup_msg_raw not in self.startup_msg_raw_to_conn_map:
                    self.startup_msg_raw_to_conn_map[startup_msg_raw] = 0
                self.startup_msg_raw_to_conn_map[startup_msg_raw] += main_use_idle_cnn - proxy_use_idle_cnn
            elif msg[0] == b'D': # b'D'消息数据格式：len + pair_id;1/0;time;main_use_idle_cnn;proxy_use_idle_cnn + startup_msg_raw。1表示完全断开，0表示只是s_fe断开。len不包括startup_msg_raw。
                sub_data = sub_data.decode('latin1')
                startup_msg_raw = msg_data[msg_len:]
                pair_id, is_complete_disconn, status_time, main_use_idle_cnn, proxy_use_idle_cnn = (int(x) for x in sub_data.split(';'))
                
                if startup_msg_raw not in self.startup_msg_raw_to_conn_map:
                    self.startup_msg_raw_to_conn_map[startup_msg_raw] = 0
                logging.debug('(main_use_idle_cnn, proxy_use_idle_cnn) = (%d, %d)', main_use_idle_cnn, proxy_use_idle_cnn)
                conn_info = self.proxy_conn_info_map.get(pair_id, None)
                if not conn_info: # 全新的fe_be_pair，之前没有发送'C'消息。
                    self.startup_msg_raw_to_conn_map[startup_msg_raw] += main_use_idle_cnn - proxy_use_idle_cnn
                    if main_use_idle_cnn == 0:
                        self.pending_cnn_num -= 1
                    logging.debug('can not find proxy_conn_info for pair_id(%d)', pair_id)
                    return
                # TODO:检查conn_info中的信息是否与消息中的一致
                if is_complete_disconn: # 全新的fe_be_pair，之前发送过'C'消息。或者 空闲的fe_be_pair
                    self.proxy_conn_info_map.pop(pair_id)
                    if not conn_info.fe_ip: # 空闲的fe_be_pair
                        if self.startup_msg_raw_to_conn_map[startup_msg_raw] <= 0:
                            logging.error('BUG: idle_cnn_num <= 0: %d', conn_info.pair_id)
                        self.startup_msg_raw_to_conn_map[startup_msg_raw] -= 1
                else: # 全新的fe_be_pair，之前发送过'C'消息。或者 复用的fe_be_pair
                    conn_info.fe_disconnected(status_time)
                    self.startup_msg_raw_to_conn_map[startup_msg_raw] += 1
                    if not conn_info.fe_ip:
                        if main_use_idle_cnn == 0:
                            self.pending_cnn_num -= 1
                        self.startup_msg_raw_to_conn_map[startup_msg_raw] += main_use_idle_cnn - proxy_use_idle_cnn
                
class work_worker_process(worker_process_base):
    def handle_event(self, poll, event):
        if event & poll.POLLOUT:
            x = self.ep.send()
            if x == None:
                logging.debug('[work_worker_process][%d]send done', self.pid)
                poll.register(self, poll.POLLIN)
        if event & poll.POLLIN:
            x = self.ep.recv()
            if x[0] == -1:
                logging.debug('[work_worker_process][%d]recv: %s', self.pid, x[1])

class fe_disconnected_exception(Exception): pass
class be_disconnected_exception(Exception): pass
class fe_be_pair(object):
    next_pair_id = 0
    recv_sz_per_poll = 4
    oldest_ready_for_query_recved_time = time.time()
    def __init__(self, ep, enable_active_cnn_timeout = True):
        self.ep_to_main = ep
        self.s_fe = None
        self.s_be = None
        self.startup_msg = None
        self.startup_msg_raw = None
        
        self.first_ready_for_query_recved = False
        self.auth_msg_seq = [] # auth过程中FE<->BE之间交互的消息序列。是(FE/BE, msg)列表。
        self.auth_msg_idx = 0
        self.auth_simulate = False
        self.auth_simulate_failed = False
        self.discard_all_command_complete_recved = False
        self.discard_all_ready_for_query_recved = False
        
        self.s_fe_buf1 = b''
        self.s_fe_msglist = []
        self.s_fe_buf2 = b''
        self.s_be_buf1 = b''
        self.s_be_msglist = []
        self.s_be_buf2 = b''
        
        self.id = fe_be_pair.next_pair_id
        fe_be_pair.next_pair_id += 1
        self.status_time = time.time()
        self.use_num = 1;
        
        self.main_use_idle_cnn = 0
        self.proxy_use_idle_cnn = 0
        
        self.enable_active_cnn_timeout = enable_active_cnn_timeout
        self.query_recved_time = time.time()
        self.ready_for_query_recved_time = time.time()
    # 返回True表示fe/be都已经关闭，返回False表示只有fe关闭，本pair还可复用。
    # 有三种情况会调用close：活动连接/空闲连接/auth模拟活动连接
    def close(self, poll, ex, fe_be_to_pair_map):
        if self.s_fe:
            poll.unregister(self.s_fe)
            fe_be_to_pair_map.pop(self.s_fe)
            self.s_fe.close()
        if not self.auth_simulate:
            poll.unregister(self.s_be)
        fe_be_to_pair_map.pop(self.s_be)
        
        if type(ex) == be_disconnected_exception or not self.first_ready_for_query_recved:
            self.s_be.close()
            # 向主进程发送消息
            self.send_disconnect_msg_to_main(poll, True)
            return True
        else:
            self.s_fe = None
            self.auth_msg_idx = 0
            
            if not self.auth_simulate:
                self.s_be_buf1 = self.s_fe_buf1
                self.s_fe_buf1 = b''
            else:
                self.s_be_buf1 = b''
                self.s_fe_buf1 = b''
            self.s_fe_msg_list = []
            self.s_fe_buf2 = b''
            # 向BE发送abort和discard all命令。
            self.s_be_msglist = []
            if not self.auth_simulate:
                self.s_be_buf2 += make_Query2(b'abort')
                self.s_be_buf2 += make_Query2(b'discard all')
            if self.s_be_buf2:
                poll.register(self.s_be, poll.POLLOUT|poll.POLLIN)
            else:
                poll.register(self.s_be, poll.POLLIN)
            fe_be_to_pair_map[self.s_be] = self
            self.auth_simulate = False
            # 向主进程发送消息
            self.send_disconnect_msg_to_main(poll, False)
            return False
    # startup_msg_raw包括开头那表示消息长度的4个字节
    # 建立到be的新的连接
    def start(self, poll, fe_be_to_pair_map, be_addr, startup_msg, fd):
        self.s_fe = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
        os.close(fd)
        self.s_fe.settimeout(0)
        
        self.startup_msg = startup_msg
        self.startup_msg_raw = make_StartupMessage1(self.startup_msg)
        self.s_be = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_be.settimeout(0)
        ret = self.s_be.connect_ex(be_addr)
        if ret not in NONBLOCK_CONNECT_EX_OK:
            self.s_fe.close()
            raise RuntimeError('connect_ex fail:%s' % (os.strerror(ret), ))
        logging.debug('[FE] %s', self.startup_msg)
        self.s_be_buf2 = self.startup_msg_raw
        
        poll.register(self.s_be, poll.POLLOUT|poll.POLLIN)
        poll.register(self.s_fe, poll.POLLIN)
        fe_be_to_pair_map[self.s_fe] = self
        fe_be_to_pair_map[self.s_be] = self
        
        if self.enable_active_cnn_timeout:
            self.query_recved_time = self.ready_for_query_recved_time = time.time()
    # 复用be连接
    def start2(self, poll, fe_be_to_pair_map, be_addr, startup_msg, fd):
        self.auth_msg_idx = 0
        self.auth_simulate = True
        self.auth_simulate_failed = False
        poll.unregister(self.s_be)
        
        self.s_fe = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
        os.close(fd)
        self.s_fe.settimeout(0)
        
        logging.debug('start auth_simulate: %s %s %s %s', self.auth_msg_idx, self.s_fe_buf1, self.s_fe_msglist, self.s_fe_buf2)
        logging.debug('[FE] %s', startup_msg)
        while True:
            if self.auth_msg_idx >= len(self.auth_msg_seq):
                break
            x = self.auth_msg_seq[self.auth_msg_idx]
            if x[0] == 'BE':
                logging.debug('[BE] %s', x[1])
                self.s_fe_buf2 += make_Msg1(x[1])
                self.auth_msg_idx += 1
            else:
                break
        poll.register(self.s_fe, poll.POLLIN|poll.POLLOUT)
        fe_be_to_pair_map[self.s_fe] = self
        fe_be_to_pair_map[self.s_be] = self
        
        if self.enable_active_cnn_timeout:
            self.query_recved_time = self.ready_for_query_recved_time = time.time()
    def handle_event(self, poll, fobj, event):
        s_str = ('s_fe' if fobj==self.s_fe else 's_be')
        # recv
        if event & poll.POLLIN:
            try:
                data = myrecv(fobj, 1024*self.recv_sz_per_poll)
                if data == None:
                    return
                if not data:
                    raise RuntimeError("the %s's peer (%s) closed the connection" % (s_str, fobj.getpeername()))
            except (OSError, RuntimeError) as ex:
                logging.info('[%s]Exception: %s', s_str, str(ex))
                if fobj == self.s_fe:
                    raise fe_disconnected_exception()
                else:
                    raise be_disconnected_exception()
            if fobj == self.s_fe:
                self.s_be_buf1 += data
                ret = parse_fe_msg(self.s_be_buf1)
                self.s_be_msglist.extend(ret[1])
                self.s_be_buf1 = self.s_be_buf1[ret[0]:]
                
                if self.s_be_msglist: logging.debug('')
                for msg in self.s_be_msglist:
                    logging.debug('[FE] %s', msg)
                    if msg[0] == 'Terminate':
                        raise fe_disconnected_exception()
                    self.s_be_buf2 += make_Msg1(msg, is_from_be = False)
                    if self.enable_active_cnn_timeout:
                        self.query_recved_time = time.time()
                    if not self.first_ready_for_query_recved:
                        self.auth_msg_seq.append(('FE', msg))
                self.s_be_msglist = []
            else: # s_be
                self.s_fe_buf1 += data
                ret = parse_be_msg(self.s_fe_buf1)
                self.s_fe_msglist.extend(ret[1])
                self.s_fe_buf1 = self.s_be_buf1[ret[0]:]
                
                for msg in self.s_fe_msglist:
                    logging.debug('[BE] %s', msg)
                    self.s_fe_buf2 += make_Msg1(msg, is_from_be = True)
                    if self.enable_active_cnn_timeout and msg[0] == 'ReadyForQuery':
                        self.ready_for_query_recved_time = time.time()
                        self.query_recved_time = 0
                    if not self.first_ready_for_query_recved:
                        self.auth_msg_seq.append(('BE', msg))
                        if msg[0] == 'ReadyForQuery': 
                            self.first_ready_for_query_recved = True
                            # 登陆完成，需要向主进程发送消息。
                            self.send_connect_msg_to_main(poll, True)
                self.s_fe_msglist = []
        # send
        if event & poll.POLLOUT:
            try:
                if fobj == self.s_fe:
                    n = fobj.send(self.s_fe_buf2)
                    self.s_fe_buf2 = self.s_fe_buf2[n:]
                else:
                    n = fobj.send(self.s_be_buf2)
                    self.s_be_buf2 = self.s_be_buf2[n:]
            except OSError as ex:
                logging.info('[%s]Exception: %s', s_str, str(ex))
                if fobj == self.s_fe:
                    raise fe_disconnected_exception()
                else:
                    raise be_disconnected_exception()
        # register eventmask
        if self.s_fe_buf2:
            poll.register(self.s_fe, poll.POLLOUT|poll.POLLIN)
        else:
            poll.register(self.s_fe, poll.POLLIN)
        if self.s_be_buf2:
            poll.register(self.s_be, poll.POLLOUT|poll.POLLIN)
        else:
            poll.register(self.s_be, poll.POLLIN)
    # 空闲pair的事件处理
    def handle_event2(self, poll, fobj, event):
        if fobj != self.s_be:
            raise SystemError('BUG: handle_event2 fobj != self.s_be (%s, %s)' % (fobj, self.s_be))
        if event & poll.POLLIN:
            try:
                data = myrecv(self.s_be, 1024*4)
                if data == None:
                    return
                if not data:
                    raise RuntimeError("the s_be's peer (%s) closed the connection" % (fobj.getpeername(), ))
            except (OSError, RuntimeError) as ex:
                logging.info('[s_be]Exception: %s', str(ex))
                raise be_disconnected_exception()
            # 检查是否接收到discard all命令的相应。
            self.s_be_buf1 += data
            ret = parse_be_msg(self.s_be_buf1)
            self.s_be_msglist.extend(ret[1])
            self.s_be_buf1 = self.s_be_buf1[ret[0]:]
            for msg in self.s_be_msglist:
                logging.debug('[idle fe_be_pair] recved: %s', msg)
                if msg[0] == 'CommandComplete' and msg[2] == b'DISCARD ALL\x00':
                    self.discard_all_command_complete_recved = True
                    self.discard_all_ready_for_query_recved = False
                elif msg[0] == 'ReadyForQuery':
                    self.discard_all_ready_for_query_recved = True
            self.s_be_msglist = []
        if event & poll.POLLOUT:
            try:
                n = self.s_be.send(self.s_be_buf2)
                self.s_be_buf2 = self.s_be_buf2[n:]
            except OSError as ex:
                logging.info('[%s]Exception: %s', s_str, str(ex))
                raise be_disconnected_exception()
            if not self.s_be_buf2:
                poll.register(self.s_be, poll.POLLIN)
    # auth模拟过程中的事件处理，只有s_fe的事件，没有s_be的。
    def handle_event_simulate(self, poll, fobj, event):
        if fobj != self.s_fe:
            raise SystemError('BUG: handle_event_simulate fobj != self.s_fe (%s %s)' % (fobj, self.s_fe))
        if event & poll.POLLIN:
            try:
                data = myrecv(self.s_fe, 1024*4)
                if data == None:
                    return
                if not data:
                    raise RuntimeError("the s_fe's peer (%s) closed the connection" % (fobj.getpeername(), ))
            except (OSError, RuntimeError) as ex:
                logging.info('[s_fe]Exception: %s', str(ex))
                raise fe_disconnected_exception()
            self.s_fe_buf1 += data
            ret = parse_fe_msg(self.s_fe_buf1)
            self.s_fe_msglist.extend(ret[1])
            self.s_fe_buf1 = self.s_fe_buf1[ret[0]:]
            for msg in self.s_fe_msglist:
                msg2 = self.auth_msg_seq[self.auth_msg_idx][1]
                logging.debug('[FE] %s <-> %s', msg, msg2)
                if msg != msg2:
                    self.auth_simulate_failed = True
                    logging.info('unmatched msg from FE: msg(%s) != msg2(%s)', msg, msg2)
                    if msg[0] == 'PasswordMessage' and msg2[0] == 'PasswordMessage':
                        self.s_fe_buf2 += make_ErrorResponse2([(b'S', b'ERROR'), (b'C', b'28P01'), (b'M', b'invalid password')])
                    break
                else:
                    self.auth_msg_idx += 1
            if not self.auth_simulate_failed:
                # 匹配成功后向FE发送来自BE的消息。
                logging.debug('match %d msg from FE. ', len(self.s_fe_msglist))
                while True:
                    if self.auth_msg_idx >= len(self.auth_msg_seq):
                        break
                    x = self.auth_msg_seq[self.auth_msg_idx]
                    if x[0] == 'BE':
                        logging.debug('[BE] %s', x[1])
                        self.s_fe_buf2 += make_Msg1(x[1])
                        self.auth_msg_idx += 1
                    else:
                        break
            self.s_fe_msglist = []
        if event & poll.POLLOUT:
            try:
                n = self.s_fe.send(self.s_fe_buf2)
            except (OSError, RuntimeError) as ex:
                logging.info('[s_fe]Exception: %s', str(ex))
                raise fe_disconnected_exception()
            self.s_fe_buf2 = self.s_fe_buf2[n:]
            if self.s_fe_buf2:
                return
            if self.auth_simulate_failed:
                raise fe_disconnected_exception()
            if self.auth_msg_idx >= len(self.auth_msg_seq):
                logging.debug('auth_simulate done: fe:(%s %s %s) be:(%s %s %s)', 
                              self.s_fe_buf1, self.s_fe_msg_list, self.s_fe_buf2, self.s_be_buf1, self.s_be_msglist, self.s_be_buf2)
                self.auth_simulate = False
                self.discard_all_command_complete_recved = False
                self.discard_all_ready_for_query_recved = False
                self.use_num += 1
                
                poll.register(self.s_fe, poll.POLLIN)
                poll.register(self.s_be, poll.POLLIN)
                # 登陆完成，需要向主进程发送消息。
                self.send_connect_msg_to_main(poll, False)
                
                if self.enable_active_cnn_timeout:
                    self.ready_for_query_recved_time = time.time()
                    self.query_recved_time = 0
    # b'C'消息数据格式：len + pair_id;ip,port;ip,port;time;use_num;main_use_idle_cnn;proxy_use_idle_cnn + startup_msg_raw。len不包括startup_msg_raw。
    def send_connect_msg_to_main(self, poll, is_new):
        self.status_time = time.time()
        addr = self.s_fe.getpeername()
        msg_data = '%d' % self.id
        msg_data += ';%s,%d' % (addr[0], addr[1])
        addr = self.s_be.getpeername()
        msg_data += ';%s,%d' % (addr[0], addr[1])
        msg_data += ';%d;%d;%d;%d' % (self.status_time, self.use_num, self.main_use_idle_cnn, self.proxy_use_idle_cnn)
        
        msg_data = msg_data.encode('latin1')
        msg_data = struct.pack('>i', len(msg_data)+4) + msg_data
        msg_data += self.startup_msg_raw
        self.ep_to_main.put_msg(b'C', msg_data, [])
        poll.register(self.ep_to_main, poll.POLLIN|poll.POLLOUT)
        self.main_use_idle_cnn = -1
        self.proxy_use_idle_cnn = -1
    # b'D'消息数据格式：len + pair_id;1/0;time;main_use_idle_cnn;proxy_use_idle_cnn + startup_msg_raw。1表示完全断开，0表示只是s_fe断开。len不包括startup_msg_raw。
    def send_disconnect_msg_to_main(self, poll, is_complete_disconn):
        self.status_time = time.time()
        if is_complete_disconn:
            msg_data = '%d;1;%d' % (self.id, self.status_time)
        else:
            msg_data = '%d;0;%d' % (self.id, self.status_time)
        msg_data += ';%d;%d' % (self.main_use_idle_cnn, self.proxy_use_idle_cnn)
        
        msg_data = msg_data.encode('latin1')
        msg_data = struct.pack('>i', len(msg_data)+4) + msg_data
        msg_data += self.startup_msg_raw
        self.ep_to_main.put_msg(b'D', msg_data, [])
        poll.register(self.ep_to_main, poll.POLLIN|poll.POLLOUT)
        self.main_use_idle_cnn = -1
        self.proxy_use_idle_cnn = -1
# 
# 找到可用的匹配的idle pair
# 返回(pair, has_matched)
#   pair != None, has_matched = True     有匹配的可用的idle pair
#   pair = None,  has_matched = True     有匹配的但是目前还不可能的idle pair
#   pair = None,  has_matched = False    没有匹配的idle pair
def find_matched_idle_pair(idle_pair_list, be_addr):
    pair = None
    has_matched = False
    if not idle_pair_list:
        return (pair, has_matched)
    for p in idle_pair_list:
        if not p.s_be:
            logging.info('[find_matched_idle_pair] p.s_be is None')
            continue
        if p.s_be.getpeername() != be_addr:
            continue
        has_matched = True
        if p.discard_all_command_complete_recved and p.discard_all_ready_for_query_recved:
            pair = p
            break
    return (pair, has_matched)
def proxy_worker(ipc_uds_path):
    # 先建立到主进程的连接
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(ipc_uds_path)
    s.sendall(b's' + struct.pack('>ii', 8, os.getpid()))
    ipc_ep = uds_ep(s)
    
    poll = spoller()
    poll.register(ipc_ep, poll.POLLIN)
    fe_be_to_pair_map = {} # s_fe/s_be -> fe_be_pair
    startup_msg_raw_to_idle_pair_map = {} # 可复用的pair。startup_msg_raw -> [pair1, ...]
    idle_pair_map = {} # (startup_msg_raw, be_ip, be_port) -> [pair1, ...]
    msglist_from_main = []
    waiting_fmsg_list = [] # 等待处理的'f'消息列表
    
    while True:
        x = poll.poll(0.1)
        for fobj, event in x:
            if fobj == ipc_ep:
                if event & poll.POLLOUT:
                    x = fobj.send()
                    if x == None:
                        poll.register(fobj, poll.POLLIN)
                if event & poll.POLLIN:
                    x = fobj.recv()
                    if x[0] != -1:
                        continue
                    msg = x[1]
                    logging.debug('[proxy_worker] uds_ep recved: %s', msg)
                    msglist_from_main.append(msg) # 来自主进程的消息在事件for循环之外处理。
            else: # fe or be
                pair = fe_be_to_pair_map.get(fobj, None)
                if not pair:
                    logging.debug('fe_be_pair had been removed')
                    continue
                try:
                    if pair.s_fe:
                        if pair.auth_simulate:
                            pair.handle_event_simulate(poll, fobj, event)
                        else:
                            pair.handle_event(poll, fobj, event)
                    else:
                        pair.handle_event2(poll, fobj, event)
                except (fe_disconnected_exception, be_disconnected_exception) as ex:
                    if pair.startup_msg_raw not in startup_msg_raw_to_idle_pair_map:
                        startup_msg_raw_to_idle_pair_map[pair.startup_msg_raw] = []
                    idle_pair_list = startup_msg_raw_to_idle_pair_map[pair.startup_msg_raw]
                    
                    if pair.close(poll, ex, fe_be_to_pair_map):
                        if pair in idle_pair_list:
                            idle_pair_list.remove(pair)
                    else:
                        idle_pair_list.append(pair)
        # 检查活动的fe_be_pair是否超时
        if g_conf['active_cnn_timeout'] > 0:
            t = time.time()
            if t - fe_be_pair.oldest_ready_for_query_recved_time >= g_conf['active_cnn_timeout']: # g_conf is global var
                pair_set = set()
                for s in fe_be_to_pair_map:
                    pair = fe_be_to_pair_map[s]
                    if not pair.s_fe or not pair.enable_active_cnn_timeout or pair.query_recved_time > 0:
                        continue
                    pair_set.add(pair)
                oldest_time = time.time()
                for pair in pair_set:
                    if pair.startup_msg_raw not in startup_msg_raw_to_idle_pair_map:
                        startup_msg_raw_to_idle_pair_map[pair.startup_msg_raw] = []
                    idle_pair_list = startup_msg_raw_to_idle_pair_map[pair.startup_msg_raw]
                    if t - pair.ready_for_query_recved_time >= g_conf['active_cnn_timeout']:
                        logging.info('close s_fe in fe_be_pair because active_cnn_timeout: %d', pair.id)
                        pair.close(poll, fe_disconnected_exception(), fe_be_to_pair_map)
                        idle_pair_list.append(pair)
                    else:
                        if pair.ready_for_query_recved_time < oldest_time:
                            oldest_time = pair.ready_for_query_recved_time
                fe_be_pair.oldest_ready_for_query_recved_time = oldest_time
        # 处理来自主进程的消息
        for msg in msglist_from_main:
            if msg[0] == b'f': # len + ip,port,use_idle_cnn + startup_msg_raw。len不包括startup_msg_raw
                msg_len = struct.unpack('>i', msg[1][:4])[0]
                ip, port, use_idle_cnn = msg[1][4:msg_len].decode('latin1').split(',')
                addr = (ip, int(port))
                use_idle_cnn = int(use_idle_cnn)
                startup_msg_raw = msg[1][msg_len:]
                startup_msg = process_Startup(startup_msg_raw[4:])
                fd = msg[2][0]
                
                idle_pair_list = startup_msg_raw_to_idle_pair_map.get(startup_msg_raw, None)
                pair, has_matched = find_matched_idle_pair(idle_pair_list, addr)
                if has_matched:
                    if pair:
                        idle_pair_list.remove(pair)
                        pair.main_use_idle_cnn = use_idle_cnn
                        pair.proxy_use_idle_cnn = 1
                        pair.start2(poll, fe_be_to_pair_map, addr, startup_msg, fd)
                    else: # 空闲的fe_be_pair目前还都不可用，需要等待。
                        waiting_fmsg_list.append((addr, startup_msg, fd, startup_msg_raw, use_idle_cnn))
                else:
                    if g_conf['active_cnn_timeout'] <= 0 or match_conds(startup_msg, addr, g_conf['disable_conds_list']): # g_conf is global var
                        pair = fe_be_pair(ipc_ep, False)
                    else:
                        pair = fe_be_pair(ipc_ep, True)
                    pair.main_use_idle_cnn = use_idle_cnn
                    pair.proxy_use_idle_cnn = 0
                    pair.start(poll, fe_be_to_pair_map, addr, startup_msg, fd)
            else:
                logging.error('unknown msg from main process: %s', msg)
        if msglist_from_main:
            msglist_from_main.clear()
        # 处理waiting_fmsg_list
        del_list = []
        for msg in waiting_fmsg_list:
            addr = msg[0]
            startup_msg = msg[1]
            fd = msg[2]
            startup_msg_raw = msg[3]
            use_idle_cnn = msg[4]
            
            idle_pair_list = startup_msg_raw_to_idle_pair_map.get(startup_msg_raw, None)
            pair, has_matched = find_matched_idle_pair(idle_pair_list, addr)
            if has_matched:
                if pair:
                    idle_pair_list.remove(pair)
                    pair.main_use_idle_cnn = use_idle_cnn
                    pair.proxy_use_idle_cnn = 1
                    pair.start2(poll, fe_be_to_pair_map, addr, startup_msg, fd)
                    del_list.append(msg)
            else: # 没有匹配的idle pair, 可能上次检查的时候找到匹配但还不可用的pair已经close掉了。
                if g_conf['active_cnn_timeout'] <= 0 or match_conds(startup_msg, addr, g_conf['disable_conds_list']): # g_conf is global var
                    pair = fe_be_pair(ipc_ep, False)
                else:
                    pair = fe_be_pair(ipc_ep, True)
                pair.main_use_idle_cnn = use_idle_cnn
                pair.proxy_use_idle_cnn = 0
                pair.start(poll, fe_be_to_pair_map, addr, startup_msg, fd)
                del_list.append(msg)
        for msg in del_list:
            waiting_fmsg_list.remove(msg)
        del_list = None
        # 关闭超时的空闲fe_be_pair
        t = time.time()
        for k in startup_msg_raw_to_idle_pair_map:
            close_list = []
            idle_pair_list = startup_msg_raw_to_idle_pair_map [k]
            for pair in idle_pair_list:
                if t - pair.status_time >= g_conf['idle_cnn_timeout']: # g_conf is global var
                    close_list.append(pair)
            for pair in close_list:
                logging.info('[proxy process] close idle fe_be_pair because idle_cnn_timeout:%d', pair.id)
                idle_pair_list.remove(pair)
                pair.close(poll, be_disconnected_exception(), fe_be_to_pair_map)
            close_list = None

# 把CancelRequest消息msg_raw发给主库和所有从库
def send_cancel_request(msg_raw):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(g_conf['master'])
        s.sendall(msg_raw)
        s.close()
    except Exception as ex:
        logging.warning('Exception: %s', str(ex))
    
    for slaver in g_conf['slaver_list']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(slaver)
            s.sendall(msg_raw)
            s.close()
        except Exception as ex:
            logging.warning('Exception: %s', str(ex))
def process_promote_result(msg_data):
    if msg_data[0] == 'E':
        # 这里需要发送报警邮件
        logging.warning('promote fail:%s' % (msg_data[1:], ))
    else:
        addr_list = msg_data[1:].split(';')
        g_conf['master'] = (addr_list[0][0], int(addr_list[0][1]))
        s_list = []
        for addr in addr_list[1:]:
            s_list.append((addr[0], int(addr[1])))
        g_conf['slaver_list'] = s_list
def work_worker(ipc_uds_path):
    # 先建立到主进程的连接
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(ipc_uds_path)
    s.sendall(b's' + struct.pack('>ii', 8, os.getpid()))
    ipc_ep = uds_ep(s)
    
    poll = spoller()
    poll.register(ipc_ep, poll.POLLIN)
    while True:
        x = poll.poll()
        for fobj, event in x:
            if fobj == ipc_ep:
                if event & poll.POLLOUT:
                    x = fobj.send()
                    if x == None:
                        poll.register(fobj, poll.POLLIN)
                if event & poll.POLLIN:
                    x = fobj.recv()
                    if x[0] != -1:
                        continue
                    msg = x[1]
                    logging.debug('[work_worker] uds_ep recved: %s', msg)
                    if msg[0] == b'c': # CancelRequest消息
                        send_cancel_request(msg[1])
                    elif msg[0] == b'P': # 提升结果消息
                        msg_data = msg[1].decode('utf8')
                        process_promote_result(msg_data)
                    else:
                        logging.error('unknown msg from main process: %s', msg)
            else:
                logging.error('BUG: unknown fobj: %s' % (fobj, ))
# TODO: 通过DELETE命令来关闭某些连接。
class pseudo_pg_pg_proxy(pseudo_pg):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.proxy_pobj_list = None
    def select_table(self, tablename, sql):
        if tablename == 'connection':
            return self.select_table_connection(tablename, sql)
        elif tablename == 'process':
            return self.select_table_process(tablename, sql)
        elif tablename == 'server':
            return self.select_table_server(tablename, sql)
        elif tablename == 'startupmsg':
            return self.select_table_startupmsg(tablename, sql)
        else:
            err = 'undefined table %s. only support select on table connection|startupmsg|process|server.' % (tablename, )
            err = err.encode(self.client_encoding)
            return make_ErrorResponse2([(b'S', b'ERROR'), (b'C', b'42P01'), (b'M', err)])
    # sqlite3相关的公用函数
    def sqlite3_begin(self, create_table_sql):
        db = sqlite3.connect(':memory:')
        c = db.cursor()
        c.execute(create_table_sql)
        return c
    def sqlite3_end(self, c, tablename, sql):
        data = b''
        c.execute(sql)
        row_cnt = 0
        for row in c:
            col_val_list = []
            for v in row:
                v = '%s' % (v, ); v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            data += make_DataRow2(col_val_list)
            row_cnt += 1
        data += make_CommandComplete2(('SELECT %d'%row_cnt).encode(self.client_encoding))
        row_desc = self.make_row_desc((col_desc[0].encode('latin') for col_desc in c.description))
        data = row_desc + data
        c.connection.close()
        return data
    def select_table_connection(self, tablename, sql):
        # 需要发送 RowDescription / DataRow / CommandComplete
        try:
            c = self.sqlite3_begin('create table %s(pid int, id int, fe_ip text, fe_port int, be_ip text, be_port int, user text, database text, status_time text, use_num int)' % (tablename, ))
            for p in self.proxy_pobj_list:
                for x in p.proxy_conn_info_map:
                    cnn = p.proxy_conn_info_map[x]
                    user = get_param_val_from_startupmsg(cnn.startup_msg, 'user').rstrip(b'\x00').decode('latin1')
                    db = get_param_val_from_startupmsg(cnn.startup_msg, 'database').rstrip(b'\x00').decode('latin1')
                    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cnn.status_time))
                    c.execute("insert into %s values('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')" % 
                              (tablename, p.pid, cnn.pair_id, cnn.fe_ip, cnn.fe_port, cnn.be_ip, cnn.be_port, user, db, t, cnn.use_num))
            data = self.sqlite3_end(c, tablename, sql)
        except sqlite3.Error as ex:
            err = str(ex)
            data = make_ErrorResponse2([(b'S', b'ERROR'), (b'C', b'42601'), (b'M', err.encode(self.client_encoding))])
        return data
    def select_table_process(self, tablename, sql):
        # 需要发送 RowDescription / DataRow / CommandComplete
        data = self.make_row_desc((b'pid', b'total_cnn_num', b'idle_cnn_num', b'pending_cnn_num'))
        row_cnt = 0
        for p in self.proxy_pobj_list:
            col_val_list = []
            v = '%d' % p.pid; v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            v = '%d' % p.get_total_cnn_num(); v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            v = '%d' % p.get_idle_cnn_num(); v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            v = '%d' % p.get_pending_cnn_num(); v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            data += make_DataRow2(col_val_list)
            row_cnt += 1
        data += make_CommandComplete2(('SELECT %d'%row_cnt).encode(self.client_encoding))
        return data
    def select_table_server(self, tablename, sql):
        # 需要发送 RowDescription / DataRow / CommandComplete
        data = self.make_row_desc((b'server', b'total_cnn_num', b'idle_cnn_num'))
        
        server_info = {} # (host, port) -> [total_cnn_num, idle_cnn_num]
        for p in self.proxy_pobj_list:
            for x in p.proxy_conn_info_map:
                cnn = p.proxy_conn_info_map[x]
                key = (cnn.be_ip, cnn.be_port)
                if key not in server_info:
                    server_info[key] = [0, 0]
                info = server_info[key]
                info[0] += 1
                if not cnn.fe_ip:
                    info[1] += 1
        
        row_cnt = 0
        for k in server_info:
            info = server_info[k]
            col_val_list = []
            v = '%s:%d' % (k[0], k[1]); v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            v = '%d' % info[0]; v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            v = '%d' % info[1]; v = v.encode(self.client_encoding); col_val_list.append((len(v), v))
            data += make_DataRow2(col_val_list)
            row_cnt += 1
        data += make_CommandComplete2(('SELECT %d'%row_cnt).encode(self.client_encoding))
        return data
    def select_table_startupmsg(self, tablename, sql):
        # 需要发送 RowDescription / DataRow / CommandComplete
        try:
            c = self.sqlite3_begin('create table %s(pid int, id int, idle text, msg text)' % (tablename, ))
            for p in self.proxy_pobj_list:
                for x in p.proxy_conn_info_map:
                    cnn = p.proxy_conn_info_map[x]
                    idle = ('False' if cnn.fe_ip else 'True')
                    msg = ''
                    for param in cnn.startup_msg[3]:
                        msg += param[0].rstrip(b'\x00').decode('latin1') + '=' + param[1].rstrip(b'\x00').decode('latin1') + ' '
                    c.execute("insert into %s values('%s', '%s', '%s', '%s')" % (tablename, p.pid, cnn.pair_id, idle, msg))
            data = self.sqlite3_end(c, tablename, sql)
        except sqlite3.Error as ex:
            err = str(ex)
            data = make_ErrorResponse2([(b'S', b'ERROR'), (b'C', b'42601'), (b'M', err.encode(self.client_encoding))])
        return data


# 'P'类型的消息：'E' + errmsg 或者 'S' + m_ip,m_port;s_ip,s_port;...
def make_P_msg_data(success, *args):
    if not success:
        data = 'E' + args[0]
    else:
        m, s_list = args
        data = 'S%s,%d' % (m[0], m[1])
        for s in s_list:
            data += ';%s,%d' % (s[0], s[1])
    return data.encode('utf8')
# 
# 执行切换操作
def do_switch(poll):
    global master_mon
    logging.info('do_switch')
    if not g_conf['promote']:
        put_msg_to_work_worker(poll, b'P', make_P_msg_data(False, 'the master(%s) is down, but no promote provided' % (g_conf['master'], )))
        master_mon.close(is_down=False)
        return
    # TODO:是否需要先kill掉现有的工作进程，以防错误判断主库已经down掉。
    # 连接到promote执行提升操作
    promote = g_conf['promote']
    pw = g_conf['conninfo']['pw'].encode('latin1')
    user = g_conf['conninfo']['user'].encode('latin1')
    database = g_conf['conninfo']['db'].encode('latin1')
    lo_oid = g_conf['conninfo']['lo_oid']
    try:
        s, param_dict, key_data = make_pg_login(promote[0], promote[1], password=pw, user=user, database=database)
        res = execute(s, ("select lo_export(%d, 'trigger_file')"%lo_oid).encode('latin1'))
    except (OSError, RuntimeError) as ex:
        # 提升失败。需要发送报警。
        logging.warning('do_switch exception: %s' % (str(ex), ))
        master_mon.close(is_down=False)
        # 把提升失败结果发给工作进程。
        put_msg_to_work_worker(poll, b'P', make_P_msg_data(False, str(ex)))
        return
    logging.info('promote done')
    # TODO:检查从库是否已恢复完成
    # 提升成功之后修改配置参数
    g_conf['master'] = g_conf['promote']
    g_conf['promote'] = None
    if g_conf['slaver_list'] and g_conf['master'] in g_conf['slaver_list']:
        g_conf['slaver_list'].remove(g_conf['master'])
    # 重新初始化master_mon
    # 在try_go中已经把master_mon从poll中unregister了。
    master_mon.close(is_down=False)
    master_mon = pg_monitor(g_conf['master'], g_conf['conninfo'])
    master_mon.connect_first()
    # 把提升成功结果发给工作进程。
    put_msg_to_work_worker(poll, b'P', make_P_msg_data(True, g_conf['master'], g_conf['slaver_list']))
    logging.info('do_switch done')
# 成功put返回True，否则返回False。
def put_msg_to_work_worker(poll, msg_type, msg_data, fdlist=[]):
    for pobj in work_worker_pobj_list:
        if pobj.is_connected():
            pobj.put_msg(msg_type, msg_data, fdlist)
            poll.register(pobj, poll.POLLOUT|poll.POLLIN)
            return True
    return False
def make_f_msg_data(addr, use_idle_cnn, startup_msg_raw):
    msg_data = '%s,%d,%d' % (addr[0], addr[1], use_idle_cnn)
    msg_data = msg_data.encode('latin1')
    msg_data = struct.pack('>i', len(msg_data)+4) + msg_data + cnn.startup_msg_raw
    return msg_data
# 
def match_conds(startup_msg, addr, disable_conds_list):
    msg = {}
    for kv in startup_msg[3]:
        msg[kv[0].rstrip(b'\x00').decode('latin1')] = kv[1].rstrip(b'\x00').decode('latin1')
    for disable_conds in disable_conds_list:
        match = True
        for cond in disable_conds:
            cond_name = cond[0]
            if cond_name not in msg:
                match = False
                break
            if not re.match(cond[1], msg[cond_name]):
                match = False
                break
        if match:
            return True
    return False
def sigterm_handler(signum, frame):
    logging.info('got SIGTERM')
    for pobj in work_worker_pobj_list:
        logging.info('kill work_worker %d', pobj.pid)
        os.kill(pobj.pid, signal.SIGTERM)
    for pobj in proxy_worker_pobj_list:
        logging.info('kill proxy_worker %d', pobj.pid)
        os.kill(pobj.pid, signal.SIGTERM)
    logging.info('unlink unix domain socket:%s', g_conf['ipc_uds_path'])
    os.unlink(g_conf['ipc_uds_path'])
    logging.info('unlink pid_file:%s', g_conf['pid_file'])
    os.unlink(g_conf['pid_file'])
    sys.exit(0)
# main
proxy_worker_pobj_list = []
work_worker_pobj_list = []
g_conf_file = None
g_conf = None
# TODO: 主进程在检测到work子进程退出后，重启work子进程。
# TODO: SIGUSR1信号重新打开日志文件。
if __name__ == '__main__':
    if len(sys.argv) == 1:
        g_conf_file = os.path.join(os.path.dirname(__file__), 'pg_proxy.conf.py')
    elif len(sys.argv) == 2:
        g_conf_file = sys.argv[1]
    else:
        print('usage: %s [conf_file]' % (sys.argv[0], ))
        sys.exit(1)
    
    g_conf = read_conf_file(g_conf_file, 'pg_proxy_conf')
    w = get_max_len(g_conf['_print_order'])
    for k in g_conf['_print_order']: 
        print(k.ljust(w), ' = ', g_conf[k])
    fe_be_pair.recv_sz_per_poll = g_conf['recv_sz_per_poll']
    try:
        f = open(g_conf['pid_file'], 'x')
        f.write('%s' % (os.getpid(), ))
        f.close()
    except OSError as ex:
        print('%s' % (str(ex), ))
        sys.exit(1)
    
    master_mon = pg_monitor(g_conf['master'], g_conf['conninfo'])
    master_mon.connect_first()
    
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    
    listen_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_s.bind(g_conf['listen'])
    listen_s.listen(100)
    listen_s.settimeout(0)
    
    ipc_s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ipc_s.bind(g_conf['ipc_uds_path'])
    ipc_s.listen(100)
    ipc_s.settimeout(0)
    # 启动池进程
    for i in range(g_conf['proxy_worker_num']):
        pid = os.fork()
        if pid == 0:
            proxy_worker_pobj_list.clear()
            master_mon.close(is_down=False)
            listen_s.close()
            ipc_s.close()
            if g_conf['log']['filename']:
                g_conf['log']['filename'] += '.proxy%d' % (i+1, )
            logging.basicConfig(**g_conf['log'])
            set_process_title('pg_proxy.py: proxy worker')
            proxy_worker(g_conf['ipc_uds_path'])
        proxy_worker_pobj_list.append(proxy_worker_process(pid, i))
    # 启动工作进程
    pid = os.fork()
    if pid == 0:
        proxy_worker_pobj_list.clear()
        master_mon.close(is_down=False)
        listen_s.close()
        ipc_s.close()
        if g_conf['log']['filename']:
            g_conf['log']['filename'] += '.work'
        logging.basicConfig(**g_conf['log'])
        set_process_title('pg_proxy.py: work worker')
        work_worker(g_conf['ipc_uds_path'])
    work_worker_pobj_list.append(work_worker_process(pid, 0))
    
    if g_conf['log']['filename']:
        g_conf['log']['filename'] += '.main'
    logging.basicConfig(**g_conf['log'])
    
    signal.signal(signal.SIGTERM, sigterm_handler)
    
    pseudo_db_list = [] # 伪数据库连接
    pending_fe_conns = [] # 还没接收完startup_msg的fe连接
    cancel_request_list = [] # 等待发给工作进程的CancelRequest
    send_fe_cnn_list = [] # 等待发给proxy进程的fe连接
    next_slaver_idx = 0
    master_mon_ret = None
    poll = spoller()
    poll.register(listen_s, poll.POLLIN)
    poll.register(ipc_s, poll.POLLIN)
    
    while True:
        master_mon_called = False
        to_v = 10000
        if master_mon_ret == None:
            to_v = 0.1
        
        down_proxy_worker_pobj_list = []
        x = poll.poll(to_v)
        for fobj, event in x:
            if fobj == listen_s:
                fe_conn = pending_fe_connection(listen_s.accept()[0])
                poll.register(fe_conn, poll.POLLIN)
                pending_fe_conns.append(fe_conn)
            elif fobj == ipc_s:
                conn = uds_ep(ipc_s.accept()[0])
                poll.register(conn, poll.POLLIN)
            elif type(fobj) == uds_ep: # 接收第一个消息
                ret = fobj.recv()
                if ret[0] > 0:
                    continue
                poll.unregister(fobj)
                msg = ret[1]
                logging.debug('[main][uds_ep]recv: %s', msg)
                pid = struct.unpack('>i', msg[1])[0]
                for pobj in (proxy_worker_pobj_list + work_worker_pobj_list):
                    if pobj.pid == pid:
                        pobj.ep = fobj
                        poll.register(pobj, poll.POLLIN)
                        break
            elif type(fobj) == work_worker_process:
                fobj.handle_event(poll, event)
            elif type(fobj) == proxy_worker_process:
                try:
                    fobj.handle_event(poll, event)
                    # close已经发送的pending_fe_connection
                    fobj.close_fe_cnn()
                except (OSError, RuntimeError) as ex:
                    logging.error('proxy worker process(%d) is down: %s', fobj.pid, str(ex))
                    poll.unregister(fobj)
                    proxy_worker_pobj_list.remove(fobj)
                    fobj.close()
                    logging.info('try to kill the proxy worker process:%d', fobj.pid)
                    try:
                        os.kill(fobj.pid, signal.SIGTERM)
                        logging.info('kill done')
                    except OSError as ex:
                        logging.info('kill fail:%s', str(ex))
                    down_proxy_worker_pobj_list.append(fobj)
            elif type(fobj) == pending_fe_connection: # pending_fe_connection
                try:
                    fobj.recv()
                except Exception as ex:
                    logging.info('pending_fe_connection.recv error: Exception: %s', str(ex))
                    poll.unregister(fobj)
                    fobj.close()
                    pending_fe_conns.remove(fobj)
            elif type(fobj) == pseudo_pg_pg_proxy:
                try:
                    ret = ''
                    if event & poll.POLLIN:
                        ret = fobj.recv()
                    if event & poll.POLLOUT:
                        ret += fobj.send()
                    logging.debug('pseudo_pg: %s', ret)
                    if 'w' in ret:
                        poll.register(fobj, poll.POLLIN|poll.POLLOUT)
                    else:
                        poll.register(fobj, poll.POLLIN)
                except Exception as ex:
                    logging.info('pseudo_pg error: Exception: %s', str(ex))
                    #traceback.print_exc()
                    poll.unregister(fobj)
                    pseudo_db_list.remove(fobj)
                    fobj.close()
            elif fobj == master_mon:
                master_mon_called = True
                master_mon_ret = master_mon.try_go(poll, True)                  
        # 处理master_mon
        if not master_mon_called:
            master_mon_ret = master_mon.try_go(poll, False)
        if master_mon.check_down():
            do_switch(poll)
        # 处理pending_fe_connection
        # 检查pending_fe_connection是否已接收到startup消息
        del_cnns = []
        for cnn in pending_fe_conns:
            if not cnn.check_startup():
                continue
            
            poll.unregister(cnn) # StartupMessage接收完之后就可以从poll中删除了。
            if cnn.is_CancelRequest():
                cancel_request_list.append(cnn.startup_msg_raw)
                cnn.close()
                del_cnns.append(cnn)
                continue
            if cnn.is_SSLRequest() or cnn.is_StartupMessageV2() or cnn.get_param_val(b'replication') != None:
                cnn.close()
                del_cnns.append(cnn)
                continue
            # version 3 StartupMessage
            send_fe_cnn_list.append(cnn)
            del_cnns.append(cnn)
        # 移除已经处理过的pending_fe_connection
        for cnn in del_cnns:
            pending_fe_conns.remove(cnn)
        del_cnns.clear()
        # 向任意一个work进程发送CancelRequest
        for pobj in work_worker_pobj_list:
            if pobj.is_connected():
                for x in cancel_request_list:
                    pobj.put_msg(b'c', x)
                if cancel_request_list:
                    poll.register(pobj, poll.POLLOUT|poll.POLLIN)
                    cancel_request_list.clear()
                break
        # 向proxy进程发送fe连接
        del_cnns.clear()
        pseudo_db_cnns = []
        pobj_set = set()
        for cnn in send_fe_cnn_list:
            slaver_selected = False
            user = cnn.get_param_val('user')
            dbname = cnn.get_param_val('database')
            if dbname == b'pg_proxy\x00':
                pseudo_db_cnns.append(cnn)
                continue
            if cnn.is_readonly() and g_conf['slaver_list']:
                slaver_selected = True
                be_addr = g_conf['slaver_list'][next_slaver_idx%len(g_conf['slaver_list'])]
            else:
                be_addr = g_conf['master']
            
            pobj = None
            min_active_cnn = 1024*1024
            has_matched = False
            for p in proxy_worker_pobj_list:
                if not p.is_connected():
                    continue
                if p.has_matched_idle_conn(cnn.startup_msg_raw, be_addr):
                    logging.info('[%d]found idle cnn to %s for %s' % (p.pid, be_addr, cnn.startup_msg))
                    p.put_msg(b'f', make_f_msg_data(be_addr, 1, cnn.startup_msg_raw), [cnn.fileno()])
                    p.add_closing_fe_cnn(cnn)
                    p.remove_idle_conn(cnn.startup_msg_raw)
                    pobj_set.add(p)
                    del_cnns.append(cnn)
                    has_matched = True
                    break
                if p.get_active_cnn_num() < min_active_cnn:
                    min_active_cnn = p.get_active_cnn_num()
                    pobj = p
            if has_matched:
                continue
            if not pobj: # 所有pobj都未连接到主进程。
                logging.warning('all pobj in proxy_worker_pobj_list are not connected')
                break
            # 发给当前活动连接数最少的proxy进程。
            logging.info('[%d]no idle cnn to %s for %s' % (pobj.pid, be_addr, cnn.startup_msg))
            pobj.put_msg(b'f',  make_f_msg_data(be_addr, 0, cnn.startup_msg_raw), [cnn.fileno()])
            pobj.add_closing_fe_cnn(cnn)
            if pobj.pending_cnn_num < 0:
                logging.warning('pending_cnn_num < 0')
                pobj.pending_cnn_num = 1
            else:
                pobj.pending_cnn_num += 1
            pobj_set.add(pobj)
            del_cnns.append(cnn)
            if slaver_selected:
                next_slaver_idx += 1
        for pobj in pobj_set:
            poll.register(pobj, poll.POLLOUT|poll.POLLIN)
        pobj_set.clear()
        for cnn in del_cnns:
            send_fe_cnn_list.remove(cnn)
        del_cnns.clear()
        # 处理伪数据库
        for cnn in pseudo_db_cnns:
            pseudo_db = pseudo_pg_pg_proxy(g_conf['pg_proxy_pw'].encode('latin1'), cnn.s, cnn.startup_msg)
            pseudo_db.proxy_pobj_list = proxy_worker_pobj_list
            poll.register(pseudo_db, poll.POLLIN|poll.POLLOUT)
            pseudo_db_list.append(pseudo_db)
            send_fe_cnn_list.remove(cnn)
        pseudo_db_cnns.clear()
        # 检查是否需要重启子进程
        for pobj in down_proxy_worker_pobj_list:
            logging.info('restart proxy worker:%d', pobj.idx)
            pid = os.fork()
            if pid == 0:
                master_mon.close(is_down=False)
                close_fobjs([listen_s, ipc_s, poll, pseudo_db_list, pending_fe_conns, send_fe_cnn_list, proxy_worker_pobj_list, work_worker_pobj_list])                
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                
                if g_conf['log']['filename']:
                    g_conf['log']['filename'] += '.proxy%d' % (pobj.idx+1, )
                logging.basicConfig(**g_conf['log'])
                set_process_title('pg_proxy.py: proxy worker')
                proxy_worker(g_conf['ipc_uds_path'])
            proxy_worker_pobj_list.append(proxy_worker_process(pid, pobj.idx))


