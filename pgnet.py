#!/bin/env python3
# -*- coding: GBK -*-
# 
# ʹ��pgconn�ĵ��̳߳��������pypy��ִ�У�����������ܡ�
# 
import sys, os, socket, time
import traceback
import functools, collections
import getpass
import netutils
import miscutils
import pgprotocol3 as p
import scram
import pgtypes

def quote_literal(v):
    if v is None:
        return 'NULL'
    if type(v) is not str:
        v = str(v)
    if '\\' in v:
        res = "E'"
    else:
        res = "'"
    for c in v:
        if c in ('\'', '\\'):
            res += c
        res += c
    res += "'"
    return res
def quote_ident(v):
    res = '"'
    for c in v:
        if c == '"':
            res += c
        res += c
    res += '"'
    return res
# �����Ƿ������ģ�����connect��ʱ��
@netutils.pollize
class connbase():
    log_msg = False
    def __init__(self, s):
        self.s = s
        self.s.settimeout(0)
        self.recv_buf = b''
        self.send_buf = b''
        self.readsz = -1 # _read����ÿ������ȡ�����ֽڣ�<=0��ʾ���ޡ�
        self.readunit = 32*1024
    def is_fe(self):
        raise RuntimeError('should not call connbase.is_fe()')
    def fileno(self):
        return self.s.fileno()
    def close(self):
        self.s.close()
        self.status = 'disconnected'
    def __repr__(self):
        return '<%s peer=%s>' % (type(self).__name__, self.s.getpeername())
    def __getattr__(self, name):
        return getattr(self.s, name)
    # ��ȡ����ֱ��û�����ݿɶ�
    def _read(self):
        while True:
            try:
                data = netutils.myrecv(self.s, self.readunit)
            except ConnectionError as ex:
                raise pgfatal(None, '%s' % ex, self)
            if data is None:
                break
            elif not data:
                raise pgfatal(None, 'the peer(%s) closed connection' % (self.s.getpeername(),), self)
            self.recv_buf += data
            if len(data) < self.readunit:
                break
            if self.readsz > 0 and len(self.recv_buf) >= self.readsz:
                break
    def _write(self):
        if self.send_buf:
            try:
                sz = self.s.send(self.send_buf)
            except ConnectionError as ex:
                raise pgfatal(None, '%s' % ex, self)
            except BlockingIOError:
                return
            self.send_buf = self.send_buf[sz:]
    # ͨ�ö�д��Ϣ����
    # ������Ϣ�б�max_msgָ����෵�ض��ٸ���Ϣ��
    def _read_x_msgs(self, parsefunc, max_msg=0, stop=None):
        self._read()
        if not self.recv_buf:
            return []
        idx, msg_list = parsefunc(self.recv_buf, max_msg, stop)
        if msg_list:
            self.recv_buf = self.recv_buf[idx:]
        return msg_list
    # ���ػ�ʣ���ٸ��ֽ�û�з��͡�msg_listΪ����ᷢ���ϴ�ʣ�µ����ݡ�
    def _write_x_msgs(self, msgs_type, msg_list=()):
        if self.log_msg and msg_list:
            fe = self.is_fe()
            prefix_str = 'BE' if fe else 'FE'
            for msg in msg_list:
                if type(msg) is p.RawMsg and msg.msg_type == p.BeMsgType.MT_DataRow:
                    print('%s: DataRow(%s)' % (prefix_str, bytes(msg)));
                else:
                    print('%s: %s' % (prefix_str, msg.to_msg(fe=not fe)))
        if msg_list:
            if type(msg_list) is msgs_type:
                self.send_buf += bytes(msg_list)
            else:
                self.send_buf += b''.join(bytes(msg) for msg in msg_list)
        self._write()
        return len(self.send_buf)
    # һֱ��ֱ������ϢΪֹ
    def _read_x_msgs_until_avail(self, read_msgs_func, max_msg=0, stop=None):
        msg_list = read_msgs_func(max_msg, stop)
        while not msg_list:
            self.pollin()
            msg_list = read_msgs_func(max_msg, stop)
        return msg_list
    # һֱдֱ��д��Ϊֹ
    def _write_x_msgs_until_done(self, write_msgs_func, msg_list=()):
        if msg_list:
            if not write_msgs_func(msg_list):
                return
        if not self.send_buf:
            return
        while write_msgs_func():
            self.pollout()
    # ����read������ֵ��MsgChunk��
    # ����write��msg_list��MsgChunk����Msg�б�
    def read_msgs(self, max_msg=0, stop=None):
        return self._read_x_msgs(functools.partial(p.parse_pg_msg, fe=self.is_fe()), max_msg, stop)
    def write_msgs(self, msg_list=()):
        return self._write_x_msgs(p.MsgChunk, msg_list)
    def read_msgs_until_avail(self, max_msg=0, stop=None):
        return self._read_x_msgs_until_avail(self.read_msgs, max_msg, stop)
    def write_msgs_until_done(self, msg_list=()):
        return self._write_x_msgs_until_done(self.write_msgs, msg_list)
    def write_msg(self, msg):
        return self.write_msgs((msg,))
    # raw��Ϣ��д
    # ����read������ֵ��RawMsgChunk��
    # ����write��raw_msg_list��RawMsgChunk����RawMsg�б�
    def read_raw_msgs(self, max_msg=0, stop=None):
        return self._read_x_msgs(p.parse_raw_pg_msg, max_msg, stop)
    def write_raw_msgs(self, raw_msg_list=()):
        return self._write_x_msgs(p.RawMsgChunk, raw_msg_list)
    def read_raw_msgs_until_avail(self, max_msg=0, stop=None):
        return self._read_x_msgs_until_avail(self.read_raw_msgs, max_msg, stop)
    def write_raw_msgs_until_done(self, raw_msg_list=()):
        return self._write_x_msgs_until_done(self.write_raw_msgs, raw_msg_list)
    def write_raw_msg(self, raw_msg):
        return self.write_raw_msgs((raw_msg,))
    # context manager
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
class feconn(connbase):
    def __init__(self, s):
        self.status = 'connected'
        super().__init__(s)
        self.startup_msg = None
    def is_fe(self):
        return True
    # ��ȡ��һ����Ϣ�������1����SSLRequest����ô���е�2��startup_msg��
    def read_startup_msg(self):
        self._read()
        if p.startup_msg_is_complete(self.recv_buf):
            try:
                self.startup_msg = p.parse_startup_msg(self.recv_buf)
            except RuntimeError as ex:
                raise pgfatal(None, 'RuntimeError: %s' % ex)
            self.recv_buf = b''
            return self.startup_msg
        else:
            return None
    # �����յ�SSLRequest��ʱ�򣬵��øú������߿ͻ��˲�֧��SSL��
    def write_no_ssl(self):
        self.send_buf = b'N'
        self.write_msgs_until_done()
# ���ڶ�ȡstatup message
class feconn4startup():
    def __init__(self, cnn):
        self.cnn = cnn
    def __getattr__(self, name):
        return getattr(self.cnn, name)
class beconn(connbase):
    def __init__(self, addr, async_conn=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.status = 'connecting'
        # connect_exҲ�����׳��쳣��֮����Ҫ�ȼ��POLLOUT|POLLERR��
        # POLLERR��ʾ����ʧ�ܣ���ʱ��ͨ��netutils.get_socket_error�������ʧ�ܵ�ԭ��
        # POLLOUT��ʾ���ӳɹ����Է������ݡ�
        # connect�����׳����쳣:socket.gaierror, TimeoutError, ConnectionError
        try:
            if async_conn:
                s.settimeout(0)
                s.connect_ex(addr)
            else:
                s.connect(addr)
                self.status = 'connected'
        except OSError as ex:
            raise pgfatal(None, 'connect fail for %s: %s' % (addr, ex), self)
        super().__init__(s)
    def is_fe(self):
        return False
    # ֻ���ڵ�½�ɹ��󣬲��ҷ�����Ϣ������self.params��self.be_keydata֮��ſ��Ե��á�
    # str <-> bytes
    def encode(self, data):
        if data is not None and type(data) is not bytes:
            data = str(data).encode(self.params['client_encoding'])
        return data
    def decode(self, data):
        if data is not None and type(data) is not str:
            data = bytes(data).decode(self.params['client_encoding'])
        return data
# ��Ч�Ĺؼ��ֲ�������: host, port, database, user, password, �Լ�����GUC����������client_encoding, application_name��
# ���pg_shadow�е�������md5������pg_hba.conf�е�auth����Ҳ��md5����ôpassword����ֵ������pg_shadow�е�md5����
# 
# ����password��Ҫ�ر�ע�����: 
#   ����create role/alter role�����û������ʱ�򣬷������˴�������������ݿ�����ʽ�ġ����ڽ������ӵ�ʱ���޷�֪��
#   ���ݿ�ı��룬��˿ͻ�����Ҫȷ������ĸ�ʽ�����ݿ����ģ��������û�������ַ�(��������)�Ǿ�û���⣬���������
#   ���ĵ������ַ����������ݿ���벻��utf8������Ҫ�������bytes����password������bytes�ĸ�ʽ��Ҫ�����ݿ���롣
#   ��˾��������в�Ҫ������latin�����ַ���
class AuthContext: pass
class pgconn(beconn):
    def __init__(self, **kwargs):
        self.async_msgs = { 
            p.MsgType.MT_NoticeResponse :       [], 
            p.MsgType.MT_NotificationResponse : [], 
            p.MsgType.MT_ParameterStatus : [], 
        }
        self.processer = None
        self.auth_ctx = AuthContext()
        host = kwargs.pop('host', '127.0.0.1')
        port = kwargs.pop('port', 5432)
        super().__init__((host, port))
        if 'database' not in kwargs:
            kwargs['database'] = 'postgres'
        if 'user' not in kwargs:
            kwargs['user'] = getpass.getuser()
        password = kwargs.pop('password', '')
        self.startup_msg = p.StartupMessage.make(**kwargs)
        self.write_msg(self.startup_msg)
        self.auth_ctx.password = password.encode('utf8') if type(password) is str else password
        self.auth_ctx.user = kwargs['user'].encode('utf8') if type(kwargs['user']) is str else kwargs['user']
        try:
            self._process_auth()
        except RuntimeError as ex:
            raise pgfatal(None, '%s' % ex)
        # auth ok�������self.params��self.be_keydata
    def _process_auth(self):
        m = self.processer.process()
        if m.authtype == p.AuthType.AT_Ok:
            #self.auth_ctx = None
            return
        elif m.authtype == p.AuthType.AT_CleartextPassword:
            self.write_msg(m.make_ar(password=self.auth_ctx.password))
        elif m.authtype == p.AuthType.AT_MD5Password:
            self.write_msg(m.make_ar(password=self.auth_ctx.password, user=self.auth_ctx.user))
        elif m.authtype == p.AuthType.AT_SASL:
            self.auth_ctx.sasl_init_resp_msg = scram.make_SASLInitialResponse()
            auth_resp_msg = m.make_ar(sasl_init_resp_msg=self.auth_ctx.sasl_init_resp_msg)
            self.write_msg(auth_resp_msg)
        elif m.authtype == p.AuthType.AT_SASLContinue:
            scram.parse_SASLContinue(m)
            password = scram.mysaslprep(self.auth_ctx.password)
            self.auth_ctx.salted_password = scram.scram_salted_password(password, m.salt, m.iter_num)
            self.auth_ctx.sasl_continue_msg = m
            
            self.auth_ctx.sasl_resp_msg = scram.make_SASLResponse(self.auth_ctx.salted_password, 
                                                                  self.auth_ctx.sasl_init_resp_msg, 
                                                                  self.auth_ctx.sasl_continue_msg)
            auth_resp_msg = m.make_ar(sasl_resp_msg=self.auth_ctx.sasl_resp_msg)
            self.write_msg(auth_resp_msg)
        elif m.authtype == p.AuthType.AT_SASLFinal:
            scram.parse_SASLFinal(m)
            proof = scram.calc_SASLFinal(self.auth_ctx.salted_password, self.auth_ctx.sasl_init_resp_msg, 
                                         self.auth_ctx.sasl_continue_msg, self.auth_ctx.sasl_resp_msg)
            if proof != m.proof:
                raise pgfatal(None, 'wrong server proof')
            self.processer = AuthResponseProcesser(self)
        else:
            raise pgfatal(m, 'unsupported authentication type')
        self._process_auth()
    def write_msg(self, msg):
        if self.processer:
            raise SystemError('BUG:you should not call write_msg while processer(%s) is not None' % self.processer)
        ret = super().write_msg(msg)
        self.processer = get_processer_for_msg(msg)(self)
        return self.processer
    # async msg
    def _got_async_msg(self, m):
        self.async_msgs[m.msg_type].append(m)
        if m.msg_type == p.MsgType.MT_ParameterStatus:
            self.params[bytes(m.name).decode('ascii')] = bytes(m.val).decode('ascii')
    def clear_async_msgs(self):
        for k in list(self.async_msgs):
            self.async_msgs[k] = []
    def _get_async_msg(self, msgtype):
        ret = self.async_msgs[msgtype]
        self.async_msgs[msgtype] = []
        return ret
    def parameter_status_am(self):
        msg_list = self._get_async_msg(p.MsgType.MT_ParameterStatus)
        return [(bytes(msg.name).decode('ascii'), bytes(msg.val).decode('ascii')) for msg in msg_list]
    def notice_am(self):
        msg_list = self._get_async_msg(p.MsgType.MT_NoticeResponse)
        return [collections.OrderedDict(msg.get(decode=self.decode)) for msg in msg_list]
    def notification_am(self):
        msg_list = self._get_async_msg(p.MsgType.MT_NotificationResponse)
        return [(msg.pid, self.decode(msg.channel), self.decode(msg.payload)) for msg in msg_list]
    def read_async_msgs(self, timeout=0):
        if self.processer:
            raise SystemError('BUG:you should not call read_async_msgs while processer(%s) is not None' % self.processer)
        if not self.pollin(timeout):
            return 0
        msg_list = self.read_msgs()
        for m in msg_list:
            self._got_async_msg(m.copy())
        return len(msg_list)
    # �򵥲�ѯ���������ֵ��CopyResponse����Ҫ����process��������copy������
    def query(self, sql):
        sql = self.encode(sql)
        return self.write_msg(p.Query.make(sql)).process()
    # ��չ��ѯ����֧��copy��䡣
    # sql����еĲ�����$1..$n��ʾ��
    # �����д���insert/update/delete��ʱ�򣬿��԰�discard_qr��ΪTrue�������Ͳ��᷵�ش�����QueryResult��
    # 
    # ��args_list�ܴ�ʱ��������Ϣ��������Ƿ�ɶ�������ᷢ�������ݣ���Ϊ��������Ҳ�᲻ͣ�����ͻ���д��Ϣ��
    # ����������дbuffer����֮��������ˣ������Ͷ����˿ͻ��˷��͵���Ϣ�����������
    def query2(self, sql, args_list, discard_qr=False, resfc=None):
        processer = Query2Processer(self, discard_qr)
        sql = self.encode(sql)
        self.write_msgs((p.Parse.make(sql),))
        processer.process()
        for args in args_list:
            x = [self.encode(arg) for arg in args]
            if discard_qr:
                self.write_msgs((p.SimpleBind(x, resfc), p.Execute.Default))
            else:
                self.write_msgs((p.SimpleBind(x, resfc), p.Describe.DefaultPortal, p.Execute.Default))
            processer.process()
        self.write_msgs((p.Close.stmt(), p.Sync()))
        while not processer.process(synced=True):
            self.pollin()
        if len(processer.qres_list) == 1:
            return processer.qres_list[0]
        else:
            return processer.qres_list
    def copyin(self, sql, data_list, batch=10):
        m = self.query(sql)
        if isinstance(m, p.CopyInResponse):
            self.processer.process(data_list, batch=batch)
            return self.processer.process()
        elif isinstance(m, p.CopyOutResponse):
            for r in self.processer.process_iter():
                pass
            self.processer.reset_processer()
            try:
                self.processer.process()
            except Exception:
                pass
            raise pgerror(None, 'sql(%s) is not copy in statement' % sql)
        else:
            raise pgerror(None, 'sql(%s) is not copy in statement' % sql)
    def copyout(self, sql, outf=None):
        res = []
        m = self.query(sql)
        if isinstance(m, p.CopyOutResponse):
            for r in self.processer.process_iter():
                if outf:
                    outf(r)
                else:
                    res.append(r)
            self.processer.reset_processer()
            return self.processer.process(), res
        elif isinstance(m, p.CopyInResponse):
            self.processer.process((), abort=True)
            try:
                self.processer.process()
            except Exception:
                pass
            raise pgerror(None, 'sql(%s) is not copy out statement' % sql)
        else:
            raise pgerror(None, 'sql(%s) is not copy out statement' % sql)
    def trans(self):
        return pgtrans(self)
    def errmsg(self, pgerr_ex):
        if pgerr_ex.errmsg is None:
            return None
        return collections.OrderedDict(pgerr_ex.errmsg.get(decode=self.decode))
    # ���auth�ɹ���ӷ������˷��ظ��ͻ��˵���Ϣ����AuthenticationOk��ʼֱ��ReadyForQuery��
    def make_auth_ok_msgs(self):
        return p.make_auth_ok_msgs(self.params, self.be_keydata)
    @staticmethod
    def quote_literal(v):
        return quote_literal(v)
    @staticmethod
    def quote_ident(v):
        return quote_ident(v)
# errmsg��ErrorResponse����������ʶ����Ϣ��
# pgerror��ʾ���ӻ����Լ���ʹ�ã���pgfatal��ʾ�����Ĵ��������Ӳ����á�
# pgfatal���������socket��дʧ�ܵ��µģ���cnn����Ϊ��Ӧ�����Ӷ���
# ������postgresql�޹صĴ������׳�RuntimeError��
class pgexception(Exception):
    def __init__(self, errmsg, errstr=None, cnn=None):
        self.errmsg = errmsg
        self.errstr = errstr
        self.cnn = cnn
    def __repr__(self):
        return "errstr:%s errmsg:%s" % (self.errstr, self.errmsg)
    __str__ = __repr__
class pgerror(pgexception):
    pass
class pgfatal(pgexception):
    pass
# transaction context manager
class pgtrans():
    def __init__(self, cnn):
        self.cnn = cnn
    def __enter__(self):
        self.cnn.query('begin')
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            self.cnn.query('commit')
        else:
            self.cnn.query('abort')
# ���rowdesc!=None����������з��ؽ�����Ĳ�ѯ(����select)���������û�н������(����insert/delete)��
# ����rowdesc�е�������������ͬ���ġ�
class QueryResult():
    class rowtype():
        # r : row data�������tuple/list�������ǽ������ģ������bytes��������ԭʼ��DataRow��Ϣ����
        # qres : QueryResult which contains the row data
        def __init__(self, r, qres):
            self.r = r
            self.qres = qres
        def __iter__(self):
            for idx, c in enumerate(self.r):
                yield self[idx]
        def __len__(self):
            return len(self.r)
        def __getitem__(self, idx):
            if type(idx) is str:
                idx = self.qres.field_map[idx]
            field = self.qres.rowdesc[idx]
            return pgtypes.parse(self.r[idx], field.typoid, self.qres.client_encoding)
        def __getattr__(self, name):
            if name not in self.qres.field_map:
                raise AttributeError('no attribute %s' % name)
            return self[name]
        def __repr__(self):
            if type(self.r) is bytes: # ԭʼDataRow��Ϣ��
                return str(self.r);
            ret = '('
            for idx, _ in enumerate(self.qres.rowdesc):
                ret += '%s, ' % (self[idx], )
            ret = ret[:-2] + ')'
            return ret
    
    def __init__(self, cmdtag, rowdesc, rows, client_encoding):
        self.cmdtag = cmdtag
        self.rowdesc = rowdesc
        self.rows = rows
        self.client_encoding = client_encoding
        self._parse_cmdtag()
        self._make_field_map()
    def _parse_cmdtag(self):
        s1, *s2 = self.cmdtag.split(maxsplit=1)
        if s1 in ('UPDATE', 'DELETE', 'SELECT', 'MOVE', 'FETCH', 'COPY'):
            self.cmdtag = (s1, int(s2[0]))
        elif s1 in ('INSERT',):
            oid, rownum = s2[0].split(maxsplit=1)
            self.cmdtag = (s1, int(rownum), int(oid))
        else:
            self.cmdtag = (self.cmdtag, )
    def _make_field_map(self):
        if self.rowdesc is None:
            return
        self.field_map = {field.name : idx for idx, field in enumerate(self.rowdesc)}
    def __repr__(self):
        return "<%s %s %s>" % (self.cmdtag, self.rowdesc, self.rowcount())
    def __iter__(self):
        for r in self.rows:
            yield type(self).rowtype(r, self)
    def __len__(self):
        return len(self.rows)
    def __getitem__(self, idx):
        return type(self).rowtype(self.rows[idx], self)
    def rowcount(self):
        if self.rowdesc is None:
            if len(self.cmdtag) >= 2:
                return self.cmdtag[1]
            else:
                return -1
        return len(self)
    def column_info(self, colname):
        if self.rowdesc is None:
            return None
        return self.rowdesc[self.field_map[colname]]
    def columns(self):
        if self.rowdesc is None:
            return ()
        return list(f.name for f in self.rowdesc)
# 
# processer for response msg after sending message
# 
def get_processer_for_msg(msg):
    msgname = type(msg).__name__
    pname = msgname + 'Processer'
    return globals()[pname]
class MsgProcesser():
    def __init__(self, cnn, prev_processer=None):
        self.cnn = cnn
        self.prev_processer = prev_processer
    def process(self, *args, **kwargs):
        self.cnn.write_msgs_until_done()
        try:
            return self._process(*args, **kwargs)
        finally:
            self.reset_processer()
    # ��cnn��processer����Ϊprev_processer
    def reset_processer(self):
        if self.cnn.processer is self:
            self.cnn.processer = self.prev_processer
class StartupMessageProcesser(MsgProcesser):
    UnknownMsgErr = 'unknown response msg for startup message'
    def __init__(self, cnn):
        super().__init__(cnn)
        self.params = {}
        self.be_keydata = None
    # ����authtype��Ok/CleartextPasword/MD5Password��Authentication�������׳��쳣��
    # ���ú�Ӧ�ü��cnn.async_msgs[MsgType.MT_NoticeResponse]�Ƿ�Ϊ�ա�
    def _process(self):
        m1 = self.cnn.read_msgs_until_avail(max_msg=1)[0]
        if m1.msg_type == p.MsgType.MT_Authentication:
            if m1.authtype == p.AuthType.AT_Ok:
                self._process_msg_list(self.cnn.read_msgs_until_avail())
                self.cnn.params = self.params
                self.cnn.be_keydata = self.be_keydata
                return m1
            elif m1.authtype in (p.AuthType.AT_CleartextPassword, p.AuthType.AT_MD5Password):
                return m1
            elif m1.authtype in (p.AuthType.AT_SASL, p.AuthType.AT_SASLContinue, p.AuthType.AT_SASLFinal):
                return m1
            else:
                raise pgfatal(m1, 'unsupported authentication type')
        elif m1.msg_type == p.MsgType.MT_ErrorResponse:
            raise pgfatal(m1, 'auth fail')
        else:
            raise pgfatal(m1, cls.UnknownMsgErr)
    # ����authtype=Ok�������Ϣ��Ҳ������ErrorResponse��������֤�ɹ����鷢�����ݿⲻ���ڡ�
    def _process_msg_list(self, msg_list):
        got_ready = False
        for m in msg_list:
            if m.msg_type == p.MsgType.MT_ParameterStatus:
                self.params[bytes(m.name).decode('ascii')] = bytes(m.val).decode('ascii')
            elif m.msg_type == p.MsgType.MT_BackendKeyData:
                self.be_keydata = (m.pid, m.skey)
            elif m.msg_type == p.MsgType.MT_ReadyForQuery:
                got_ready = True
                break
            elif m.msg_type == p.MsgType.MT_NoticeResponse:
                self.cnn._got_async_msg(m.copy())
            elif m.msg_type == p.MsgType.MT_ErrorResponse:
                raise pgfatal(m.copy())
            else:
                raise pgfatal(m.copy(), self.UnknownMsgErr)
        if got_ready:
            return
        msg_list = self.cnn.read_msgs_until_avail()
        self._process_msg_list(msg_list)
class AuthResponseProcesser(StartupMessageProcesser):
    UnknownMsgErr = 'unknown response msg for AuthResponse message'
class QueryProcesser(MsgProcesser):
    UnknownMsgErr = 'unknown response msg for Query message'
    def __init__(self, cnn, discard_qr=False):
        super().__init__(cnn)
        self.discard_qr = discard_qr
        self.msgs_from_copy = []
        self.ex = None
        self.qres_list = []
        self.cmdtag = self.rowdesc = self.rows = None
    # ����QueryResult�����б�(����Ƕ������)������CopyResponse��Ϣ�������׳��쳣��
    # ���rowdescΪNone��ôrowsҲΪNone��
    # �������CopyResponse��Ϣ����ô��Ҫ��������cnn.processer.process������copy��
    # ����ٵ���cnn.processer.process�����copy����Ĵ�������
    def _process(self):
        if self.msgs_from_copy:
            msg_list = self.msgs_from_copy
            self.msgs_from_copy = []
        else:
            msg_list = self.cnn.read_msgs_until_avail()
        while True:
            ret = self._process_msg_list(msg_list)
            if ret: # True or CopyResponse
                break
            msg_list = self.cnn.read_msgs_until_avail()
        if isinstance(ret, p.CopyResponse):
            return ret
        if self.ex:
            raise self.ex
        if len(self.qres_list) == 1:
            return self.qres_list[0]
        else:
            return self.qres_list
    # ����True/False����CopyResponse
    def _process_msg_list(self, msg_list):
        got_ready = False
        for idx, m in enumerate(msg_list):
            if m.msg_type == p.MsgType.MT_DataRow:
                if not self.discard_qr:
                    self.rows.append(m.col_vals)
                    #self.rows.append(tuple(c if c is None else self.cnn.decode(c) for c in m))
            elif m.msg_type == p.MsgType.MT_RowDescription:
                self.rowdesc = list(c._replace(name=self.cnn.decode(c.name)) for c in m)
                self.rows = []
            elif m.msg_type == p.MsgType.MT_CommandComplete:
                self.cmdtag = self.cnn.decode(m.tag)
                if not self.discard_qr:
                    self.qres_list.append(QueryResult(self.cmdtag, self.rowdesc, self.rows, self.cnn.params['client_encoding']))
                self.cmdtag = self.rowdesc = self.rows = None
            elif m.msg_type == p.MsgType.MT_ReadyForQuery:
                got_ready = True
                break
            elif m.msg_type == p.MsgType.MT_ErrorResponse:
                self.ex = pgerror(m.copy())
            elif m.msg_type == p.MsgType.MT_EmptyQueryResponse:
                self.ex = pgerror(m.copy())
            elif m.msg_type in self.cnn.async_msgs: # async msg
                self.cnn._got_async_msg(m.copy())
            elif m.msg_type == p.MsgType.MT_CopyInResponse:
                self.cnn.processer = CopyInResponseProcesser(self.cnn, msg_list[idx:])
                return m.copy()
            elif m.msg_type == p.MsgType.MT_CopyOutResponse:
                self.cnn.processer = CopyOutResponseProcesser(self.cnn, msg_list[idx:])
                return m.copy()
            # ��չ��ѯ��ص���Ϣ
            elif m.msg_type == p.MsgType.MT_ParseComplete:
                pass
            elif m.msg_type == p.MsgType.MT_BindComplete:
                pass
            elif m.msg_type == p.MsgType.MT_NoData:
                pass
            elif m.msg_type == p.MsgType.MT_CloseComplete:
                pass
            else:
                # ���ﲻֱ���׳��쳣����Ҫ����ReadyForQuery֮����ܰ����׳���
                self.ex = pgerror(m.copy(), self.UnknownMsgErr)
        return got_ready
class Query2Processer(QueryProcesser):
    def __init__(self, cnn, discard_qr=False):
        super().__init__(cnn, discard_qr)
    def process(self, synced=False):
        self.cnn.write_msgs_until_done()
        msg_list = self.cnn.read_msgs()
        ret = self._process_msg_list(msg_list)
        if self.ex:
            self._finish(synced)
            raise self.ex
        return ret
    def _finish(self, synced):
        if not synced:
            self.cnn.write_msgs_until_done((p.Sync(),))
        while True:
            msg_list = self.cnn.read_msgs_until_avail()
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
class CopyResponseProcesser(MsgProcesser):
    # msg_list[0] is CopyInResponse or CopyOutResponse msg
    def __init__(self, cnn, msg_list):
        super().__init__(cnn, cnn.processer)
        self.cr_msg = msg_list[0].copy()
        self.msg_list = msg_list[1:]
    def _get_msg_list(self):
        if self.msg_list:
            msg_list = self.msg_list
            self.msg_list = None
        else:
            msg_list = self.cnn.read_msgs()
        return msg_list
class CopyInResponseProcesser(CopyResponseProcesser):
    # ���CopyIn�ɹ��򷵻�True�����򷵻�False��
    # batchָ��ÿ�η��Ͷ��ٸ�CopyData��Ϣ��
    def _process(self, data_list, abort=False, batch=10):
        if abort:
            self.cnn.write_msgs((p.CopyDone(),))
            return True
        msgs = []
        for data in data_list:
            data = self.cnn.encode(data)
            m = p.CopyData(data=data)
            msgs.append(m)
            if len(msgs) < batch:
                continue
            self.cnn.write_msgs(msgs)
            msgs = []
            msg_list = self._get_msg_list()
            for m in msg_list:
                if m.msg_type in self.cnn.async_msgs:
                    self.cnn._got_async_msg(m.copy())
                else: # �쳣��Ϣ(����ErrorResponse)���˳�CopyInģʽ������Ҫ����CopyFail��
                    self.prev_processer.msgs_from_copy.append(m.copy())
            if self.prev_processer.msgs_from_copy:
                return False
        msgs.append(p.CopyDone())
        self.cnn.write_msgs(msgs)
        return True
class CopyOutResponseProcesser(CopyResponseProcesser):
    # �������˿����ڷ��ز��ֽ�����ٷ���ErrorResponse�����Ա���鿴QueryProcesser�Ľ�����Ƿ��д���
    def _process(self):
        return list(self.process_iter())
    # һ��һ�����أ����Ƿ�����������������øú������������ݺ���Ҫ�ٵ���reset_processer��
    def process_iter(self):
        self.cnn.write_msgs_until_done()
        while True:
            msg_list = self._get_msg_list()
            for idx, m in enumerate(msg_list):
                if m.msg_type == p.MsgType.MT_CopyData:
                    yield self.cnn.decode(m.data)
                elif m.msg_type == p.MsgType.MT_CopyDone:
                    self.prev_processer.msgs_from_copy.extend(msg_list[idx+1:])
                    return
                elif m.msg_type in self.cnn.async_msgs:
                    self.cnn._got_async_msg(m.copy())
                else: # �쳣��Ϣ(����ErrorResponse)���˳�CopyOutģʽ��
                    self.prev_processer.msgs_from_copy.extend(msg_list[idx:])
                    return
# main
if __name__ == '__main__':
    if len(sys.argv) > 4:
        print('usage: %s [be_addr=127.0.0.1:5432] [listen_addr=:9999] [log_msg=0]' % sys.argv[0])
        sys.exit(1)
    xargs = miscutils.parse_args(sys.argv[1:])
    be_addr = ('127.0.0.1', 5432)
    listen_addr = ('0.0.0.0', 9999)
    log_msg = 0
    if xargs['be_addr']:
        host, port = xargs['be_addr'][0].split(':')
        be_addr = (host, int(port))
    if xargs['listen_addr']:
        host, port = xargs['listen_addr'][0].split(':')
        listen_addr = (host, int(port))
    if xargs['log_msg']:
        log_msg = int(xargs['log_msg'][0])
    connbase.log_msg = bool(log_msg)
    print(be_addr, listen_addr)
        
    listen_s = netutils.listener(listen_addr)
    poll = netutils.spoller()
    while True:
        s, peer = listen_s.accept()
        print('accept connection from %s' % (peer,))
        poll.clear()
        try:
            with feconn(s) as fe_c, beconn(be_addr) as be_c:
                while True:
                    m = fe_c.read_startup_msg();
                    if not m:
                        time.sleep(0.001)
                        continue
                    if m.code == p.PG_SSLREQUEST_CODE:
                        fe_c.write_no_ssl()
                        continue
                    be_c.write_msgs_until_done((m,))
                    break
                poll.register(fe_c, poll.POLLIN)
                poll.register(be_c, poll.POLLIN)
                while True:
                    poll.poll()
                    if be_c.write_raw_msgs(fe_c.read_raw_msgs()):
                        poll.register(be_c, poll.POLLIN|poll.POLLOUT)
                    else:
                        poll.register(be_c, poll.POLLIN)
                    if fe_c.write_raw_msgs(be_c.read_raw_msgs()):
                        poll.register(fe_c, poll.POLLIN|poll.POLLOUT)
                    else:
                        poll.register(fe_c, poll.POLLIN)
        except Exception as ex:
            print('%s: %s' % (ex.__class__.__name__, ex))
            #traceback.print_tb(sys.exc_info()[2])
