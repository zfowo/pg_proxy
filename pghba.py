#!/bin/env python3
# -*- coding: GBK -*-
# 
# 处理pg_hba.conf。当前不支持database/user用引号括起来，也就是不能有特殊字符，比如空格。
# 不支持samerole，以及+user。
# 
import sys, os, io
import ipaddress
import struct, random
import pgprotocol3 as p
import scram
from base64 import b64encode, b64decode

# 保存的数据以及check_xxx的参数都是str不是bytes。
class pghba:
    def __init__(self, f):
        self.host_items = []
        self.local_items = []
        self._parse_hba(f)
    def _parse_hba(self, f):
        for L in f:
            L = L.strip()
            if not L or L[0] == '#': 
                continue
            x = L.split(maxsplit=1)
            t = x[0]
            if t == 'host':
                self.host_items.append(hba_host_item(x[1]))
            elif t == 'local':
                self.local_items.append(hba_local_item(x[1]))
            else:
                print('skip unsupported line:%s' % L)
    def check_host(self, d, u, a):
        for item in self.host_items:
            if item.check(d, u, a):
                return item.method, item.options
        return 'deny', ''
    def check_local(self, d, u):
        for item in self.local_items:
            if item.check(d, u):
                return item.method, item.options
        return 'deny', ''
    @classmethod
    def from_database(cls, cnn):
        res = cnn.query("select pg_read_file('pg_hba.conf')")
        f = io.StringIO(res[0][0], newline=None)
        return cls(f)
    @classmethod
    def from_file(cls, fn):
        with open(fn, 'rt') as f:
            return cls(f)

class hba_item():
    def __init__(self, database, user, method, options):
        self.database = self._parse_database(database)
        self.user = self._parse_user(user)
        self.method = method
        self.options = options
    def _parse_database(self, d):
        return set(d.split(','))
    def _parse_user(self, u):
        return set(u.split(','))
    def _check_database(self, d, u):
        return any(('all' in self.database , 
                    'sameuser' in self.database and d == u, 
                    d in self.database, 
                  ))
    def _check_user(self, u):
        return any(('all' in self.user, u in self.user))
class hba_host_item(hba_item):
    def __init__(self, s):
        x = s.split(maxsplit=4)
        x.append('')
        if len(x) != 5 and len(x) != 6:
            raise RuntimeError('wrong line for host type:%s' % s)
        super().__init__(x[0], x[1], x[3], x[4])
        self.address = ipaddress.ip_network(x[2])
    def check(self, d, u, a):
        return all((self._check_database(d, u), self._check_user(u), self._check_addr(a)))
    def _check_addr(self, a):
        return ipaddress.ip_address(a) in self.address
class hba_local_item(hba_item):
    def __init__(self, s):
        x = s.split(maxsplit=3)
        x.append('')
        if len(x) != 4 and len(x) != 5:
            raise RuntimeError('wrong line for local type:%s' % s)
        super().__init__(*x[:4])
    def check(self, d, u):
        return all((self._check_database(d, u), self._check_user(u)))
# 保存用户名和密码的加密形式。返回值中的数据都是bytes
MD5_PREFIX = b'md5'
SCRAM_PREFIX = b'SCRAM-SHA-256'
class pgshadow():
    def __init__(self, f):
        self.shadow = {}
        self._parse_shadow(f)
    def _parse_shadow(self, f):
        for L in f:
            L = L.strip()
            if not L or L[0] == '#':
                continue
            u, pwd = L.split(':', maxsplit=1)
            self.shadow[u.encode('ascii')] = pwd.encode('ascii')
    # 如果username不存在则返回None，如果用户没有设置密码则返回空bytes，否则返回(...)
    def get_shadow(self, username):
        username = username.encode('ascii') if type(username) is str else username
        pwd = self.shadow.get(username, None)
        if not pwd:
            return pwd
        if pwd.startswith(MD5_PREFIX):
            return (MD5_PREFIX, pwd[len(MD5_PREFIX):])
        elif pwd.startswith(SCRAM_PREFIX):
            pwd = pwd[len(SCRAM_PREFIX)+1:]
            x1, x2 = pwd.split(b'$', maxsplit=1)
            cnt, salt = x1.split(b':', maxsplit=1)
            storedkey, serverkey = x2.split(b':', maxsplit=1)
            return (SCRAM_PREFIX, cnt, salt, storedkey, serverkey)
        else:
            print('unknown shadow:%s' % pwd)
    @classmethod
    def from_database(cls, cnn):
        res = cnn.query(r"select string_agg(usename||':'||coalesce(passwd, ''), E'\n') from pg_shadow")
        f = io.StringIO(res[0][0])
        return cls(f)
    @classmethod
    def from_file(cls, fn):
        with open(fn, 'rt') as f:
            return cls(f)
# auth process
# 如果shadow是md5，那么authtype不支持scram；
# 如果shadow是scram，而authtype是md5，那么authtype会改为scram。
# shadow是pgshadow.get_shadow返回的元组
AUTH_OK = 'ok'
AUTH_FAIL = 'fail'
class pgauth():
    def __init__(self, cnn, user, shadow):
        self.cnn = cnn
        self.user = user.encode('utf8') if type(user) is str else user
        self.shadow = shadow
        self.status = 0
    # 读取下一个消息，如果还有之前的消息没有发送完则返回'pollout'，如果还没有消息则返回'pollin'
    def _read_next_msg(self):
        if self.cnn.write_msgs():
            return 'pollout'
        m = self.cnn.read_msgs(max_msg=1)
        if not m:
            return 'pollin'
        return m[0]
    def fileno(self):
        return self.cnn.fileno()
    # 在调用之前需要poll.unregister本auth。返回True表示auth成功。
    def handle_event(self, poll):
        ret = self.go()
        if ret == AUTH_OK:
            if self.cnn.write_msgs(self.auth_ok_msgs):
                poll.register(self.cnn, poll.POLLOUT)
            else:
                poll.register(self.cnn, poll.POLLIN)
            return True
        elif ret == AUTH_FAIL:
            self.cnn.write_msgs(self.auth_fail_msgs)
            self.cnn.close()
        elif ret == 'pollin':
            poll.register(self, poll.POLLIN)
        elif ret == 'pollout':
            poll.register(self, poll.POLLOUT)
        else:
            raise RuntimeError('unknown return value(%s) from auth.go' % ret)
class pgdenyauth(pgauth):
    def go(self):
        return AUTH_FAIL
class pgtrustauth(pgauth):
    def go(self):
        return AUTH_OK
# AT_CleartextPassword，shadow可以是md5/scram
class pgpwdauth(pgauth):
    def go(self):
        if self.status == 0:
            self.status = 1
            m = p.Authentication(authtype=p.AuthType.AT_CleartextPassword, data=b'')
            self.cnn.write_msgs((m,))
            return self.go()
        if self.status == 1:
            m = self._read_next_msg()
            if type(m) is str: 
                return m
            self.status = 2
            m = p.PasswordMessage(m.data)
            self.result = AUTH_OK if self._check(bytes(m.password)) else AUTH_FAIL
            return self.result
        return self.result
    def _check(self, pwd):
        if self.shadow[0] == MD5_PREFIX:
            return p.md5(pwd + self.user) == self.shadow[1]
        elif self.shadow[0] == SCRAM_PREFIX:
            iter_num = int(self.shadow[1])
            salt = b64decode(self.shadow[2])
            storedkey = b64decode(self.shadow[3])
            salted_pwd = scram.scram_salted_password(pwd, salt, iter_num)
            storedkey2 = scram.sha256(scram.scram_clientkey(salted_pwd))
            return storedkey == storedkey2
        else:
            raise RuntimeError('unknow shadow:%s' % self.shadow)
# AT_MD5Password，shadow必须md5。
class pgmd5auth(pgauth):
    def __init__(self, cnn, user, shadow):
        super().__init__(cnn, user, shadow)
        self.salt = struct.pack('>I', random.randint(1, 0xFFFFFFFF))
    def go(self):
        if self.status == 0:
            self.status = 1
            m = p.Authentication(authtype=p.AuthType.AT_MD5Password, data=self.salt)
            self.cnn.write_msgs((m,))
            return self.go()
        if self.status == 1:
            m = self._read_next_msg()
            if type(m) is str:
                return m
            self.status = 2
            m = p.PasswordMessage(m.data)
            self.result = AUTH_OK if bytes(m.password) == b'md5' + p.md5(self.shadow[1] + self.salt) else AUTH_FAIL
            return self.result
        return self.result
# AT_SASL，shadow必须是scram。
class pgscramauth(pgauth):
    def go(self):
        if self.status == 0:
            self.status = 1
            sasl = p.SASL.make('SCRAM-SHA-256')
            m = p.Authentication(authtype=p.AuthType.AT_SASL, data=bytes(sasl))
            self.cnn.write_msgs((m,))
            return self.go()
        if self.status == 1:
            m = self._read_next_msg()
            if type(m) is str:
                return m
            # m is AuthResponse(SASLInitialResponse)
            self.status = 2
            self.sasl_init_resp_msg = p.SASLInitialResponse(m.data)
            if bytes(self.sasl_init_resp_msg.name) != b'SCRAM-SHA-256':
                self.status = 100
                self.result = AUTH_FAIL
                return self.result
            scram.parse_SASLInitialResponse(self.sasl_init_resp_msg)
            # send SASLContinue to client
            self.sasl_continue_msg = scram.make_SASLContinue(self.sasl_init_resp_msg.client_nonce, self.shadow[2], self.shadow[1])
            self.cnn.write_msgs((self.sasl_continue_msg,))
            return self.go()
        if self.status == 2:
            m = self._read_next_msg()
            if type(m) is str:
                return m
            # m is AuthResponse(SASLReponse)
            self.status = 3
            self.sasl_resp_msg = p.SASLResponse(m.data)
            scram.parse_SASLResponse(self.sasl_resp_msg)
            if self.sasl_resp_msg.nonce != self.sasl_init_resp_msg.client_nonce + self.sasl_continue_msg.server_nonce:
                self.status = 100
                self.result = AUTH_FAIL
                return self.result
            storedkey = b64decode(self.shadow[3])
            if not scram.verify_SASLResponse(storedkey, self.sasl_init_resp_msg, self.sasl_continue_msg, self.sasl_resp_msg):
                self.status = 100
                self.result = AUTH_FAIL
                return self.result
            # send SASLFinal to client
            serverkey = b64decode(self.shadow[4])
            self.sasl_final_msg = scram.make_SASLFinal(serverkey, self.sasl_init_resp_msg, self.sasl_continue_msg, self.sasl_resp_msg)
            self.cnn.write_msgs((self.sasl_final_msg,))
            return self.go()
        if self.status == 3:
            if self.cnn.write_msgs():
                return 'pollout'
            self.status = 4
            self.result = AUTH_OK
            return self.result
        return self.result
# 
default_auth_fail_msgs = [p.ErrorResponse.make((b'S', b'FATAL'), (b'V', b'FATAL'), (b'M', b'authentication fail')), ]
def get_auth(hba, shadows, cnn, startup_msg, auth_ok_msgs, auth_fail_msgs=None):
    if not auth_fail_msgs:
        auth_fail_msgs = default_auth_fail_msgs
    auth = _get_auth(hba, shadows, cnn, startup_msg)
    auth.startup_msg = startup_msg
    auth.auth_ok_msgs = auth_ok_msgs
    auth.auth_fail_msgs = auth_fail_msgs
    return auth
def _get_auth(hba, shadows, cnn, startup_msg):
    database = startup_msg['database'].decode('ascii')
    user = startup_msg['user'].decode('ascii')
    addr = cnn.getpeername()
    if type(addr) is tuple:
        hba_res = hba.check_host(database, user, addr[0])
    else:
        hba_res = hba.check_local(database, user)
    shadow = shadows.get_shadow(user)
    authtype = hba_res[0]
    if authtype == 'deny' or shadow is None: # 拒绝或者用户不存在
        return pgdenyauth(cnn, user,shadow)
    if authtype == 'trust':
        return pgtrustauth(cnn, user, shadow)
    if not shadow: #空密码
        return pgdenyauth(cnn, user, shadow)
    if authtype == 'password':
        return pgpwdauth(cnn, user, shadow)
    elif authtype == 'md5':
        if shadow[0] == MD5_PREFIX:
            return pgmd5auth(cnn, user, shadow)
        elif shadow[0] == SCRAM_PREFIX:
            return pgscramauth(cnn, user, shadow)
        else:
            raise RuntimeError('unknown shadow:%s' % shadow)
    elif authtype == 'scram-sha-256':
        if shadow[0] == MD5_PREFIX:
            return pgdenyauth(cnn, user,shadow)
        elif shadow[0] == SCRAM_PREFIX:
            return pgscramauth(cnn, user, shadow)
        else:
            raise RuntimeError('unknown shadow:%s' % shadow)
    else:
        raise RuntimeError('unknown authtype in hba:%s' % hba_res)
# main
auth_fail_msgs = [p.ErrorResponse.make((b'S', b'FATAL'), (b'V', b'FATAL'), (b'M', b'authentication fail')), ]
auth_ok_msgs = [
    p.Authentication(authtype=p.AuthType.AT_Ok, data=b''), 
    p.ParameterStatus(name=b'application_name', val=b'pghba'), 
    p.ParameterStatus(name=b'client_encoding', val=b'UTF8'), 
    p.ParameterStatus(name=b'DateStyle', val=b'ISO, MDY'), 
    p.ParameterStatus(name=b'integer_datetimes', val=b'on'), 
    p.ParameterStatus(name=b'IntervalStyle', val=b'postgres'), 
    p.ParameterStatus(name=b'is_superuser', val=b'on'), 
    p.ParameterStatus(name=b'server_encoding', val=b'UTF8'), 
    p.ParameterStatus(name=b'server_version', val=b'11devel'), 
    p.ParameterStatus(name=b'session_authorization', val=b'zhb'), 
    p.ParameterStatus(name=b'standard_conforming_strings', val=b'on'), 
    p.ParameterStatus(name=b'TimeZone', val=b'Asia/Hong_Kong'), 
    p.BackendKeyData(pid=1234, skey=1234), 
    p.ReadyForQuery(trans_status=b'I'), 
]
if __name__ == '__main__':
    import pgnet, socket
    cnn = pgnet.pgconn()
    hba = pghba.from_database(cnn)
    shadows = pgshadow.from_database(cnn)
    
    listen_s = socket.socket()
    listen_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_s.bind(('', 9898))
    listen_s.listen()
    while True:
        s, peer = listen_s.accept()
        print('accept connection from %s' % (peer,))
        try:
            with pgnet.feconn(s) as fe:
                m = fe.read_startup_msg()
                while not m:
                    m = fe.read_startup_msg()
                auth = get_auth(hba, shadows, fe, m, auth_ok_msgs, auth_fail_msgs)
                while auth.go() not in (AUTH_OK, AUTH_FAIL):
                    pass
                if auth.go() == AUTH_FAIL:
                    ret = fe.write_msgs(auth_fail_msgs)
                else:
                    ret = fe.write_msgs(auth_ok_msgs)
                print('write_msgs return %s' % ret)
                fe.pollin()
                for m in fe.read_msgs(): 
                    print(m)
        except (RuntimeError, pgnet.pgexception) as ex:
            print('%s: %s' % (ex.__class__.__name__, ex))
