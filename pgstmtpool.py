#!/bin/env python3
# -*- coding: GBK -*-
# 
# 语句级别的连接池。
# 使用有名字的Parse/Bind的时候，如果前端在发送Close之前就异常断开了，那么语句/portal不会被close。
# 
import sys, os
import collections, socket
import threading, queue
import pgnet
import pgprotocol3 as p
import pghba
import netutils
import pseudodb

class fepgfatal(Exception):
    def __init__(self, fatal_ex):
        self.fatal_ex = fatal_ex
class pgworker():
    nextid = 0
    @classmethod
    def get_nextid(cls):
        cls.nextid += 1
        return cls.nextid
    def __init__(self, be_addr, max_msg=0):
        self.be_addr = be_addr
        self.msg_queue = queue.Queue(maxsize=max_msg)
        self.id = self.get_nextid()
        self.becnn = None
        self.startup_msg = None
        self.auth_ok_msgs = []
        self.num_processed_msg = 0
    def _process_auth(self, fecnn, main_queue):
        self.startup_msg = fecnn.startup_msg
        self.becnn = pgnet.beconn(self.be_addr)
        self.becnn.write_msgs_until_done((fecnn.startup_msg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            fecnn.write_msgs_until_done(msg_list)
            self.auth_ok_msgs.extend(msg_list)
            msg = msg_list[-1]
            if msg.msg_type == p.MsgType.MT_ReadyForQuery:
                break
            elif msg.msg_type == p.MsgType.MT_ErrorResponse:
                main_queue.put(('fail', fecnn))
                return False
            elif msg.msg_type == p.MsgType.MT_Authentication:
                if msg.authtype not in (p.AuthType.AT_Ok, p.AuthType.AT_SASLFinal):
                    self.becnn.write_msgs_until_done(fecnn.read_msgs_until_avail())
        # auth ok
        for idx, msg in enumerate(self.auth_ok_msgs):
            if msg.msg_type == p.MsgType.MT_Authentication and msg.authtype == p.AuthType.AT_Ok:
                self.auth_ok_msgs = self.auth_ok_msgs[idx:]
                break
        main_queue.put(('ok', fecnn, self))
        return True
    # 当由前端负责auth的时候用该函数作为线程的target。
    def run(self, fecnn, main_queue):
        try:
            if not self._process_auth(fecnn, main_queue):
                return
        except pgnet.pgfatal as ex:
            err = '<thread %d> %s fe:%s' % (self.id, ex, fecnn.getpeername())
            if self.becnn:
                err += ' be:%s' % (self.becnn.getpeername(),)
                self.becnn.close()
            print(err)
            main_queue.put(('fail', fecnn))
            return
        
        self._process_loop(main_queue)
        main_queue.put(('exit', self))
    # 不需要前端参与auth。关键字参数指定auth参数，关键字参数不能指定host/port。
    def run2(self, main_queue, kwargs):
        kwargs['host'] = self.be_addr[0]
        kwargs['port'] = self.be_addr[1]
        try:
            self.becnn = pgnet.pgconn(**kwargs)
        except pgnet.pgfatal as ex:
            print('<thread %d> %s' % ex)
            main_queue.put(('fail', None))
            return
        self.startup_msg = self.becnn.startup_msg
        self.auth_ok_msgs = self.becnn.make_auth_ok_msgs()
        main_queue.put(('ok', None, self))
        
        self._process_loop(main_queue)
        main_queue.put(('exit', self))
    def _process_loop(self, main_queue):
        # process Query msg from queue
        while True:
            self.fe_fatal = None
            try:
                fecnn, msg = self.msg_queue.get()
                if not fecnn: # 结束线程
                    break
                self._process_one(fecnn, msg)
            except pgnet.pgfatal as ex:
                fecnn.close()
                print('<thread %d> BE%s: %s' % (self.id, self.becnn.getpeername(), ex))
                break
            else:
                main_queue.put(('done', fecnn))
    def _process_one(self, fecnn, msg):
        if msg.msg_type == p.MsgType.MT_Terminate:
            print('<trhead %d> recved Terminate from %s' % (self.id, fecnn.getpeername()))
        elif msg.msg_type == p.MsgType.MT_Query:
            self._process_query(fecnn, msg)
        elif msg.msg_type == p.MsgType.MT_Parse:
            self._process_parse(fecnn, msg)
        else:
            self._process_unsupported(fecnn,  msg)
        self.num_processed_msg += 1
    def _process_query(self, fecnn, femsg):
        self.becnn.write_msgs_until_done((femsg,))
        m = self.becnn.read_msgs_until_avail(max_msg=1)[0]
        if m.msg_type == p.MsgType.MT_CopyInResponse:
            self._process_copyin(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyOutResponse:
            self._process_copyout(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyBothResponse:
            raise pgnet.pgfatal(None, 'do not support CopyBothResponse')
        else:
            self._process_query2(fecnn, m)
    def _process_query2(self, fecnn, bemsg):
        msg_list = (bemsg,)
        while True:
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
            msg_list = self.becnn.read_msgs_until_avail()
    def _process_copyin(self, fecnn, bemsg):
        self._write_msgs_to_fe(fecnn, (bemsg,))
        try:
            self._process_both(fecnn)
        except fepgfatal as ex:
            err_msg = str(ex.fatal_ex).encode('utf8')
            self.becnn.write_msgs_until_done((p.CopyFail(err_msg=err_msg),))
            self._skip_be_msgs()
    def _process_copyout(self, fecnn, bemsg):
        self._write_msgs_to_fe(fecnn, (bemsg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
    def _process_parse(self, fecnn, femsg):
        self.becnn.write_msgs_until_done((femsg,))
        try:
            self._process_both(fecnn)
        except fepgfatal as ex:
            # 这里有个问题，如果Parse/Bind使用了有名字的语句/portal，那么它们不会被close。
            self.becnn.write_msgs_until_done((p.Sync(),))
            self._skip_be_msgs()
    # 处理前后端消息直到从后端接收到ReadyForQuery
    def _process_both(self, fecnn):
        while True:
            netutils.poll2in(fecnn, self.becnn)
            try:
                msg_list = fecnn.read_msgs()
            except pgnet.pgfatal as ex:
                raise fepgfatal(ex)
            self.becnn.write_msgs_until_done(msg_list)
            msg_list = self.becnn.read_msgs()
            self._write_msgs_to_fe(fecnn, msg_list)
            if msg_list and msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
    def _process_unsupported(self, fecnn, femsg):
        errmsg = p.ErrorResponse.make_error(b'unsupported msg type:%s' % femsg.msg_type)
        try:
            fecnn.write_msgs_until_done((errmsg, p.ReadyForQuery.Idle))
        except pgnet.pgfatal as ex:
            pass # 不需要处理，主线程在下次read的时候会报错
    def _write_msgs_to_fe(self, fecnn, msg_list):
        if self.fe_fatal:
            return False
        try:
            fecnn.write_msgs_until_done(msg_list)
        except pgnet.pgfatal as ex:
            self.fe_fatal = ex
            return False
        return True
    def _skip_be_msgs(self, msg_list=()):
        if not msg_list:
            msg_list = self.becnn.read_msgs_until_avail()
        while True:
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                return
            msg_list = self.becnn.read_msgs_until_avail()
    def put(self, fecnn, msg):
        self.msg_queue.put_nowait((fecnn, msg))
# 记录某个be_addr的所有pgworker，按startup_msg分组。
class pgworkerpool():
    def __init__(self, be_addr):
        self.be_addr = be_addr
        self.workers_map = collections.defaultdict(list) # startup_msg -> worker_list
        self.nextidx_map = collections.defaultdict(int)  # startup_msg -> nextidx for accessing worker_list
        self.id2worker_map = {}
    # 启动一个新的worker，此时该worker还没有添加到pool里面，
    # 主线程从main_queue接收到auth成功之后才会把worker加到pool。
    def new_worker(self, fecnn, main_queue):
        w = pgworker(self.be_addr)
        thr = threading.Thread(target=w.run, args=(fecnn, main_queue))
        thr.start()
    def add(self, w):
        worker_list = self.workers_map[w.startup_msg]
        worker_list.append(w)
        self.nextidx_map[w.startup_msg] = len(worker_list)-1
        self.id2worker_map[w.id] = w
    def remove(self, w):
        worker_list = self.workers_map[w.startup_msg]
        try:
            worker_list.remove(w)
            self.id2worker_map.pop(w.id)
        except ValueError:
            return None
        return w
    def remove_byid(self, wid):
        if wid not in self.id2worker_map:
            return None
        return self.remove(self.id2worker_map[wid])
    # 参数startup_msg可以是fecnn或者worker
    def get(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return self.workers_map[startup_msg]
    def count(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return len(self.workers_map[startup_msg])
    def __iter__(self):
        for msg, worker_list in self.workers_map.items():
            for w in worker_list:
                yield msg, w
    # 把来自前端cnn的消息msg分发给相应的worker
    def dispatch_fe_msg(self, poll, cnn, msg):
        worker_list = self.workers_map[cnn.startup_msg]
        nextidx = self.nextidx_map[cnn.startup_msg] % len(worker_list)
        if not worker_list: # 没有可用的worker则断开连接
            cnn.close()
        else:
            worker_list[nextidx].put(cnn, msg)
            self.nextidx_map[cnn.startup_msg] = (nextidx + 1) % len(worker_list)
    # 当worker异常退出时需要把剩下的消息分发到其他worker上。在调用之前必须先remove worker。
    def dispatch_worker_remain_msg(self, poll, w):
        while True:
            try:
                cnn, msg = w.msg_queue.get_nowait()
            except queue.Empty:
                break
            self.dispatch_fe_msg(poll, cnn, msg)
# 记录所有auth成功的fe连接，按startup_msg分组。
# 有2种auth成功的情况: new_worker成功的时候和pgauth成功的时候。
class feconnpool():
    def __init__(self):
        self.fecnns_map = collections.defaultdict(set)
    def add(self, fecnn):
        self.fecnns_map[fecnn.startup_msg].add(fecnn)
    def remove(self, fecnn):
        x = self.fecnns_map[fecnn.startup_msg]
        if fecnn in x:
            x.remove(fecnn)
    # 返回有多少个和startup msg对应的fecnn。参数startup_msg可以是fecnn。
    def count(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return len(self.fecnns_map[startup_msg])
    def __contains__(self, fecnn):
        return fecnn in self.fecnns_map[fecnn.startup_msg]
    def __iter__(self):
        for msg, fecnns in self.fecnns_map.items():
            for cnn in fecnns:
                yield msg, cnn
# pseudo db
class pooldb(pseudodb.pseudodb):
    def __init__(self, cnn, wpool, fepool, main_queue):
        super().__init__(cnn)
        self.wpool = wpool
        self.fepool = fepool
        self.main_queue = main_queue
    def process_query(self, query):
        query = query.strip().strip(';')
        cmd, *args = query.split(maxsplit=1)
        if cmd not in self.cmd_map:
            return self._write_error('unknown command:%s' % cmd)
        f, sub_cmd_map = self.cmd_map[cmd]
        return f(self, args, sub_cmd_map)
    # 各种命令实现。args参数是list，为空或者只有一个元素。
    cmd_map = {}
    def _process_cmd(self, args, sub_cmd_map, default_sub_cmd='list'):
        if not args:
            args.append(default_sub_cmd)
        sub_cmd, *sub_cmd_args = args[0].split(maxsplit=1)
        if sub_cmd not in sub_cmd_map:
            return self._write_error('unknown sub cmd(%s) in be' % sub_cmd)
        return sub_cmd_map[sub_cmd](self, sub_cmd_args)
    # fe [list] ...
    def _process_fe_list(self, args):
        rows = []
        for m, fecnn in self.fepool:
            host, port = fecnn.getpeername()
            startup_msg = self._make_startup_msg(m)
            rows.append((host, port, m['database'], m['user'], startup_msg))
        return self._write_result(['host', 'port', 'database', 'user', 'startup_msg'], rows)
    cmd_map['fe'] = (_process_cmd, {})
    cmd_map['fe'][1]['list'] = _process_fe_list
    del _process_fe_list
    # be [list|remove|new] ...
    def _process_be_list(self, args):
        rows = []
        for m, w in self.wpool:
            host, port = w.becnn.getpeername()
            startup_msg = self._make_startup_msg(m)
            rows.append((w.id, host, port, m['database'], m['user'], startup_msg, w.num_processed_msg))
        return self._write_result(['id', 'host', 'port', 'database', 'user', 'startup_msg', 'processed'], rows)
    def _process_be_remove(self, args):
        if not args:
            return self._write_error("'be remove' should provide worker id")
        try:
            wid = int(args[0])
        except ValueError as ex:
            return self._write_error('%s' % ex)
        w = self.wpool.remove_byid(wid)
        if not w:
            return self._write_error('there is no worker with id(%s)' % wid)
        w.put(None, None)
        return self._write_result(['id'], [[wid]])
    # args[0]指定startup msg的内容，另外还可以包含password，不需要包含host/port
    # args[0]的格式为: key=value,key=value...
    def _process_be_new(self, args):
        if not args:
            args.append('')
        try:
            kvs = (kv.split('=', maxsplit=1) for kv in args[0].split(',') if kv)
            kwargs = {k : v for k, v in kvs}
            w = pgworker(self.wpool.be_addr)
            thr = threading.Thread(target=w.run2, args=(self.main_queue, kwargs))
            thr.start()
        except Exception as ex:
            return self._write_error('exception:%s' % ex)
        return self._write_result(['id'], [[w.id]])
    # 
    cmd_map['be'] = (_process_cmd, {})
    cmd_map['be'][1]['list'] = _process_be_list
    cmd_map['be'][1]['remove'] = _process_be_remove
    cmd_map['be'][1]['new'] = _process_be_new
    del _process_be_list, _process_be_remove, _process_be_new
    del _process_cmd # 最后删除
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
    def _make_startup_msg(self, m):
        params = ((k, v) for k, v in m.get_params().items() if k not in ('database', 'user'))
        res = b'{'
        for k, v in params:
            res += b'%s:%s ' % (k.encode('utf8'), v)
        if len(res) > 1:
            res = res[:-1]
        res += b'}'
        return res
# main
def need_new_worker(startup_msg):
    wcnt = wpool.count(startup_msg)
    if wcnt == 0:
        return True
    fecnt = fepool.count(startup_msg)
    return fecnt/wcnt >= 10
if __name__ == '__main__':
    be_addr = ('127.0.0.1', 5432)
    if len(sys.argv) >= 2:
        host, port = sys.argv[1].split(':')
        be_addr = (host, int(port))
    
    auth_cnn = pgnet.pgconn(host=be_addr[0], port=be_addr[1])
    hba = pghba.pghba.from_database(auth_cnn)
    shadows = pghba.pgshadow.from_database(auth_cnn)
    auth_cnn.close()
    
    wpool = pgworkerpool(be_addr)
    fepool = feconnpool()
    main_queue = queue.Queue()
    
    listen = netutils.listener(('', 7777), async=True)
    poll = netutils.spoller()
    poll.register(listen, poll.POLLIN)
    while True:
        x = poll.poll(0.001)
        for fobj, event in x:
            try:
                if fobj is listen:
                    cs, addr = fobj.accept()
                    print('accept connection from %s' % (addr,))
                    poll.register(pgnet.feconn4startup(pgnet.feconn(cs)), poll.POLLIN)
                elif type(fobj) is pgnet.feconn4startup:
                    m = fobj.read_startup_msg()
                    if not m:
                        continue
                    poll.unregister(fobj)
                    is_pseudo = (m['database'] == b'pseudo')
                    if not is_pseudo and need_new_worker(m):
                        wpool.new_worker(fobj.cnn, main_queue)
                        continue
                    
                    auth_ok_msgs = pooldb.auth_ok_msgs if is_pseudo else wpool.get(m)[0].auth_ok_msgs
                    cnn = pooldb(fobj.cnn, wpool, fepool, main_queue) if is_pseudo else fobj.cnn
                    auth = pghba.get_auth(hba, shadows, cnn, m, auth_ok_msgs)
                    if auth.handle_event(poll, event):
                        if not isinstance(auth.cnn, pseudodb.pseudodb):
                            fepool.add(auth.cnn)
                elif isinstance(fobj, pghba.pgauth):
                    poll.unregister(fobj)
                    if fobj.handle_event(poll, event):
                        if not isinstance(auth.cnn, pseudodb.pseudodb):
                            fepool.add(fobj.cnn)
                elif type(fobj) is pgnet.feconn:
                    if event & poll.POLLOUT:
                        if not fobj.write_msgs():
                            poll.register(fobj, poll.POLLIN)
                        continue
                    m = fobj.read_msgs(max_msg=1)
                    if not m:
                        continue
                    poll.unregister(fobj) # 主线程停止检测，把控制权交给worker
                    wpool.dispatch_fe_msg(poll, fobj, m[0])
                elif isinstance(fobj, pseudodb.pseudodb):
                    fobj.handle_event(poll, event)
            except pgnet.pgfatal as ex:
                print('%s: %s' % (ex.__class__.__name__, ex))
                poll.clear((fobj,))
                if type(fobj) is pgnet.feconn:
                    fepool.remove(fobj)
        # process main_queue
        while True:
            try:
                x = main_queue.get_nowait()
            except queue.Empty:
                break
            print(x)
            if x[0] == 'ok': # ('ok', fecnn, worker)
                if x[1]:
                    poll.register(x[1], poll.POLLIN)
                    fepool.add(x[1])
                wpool.add(x[2])
            elif x[0] == 'fail': # ('fail', fecnn)
                if x[1]:
                    x[1].close()
            elif x[0] == 'exit': # ('exit', worker)
                wpool.remove(x[1])
                wpool.dispatch_worker_remain_msg(poll, x[1])
            elif x[0] == 'done': # ('done', fecnn)
                poll.register(x[1], poll.POLLIN)
            else:
                raise RuntimeError('unknow x from main_queue:%s' % (x,))
