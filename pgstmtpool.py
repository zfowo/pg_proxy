#!/bin/env python3
# -*- coding: GBK -*-
# 
# 语句级别的连接池。
# 使用有名字的Parse/Bind的时候，如果前端在发送Close之前就异常断开了，那么语句/portal不会被close。
# 
import sys, os, time
import collections, socket, copy
import threading, queue
import pgnet
import pgprotocol3 as p
import pghba
import netutils
import pseudodb
import mputils
import miscutils

class fepgfatal(Exception):
    def __init__(self, fatal_ex, last_fe_msg=None):
        self.fatal_ex = fatal_ex
        self.last_fe_msg = None
@mputils.generateid
class pgworker():
    def __init__(self, pool_id, be_addr, max_msg=0):
        self.pool_id = pool_id
        self.be_addr = be_addr
        self.msg_queue = queue.Queue(maxsize=max_msg)
        self.becnn = None
        self.startup_msg = None
        self.auth_ok_msgs = []
        self.num_processed_msg = 0
    def __repr__(self):
        return '<pgworker pool_id=%s id=%s be_addr=%s>' % (self.pool_id, self.id, self.be_addr)
    def put(self, fecnn, msg):
        self.msg_queue.put_nowait((fecnn, msg))
    def _process_auth(self, fecnn, main_queue):
        self.startup_msg = fecnn.startup_msg
        try:
            self.becnn = pgnet.beconn(self.be_addr)
        except pgnet.pgfatal as ex:
            print('<thread %d> %s' % (self.id, ex))
            main_queue.put(('fail', fecnn, self, True))
            return False
        self.becnn.startup_msg = self.startup_msg
        self.becnn.write_msgs_until_done((fecnn.startup_msg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            fecnn.write_msgs_until_done(msg_list)
            self.auth_ok_msgs.extend(msg_list)
            msg = msg_list[-1]
            if msg.msg_type == p.MsgType.MT_ReadyForQuery:
                break
            elif msg.msg_type == p.MsgType.MT_ErrorResponse:
                main_queue.put(('fail', fecnn, self, False))
                return False
            elif msg.msg_type == p.MsgType.MT_Authentication:
                if msg.authtype not in (p.AuthType.AT_Ok, p.AuthType.AT_SASLFinal):
                    self.becnn.write_msgs_until_done(fecnn.read_msgs_until_avail())
        # auth ok
        for idx, msg in enumerate(self.auth_ok_msgs):
            if msg.msg_type == p.MsgType.MT_Authentication and msg.authtype == p.AuthType.AT_Ok:
                self.auth_ok_msgs = self.auth_ok_msgs[idx:]
                break
        self.becnn.params, self.becnn.be_keydata = p.parse_auth_ok_msgs(self.auth_ok_msgs)
        main_queue.put(('ok', fecnn, self))
        return True
    # 当由前端负责auth的时候用该函数作为线程的target。
    def run(self, fecnn, main_queue):
        try:
            if not self._process_auth(fecnn, main_queue):
                return
        except pgnet.pgfatal as ex:
            err = '<thread %d> %s fe:%s be:%s' % (self.id, ex, fecnn.getpeername(), self.becnn.be_addr)
            print(err)
            if self.becnn and ex.cnn is self.becnn:
                main_queue.put(('fail', fecnn, self, True))
            else:
                main_queue.put(('fail', fecnn, self, False))
            self.becnn.close()
            return
        
        normal_exit = self._process_loop(main_queue)
        main_queue.put(('exit', None if normal_exit else self))
    # 不需要前端参与auth。关键字参数指定auth参数，关键字参数不能指定host/port。
    def run2(self, kwargs, main_queue):
        kwargs['host'] = self.be_addr[0]
        kwargs['port'] = self.be_addr[1]
        try:
            self.becnn = pgnet.pgconn(**kwargs)
        except pgnet.pgfatal as ex:
            print('<thread %d> %s' % ex)
            main_queue.put(('fail', None, self, True if ex.cnn else False))
            return
        self.startup_msg = self.becnn.startup_msg
        self.auth_ok_msgs = self.becnn.make_auth_ok_msgs()
        main_queue.put(('ok', None, self))
        
        normal_exit = self._process_loop(main_queue)
        main_queue.put(('exit', None if normal_exit else self))
    def _process_loop(self, main_queue):
        # process Query msg from queue
        while True:
            self.fe_fatal = None
            try:
                # fecnn可以是前端连接对象，None，或者字符串
                fecnn, msg = self.msg_queue.get()
                if fecnn is None: # 结束线程
                    return True
                elif type(fecnn) is str:
                    self._process_cmd(fecnn, msg)
                else:
                    self._process_msg(fecnn, msg)
            except pgnet.pgfatal as ex:
                fecnn.close()
                print('<thread %d> BE%s: %s' % (self.id, self.becnn.getpeername(), ex))
                return False
            else:
                main_queue.put(('done', fecnn))
    def _process_cmd(self, cmd, args):
        pass
    def _process_msg(self, fecnn, msg):
        if msg.msg_type == p.MsgType.MT_Terminate:
            print('<trhead %d> recved Terminate from %s' % (self.id, fecnn.getpeername()))
            self.num_processed_msg -= 1
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
        msg_list = [bemsg] + self.becnn.read_msgs()
        while True:
            if self._write_msgs_to_fe(fecnn, msg_list)[1]:
                break
            msg_list = self.becnn.read_msgs_until_avail()
    def _process_copyout(self, fecnn, bemsg):
        msg_list = [bemsg] + self.becnn.read_msgs()
        while True:
            if self._write_msgs_to_fe(fecnn, msg_list)[1]:
                break
            msg_list = self.becnn.read_msgs_until_avail()
    def _process_copyin(self, fecnn, bemsg):
        self._write_msgs_to_fe(fecnn, (bemsg,))
        try:
            self._process_both(fecnn)
        except fepgfatal as ex:
            if ex.last_fe_msg and ex.last_fe_msg.msg_type not in (p.MsgType.MT_CopyDone, p.MsgType.MT_CopyFail):
                err_msg = str(ex.fatal_ex).encode('utf8')
                self.becnn.write_msgs_until_done((p.CopyFail(err_msg=err_msg),))
            self._skip_be_msgs()
    def _process_parse(self, fecnn, femsg):
        self.becnn.write_msgs_until_done((femsg,))
        try:
            self._process_both(fecnn)
        except fepgfatal as ex:
            # 这里有个问题，如果Parse/Bind使用了有名字的语句/portal，那么它们不会被close。
            if ex.last_fe_msg and ex.last_fe_msg.msg_type != p.MsgType.MT_Sync:
                self.becnn.write_msgs_until_done((p.Sync(),))
            self._skip_be_msgs()
    # 处理前后端消息直到从后端接收到ReadyForQuery
    def _process_both(self, fecnn):
        last_fe_msg = None
        while True:
            netutils.poll2in(fecnn, self.becnn)
            try:
                msg_list = fecnn.read_msgs()
                if msg_list:
                    last_fe_msg = msg_list[-1]
            except pgnet.pgfatal as ex:
                raise fepgfatal(ex, last_fe_msg_type)
            self.becnn.write_msgs_until_done(msg_list)
            msg_list = self.becnn.read_msgs()
            if self._write_msgs_to_fe(fecnn, msg_list)[1]:
                break
    def _process_unsupported(self, fecnn, femsg):
        errmsg = p.ErrorResponse.make_error(b'unsupported msg type:%s' % femsg.msg_type)
        try:
            fecnn.write_msgs_until_done((errmsg, p.ReadyForQuery.Idle))
        except pgnet.pgfatal as ex:
            pass # 不需要处理，主线程在下次read的时候会报错
    # 返回(是否写成功, 是否有ReadyForQuery消息)
    def _write_msgs_to_fe(self, fecnn, msg_list):
        got_ready = False
        if  msg_list and msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
            got_ready = True
            if msg_list[-1].trans_status != p.TransStatus.TS_Idle:
                self.becnn.write_msgs_until_done((p.Query(query=b'abort'),))
                self._skip_be_msgs()
                self._change_msgs_to_idle(msg_list)
        if self.fe_fatal:
            return False, got_ready
        try:
            fecnn.write_msgs_until_done(msg_list)
        except pgnet.pgfatal as ex:
            self.fe_fatal = ex
            return False, got_ready
        return True, got_ready
    def _skip_be_msgs(self, msg_list=()):
        if not msg_list:
            msg_list = self.becnn.read_msgs_until_avail()
        while True:
            if msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                return
            msg_list = self.becnn.read_msgs_until_avail()
    def _change_msgs_to_idle(self, msg_list):
        m = msg_list[-1]
        msg_list[-1] = p.ReadyForQuery.Idle
        if m.trans_status == p.TransStatus.TS_InBlock:
            msg_list.insert(-1, p.ErrorResponse.make_error(b'do not supoort transaction statement. abort it'))
            return
        # TS_Fail
        for i in range(len(msg_list)-1, -1, -1):
            if msg_list[i].msg_type == p.MsgType.MT_ErrorResponse:
                msg_list[i] = p.ErrorResponse.make_error(b'do not supoort transaction statement. abort it')
                return
# 记录某个be_addr的所有pgworker，按startup_msg分组。
# pgworker中记录所属的pool的id。
@mputils.generateid
class pgworkerpool():
    def __init__(self, be_addr):
        self.be_addr = be_addr
        self.workers_map = collections.defaultdict(list) # startup_msg -> worker_list
        self.nextidx_map = collections.defaultdict(int)  # startup_msg -> nextidx for accessing worker_list
        self.id2worker_map = {}
        self.admin_cnn = None # 用于管理目的的连接，一般是超级用户
    def get_admin_cnn(self, cnn_params):
        if self.admin_cnn:
            return self.admin_cnn
        cnn_params = copy.copy(cnn_params)
        cnn_params['host'] = self.be_addr[0]
        cnn_params['port'] = self.be_addr[1]
        self.admin_cnn = pgnet.pgconn(**cnn_params)
        return self.admin_cnn
    def close_admin_cnn(self):
        if self.admin_cnn:
            self.admin_cnn.close()
            self.admin_cnn = None
    # 启动一个新的worker，此时该worker还没有添加到pool里面，
    # 主线程从main_queue接收到auth成功之后才会把worker加到pool。
    def new_worker(self, fecnn, main_queue):
        w = pgworker(self.id, self.be_addr)
        thr = threading.Thread(target=w.run, args=(fecnn, main_queue))
        thr.start()
        return w
    def new_worker2(self, kwargs, main_queue):
        w = pgworker(self.id, self.be_addr)
        thr = threading.Thread(target=w.run2, args=(kwargs, main_queue))
        thr.start()
        return w
    def add(self, w):
        worker_list = self.workers_map[w.startup_msg]
        worker_list.append(w)
        self.nextidx_map[w.startup_msg] = len(worker_list)-1
        self.id2worker_map[w.id] = w
    def remove(self, w):
        worker_list = self.workers_map[w.startup_msg]
        try:
            worker_list.remove(w)
            w.put(None, None)
            self.id2worker_map.pop(w.id)
        except ValueError:
            return None
        return w
    def remove_byid(self, wid):
        if wid not in self.id2worker_map:
            return None
        return self.remove(self.id2worker_map[wid])
    def clear(self):
        for msg, w in self:
            w.put(None, None)
        self.workers_map.clear()
        self.nextidx_map.clear()
        self.id2worker_map.clear()
    def get_byid(self, wid):
        return self.id2worker_map.get(wid)
    # 参数startup_msg可以是fecnn或者worker
    def get(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return self.workers_map[startup_msg]
    def count(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return len(self.workers_map[startup_msg])
    def has_worker(self, startup_msg):
        return bool(self.get(startup_msg))
    def __iter__(self):
        for msg, worker_list in self.workers_map.items():
            for w in worker_list:
                yield msg, w
    def __len__(self):
        return len(self.id2worker_map)
    def __bool__(self):
        return True
    # 把来自前端cnn的消息msg分发给相应的worker
    def dispatch_fe_msg(self, poll, cnn, msg):
        if not cnn:
            return
        worker_list = self.workers_map[cnn.startup_msg]
        if not worker_list: # 没有可用的worker则断开连接
            cnn.close()
        else:
            nextidx = self.nextidx_map[cnn.startup_msg] % len(worker_list)
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
# 管理一组pool组成的列表
class pgworkerpools():
    def __init__(self, *be_addr_list):
        self.pools = []
        for be_addr in be_addr_list:
            self.pools.append(pgworkerpool(be_addr))
        self.pools_map = collections.defaultdict(list) # startup_msg -> pool_list
        self.nextidx_map = collections.defaultdict(int) # startup_msg -> nextidx for pool_list
    def close_admin_cnn(self):
        for pool in self:
            pool.close_admin_cnn()
    def has_worker(self, startup_msg):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        return bool(self.pools_map[startup_msg])
    def __getitem__(self, idx):
        return self.pools[idx]
    def __len__(self):
        return len(self.pools)
    def __iter__(self):
        yield from self.pools
    def add(self, be_addr):
        pool = pgworkerpool(be_addr)
        self.pools.append(pool)
        return pool
    # id参数可以是整数也可以是pool对象
    # clear表示停止pool中的workers
    def remove(self, id, clear=True):
        pool = self.get(id) if type(id) is int else id
        if not pool:
            return None
        self.pools.remove(pool)
        msg_list = []
        for msg, pool_list in self.pools_map.items():
            try:
                pool_list.remove(pool)
                if not pool_list:
                    msg_list.append(msg)
            except ValueError:
                pass
        for msg in msg_list:
            self.pools_map.pop(msg)
        if clear:
            pool.clear()
        return pool
    def get(self, id):
        for pool in self.pools:
            if pool.id == id:
                return pool
        return None
    def get_some(self, id_list):
        res = []
        for pool in self:
            if pool.id in id_list:
                res.append(pool)
            else:
                res.append(None)
        return res
    def get_byaddr(self, addr):
        ret = []
        for pool in self.pools:
            if pool.be_addr == addr:
                ret.append(pool)
        return ret
    def new_worker(self, id, fecnn, main_queue):
        pool = self.get(id) if type(id) is int else id
        if not pool:
            return None
        return pool.new_worker(fecnn, main_queue)
    # 在指定的pool中启动cnt个worker
    def new_worker2(self, id, cnt, kwargs, main_queue):
        pool = self.get(id) if type(id) is int else id
        if not pool:
            return None
        worker_list = []
        for i in range(cnt):
            worker_list.append(pool.new_worker2(kwargs, main_queue))
        return worker_list
    # 每个pool都启动cnt个worker
    def new_some_workers(self, cnt, kwargs, main_queue):
        worker_list = []
        for pool in self:
            for i in range(cnt):
                worker_list.append(pool.new_worker2(kwargs, main_queue))
        return worker_list
    # cnt是主库已有的worker数目，启动从库worker使得每个slaver pool都有cnt个worker
    def new_some_workers_if(self, cnt, startup_msg, kwargs, main_queue):
        if type(startup_msg) is not p.StartupMessage:
            startup_msg = startup_msg.startup_msg
        pool_list = self.pools_map[startup_msg]
        for pool in pool_list:
            avail_cnt = pool.count(startup_msg)
            if avail_cnt >= cnt:
                continue
            self.new_worker2(pool, cnt-avail_cnt, kwargs, main_queue)
        for pool in self:
            if pool in pool_list:
                continue
            self.new_worker2(pool, cnt, kwargs, main_queue)
    def add_worker(self, w):
        pool = self.get(w.pool_id)
        if not pool:
            pool = self.add(w.be_addr)
        pool.add(w)
        pool_list = self.pools_map[w.startup_msg]
        if pool not in pool_list:
            pool_list.append(pool)
    def remove_worker(self, w):
        pool = self.get(w.pool_id)
        if not pool:
            return
        if not pool.remove(w): # w之前已经被remove。有时可能会被remove2次，一次手动remove，一次worker异常退出时remove。
            return
        if pool.count(w.startup_msg):
            return
        pool_list = self.pools_map[w.startup_msg]
        pool_list.remove(pool)
    # 把来自前端cnn的消息msg分发给相应的worker
    def dispatch_fe_msg(self, poll, cnn, msg):
        if not cnn:
            return
        pool_list = self.pools_map[cnn.startup_msg]
        if not pool_list:
            cnn.close()
        else:
            nextidx = self.nextidx_map[cnn.startup_msg] % len(pool_list)
            pool_list[nextidx].dispatch_fe_msg(poll, cnn, msg)
            self.nextidx_map[cnn.startup_msg] = (nextidx + 1) % len(pool_list)
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
    def __init__(self, cnn, master_pool, slaver_pools, fepool, main_queue):
        super().__init__(cnn)
        self.master_pool = master_pool
        self.slaver_pools = slaver_pools
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
    def _process_listcmd(self, args, sub_cmd_map):
        cmd_list = []
        for cmd, (_, x) in self.cmd_map.items():
            cmd_list.append(cmd)
            for sub_cmd in x:
                cmd_list.append(cmd + ' ' + sub_cmd)
        self._write_result(['cmd'], [(cmd,) for cmd in cmd_list])
    cmd_map['cmd'] = (_process_listcmd, {})
    del _process_listcmd
    def _process_shutdown(self, args, sub_cmd_map):
        print('shutdown...')
        # sys.exit(1) will waiting threads to exit
        os._exit(1)
    cmd_map['shutdown'] = (_process_shutdown, {})
    del _process_shutdown
    # 有子命令的通用入口
    def _process_cmd(self, args, sub_cmd_map, default_sub_cmd='list'):
        if not args:
            args.append(default_sub_cmd)
        sub_cmd, *sub_cmd_args = args[0].split(maxsplit=1)
        if sub_cmd not in sub_cmd_map:
            return self._write_error('unknown sub cmd:%s' % sub_cmd)
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
    # pool [list|show|add|remove|remove_worker|new_worker] ...
    def _process_pool_list(self, args):
        rows = []
        pool = self.master_pool
        rows.append((pool.id, 'true', pool.be_addr, len(pool)))
        for pool in slaver_pools:
            rows.append((pool.id, 'false', pool.be_addr, len(pool)))
        return self._write_result(['pool_id', 'master', 'addr', 'worker'], rows)
    def _process_pool_show(self, args):
        pool_list = []
        if not args:
            pool_list.append(self.master_pool)
            pool_list += list(self.slaver_pools)
        else:
            pool_id_list = [int(i) for i in args[0].split(',')]
            if self.master_pool.id in pool_id_list:
                pool_list.append(self.master_pool)
            pool_list += [pool for pool in self.slaver_pools.get_some(pool_id_list) if pool]
        rows = []
        for pool in pool_list:
            for m, w in pool:
                startup_msg = self._make_startup_msg(m)
                rows.append((pool.id, w.id, w.be_addr, m['database'], m['user'], startup_msg, w.num_processed_msg))
        return self._write_result(['pool_id', 'worker_id', 'addr', 'database', 'user', 'startup_msg', 'processed'], rows)
    def _process_pool_add(self, args):
        if not args:
            return self._write_error("'pool add' should provide addr(host:port)")
        host, port = args[0].split(':')
        port = int(port)
        pool = self.slaver_pools.add((host, port))
        self._write_result(['pool_id'], [[pool.id]])
    def _process_pool_remove(self, args):
        if not args:
            return self._write_error("'pool remove' should provide pool id")
        pool_id = int(args[0])
        pool = self.slaver_pools.remove(pool_id)
        if not pool:
            return self._write_error('no pool for id %d' % pool_id)
        return self._write_result(['pool_id', 'addr', 'worker'], [[pool.id, pool.be_addr, len(pool)]])
    def _process_pool_remove_worker(self, args):
        if not args:
            return self._write_error("'pool remove_worker' should provide pool id and worker id")
        pool_id, worker_id = args[0].split()
        pool_id = int(pool_id)
        worker_id = int(worker_id)
        if pool_id == self.master_pool.id:
            w = self.master_pool.remove_byid(worker_id)
        else:
            pool = self.slaver_pools.get(pool_id)
            if not pool:
                return self._write_error('no pool for id %d' % pool_id)
            w = pool.get_byid(worker_id)
            if w:
                self.slaver_pools.remove_worker(w)
        if not w:
            return self._write_error('no worker with id(%s) in pool %d' % (worker_id, pool_id))
        return self._write_result(['pool_id', 'worker_id'], [[pool_id, worker_id]])
    # args指定pool_id和connection params，可以包含password，不需要包含host/port
    # connection params的格式为: key=value,key=value...
    def _process_pool_new_worker(self, args):
        if not args:
            return self._write_error("'pool new_worker' should provide pool id and connection params")
        pool_id, *params = args[0].split()
        pool_id = int(pool_id)
        if not params: 
            params.append('')
        params = params[0]
        kvs = (kv.split('=', maxsplit=1) for kv in params.split(',') if kv)
        kwargs = {k : v for k, v in kvs}
        if pool_id == self.master_pool.id:
            pool = self.master_pool
        else:
            pool = self.slaver_pools.get(pool_id)
            if not pool:
                return self._write_error('no pool for id %d' % pool_id)
        w = pool.new_worker2(kwargs, self.main_queue)
        return self._write_result(['pool_id', 'worker_id'], [[pool_id, w.id]])
    # 
    cmd_map['pool'] = (_process_cmd, {})
    cmd_map['pool'][1]['list'] = _process_pool_list
    cmd_map['pool'][1]['show'] = _process_pool_show
    cmd_map['pool'][1]['add'] = _process_pool_add
    cmd_map['pool'][1]['remove'] = _process_pool_remove
    cmd_map['pool'][1]['remove_worker'] = _process_pool_remove_worker
    cmd_map['pool'][1]['new_worker'] = _process_pool_new_worker
    del _process_pool_list, _process_pool_show, _process_pool_add, _process_pool_remove, _process_pool_remove_worker, _process_pool_new_worker
    del _process_cmd # 最后删除
    def _make_startup_msg(self, m):
        params = [(k, v) for k, v in m.get_params().items() if k not in ('database', 'user')]
        params.sort()
        res = b'{'
        for k, v in params:
            res += b'%s:%s ' % (k.encode('utf8'), v)
        if len(res) > 1:
            res = res[:-1]
        res += b'}'
        return res
# misc worker。负责额外的一些任务，目前包括: 
#   .) 发送CancelRequest
#   .) 发送报警邮件
class pgmiscworker():
    def __init__(self):
        self.work_queue = queue.Queue()
    def put(self, name, args):
        self.work_queue.put_nowait((name, args))
    def run(self):
        while True:
            name, args = self.work_queue.get()
            if name is None:
                return
            if name == 'CancelRequest':
                self._process_CancelRequest(args)
            else:
                print('<miscworker> unknown work name:%s args:%s' % (name, args))
    def _process_CancelRequest(self, args):
        msg, addr_list = args
        for addr in addr_list:
            try:
                cnn = pgnet.beconn(addr)
            except pgnet.pgexception as ex:
                print('<miscworker> connecting to %s fail: %s' % (addr, ex))
                continue
            cnn.write_msgs_until_done((msg,))
            cnn.close()
    @classmethod
    def start(cls):
        w = cls()
        thr = threading.Thread(target=w.run)
        thr.start()
        return w
# main
def get_match_cnn_param(startup_msg):
    for param in g_conf.get('conn_params',()):
        if startup_msg.match(param):
            return param
    return None
def need_new_worker(startup_msg):
    need = False
    wcnt = master_pool.count(startup_msg)
    if wcnt == 0:
        need = True
    else:
        fecnt = fepool.count(startup_msg) + 1
        worker_min_cnt = g_conf.get('worker_min_cnt', [])
        worker_per_fe_cnt = g_conf.get('worker_per_fe_cnt', 10)
        if fecnt > len(worker_min_cnt):
            need = fecnt/worker_per_fe_cnt > wcnt
        else:
            need = worker_min_cnt[fecnt-1] > wcnt
    param = get_match_cnn_param(startup_msg) if need else None
    return need, param
def can_send_to_slaver(fecnn, msg):
    if msg.msg_type != p.MsgType.MT_Query:
        return False
    sql = bytes(msg.query)
    if sql.startswith(b'/*s*/'):
        return True
    return False
# HA
# 检查大对象lo_oid是否存在，如果不存在则创建。
def check_largeobject(cnn, lo_oid):
    res = cnn.query('select * from pg_largeobject_metadata where oid=%s' % lo_oid)
    if res:
        return
    print('no largeobject with oid %s. create it' % lo_oid)
    cnn.query('select lo_create(%s)' % lo_oid)
def get_newest_slaver():
    addrs_processed = set()
    max_lsn = (0, 0)
    newest_pool = None
    for pool in slaver_pools:
        if pool.be_addr in addrs_processed:
            continue
        addrs_processed.add(pool.be_addr)
        try:
            cnn = pool.get_admin_cnn(g_conf['admin_cnn'])
            res = cnn.query('select  pg_last_wal_receive_lsn()')
        except pgnet.pgexception as ex:
            print('pg_last_wal_receive_lsn fail for pool %s: %s' % (pool.id, ex))
            continue
        if res[0][0] is None:
            continue
        hi, lo = res[0][0].split('/')
        hi, lo = int(hi, 16), int(lo, 16)
        if max_lsn < (hi, lo):
            max_lsn = (hi, lo)
            newest_pool = pool
    return (newest_pool, max_lsn)
def promote_slaver(pool):
    try:
        cnn = pool.get_admin_cnn(g_conf['admin_cnn'])
        lo_oid = g_conf.get('lo_oid', 9999)
        trigger_file = g_conf.get('trigger_file', 'trigger')
        cnn.query("select lo_export(%s, '%s')" % (lo_oid, trigger_file))
    except pgnet.pgexception as ex:
        print('promote_slaver fail: %s' % ex)
        return False
    return True
# 修改从库中的recovery.conf指向新的主库。
# 返回从库使用的复制slot名字列表。如果没有使用slot则返回空串。
def modify_recovery_conf():
    addrs_processed = set()
    addrs_processed.add(master_pool.be_addr)
    slot_name_list = []
    m_host, m_port = master_pool.be_addr
    for pool in slaver_pools:
        if pool.be_addr in addrs_processed:
            continue
        addrs_processed.add(pool.be_addr)
        try:
            cnn = pool.get_admin_cnn(g_conf['admin_cnn'])
            res = cnn.query("select z_change_recovery_conf('%s', %s)" % (m_host, m_port))
        except pgnet.pgexception as ex:
            print('z_change_recovery_conf fail for pool %s: %s' % (pool.id, ex))
            continue
        slot_name_list.append(res[0][0])
    return slot_name_list
# 返回创建成功的slot名字列表。
def create_slot_for_slaver(slot_name_list):
    ret = []
    for name in slot_name_list:
        try:
            cnn = master_pool.get_admin_cnn(g_conf['admin_cnn'])
            cnn.query("select pg_create_physical_replication_slot('%s')" % name)
        except pgnet.pgexception as ex:
            print('pg_create_physical_replication_slot fail for %s: %s' % (name, ex))
            continue
        ret.append(name)
    return ret
def restart_slaver():
    addrs_processed = set()
    addrs_processed.add(master_pool.be_addr)
    for pool in slaver_pools:
        if pool.be_addr in addrs_processed:
            continue
        addrs_processed.add(pool.be_addr)
        try:
            cnn = pool.get_admin_cnn(g_conf['admin_cnn'])
            cnn.query("select z_restart_pg()")
        except pgnet.pgexception as ex:
            pass
# in event loop
def process_main_queue():
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
            w = x[2]
            if w.pool_id == master_pool.id:
                master_fail_history.clear()
                master_pool.add(w)
            else:
                slaver_pools.add_worker(w)
            # 启动slaver workers
            param = slaver_workers_to_start.pop(w.id, None)
            if param:
                wcnt = master_pool.count(w)
                slaver_pools.new_some_workers_if(wcnt, w.startup_msg, param, main_queue)
        elif x[0] == 'fail': # ('fail', fecnn, worker, is_be_problem)
            if x[1]:
                x[1].close()
            w = x[2]
            slaver_workers_to_start.pop(w.id, None)
            if w.pool_id == master_pool.id:
                if x[3]: # is_be_problem==True表示后端出问题了
                    master_fail_history.append(time.time())
                else:
                    master_fail_history.clear()
        elif x[0] == 'exit': # ('exit', worker)
            # x[1]==None表示worker已经被删除，正常退出，此时队列里应该没有东西
            # x[1]!=None表示后端出问题了
            w = x[1]
            if w is None:
                continue
            if w.pool_id == master_pool.id:
                master_fail_history.append(time.time())
                master_pool.remove(w)
                master_pool.dispatch_worker_remain_msg(poll, w)
            else:
                slaver_pools.remove_worker(w)
                slaver_pools.dispatch_worker_remain_msg(poll, w)
        elif x[0] == 'done': # ('done', fecnn)
            poll.register(x[1], poll.POLLIN)
        else:
            raise RuntimeError('unknow x from main_queue:%s' % (x,))
def process_ha():
    global master_pool
    if not g_conf.get('enable_ha', False):
        if len(master_fail_history) >= g_conf.get('', 10):
            print('master_fail_history: %s' % master_fail_history)
            master_fail_history.clear()
        return
    if len(master_fail_history) < g_conf.get('', 10):
        return
    print('start process_ha')
    master_fail_history.clear()
    pool, max_lsn = get_newest_slaver()
    if not pool:
        print('no newest slaver')
        slaver_pools.close_admin_cnn()
        return
    if not promote_slaver(pool):
        slaver_pools.close_admin_cnn()
        return
    slaver_pools.remove(pool, clear=False)
    master_pool.clear()
    master_pool = pool
    g_conf['master'] = master_pool.be_addr
    g_conf['slaver'].remove(master_pool.be_addr)
    # 把剩下的从库指向新的主库
    slot_name_list = modify_recovery_conf()
    create_slot_for_slaver([s for s in slot_name_list if s])
    restart_slaver()
    master_pool.close_admin_cnn()
    slaver_pools.close_admin_cnn()
    print('process_ha done. master changed to %s' % (master_pool.be_addr,))
if __name__ == '__main__':
    g_conf = miscutils.read_conf(os.path.dirname(__file__))
    
    cnn_param = copy.copy(g_conf['admin_cnn'])
    cnn_param['host'] = g_conf['master'][0]
    cnn_param['port'] = g_conf['master'][1]
    admin_cnn = pgnet.pgconn(**cnn_param)
    check_largeobject(admin_cnn, g_conf.get('lo_oid', 9999))
    hba = pghba.pghba.from_database(admin_cnn)
    shadows = pghba.pgshadow.from_database(admin_cnn)
    admin_cnn.close()
    
    master_pool = pgworkerpool(g_conf['master'])
    slaver_pools = pgworkerpools(*g_conf.get('slaver',()))
    fepool = feconnpool()
    main_queue = queue.Queue()
    slaver_workers_to_start = {} # 记录下需要启动的slaver workers
    master_fail_history = [] # 后端连续出问题的时间记录，如果有连接成功则清空
    
    misc_worker = pgmiscworker.start()
    
    listen = netutils.listener(g_conf.get('listen', ('', 7777)), async=True)
    poll = netutils.spoller()
    poll.register(listen, poll.POLLIN)
    while True:
        poll_res = poll.poll(0.001)
        for fobj, event in poll_res:
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
                    if m.code == p.PG_CANCELREQUEST_CODE:
                        addr_list = [g_conf['master']] + g_conf.get('slaver', [])
                        misc_worker.put('CancelRequest', (m, addr_list))
                        fobj.close()
                        continue
                    if m.code != p.PG_PROTO_VERSION3_NUM or 'replication' in m.get_params():
                        fobj.write_msgs((p.ErrorResponse.make_error(b'do not support SSL or replication connection'),))
                        fobj.close()
                        continue
                    # 由于SCRAM，一个fecnn无法用于auth多个后端，所以现在只有当g_conf['conn_params']中有和startup_msg匹配的时候才会启动slaver workers。
                    # 另外slaver workers只有当master worker启动成功后才会启动。因为psql会用一个立马断开的连接来判断是否需要密码。
                    is_pseudo = (m['database'] == b'pseudo')
                    if not is_pseudo:
                        need, param = need_new_worker(m)
                        if need:
                            w = master_pool.new_worker(fobj.cnn, main_queue)
                            if param:
                                slaver_workers_to_start[w.id] = param
                            continue
                    
                    auth_ok_msgs = pooldb.auth_ok_msgs if is_pseudo else master_pool.get(m)[0].auth_ok_msgs
                    cnn = pooldb(fobj.cnn, master_pool, slaver_pools, fepool, main_queue) if is_pseudo else fobj.cnn
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
                    m = m[0]
                    poll.unregister(fobj) # 主线程停止检测，把控制权交给worker
                    if not can_send_to_slaver(fobj, m):
                        master_pool.dispatch_fe_msg(poll, fobj, m)
                        continue
                    if slaver_pools.has_worker(fobj):
                        slaver_pools.dispatch_fe_msg(poll, fobj, m)
                    else: 
                        # fobj.startup_msg和g_conf['conn_params']不匹配，或者所有从库worker已经异常结束。
                        master_pool.dispatch_fe_msg(poll, fobj, m)
                        wcnt = master_pool.count(fobj)
                        if wcnt > 0: 
                            cnn_param = get_match_cnn_param(fobj.startup_msg)
                            if cnn_param:
                                slaver_pools.new_some_workers_if(wcnt, fobj, cnn_param, main_queue)
                elif isinstance(fobj, pseudodb.pseudodb):
                    fobj.handle_event(poll, event)
            except pgnet.pgfatal as ex:
                print('%s: %s' % (ex.__class__.__name__, ex))
                poll.clear((fobj,))
                if type(fobj) is pgnet.feconn:
                    fepool.remove(fobj)
                fobj.close()
        process_main_queue()
        process_ha()
