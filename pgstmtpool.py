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
import mputils
import miscutils

class fepgfatal(Exception):
    def __init__(self, fatal_ex):
        self.fatal_ex = fatal_ex
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
                main_queue.put(('fail', fecnn, self))
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
            main_queue.put(('fail', fecnn, self))
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
            main_queue.put(('fail', None, self))
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
                fecnn, msg = self.msg_queue.get()
                if not fecnn: # 结束线程
                    return True
                self._process_one(fecnn, msg)
            except pgnet.pgfatal as ex:
                fecnn.close()
                print('<thread %d> BE%s: %s' % (self.id, self.becnn.getpeername(), ex))
                return False
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
# pgworker中记录所属的pool的id。
@mputils.generateid
class pgworkerpool():
    def __init__(self, be_addr):
        self.be_addr = be_addr
        self.workers_map = collections.defaultdict(list) # startup_msg -> worker_list
        self.nextidx_map = collections.defaultdict(int)  # startup_msg -> nextidx for accessing worker_list
        self.id2worker_map = {}
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
        p = pgworkerpool(be_addr)
        self.pools.append(p)
        return p
    def remove(self, id):
        p = self.get(id)
        if not p:
            return None
        self.pools.remove(p)
        msg_list = []
        for msg, pool_list in self.pools_map.items():
            try:
                pool_list.remove(p)
                if not pool_list:
                    msg_list.append(msg)
            except ValueError:
                pass
        for msg in msg_list:
            self.pools_map.pop(msg)
        p.clear()
        return p
    def get(self, id):
        for p in self.pools:
            if p.id == id:
                return p
        return None
    def get_some(self, id_list):
        res = []
        for p in self:
            if p.id in id_list:
                res.append(p)
            else:
                res.append(None)
        return res
    def new_worker(self, id, fecnn, main_queue):
        p = self.get(id)
        if not p:
            return None
        return p.new_worker(fecnn, main_queue)
    # 在指定的pool中启动cnt个worker
    def new_worker2(self, id, cnt, kwargs, main_queue):
        p = self.get(id)
        if not p:
            return None
        worker_list = []
        for i in range(cnt):
            worker_list.append(p.new_worker2(kwargs, main_queue))
        return worker_list
    # 每个pool都启动cnt个worker
    def new_some_workers(self, cnt, kwargs, main_queue):
        worker_list = []
        for p in self:
            for i in range(cnt):
                worker_list.append(p.new_worker2(kwargs, main_queue))
        return worker_list
    def add_worker(self, w):
        p = self.get(w.pool_id)
        if not p:
            p = self.add(w.be_addr)
        p.add(w)
        pool_list = self.pools_map[w.startup_msg]
        if p not in pool_list:
            pool_list.append(p)
    def remove_worker(self, w):
        p = self.get(w.pool_id)
        if not p:
            return
        p.remove(w)
        if p.count(w.startup_msg):
            return
        pool_list = self.pools_map[w.startup_msg]
        pool_list.remove(p)
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
        p = self.master_pool
        rows.append((p.id, 'true', p.be_addr, len(p)))
        for p in slaver_pools:
            rows.append((p.id, 'false', p.be_addr, len(p)))
        return self._write_result(['pool_id', 'master', 'addr', 'worker'], rows)
    def _process_pool_show(self, args):
        if not args:
            return self._write_error("'pool show' should provide pool id")
        pool_id = int(args[0])
        if pool_id == self.master_pool.id:
            p = self.master_pool
        else:
            p = self.slaver_pools.get(pool_id)
        if not p:
            return self._write_error('no pool for id %d' % pool_id)
        rows = []
        for m, w in p:
            startup_msg = self._make_startup_msg(m)
            rows.append((w.id, w.be_addr, m['database'], m['user'], startup_msg, w.num_processed_msg))
        return self._write_result(['worker_id', 'addr', 'database', 'user', 'startup_msg', 'processed'], rows)
    def _process_pool_add(self, args):
        if not args:
            return self._write_error("'pool add' should provide addr(host:port)")
        host, port = args[0].split(':')
        port = int(port)
        p = self.slaver_pools.add((host, port))
        self._write_result(['pool_id'], [[p.id]])
    def _process_pool_remove(self, args):
        if not args:
            return self._write_error("'pool remove' should provide pool id")
        pool_id = int(args[0])
        p = self.slaver_pools.remove(pool_id)
        if not p:
            return self._write_error('no pool for id %d' % pool_id)
        return self._write_result(['pool_id', 'addr', 'worker'], [[p.id, p.be_addr, len(p)]])
    def _process_pool_remove_worker(self, args):
        if not args:
            return self._write_error("'pool remove_worker' should provide pool id and worker id")
        pool_id, worker_id = args[0].split()
        pool_id = int(pool_id)
        worker_id = int(worker_id)
        if pool_id == self.master_pool.id:
            w = self.master_pool.remove_byid(worker_id)
        else:
            p = self.slaver_pools.get(pool_id)
            if not p:
                return self._write_error('no pool for id %d' % pool_id)
            w = p.get_byid(worker_id)
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
            p = self.master_pool
        else:
            p = self.slaver_pools.get(pool_id)
            if not p:
                return self._write_error('no pool for id %d' % pool_id)
        w = p.new_worker2(kwargs, self.main_queue)
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
    need = False
    wcnt = master_pool.count(startup_msg)
    if wcnt == 0:
        need = True
    else:
        fecnt = fepool.count(startup_msg)
        need = fecnt/wcnt >= 10
    if need:
        for param in g_conf['conn_params']:
            if startup_msg.match(param):
                return need, param
    return need, None
def can_send_to_slaver(msg):
    if msg.msg_type != p.MsgType.MT_Query:
        return False
    sql = bytes(msg.query)
    if sql.startswith(b'/*s*/'):
        return True
    return False
if __name__ == '__main__':
    g_conf = miscutils.read_conf(os.path.dirname(__file__))
    
    auth_cnn = pgnet.pgconn(host=g_conf['master'][0], port=g_conf['master'][1])
    hba = pghba.pghba.from_database(auth_cnn)
    shadows = pghba.pgshadow.from_database(auth_cnn)
    auth_cnn.close()
    
    master_pool = pgworkerpool(g_conf['master'])
    slaver_pools = pgworkerpools(*g_conf['slaver'])
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
                    # 由于SCRAM，一个fecnn无法用于auth多个后端，所以现在只有当g_conf['conn_params']中有和startup_msg匹配的时候才会启动slaver worker。
                    if not is_pseudo:
                        need, param = need_new_worker(m)
                        if need:
                            master_pool.new_worker(fobj.cnn, main_queue)
                            if param:
                                slaver_pools.new_some_workers(1, param, main_queue)
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
                    poll.unregister(fobj) # 主线程停止检测，把控制权交给worker
                    if can_send_to_slaver(m[0]) and slaver_pools.has_worker(fobj):
                        slaver_pools.dispatch_fe_msg(poll, fobj, m[0])
                    else:
                        master_pool.dispatch_fe_msg(poll, fobj, m[0])
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
                w = x[2]
                if w.pool_id == master_pool.id:
                    master_pool.add(w)
                else:
                    slaver_pools.add_worker(w)
            elif x[0] == 'fail': # ('fail', fecnn, worker)
                if x[1]:
                    x[1].close()
            elif x[0] == 'exit': # ('exit', worker)
                # x[1]==None表示worker已经被删除，正常退出，此时队列里应该没有东西
                # x[1]!=None表示后端出问题了
                w = x[1]
                if w is None:
                    continue
                if w.pool_id == master_pool.id:
                    master_pool.remove(w)
                    master_pool.dispatch_worker_remain_msg(poll, w)
                else:
                    slaver_pools.remove_worker(w)
                    slaver_pools.dispatch_worker_remain_msg(poll, w)
            elif x[0] == 'done': # ('done', fecnn)
                poll.register(x[1], poll.POLLIN)
            else:
                raise RuntimeError('unknow x from main_queue:%s' % (x,))
