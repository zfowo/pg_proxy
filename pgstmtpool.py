#!/bin/env python3
# -*- coding: GBK -*-
# 
# 语句级别的连接池。
# 使用有名字的Parse/Bind的时候，如果前端在发送Close之前就异常断开了，那么语句/portal不会被close。
# 
import sys, os, time, datetime
import collections, socket, copy
import threading, queue
import pgnet
import pgprotocol3 as p
import pghba
import netutils
import pseudodb
import mputils
import miscutils

# tables列表里的表名以及sql都是str，不是bytes
class CacheItem():
    threshold_to_file = 10*1024*1024
    def __init__(self, timeout, tables, raw_msg_list, cfn):
        self.timeout = timeout
        self.tables = tables
        self._raw_msg_list = raw_msg_list
        self.size = 0
        self.cache_fn = cfn
        self.raw_msg_idx_table = [] # list of (idx, sz)
        self.rowdesc_raw_msg = raw_msg_list[0]
        self._save_to_file_if()
    def _save_to_file_if(self):
        self.size = 0
        for raw_msg in self._raw_msg_list:
            sz = len(bytes(raw_msg))
            self.raw_msg_idx_table.append((self.size, sz))
            self.size += sz
        if self.size < self.threshold_to_file:
            self.raw_msg_idx_table = []
            return
        self._save_to_file()
        self._raw_msg_list = None
    def _save_to_file(self):
        with open(self.cache_fn, 'wb') as f:
            f.write(b''.join(bytes(raw_msg) for raw_msg in self._raw_msg_list))
    def msg_count(self):
        return len(self._raw_msg_list) if self._raw_msg_list else len(self.raw_msg_idx_table)
    def in_file(self):
        return self._raw_msg_list is None
    def drop(self):
        if self.in_file():
            os.remove(self.cache_fn)
    # 获得所有消息，返回值类型如果是bytes那就是消息的字节串。
    def get_raw_msg_list(self):
        if self._raw_msg_list:
            return self._raw_msg_list
        with open(self.cache_fn, 'rb') as f:
            return f.read()
    # 获得指定范围的DataRow
    def get_datarow(self, offset, limit):
        if self._raw_msg_list:
            raw_msg_list = self._get_by_offsetlimit(self._raw_msg_list, offset, limit)
            return len(raw_msg_list), raw_msg_list
        raw_msg_idxs = self._get_by_offsetlimit(self.raw_msg_idx_table, offset, limit)
        if not raw_msg_idxs:
            return 0, []
        sz = sum(mi[1] for mi in raw_msg_idxs)
        with open(self.cache_fn, 'rb') as f:
            f.seek(raw_msg_idxs[0][0])
            return len(raw_msg_idxs), f.read(sz)
    def _get_by_offsetlimit(self, vs, offset, limit):
        start = offset + 1
        end = start + limit
        if end > len(vs) - 2:
            end = len(vs) - 2
        return vs[start:end]
class QueryCache():
    root_dir = 'querycache'
    def __init__(self, cache_dir):
        self.cache_dir = os.path.abspath(os.path.join(self.root_dir, cache_dir))
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cached_items = {} # sql -> CacheItem
        self.t2sqls_map = collections.defaultdict(set) # table -> sql set
        self.lock = threading.Lock()
    @mputils.AutoLock
    def __len__(self):
        return len(self.cached_items)
    @mputils.AutoLock
    def get_all(self):
        return list(self.cached_items.items())
    # 获得cache item，如果没有或者已经超时则返回None
    @mputils.AutoLock
    def get(self, sql, decode):
        sql = decode(sql)
        item = self.cached_items.get(sql, None)
        if item is None:
            return None
        if item.timeout > time.time():
            return item
        # timeouted
        self.cached_items.pop(sql)
        for t in item.tables:
            self.t2sqls_map[t].remove(sql)
        item.drop()
        return None
    @mputils.AutoLock
    def put(self, msg, raw_msg_list, decode, force=False):
        sql = decode(bytes(msg.query))
        if not force:
            item = self.cached_items.get(sql, None)
            if item and item.timeout > time.time():
                return
        timeout = msg._comment_info.cache + time.time()
        tables = tuple(decode(t) for t in msg._comment_info.tables)
        cfn = os.path.join(self.cache_dir, p.md5(sql.encode('utf8')).decode('ascii'))
        self.cached_items[sql] = CacheItem(timeout, tables, raw_msg_list, cfn)
        for t in tables:
            self.t2sqls_map[t].add(sql)
    @mputils.AutoLock
    def clear(self, tables, decode):
        tables = tuple(decode(t) for t in tables)
        cleared_items = []
        for t in tables:
            sqls = self.t2sqls_map.pop(t, None)
            if not sqls:
                continue
            for sql in sqls:
                cleared_items.append((sql, self.cached_items.pop(sql)))
        for sql, item in cleared_items:
            for t in item.tables:
                try:
                    self.t2sqls_map[t].remove(sql)
                except KeyError:
                    pass
            item.drop()
# comment格式: /*s c:n p:n t:t1,t2,...,tn*/。
# 其中s表示从从库读；c指定cache期限；p指定分页缓存；t指定相关的表，表之间用逗号分隔。
# tables是表名列表，表名是bytes；sql也是bytes
# c:n指定保存多少秒，n必须指定；t:t1,t2,...,tn是本查询相关的表列表；
# p[:n]指定分页的时候读取多少条记录，如果n<=0或者不指定则读取所有记录，sql语句的结尾必须是offset nn limit nn。必须指定c才有效。
# 当没有指定cache但是指定了tables的时候，会清空这些表相关的cache。
QueryCommentInfo = collections.namedtuple('QueryCommentInfo', 'master cache tables page offsetlimit msg_no_offsetlimit')
QueryCommentInfo.NoComment = QueryCommentInfo(True, None, (), None, None, None)
def parse_query_comment(msg):
    master, cache, tables = True, None, () 
    page, offsetlimit, msg_no_offsetlimit = None, None, None
    sql = bytes(msg.query).strip().strip(b';')
    if msg.msg_type != p.MsgType.MT_Query or sql[:2] != b'/*':
        msg._comment_info = QueryCommentInfo.NoComment
        return msg
    idx = sql.index(b'*/')
    info, sql = sql[2:idx], sql[idx+2:].strip()
    item_list = info.split()
    for item in item_list:
        if item == b's':
            master = False
        elif item == b'p':
            page = 0
        elif item[:2] == b'p:':
            page = int(item[2:])
        elif item[:2] == b'c:':
            cache = int(item[2:])
        elif item[:2] == b't:':
            tables = tuple(t for t in item[2:].split(b',') if t)
        else:
            raise RuntimeError('unknown item(%s) in comment' % item)
    if page is not None:
        sql_no_offsetlimit, *x = sql.rsplit(maxsplit=4)
        if len(x) == 4:
            x = [v.lower() for v in x]
            it = iter(x)
            x = dict(zip(it, it))
            if x.keys() == {b'offset', b'limit'}:
                offsetlimit = offset, limit = (int(x[b'offset']), int(x[b'limit']))
                msg_no_offsetlimit = p.Query(query=sql_no_offsetlimit)
            else:
                raise RuntimeError('sql should be end with offset/limit while comment contain p')
        else:
            raise RuntimeError('sql should be end with offset/limit while comment contain p')
        if cache is None:
            raise RuntimeError('comment should contain c while p is provided')
    msg = p.Query(query=sql)
    msg._comment_info = QueryCommentInfo(master, cache, tables, page, offsetlimit, msg_no_offsetlimit)
    return msg

class fepgfatal(Exception):
    def __init__(self, fatal_ex, last_fe_msg=None):
        self.fatal_ex = fatal_ex
        self.last_fe_msg = None
@mputils.generateid
class pgstmtworker():
    def __init__(self, pool_id, be_addr, main_queue, max_msg=0):
        self.pool_id = pool_id
        self.be_addr = be_addr
        self.main_queue = main_queue
        self.msg_queue = queue.Queue(maxsize=max_msg)
        self.becnn = None
        self.startup_msg = None
        self.auth_ok_msgs = []
        self.num_processed_msg = 0
        self.start_time = time.time()
        # 下面这些只能在主线程里修改
        self.last_put_time = None
        self.last_processed_msg_info = (None, None, None) # (put_time, get_time, done_time)
        # 当worker启动成功时在主线程里设置
        self.query_cache = None 
        self.idle_timeout = 600
        # 最后从队列中获得的消息
        self.last_msg = None
    def __repr__(self):
        return '<pgstmtworker pool_id=%s id=%s be_addr=%s>' % (self.pool_id, self.id, self.be_addr)
    def put(self, fecnn, msg):
        self.last_put_time = time.time()
        self.msg_queue.put_nowait((fecnn, msg, self.last_put_time))
    def _process_auth(self, fecnn):
        self.becnn = pgnet.beconn(self.be_addr)
        self.becnn.startup_msg = self.startup_msg = fecnn.startup_msg
        self.becnn.write_msgs_until_done((fecnn.startup_msg,))
        while True:
            msg_list = self.becnn.read_msgs_until_avail()
            fecnn.write_msgs_until_done(msg_list)
            self.auth_ok_msgs.extend(msg_list)
            msg = msg_list[-1]
            if msg.msg_type == p.MsgType.MT_ReadyForQuery:
                break
            elif msg.msg_type == p.MsgType.MT_ErrorResponse:
                self.main_queue.put(('fail', fecnn, self, False))
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
        self.main_queue.put(('ok', fecnn, self))
        return True
    # 当由前端负责auth的时候用该函数作为线程的target。
    def run(self, fecnn):
        try:
            if not self._process_auth(fecnn):
                return
        except pgnet.pgfatal as ex:
            print('<worker %d>: %s (ex.cnn:%s fe:%s be:%s)' % (self.id, ex, ex.cnn, fecnn, self.becnn))
            if self.becnn is None or ex.cnn is self.becnn:
                self.main_queue.put(('fail', fecnn, self, True))
            else:
                self.main_queue.put(('fail', fecnn, self, False))
            self.becnn.close()
            return
        
        exit_cause = self._process_loop()
        self.main_queue.put(('exit', exit_cause, self))
    # 不需要前端参与auth。关键字参数指定auth参数，关键字参数不能指定host/port。
    def run2(self, kwargs):
        kwargs['host'] = self.be_addr[0]
        kwargs['port'] = self.be_addr[1]
        try:
            self.becnn = pgnet.pgconn(**kwargs)
        except pgnet.pgfatal as ex:
            print('<worker %d>: %s' % (self.id, ex))
            self.main_queue.put(('fail', None, self, True if ex.cnn else False))
            return
        self.startup_msg = self.becnn.startup_msg
        self.auth_ok_msgs = self.becnn.make_auth_ok_msgs()
        self.main_queue.put(('ok', None, self))
        
        exit_cause = self._process_loop()
        self.main_queue.put(('exit', exit_cause, self))
    def _process_loop(self):
        # process Query msg from queue
        while True:
            self.fe_fatal = None
            try:
                # fecnn可以是前端连接对象，None，或者命令名
                try:
                    fecnn, self.last_msg, put_time = self.msg_queue.get(timeout=self.idle_timeout)
                    get_time = time.time()
                except queue.Empty:
                    self.becnn.close()
                    return 'idle'
                if fecnn is None: # 结束线程
                    return 'normal'
                elif type(fecnn) is tuple: # self.last_msg is None
                    self._process_cmd(fecnn)
                else:
                    self._process_msg(fecnn, self.last_msg)
                done_time = time.time()
            except pgnet.pgfatal as ex:
                fecnn.close()
                print('<worker %d>: BE%s: %s' % (self.id, self.becnn.getpeername(), ex))
                return 'befatal'
            else:
                self.main_queue.put(('done', fecnn, self, (put_time, get_time-put_time, done_time-get_time)))
    # cmd : (cmd_name, cmd_arg)。
    def _process_cmd(self, cmd):
        name, *args = cmd
        if name == 'pagecache':
            self._process_cmd_pagecache(args[0])
        else:
            print('<worker %d>: unknown cmd: %s' % name)
    def _process_cmd_pagecache(self, femsg):
        be_raw_msg_list = []
        sql = bytes(femsg._comment_info.msg_no_offsetlimit.query)
        msg_no_offsetlimit = p.Query.make(sql)
        if femsg._comment_info.page > 0:
            sql = sql + b' limit %d' % femsg._comment_info.page
        msg = p.Query.make(sql)
        self.becnn.write_msgs_until_done((msg,))
        while True:
            raw_msg_list = self.becnn.read_raw_msgs_until_avail()
            be_raw_msg_list.extend(raw_msg_list)
            if raw_msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                break
        msg_no_offsetlimit._comment_info = femsg._comment_info
        self._put_to_cache(be_raw_msg_list, msg_no_offsetlimit, force=True)
    def _process_msg(self, fecnn, msg):
        if msg.msg_type == p.MsgType.MT_Terminate:
            print('<worker %d>: recved Terminate from %s' % (self.id, fecnn.getpeername()))
            self.num_processed_msg -= 1
        elif msg.msg_type == p.MsgType.MT_Query:
            self._process_query(fecnn, msg)
        elif msg.msg_type == p.MsgType.MT_Parse:
            self._process_parse(fecnn, msg)
        else:
            self._process_unsupported(fecnn,  msg)
        self.num_processed_msg += 1
    def _process_query(self, fecnn, femsg):
        if femsg._comment_info.cache:
            if self._process_from_cache(fecnn, femsg):
                return
        self.becnn.write_msgs_until_done((femsg,))
        m = self.becnn.read_raw_msgs_until_avail(max_msg=1)[0]
        if m.msg_type == p.MsgType.MT_CopyInResponse:
            self._process_copyin(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyOutResponse:
            self._process_copyout(fecnn, m)
        elif m.msg_type == p.MsgType.MT_CopyBothResponse:
            raise pgnet.pgfatal(None, 'do not support CopyBothResponse')
        else:
            self._process_query2(fecnn, m)
    def _process_from_cache(self, fecnn, femsg):
        if femsg._comment_info.page is not None:
            return self._process_from_cache_page(fecnn, femsg)
        sql = bytes(femsg.query)
        citem = self.query_cache.get(sql, self.becnn.decode)
        if not citem:
            return False
        self._write_cached_msgs_to_fe(fecnn, citem.get_raw_msg_list())
        return True
    def _process_from_cache_page(self, fecnn, femsg):
        sql = bytes(femsg._comment_info.msg_no_offsetlimit.query)
        citem = self.query_cache.get(sql, self.becnn.decode)
        if not citem:
            return False
        page = femsg._comment_info.page
        offset, limit = femsg._comment_info.offsetlimit
        cnt, datarow_list = citem.get_datarow(offset, limit)
        if page > 0 and not datarow_list:
            # 如果offset已经超出缓存的范围，那么直接从后端读取，并且不缓存，相当于没有指定注释
            femsg._comment_info = QueryCommentInfo.NoComment
            return False
        cc_raw_msg = p.CommandComplete(tag=b'SELECT %d' % cnt).to_rawmsg()
        self._write_cached_msgs_to_fe(fecnn, (citem.rowdesc_raw_msg,), datarow_list, (cc_raw_msg, p.ReadyForQuery.Idle.to_rawmsg()))
        return True
    def _process_query2(self, fecnn, berawmsg):
        cache = self.last_msg._comment_info.cache
        page = self.last_msg._comment_info.page
        be_raw_msg_list = []
        raw_msg_list = [berawmsg] + self.becnn.read_raw_msgs()
        if cache and page is None:
            be_raw_msg_list.extend(raw_msg_list)
        while True:
            if self._write_msgs_to_fe(fecnn, raw_msg_list)[1]:
                break
            raw_msg_list = self.becnn.read_raw_msgs_until_avail()
            if cache and page is None:
                be_raw_msg_list.extend(raw_msg_list)
        if cache:
            if page is None:
                self._put_to_cache(be_raw_msg_list, self.last_msg)
            else:
                sql_no_offsetlimit = self.becnn.decode(bytes(self.last_msg._comment_info.msg_no_offsetlimit.query))
                self.main_queue.put(('pagecache', self.startup_msg, self.last_msg, sql_no_offsetlimit))
        elif self.last_msg._comment_info.tables:
            self.query_cache.clear(self.last_msg._comment_info.tables, self.becnn.decode)
    def _put_to_cache(self, be_raw_msg_list, last_msg, force=False):
        m = be_raw_msg_list[-1].to_msg(fe=False)
        if m.trans_status != p.TransStatus.TS_Idle:
            return
        for m in reversed(be_raw_msg_list):
            if m.msg_type == p.MsgType.MT_ErrorResponse:
                return
            if m.msg_type == p.MsgType.MT_CommandComplete:
                if not bytes(m.to_msg(fe=False).tag).startswith(b'SELECT'):
                    return
        be_raw_msg_list = [m for m in be_raw_msg_list if not p.MsgType.is_async_msg(m.msg_type)]
        self.query_cache.put(last_msg, be_raw_msg_list, self.becnn.decode)
    def _process_copyout(self, fecnn, berawmsg):
        raw_msg_list = [berawmsg] + self.becnn.read_raw_msgs()
        while True:
            if self._write_msgs_to_fe(fecnn, raw_msg_list)[1]:
                break
            raw_msg_list = self.becnn.read_raw_msgs_until_avail()
    def _process_copyin(self, fecnn, berawmsg):
        self._write_msgs_to_fe(fecnn, (berawmsg,))
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
                raw_msg_list = fecnn.read_raw_msgs()
                if raw_msg_list:
                    last_fe_msg = raw_msg_list[-1]
            except pgnet.pgfatal as ex:
                raise fepgfatal(ex, last_fe_msg)
            self.becnn.write_raw_msgs_until_done(raw_msg_list)
            raw_msg_list = self.becnn.read_raw_msgs()
            if self._write_msgs_to_fe(fecnn, raw_msg_list)[1]:
                break
    def _process_unsupported(self, fecnn, femsg):
        errmsg = p.ErrorResponse.make_error(b'unsupported msg type:%s' % femsg.msg_type)
        try:
            fecnn.write_msgs_until_done((errmsg, p.ReadyForQuery.Idle))
        except pgnet.pgfatal as ex:
            pass # 不需要处理，主线程在下次read的时候会报错
    # 返回(是否写成功, 是否有ReadyForQuery消息)
    def _write_msgs_to_fe(self, fecnn, raw_msg_list):
        got_ready = False
        if  raw_msg_list and raw_msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
            got_ready = True
            m = raw_msg_list[-1].to_msg(fe=False)
            if m.trans_status != p.TransStatus.TS_Idle:
                self.becnn.write_msgs_until_done((p.Query(query=b'abort'),))
                self._skip_be_msgs()
                self._change_msgs_to_idle(raw_msg_list)
        if self.fe_fatal:
            return False, got_ready
        try:
            fecnn.write_raw_msgs_until_done(raw_msg_list)
        except pgnet.pgfatal as ex:
            self.fe_fatal = ex
            return False, got_ready
        return True, got_ready
    def _write_cached_msgs_to_fe(self, fecnn, *raw_msg_lists):
        try:
            for raw_msg_list in raw_msg_lists:
                if type(raw_msg_list) is bytes:
                    fecnn.write_raw_msgs((raw_msg_list,))
                else:
                    fecnn.write_raw_msgs(raw_msg_list)
            fecnn.write_raw_msgs_until_done()
        except pgnet.pgfatal as ex:
            self.fe_fatal = ex
            return False
        return True
    def _skip_be_msgs(self, raw_msg_list=()):
        if not raw_msg_list:
            raw_msg_list = self.becnn.read_raw_msgs_until_avail()
        while True:
            if raw_msg_list[-1].msg_type == p.MsgType.MT_ReadyForQuery:
                return
            raw_msg_list = self.becnn.read_raw_msgs_until_avail()
    def _change_msgs_to_idle(self, raw_msg_list):
        m = raw_msg_list[-1].to_msg(fe=False)
        raw_msg_list[-1] = p.ReadyForQuery.Idle.to_rawmsg()
        if m.trans_status == p.TransStatus.TS_InBlock:
            raw_msg_list.insert(-1, p.ErrorResponse.make_error(b'do not supoort transaction statement. abort it').to_rawmsg())
            return
        # TS_Fail
        for m in reversed(raw_msg_list):
            if m.msg_type == p.MsgType.MT_ErrorResponse:
                raw_msg_list[i] = p.ErrorResponse.make_error(b'do not supoort transaction statement. abort it').to_rawmsg()
                return
# 记录某个be_addr的所有pgworker，按startup_msg分组。
# pgworker中记录所属的pool的id。
@mputils.generateid
class pgstmtworkerpool():
    def __init__(self, be_addr):
        self.be_addr = be_addr
        self.workers_map = collections.defaultdict(list) # startup_msg -> worker_list
        self.nextidx_map = collections.defaultdict(int)  # startup_msg -> nextidx for accessing worker_list
        self.id2worker_map = {}
        self.admin_cnn = None # 用于管理目的的连接，一般是超级用户
    def get_admin_cnn(self, cnn_param):
        if self.admin_cnn:
            return self.admin_cnn
        cnn_param = copy.copy(cnn_param)
        cnn_param.update(host=self.be_addr[0], port=self.be_addr[1])
        self.admin_cnn = pgnet.pgconn(**cnn_param)
        return self.admin_cnn
    def close_admin_cnn(self):
        if self.admin_cnn:
            self.admin_cnn.close()
            self.admin_cnn = None
    # 启动一个新的worker，此时该worker还没有添加到pool里面，
    # 主线程从main_queue接收到auth成功之后才会把worker加到pool。
    def new_worker(self, fecnn, main_queue,):
        w = pgstmtworker(self.id, self.be_addr, main_queue)
        thr = threading.Thread(target=w.run, args=(fecnn,))
        thr.start()
        return w
    def new_worker2(self, kwargs, main_queue):
        w = pgstmtworker(self.id, self.be_addr, main_queue)
        thr = threading.Thread(target=w.run2, args=(kwargs,))
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
    def dispatch_cmd_msg(self, startup_msg, cmd):
        worker_list = self.workers_map[startup_msg]
        if worker_list:
            nextidx = self.nextidx_map[startup_msg] % len(worker_list)
            worker_list[nextidx].put(cmd, None)
            self.nextidx_map[startup_msg] = (nextidx + 1) % len(worker_list)
    # 当worker异常退出时需要把剩下的消息分发到其他worker上。在调用之前必须先remove worker。
    def dispatch_worker_remain_msg(self, poll, w):
        while True:
            try:
                cnn, msg, put_time = w.msg_queue.get_nowait()
            except queue.Empty:
                break
            if type(cnn) is tuple:
                self.dispatch_cmd_msg(w.startup_msg, cnn)
            else:
                self.dispatch_fe_msg(poll, cnn, msg)
# 管理一组pool组成的列表
class pgstmtworkerpools():
    def __init__(self, *be_addr_list):
        self.pools = []
        for be_addr in be_addr_list:
            self.pools.append(pgstmtworkerpool(be_addr))
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
        pool = pgstmtworkerpool(be_addr)
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
        for pool in self:
            avail_worker_cnt = pool.count(startup_msg)
            if avail_worker_cnt >= cnt:
                continue
            self.new_worker2(pool, cnt-avail_worker_cnt, kwargs, main_queue)
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
    def dispatch_cmd_msg(self, startup_msg, cmd):
        pool_list = self.pools_map[startup_msg]
        if pool_list:
            nextidx = self.nextidx_map[startup_msg] % len(pool_list)
            pool_list[nextidx].dispatch_cmd_msg(startup_msg, cmd)
            self.nextidx_map[startup_msg] = (nextidx + 1) % len(pool_list)
    # 当worker异常退出时需要把剩下的消息分发到其他worker上。在调用之前必须先remove worker。
    def dispatch_worker_remain_msg(self, poll, w):
        while True:
            try:
                cnn, msg, put_time = w.msg_queue.get_nowait()
            except queue.Empty:
                break
            if type(cnn) is tuple:
                self.dispatch_cmd_msg(w.startup_msg, cnn)
            else:
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
    def __len__(self):
        cnt = 0
        for _, fecnns in self.fecnns_map.items():
            cnt += len(fecnns)
        return cnt
    def __contains__(self, fecnn):
        return fecnn in self.fecnns_map[fecnn.startup_msg]
    def __iter__(self):
        for msg, fecnns in self.fecnns_map.items():
            for cnn in fecnns:
                yield msg, cnn
# pseudo db
class pooldb(pseudodb.pseudodb):
    def __init__(self, cnn, g_conf):
        super().__init__(cnn)
        self.g_conf = g_conf
        self.master_pool = g_conf['global']['master_pool']
        self.slaver_pools = g_conf['global']['slaver_pools']
        self.fepool = g_conf['global']['fepool']
        self.main_queue = g_conf['global']['main_queue']
        self.query_cache_map = g_conf['global']['query_cache_map']
    def process_query(self, query):
        query = query.strip().strip(';')
        cmd, *args = query.split(maxsplit=1)
        if cmd not in self.cmd_map:
            return self._write_error('unknown command:%s' % cmd)
        f, sub_cmd_map = self.cmd_map[cmd]
        return f(self, args, sub_cmd_map)
    # 各种命令实现。args参数是list，为空或者只有一个元素。
    cmd_map = {}
    # log_msg
    @mputils.mycmd('log_msg', cmd_map)
    def cmd(self, args, sub_cmd_map):
        if not args:
            return self._write_result(['log_msg'], [(pgnet.connbase.log_msg,)])
        v = args[0].lower() in ('on', '1', 'true', 't')
        pgnet.connbase.log_msg = v
        return self._write_result(['log_msg'], [(pgnet.connbase.log_msg,)])
    # register
    @mputils.mycmd('register', cmd_map)
    def cmd(self, args, sub_cmd_map):
        if self.g_conf['mode'] != 'master':
            return self._write_error('only master connection pool can run register command ')
        if not args:
            return self._write_error('register need args host:port')
        host, port = args[0].split(':')
        if host == '0.0.0.0':
            host = self.getpeername()[0]
        self.g_conf['spool'].append((host, int(port)))
        return self._write_result(['register'], [('ok',)])
    # spool
    @mputils.mycmd('spool', cmd_map)
    def cmd(self, args, sub_cmd_map):
        if self.g_conf['mode'] != 'master':
            return self._write_error('only master connection pool can run spool command')
        return self._write_result(['host', 'port'], self.g_conf['spool'])
    # change_master
    @mputils.mycmd('change_master', cmd_map)
    def cmd(self, args, sub_cmd_map):
        if self.g_conf['mode'] != 'slaver':
            return self._write_error('only slaver connection pool can run change_master command')
        if not args:
            return self._write_error('change_master need args host:port')
        host, port = args[0].split(':')
        new_master_addr = (host, int(port))
        pool_list = self.slaver_pools.get_byaddr(new_master_addr)
        if not pool_list:
            self._write_error('no pool for %s' % (new_master_addr,))
        self.slaver_pools.remove(pool_list[0], clear=False)
        self.master_pool.clear()
        globals()['master_pool'] = pool_list[0]
        self.master_pool = globals()['master_pool']
        self.g_conf['master'] = self.master_pool.be_addr
        self.g_conf['slaver'].remove(self.master_pool.be_addr)
        return self._write_result(['change_master'], [('ok',)])
    # cmd
    @mputils.mycmd('cmd', cmd_map)
    def cmd(self, args, sub_cmd_map):
        cmd_list = []
        for cmd, (_, x) in self.cmd_map.items():
            cmd_list.append(cmd)
            for sub_cmd in x:
                cmd_list.append(cmd + ' ' + sub_cmd)
        return self._write_result(['cmd'], [(cmd,) for cmd in cmd_list])
    # shutdown
    @mputils.mycmd('shutdown', cmd_map)
    def cmd(self, args, sub_cmd_map):
        print('shutdown...')
        # sys.exit(1) will waiting threads to exit
        os._exit(1)
    # cache
    @mputils.mycmd('cache', cmd_map)
    def cmd(self, args, sub_cmd_map):
        rows = []
        for m, qc in self.query_cache_map.items():
            startup_msg = self._make_startup_msg(m)
            for sql, citem in qc.get_all():
                timeout = datetime.datetime.fromtimestamp(citem.timeout).time()
                rows.append((m['database'], m['user'], startup_msg, sql, timeout, citem.tables, citem.msg_count(), citem.size, citem.in_file()))
        return self._write_result(['database', 'user', 'startup_msg', 'sql', 'timeout', 'tables', 'msg_cnt', 'size', 'in_file'], rows)
    # 有子命令的通用入口
    def _common_with_sub_cmd(self, args, sub_cmd_map, default_sub_cmd='list'):
        if not args:
            args.append(default_sub_cmd)
        sub_cmd, *sub_cmd_args = args[0].split(maxsplit=1)
        if sub_cmd not in sub_cmd_map:
            return self._write_error('unknown sub cmd:%s' % sub_cmd)
        return sub_cmd_map[sub_cmd](self, sub_cmd_args)
    # fe [list|count] ...
    @mputils.mycmd('fe', cmd_map)
    def cmd(self, args, sub_cmd_map):
        return self._common_with_sub_cmd(args, sub_cmd_map)
    @cmd.sub_cmd(name='list')
    def cmd(self, args):
        rows = []
        for m, fecnn in self.fepool:
            host, port = fecnn.getpeername()
            startup_msg = self._make_startup_msg(m)
            rows.append((host, port, m['database'], m['user'], startup_msg))
        return self._write_result(['host', 'port', 'database', 'user', 'startup_msg'], rows)
    @cmd.sub_cmd(name='count')
    def cmd(self, args):
        return self._write_result(['count'], [(len(self.fepool),)])
    # pool [list|show|add|remove|remove_worker|new_worker] ...
    @mputils.mycmd('pool', cmd_map)
    def cmd(self, args, sub_cmd_map):
        return self._common_with_sub_cmd(args, sub_cmd_map)
    @cmd.sub_cmd(name='list')
    def cmd(self, args):
        rows = []
        pool = self.master_pool
        rows.append((pool.id, 'true', pool.be_addr, len(pool)))
        for pool in slaver_pools:
            rows.append((pool.id, 'false', pool.be_addr, len(pool)))
        return self._write_result(['pool_id', 'master', 'addr', 'worker'], rows)
    @cmd.sub_cmd(name='show')
    def cmd(self, args):
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
                f = datetime.datetime.fromtimestamp
                last_put_time = f(w.last_put_time).time() if w.last_put_time is not None else 'None'
                t1, t2, t3 = w.last_processed_msg_info
                if t1 is None:
                    lastinfo = '(None, None, None)'
                else:
                    lastinfo = '(%s, %g, %g)' % (f(t1).time(), t2*1000, t3*1000)
                rows.append((pool.id, w.id, w.be_addr, m['database'], m['user'], startup_msg, w.num_processed_msg, last_put_time, lastinfo))
        return self._write_result(['pool_id', 'worker_id', 'addr', 'database', 'user', 'startup_msg', 'processed', 'lastputtime', 'lastinfo'], rows)
    @cmd.sub_cmd(name='add')
    def cmd(self, args):
        if not args:
            return self._write_error("'pool add' should provide addr(host:port)")
        host, port = args[0].split(':')
        port = int(port)
        pool = self.slaver_pools.add((host, port))
        self._write_result(['pool_id'], [[pool.id]])
    @cmd.sub_cmd(name='remove')
    def cmd(self, args):
        if not args:
            return self._write_error("'pool remove' should provide pool id")
        pool_id = int(args[0])
        pool = self.slaver_pools.remove(pool_id)
        if not pool:
            return self._write_error('no pool for id %d' % pool_id)
        return self._write_result(['pool_id', 'addr', 'worker'], [[pool.id, pool.be_addr, len(pool)]])
    @cmd.sub_cmd(name='remove_worker')
    def cmd(self, args):
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
    # args指定pool_id和conn params,可以包含password,不需要包含host/port,conn params的格式为:key=value,key=value...
    @cmd.sub_cmd(name='new_worker')
    def cmd(self, args):
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
    del cmd
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
# 如果cnn_param没有password，那么把用户的md5密码作为password
def add_pwd_md5_if(cnn_param):
    if 'password' in cnn_param:
        return
    pwd = get_pwd_md5(g_conf['global']['shadows'], cnn_param['user'])
    if pwd:
        cnn_param['password'] = pwd
# 获得pg_shadow中的md5密码，如果不是md5则返回None
def get_pwd_md5(shadows, username):
    shadow = shadows.get_shadow(username)
    if shadow and shadow[0] == pghba.MD5_PREFIX:
        return pghba.MD5_PREFIX + shadow[1]
    else:
        return None
# 获得建立从库worker需要的连接参数
def get_slaver_cnn_param(startup_msg):
    username = startup_msg['user'].decode('utf8')
    pwd = g_conf.get('user_pwds', {}).get(username, None)
    if pwd is None:
        pwd = get_pwd_md5(g_conf['global']['shadows'], username)
    if pwd is None:
        return None
    param = copy.copy(startup_msg.get_params())
    param['password'] = pwd
    return param
def need_new_worker(startup_msg):
    need = False
    wcnt = master_pool.count(startup_msg)
    if wcnt == 0:
        need = True
    else:
        fecnt = fepool.count(startup_msg) + 1
        worker_min_cnt = g_conf.get('worker_min_cnt', [1,1,2,2,2,2,3,3,3,3])
        worker_per_fe_cnt = g_conf.get('worker_per_fe_cnt', 10)
        if fecnt > len(worker_min_cnt):
            need = fecnt/worker_per_fe_cnt > wcnt
        else:
            need = worker_min_cnt[fecnt-1] > wcnt
    param = get_slaver_cnn_param(startup_msg) if need else None
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
# 通知从连接池主库切换结果
def notify_spool():
    if g_conf['mode'] == 'slaver' or not g_conf['spool']:
        return
    cnn_param = g_conf.get('pseudo_cnn', g_conf['admin_cnn'])
    cnn_param = copy.copy(cnn_param)
    add_pwd_md5_if(cnn_param)
    for addr in g_conf['spool']:
        cnn_param.update(host=addr[0], port=addr[1], database='pseudo')
        try:
            with pgnet.pgconn(**cnn_param) as cnn:
                cnn.query('change_master %s:%s' % master_pool.be_addr)
        except pgnet.pgexception as ex:
            print('notify %s fail: %s' % (addr, ex))
# 从连接池把自己的listen_addr告诉主连接池
def register_to_mpool(addr):
    if g_conf['mode'] == 'master' or not g_conf['mpool']:
        return
    cnn_param = g_conf.get('pseudo_cnn', g_conf['admin_cnn'])
    cnn_param = copy.copy(cnn_param)
    add_pwd_md5_if(cnn_param)
    mhost, mport = g_conf['mpool']
    cnn_param.update(host=mhost, port=mport, database='pseudo')
    with pgnet.pgconn(**cnn_param) as cnn:
        cnn.query('register %s:%s' % (addr[0], addr[1]))
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
            w.idle_timeout = g_conf.get('idle_timeout', 60*60*24)
            if not query_cache_map.get(w.startup_msg, None):
                query_cache_map[w.startup_msg] = QueryCache(w.startup_msg.md5().decode('ascii'))
            w.query_cache = query_cache_map[w.startup_msg]
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
        elif x[0] == 'exit': # ('exit', exit_cause, worker)
            # exit_cause='normal' 表示worker已经被删除，正常退出，此时队列里应该没有东西
            # exit_cause='idle' 表示空闲超时，此时队列里可能有东西
            # exit_cause='befatal' 表示后端导致pgfatal异常，此时队列里可能有东西
            exit_cause, w = x[1], x[2]
            if exit_cause == 'normal':
                continue
            if w.pool_id == master_pool.id:
                if exit_cause == 'befatal':
                    master_fail_history.append(time.time())
                master_pool.remove(w)
                master_pool.dispatch_worker_remain_msg(poll, w)
            else:
                slaver_pools.remove_worker(w)
                slaver_pools.dispatch_worker_remain_msg(poll, w)
        elif x[0] == 'done': # ('done', fecnn, worker, (put_time, get_time, done_time))
            if isinstance(x[1], pgnet.feconn):
                poll.register(x[1], poll.POLLIN)
            w = x[2]
            w.last_processed_msg_info = x[3]
        elif x[0] == 'pagecache': # ('pagecache', startup_msg, femsg, sql)
            _, startup_msg, femsg, sql = x
            if time.time() > cache_timeout_map[sql]:
                cache_timeout_map[sql] = time.time() + femsg._comment_info.cache
                master_pool.dispatch_cmd_msg(startup_msg, ('pagecache', femsg))
        else:
            raise RuntimeError('unknow x from main_queue:%s' % (x,))
def process_ha():
    global master_pool
    if not g_conf.get('enable_ha', False):
        if len(master_fail_history) >= g_conf.get('ha_after_fail_cnt', 10):
            print('master_fail_history: %s' % master_fail_history)
            master_fail_history.clear()
        return
    if len(master_fail_history) < g_conf.get('ha_after_fail_cnt', 10):
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
    print('process_ha done. master changed to %s. notify spool to change master' % (master_pool.be_addr,))
    notify_spool()
# 处理命令行参数以及读取配置文件，返回g_conf。
def process_args():
    xargs = miscutils.parse_args(sys.argv[1:])
    if not xargs.keys() <= set(('mode', 'listen', 'conf', 'mpool')):
        print('usage: %s [mode=master|slaver] [listen=host:port] [mpool=host:port] [conf=pgstmtpool.conf.py]' % sys.argv[0])
        sys.exit(1)
    conf_file = xargs['conf'][0] if xargs['conf'] else os.path.join(os.path.dirname(__file__), 'pgstmtpool.conf.py')
    g_conf = miscutils.read_conf_file(conf_file, 'all')
    if xargs['mode']:
        g_conf['mode'] = xargs['mode'][0]
    else:
        g_conf['mode'] = 'master' if g_conf.get('enable_ha', False) else 'slaver'
    g_conf['enable_ha'] = g_conf['mode'] == 'master'
    g_conf['spool'] = [] # 记录从连接池的addr
    if xargs['listen']:
        host, port = xargs['listen'][0].split(':')
        g_conf['listen'] = (host, int(port))
    if 'listen' not in g_conf:
        g_conf['listen'] = ('', 7777)
    if xargs['mpool']:
        host, port = xargs['mpool'][0].split(':')
        g_conf['mpool'] = (host, int(port))
    else:
        g_conf['mpool'] = None
    if g_conf['mode'] not in ('master', 'slaver'):
        print('mode shoule be master or slaver')
        sys.exit(1)
    if (g_conf['mode'] == 'master' and g_conf['mpool']) or (g_conf['mode'] == 'slaver' and not g_conf['mpool']):
        print('WARNING: master mode should not specify mpool' if g_conf['mode'] == 'master' else 'WARNING: slaver mode should specify mpool')
    return g_conf
if __name__ == '__main__':
    g_conf = process_args()
    g_conf['global'] = {}
    print('mode:%s  listen:%s  mpool:%s' % (g_conf['mode'], g_conf['listen'], g_conf['mpool']))
    
    cnn_param = copy.copy(g_conf['admin_cnn'])
    cnn_param.update(host=g_conf['master'][0], port=g_conf['master'][1])
    admin_cnn = pgnet.pgconn(**cnn_param)
    check_largeobject(admin_cnn, g_conf.get('lo_oid', 9999))
    g_conf['global']['hba'] = hba = pghba.pghba.from_database(admin_cnn)
    g_conf['global']['shadows'] = shadows = pghba.pgshadow.from_database(admin_cnn)
    admin_cnn.close()
    
    g_conf['global']['master_pool'] = master_pool = pgstmtworkerpool(g_conf['master'])
    g_conf['global']['slaver_pools'] = slaver_pools = pgstmtworkerpools(*g_conf.get('slaver',()))
    g_conf['global']['fepool'] = fepool = feconnpool()
    g_conf['global']['main_queue'] = main_queue = queue.Queue()
    slaver_workers_to_start = {} # 记录下需要启动的slaver workers
    master_fail_history = [] # 后端连续出问题的时间记录，如果有连接成功则清空
    CacheItem.threshold_to_file = g_conf.get('cache_threshold_to_file', 10*1024)
    QueryCache.root_dir = g_conf.get('cache_root_dir', 'querycache')
    g_conf['global']['query_cache_map'] = query_cache_map = {} # startup_msg -> QueryCache
    
    # sql -> timeout  (sql is str)
    cache_timeout_map = collections.defaultdict(int)
    
    misc_worker = pgmiscworker.start()
    
    listen = netutils.listener(g_conf['listen'], async=True)
    register_to_mpool(listen.getsockname())
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
                    if m.code == p.PG_SSLREQUEST_CODE:
                        fobj.write_no_ssl()
                        poll.register(fobj, poll.POLLIN)
                        continue
                    if m.code != p.PG_PROTO_VERSION3_NUM or 'replication' in m.get_params():
                        fobj.write_msgs((p.ErrorResponse.make_error(b'do not support SSL or replication connection'),))
                        fobj.close()
                        continue
                    # 由于SCRAM，无法用pg_shadow中保存的密码来模拟登陆，所以只能由前端和后端直接进行auth。
                    # 另外slaver workers只有当master worker启动成功后才会启动。因为psql会用一个立马断开的连接来判断是否需要密码。
                    is_pseudo = (m['database'] == b'pseudo')
                    if not is_pseudo:
                        need, param = need_new_worker(m)
                        if need:
                            w = master_pool.new_worker(fobj.cnn, main_queue)
                            if param:
                                slaver_workers_to_start[w.id] = param
                            continue
                    # 由连接池进行auth
                    auth_ok_msgs = pooldb.auth_ok_msgs if is_pseudo else master_pool.get(m)[0].auth_ok_msgs
                    cnn = pooldb(fobj.cnn, g_conf) if is_pseudo else fobj.cnn
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
                    try:
                        m = parse_query_comment(m)
                    except Exception as ex:
                        errmsg = p.ErrorResponse.make_error(str(ex).encode('utf8'))
                        if fobj.write_msgs((errmsg, p.ReadyForQuery.Idle)):
                            poll.register(fobj, poll.POLLOUT)
                        else:
                            poll.register(fobj, poll.POLLIN)
                        continue
                    if m._comment_info.master:
                        master_pool.dispatch_fe_msg(poll, fobj, m)
                        continue
                    if slaver_pools.has_worker(fobj):
                        slaver_pools.dispatch_fe_msg(poll, fobj, m)
                    else: 
                        # fobj.startup_msg和g_conf['conn_params']不匹配，或者所有从库worker已经异常结束。
                        master_pool.dispatch_fe_msg(poll, fobj, m)
                        wcnt = master_pool.count(fobj)
                        if wcnt > 0: 
                            cnn_param = get_slaver_cnn_param(fobj.startup_msg)
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
