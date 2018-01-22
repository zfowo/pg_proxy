
pgstmtpool.py [args] 语句级别连接池
========================================
* 命令行参数包括：[mode=master|slaver] [listen=host:port] [mpool=host:port] [conf=pgstmtpool.conf.py]

        mode=master|slaver            指定本连接池是主连接池还是从连接池。如果没有指定那么根据配置文件中的enable_ha来确定，
                                      enable_ha=True是主连接池否则是从连接池。如果指定了mode命令行参数，那么enalbe_ha由mode
                                      来确定，mode=master表示enable_ha为True，否则为False。
        listen=host:port              指定本连接池的监听ip地址和端口。如果没有指定就用配置文件中的listen参数。
        mpool=host:port               指定主连接池的ip地址和端口。只对从连接池有效，如果指定了，那么会把本从连接池注册到主连接池。
        conf=pgstmtpool.conf.py       指定配置文件。

* 配置文件是个python文件(缺省是pgstmtpool.conf.py)，all变量字典包含配置参数，其中admin_cnn和master是必须指定的参数，具体参数包括：

        'listen' : (host, port)       指定监听ip和port。
        'pseudo_cnn' : {}             主从连接池相互通信时用该连接参数去连接到伪数据库，不要包含host/port/database。如果没指定就用admin_cnn。
        'admin_cnn' : {}              指定连接参数，不要指定host/port，连接池在需要做些admin操作的时候用该参数连接到主库和从库。
                                      需要指定密码，如果auth方法是md5则可以指定md5后的密码，否则指定明文密码。
        'enable_ha' : False           是否支持HA。
        'ha_after_fail_cnt' : 10      当主库连续出现指定次数的连接失败时启动主库切换。
        'lo_oid' : 9999               主库中大对象id，用于在从库中生成trigger文件。
        'trigger_file' : 'trigger'    从库的recovery.conf配置的触发promote的文件名。
        'worker_min_cnt' : []         用于指定当有n个前端连接时需要的后端worker数。第idx个值表示当有idx+1个前端连接时需要的worker数。
        'worker_per_fe_cnt' : 10      当前端数超过worker_min_cnt的大小时，指定每多少个前端连接需要一个后端连接。
        'master' : (host, port)       主库地址。
        'slaver' : [(),...]           从库地址列表。同一个从库可以包含多次，也可以包含主库。
        'user_pwds' : {}              包含用户密码，从库worker用这些密码连接到从库。如果用户的auth方法是md5则不需要指定，
                                      如果auth方法是password/scram-sha-256则必须指定密码，如果是trust则指定空串。
                                      如果auth不是md5并且没有指定密码，那么不会启动从库worker。

* 在pg_hba.conf中不要把连接池的host/ip配置成trust，因为后端看到的host/ip是连接池的host/ip，而不是前端的。
前端连接如果导致新的worker(由于当前worker数不够)，那么由数据库端对前端进行auth；否则就是连接池对前端进行auth。
所以在pg_hba.conf中尽量把连接池和前端配置成一样。

* admin_cnn参数中的用户需要是超级用户，需要指定密码，如果是md5 auth，密码可以是md5后的密码。

* 前端不许使用事务语句(比如begin/end)，包含事务语句的查询都会被abort，除非整个语句序列用一个Query消息被一次完整执行。
psycopg2缺省的autocommit是False，所以它会自动发送begin语句，必须把autocommit设为True才可以使用本连接池。如果想让多条
语句作为一个整体执行，可以把分号分隔的多条语句作为一个语句执行。

* 前端在连接的时候会首先发送一个startup_msg消息，该消息包含database/user以及其他数据库参数，比如client_encoding/application_name，
不支持SSL连接和复制连接。每个后端都有一个pool，pool包含worker，worker按startup_msg分组，来自前端的查询会根据startup_msg分发到相应
的worker，缺省所有查询都分发到主库worker，如果查询语句的开头是/\*s\*/并且存在从库worker的话则分发到从库worker。

* pgstmtpool.py使用线程来实现，由于python的GIL限制，导致只能使用一个CPU，所以worker数目可能会受限制。可以启动多个pgstmtpool.py，把其中
一个的enable_ha设为True(称为主连接池)，其他都设为False(称为从连接池)，然后前面放一个haproxy。主连接池在切换完成后把切换结果发给从连接池。
比如下面启动主连接池和2个从连接池:

        .) python pgstmtpool.py
        .) python pgstmtpool.py mode=slaver listen=:7778 mpool=127.0.0.1:7777
        .) python pgstmtpool.py mode=slaver listen=:7779 mpool=127.0.0.1:7777

HA主库切换
==========
* 当主库连续出现ha_after_fail_cnt次连接失败并且enable_ha为True，则会开始切换操作，切换过程如下：

        1) 从所有从库中选一个接收的wal日志最新的从库。
        2) 把选定的从库提升为主库。
        3) 修改其他从库的recovery.conf配置文件。
        4) 在新的主库上创建从库用到的复制slot。
        5) 重启从库使得修改生效。

* 前面的3/4/5中需要用到switchfunc.sql中的函数，这些函数是用pl/python3u编写的。如果只有一个从库，那么不需要这些函数。
目前switchfunc.sql中的函数有2个限制：postgresql的安装目录和data目录不能包含空格；以及primary_conninfo中的项值不能包含空格。

伪数据库pseudo
==============
* 可以用psql连接到数据库pseudo查看连接池的各种信息，用数据库中的用户名/密码，还可以在pg_hba.conf中设置pseudo的auth方法。

* 连接到pseudo后只能执行支持的命令，包括下面这些命令：

        .) cmd                  列出所有命令
        .) log_msg              是否打印出消息。没有指定参数则显示当前的log_msg设置，否则设为指定的值。
                                on/1/true/t表示True，其他表示False。
        .) spool                列出从连接池。
        .) register             内部用命令
        .) change_master        内部用命令
        .) shutdown             shutdown连接池
        .) fe [list]            列出所有前端连接
        .) fe count             显示前端连接数
        .) pool [list]          列出所有pool
        .) pool show            列出指定pool中的worker，多个pool id用逗号分割，如果没指定pool id则列出所有pool的worker。
        .) pool add             增加一个pool，参数是host:port，只能增加从库pool。
        .) pool remove          删除一个pool，参数是pool id，只能删除从库pool。
        .) pool remove_worker   删除一个worker，参数是pool id和worker id。可以删除主库或者从库pool中的worker。
        .) pool new_worker      增加一个worker，参数是pool id和连接参数。

* 不要多个用户同时连接到pseudo执行修改操作。

pgnet.pgconn
===================
* pgconn可以作为客户端库使用，不过不遵循python DB-API规范，如果出现错误会抛出异常pgfatal和pgerror，pgfatal表示连接已经不可用，
  对于pgfatal，异常对象的errstr是错误串，errmsg是和异常相关的错误消息包；对于pgerror，errstr是错误串，errmsg是错误消息包ErrorResponse，
  可以调用pgconn.errmsg(pgerror_ex)获得包含错误信息的map。errstr和errmsg可能其中一个为None，但不会两个都是None。
  接口如下：

        pgconn(**kwargs)
          创建一个连接，关键字参数包括：host/port/database/user/password/application_name/client_encoding，
          以及其他GUC参数，不支持unix domain socket。
        query(sql)
          执行sql语句，多条语句可以用分号分隔，返回QueryResult，如果是多条语句那么返回QueryResult列表。
          不要用该函数执行copy语句，用copyin/copyout函数。
        query2(sql, args_list, discard_qr=False)
          用扩展查询协议执行sql语句，sql不能包含多条语句，sql中的参数用$1..$n表示，args_list是参数值列表，
          是序列的序列，比如如果sql中有2个参数，那么args_list的元素必须是大小为2的序列。
          如果不需要查询结果(比如INSERT/UPDATE/DELETE)，那么可以把discard_qr设为True，这样可以稍微提高性能。
          不要用该函数执行copy语句，用copyin/copyout函数。
        copyin(sql, data_list, batch=10)
          执行copy...from stdin语句，data_list是行数据列表，缺省行数据中的列用\t分隔结尾是\n。
          batch指定每次发送多少个消息，根据每行数据的大小设置相应的值。
        copyout(sql, outf)
          执行copy...to stdout语句，如果给定outf函数，那么对每一行数据都回调用outf，如果outf=None，那么
          返回QueryResult和行数据列表。
        trans()
          返回事务context manager。
        errmsg(ex)
          ex是pgerror对象，返回包含错误信息的map。
        quote_literal(v)
          静态方法。对来历不明的外部串数据需要用该函数处理一下，以防止sql注入，或者用query2执行。
        quote_ident(v)
          静态方法。对来历不明的标识符名需要用该函数处理一下，以防止sql注入。注意大小写问题。

* QueryResult的rowdesc如果为None，就表示执行的是没有返回结果的语句，比如INSERT/DELETE。

        cnn = pgnet.pgconn()
        res = cnn.query('select * from t1')
        for row in res:
            print(list(row))
        
        cnn.query2('insert into t1 values($1,$2)', ((i, i*i) for i in range(1000)))
        
        cnn.copyin('copy t1 from stdin', ('%s\t%s\n' % (i, i*i) for i in range(1000)))
        
        _, rows = cnn.copyout('copy t1 to stdout')
        for r in rows:
            print(r)
        
        with cnn.trans():
            cnn.query('insert into t1 values(1, 1)')
            ....
            cnn.query('insert into t2 values(100, 100)')
        

<作废>pg_proxy.py [conf_file]
=============================
* 配置文件conf_file是个python文件，里面有一个dict对象pg_proxy_conf，该字典包含下面这些项：

        'listen' : (host, port)                               指定监听的ip和端口。
        'master' : (host, port)                               指定主库地址。
        'conninfo' : {'name':value, ...}                      指定用于连接到master和promote的用户名/数据库/密码等，必须是超级用户。可以指定的name有：user/pw/db/conn_retry_num/conn_retry_interval/query_interval/lo_oid。user必须指定。
        'promote' : (host, port)                              指定用于提升为主库的从库的地址。
        'slaver_list' : [(host, port), ...]                   指定用于只读连接的从库列表。
        'idle_cnn_timeout' : 300                              指定空闲连接的lifetime，单位是秒。
        'active_cnn_timeout' : 300                            指定活动连接空闲时间限制，如果空闲时间超时，那么就断开fe的连接。如果为0那就不限制空闲时间。(目前不支持扩展查询协议)
        'recv_sz_per_poll' : 4                                每次poll一个连接上最多接收多少数据，单位是K。
        'disable_conds_list' : [[(name, value), ...], ...]    当active_cnn_timeout>0，可以用该参数指定不限制空闲时间的连接。可以指定的name有user/database以及其他可以出现在startup消息包中的项名。
        'pg_proxy_pw' : 'pg2pg'                               指定连接到伪数据库pg_proxy的时候需要的密码。
        'log' : {'name' : value, ...}                         指定logging相关的配置，可以指定的项有：filename, level。level可以设为logging.DEBUG/INFO/WARNING/ERROR。不指定filename则往stderr输出。
* 注：master/promote/slaver_list不支持unix domain socket。listen也不支持unix domain socket。

* pg_proxy根据用户名把连接转发到主库或者从库，用户名后面添加'@ro'的连接都转发到从库，用roundrobin方式来选择从库。

* 当主库down掉后，如果指定了promote配置，那么就会把它提升为主库。如果指定了promote，那么slaver_list中的
从库必须连接到promote这个从库，而不是直接连接到master。此外在主库中必须创建一个OID为9999的内容为空的大对象。
大对象的OID可以用lo_oid来设置，缺省值为9999，该大对象用于在promote上生成trigger文件。
另外从库上的recovery.conf中的trigger_file需要设为'trigger_file'。

* pg_proxy.py只支持postgres version 3协议，不支持SSL连接，认证方法可能只支持trust/password/md5，其他认证方法没有测试。
在配置pg_hba.conf的时候需要注意的是ADDRESS部分是针对pg_proxy.py所在的服务器的IP地址，
所以最好不要配置成trust方法，否则知道用户名/数据库名后谁都可以登录数据库。

* pg_proxy.py需要python 3.3及以上版本，不支持windows。只支持session级别的连接池，不支持事务/语句级别的连接池。
不支持复制连接，修改几行代码就能支持，不过复制连接不能支持池功能，也就是说当复制客户端断开连接后，到be端的连接也应该断开。

伪数据库
========
可以用psql连接到伪数据库pg_proxy查看当前状态，缺省密码是pg2pg，用户名任意。共有4个表: connection/process/server/startupmsg。
只支持单表的select查询，其中process/server表不支持查询条件和列选择。
- connection : 包含每个fe/be连接对的信息，包括活动连接和空闲连接。
- process    : 包含每个池子进程的连接信息。
- server     : 包含每个数据库server的连接信息。
- startupmsg : 包含每个连接的startup消息包，以及连接是否空闲。

pg_proxy.py的结构
=================
* 主进程启动时创建AF_UNIX socket(用于在主进程和子进程之间通信)以及AF_INET socket(接收来自pg客户端的连接)。
* 然后创建n个连接池进程(P)，以及一个工作进程(W)用于处理来自主进程(M)的任务请求，比如发送CancelRequest，发送切换结果等等。
* M和P之间通过UDS(unix domain socket)通信，他们之间的消息有：
    * M->P 如果pending_fe_connection已经接收到StartupMessage，那么M把它的文件描述符以及StartupMessage发送给P，P的选择规则是：P中的空闲的BE连接
      的StartupMessage与pending_fe_connection匹配；如果所有P中没有匹配的连接，那么就选活动连接最少的P。从库的选择则是roundrobin方式。
    * P->M 当连接建立或者断开的时候P会把连接信息发给M。
* M和W之间主要是M向W发送工作任务消息。当前的工作任务消息有：发送CancelRequest；发送切换结果。
