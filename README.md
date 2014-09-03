
pg_proxy.py [conf_file]
=======================
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

* pg_proxy根据用户名把连接转发到主库或者从库，用户名以'_r'结尾的连接都转发到从库，用roundrobin方式来选择从库。

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
