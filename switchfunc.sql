-- 
-- 一些switch/promote相关的函数。
-- 用plpython3u编写，因为需要读写本地文件，以及访问pg的内部函数(非pg_proc函数)。
-- 在创建好下面这些函数后，必须从PUBLIC收回所有权限。revoke all on function ... from public
-- 
-- 当主库down掉后，需要执行下面这些：
--   1. 把数据最新的一个从库提升为主库。
--   2. 调用z_change_recovery_conf修改其他从库的recovery.conf，把primary_conninfo中的host/port指向新的主库。
--   3. 用z_change_recovery_conf的返回值在新的主库上创建其他从库用到的物理复制slot。
--   4. 调用z_restart_pg重启其他从库。
-- 

-- 
-- 修改从库的recovery.conf中的primary_conninfo配置项。目前该配置项不支持包含空格的子项，比如：
--   primary_conninfo = 'host=localhost port=6410 xxx="yy zz" user=zhb'
-- 
create or replace function z_change_recovery_conf(
    new_master_host text, 
    new_master_port integer, 
    do_change boolean default TRUE, 
    out slot_name text, 
    out content text[]
) returns record as 
$$
with open('recovery.conf', 'rt') as f:
  data_in = f.readlines()

slot = ''
data_out = []
for L in data_in:
  L = L.strip(' \t\r\n')
  if not L or L[0] == '#':
    data_out.append(L)
    continue
  
  conf_n, conf_v = L.split('=', 1)
  conf_n = conf_n.strip(' \t')
  conf_v = conf_v.strip(' \t')
  plpy.notice('[%s] = [%s]' % (conf_n, conf_v))
  if conf_n != 'primary_conninfo':
    data_out.append(L)
    if conf_n == 'primary_slot_name':
      slot = conf_v
    continue

  L = "primary_conninfo = '"
  got_host = False
  got_port = False
  conf_v = conf_v.strip("'")
  nv_list = [nv.split('=', 1) for nv in conf_v.split()]
  for nv in nv_list:
    n, v  = nv
    plpy.notice('    [%s] = [%s]' % (n, v))
    if n == 'host':
      got_host = True
      v = new_master_host
    elif n == 'port':
      got_port = True
      v = str(new_master_port)
    L += '%s=%s ' % (n, v)
  if not got_host:
    L += 'host=%s ' % (new_master_host, )
  if not got_port:
    L += 'port=%s ' % (new_master_port, )
  L = L.strip() + "'"
  data_out.append(L)

if do_change:
  with open('recovery.conf', 'wt') as f:
    f.writelines([L+'\n' for L in data_out])

return (slot, data_out)
$$ language plpython3u;

-- 
-- 在修改了recovery.conf后，还需要让它生效，由于在startup进程的StartupXLOG里面只读取一次recovery.conf，
-- 并且没有把PrimaryConnInfo放在共享内存中，所以无法修改它，因此为了让recovery.conf生效，只有重启。
-- 
-- 通过读取postmaster.opts文件来获得重启命令。
-- 各种路径(pg安装路径以及data目录)不要包含空格和中文。
-- 
create or replace function z_restart_pg() returns void as 
$$
import sys, os, time
import os.path
import subprocess

with open('postmaster.opts', 'rt') as f:
  data_in = f.read()
  data_in = data_in.strip(' \t\r\n')

x_list = data_in.split(maxsplit=3)
if len(x_list) < 3:
  plpy.error('postmaster.opts error: %s' % (data_in, ))
pg_ctl_cmd = '%s/pg_ctl restart %s %s -m fast>z_restart_pg.log 2>&1 &' % (os.path.dirname(x_list[0]), x_list[1], x_list[2])
plpy.notice(pg_ctl_cmd)

pid = os.fork()
if pid == 0:
  os.setsid()
  os.umask(0)
  subprocess.Popen(pg_ctl_cmd, shell=True)
  os._exit(0) # -- do not use sys.exit(0) which will raise exception
plpy.notice('fork: %s' % (pid, ))
$$ language plpython3u;

