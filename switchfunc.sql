-- 
-- һЩswitch/promote��صĺ�����
-- ��plpython3u��д����Ϊ��Ҫ��д�����ļ����Լ�����pg���ڲ�����(��pg_proc����)��
-- �ڴ�����������Щ�����󣬱����PUBLIC�ջ�����Ȩ�ޡ�revoke all on function ... from public
-- 
-- ������down������Ҫִ��������Щ������
--   1. ���������µ�һ���ӿ�����Ϊ���⡣
--   2. ����z_change_recovery_conf�޸������ӿ��recovery.conf����primary_conninfo�е�host/portָ���µ����⡣
--   3. ��z_change_recovery_conf�ķ���ֵ���µ������ϴ��������ӿ��õ���������slot��
--   4. ����z_restart_pg���������ӿ⡣
-- 

-- 
-- �޸Ĵӿ��recovery.conf�е�primary_conninfo�����Ŀǰ�������֧�ְ����ո��������磺
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
-- ���޸���recovery.conf�󣬻���Ҫ������Ч��������startup���̵�StartupXLOG����ֻ��ȡһ��recovery.conf��
-- ����û�а�PrimaryConnInfo���ڹ����ڴ��У������޷��޸��������Ϊ����recovery.conf��Ч��ֻ��������
-- 
-- ͨ����ȡpostmaster.opts�ļ�������������
-- ����·��(pg��װ·���Լ�dataĿ¼)��Ҫ�����ո�����ġ�
-- 
create or replace function z_restart_pg() returns void as 
$$
import sys, os, time
import os.path
import subprocess

with open('postmaster.opts', 'rt') as f:
  data_in = f.read()
  data_in = data_in.strip()

x_list = data_in.split(maxsplit=1)
if len(x_list) < 2:
  plpy.error('postmaster.opts error: %s' % (data_in, ))
pg_ctl_cmd = '%s/pg_ctl restart %s -m fast>z_restart_pg.log 2>&1 &' % (os.path.dirname(x_list[0]), x_list[1])
plpy.notice(pg_ctl_cmd)

pid = os.fork()
if pid == 0:
  os.setsid()
  os.umask(0)
  subprocess.Popen(pg_ctl_cmd, shell=True)
  os._exit(0) # -- do not use sys.exit(0) which will raise exception
plpy.notice('fork: %s' % (pid, ))
$$ language plpython3u;

