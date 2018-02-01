#!/bin/env python3
# -*- coding: GBK -*-
# 
# postgressql type in/out map
# 
import decimal
import codecs
import datetime
import json
import functools
import collections

def null(f):
    def wrapper(p1, *args, **kwargs):
        if p1 is None: 
            return None
        return f(p1, *args, **kwargs)
    return wrapper
# XXX_in函数把串转换为python类型的对象；而XXX_out把python类型的对象转换为串。
@null
def bytea_in(s):
    if s[:2] != r'\x':
        return s
    b = s[2:].encode('ascii')
    return codecs.decode(b, 'hex')
@null
def bytea_out(b):
    b = codecs.encode(b, 'hex')
    return (rb'\x' + b).decode('ascii')

@null
def date_in(s):
    y, m, d = s.split('-')
    return datetime.date(int(y), int(m), int(d))
@null
def date_out(d):
    return str(d)

@null
def time_in(s):
    x, ms = s.split('.')
    h, m, s = x.split(':')
    return datetime.time(int(h), int(m), int(s), int(ms))
@null
def time_out(t):
    return str(t)

@null
def timestamp_in(s):
    ds, ts = s.split()
    return datetime.datetime.combine(date_in(ds), time_in(ts))
@null
def timestamp_out(dt):
    return str(dt)

@null
def timetz_in(s):
    return s
@null
def timetz_out(t):
    return t

@null
def timestamptz_in(s):
    return s
@null
def timestamptz_out(dt):
    return dt

@null
def interval_in(s):
    return s
@null
def interval_out(iv):
    return iv

@null
def json_in(s):
    return json.loads(s)
@null
def json_out(js):
    return json.dumps(js)

# range type
# 目前pg自带的range类型都是用逗号分隔start/end的。
@null
def range_in(s, fin=str, delim=','):
    s = s.strip('()[]')
    start, end = s.split(delim)
    start = None if start == '' else fin(start)
    end = None if end == '' else fin(end)
    return (start, end)
@null
def range_out(r, fout=str, delim=','):
    res = ''
    if r[0] is None:
        res += '(%s' % delim
    else:
        res += '[%s%s' % (fout(r[0], delim))
    if r[1] is None:
        res += ')'
    else:
        res += '%s)' % fout(r[1])
    return res
# 如果某些in/out函数需要用到pgconn的一些信息的话，可以在构造pgconn的时候deepcopy这个map，然后修改。
pg_type_info_map = {
    #typoid : (typin, typout, typname)
    16 : (bool, str, 'bool'), # bool
    21 : (int, str, 'int2'),  # int2
    23 : (int, str, 'int4'),  # int4
    20 : (int, str, 'int8'),  # int8
    700 : (float, str, 'float4'), # float4
    701 : (float, str, 'float8'), # float8
    1700 : (decimal.Decimal, str, 'numeric'), # numeric
    18 : (str, str, 'char'),      # char whose length is 1
    1042 : (str, str, 'bpchar'),  # bpchar
    1043 : (str, str, 'varchar'), # varchar
    25 : (str, str, 'text'),      # text
    17 : (bytea_in, bytea_out, 'bytea'), # bytea
    26 : (int, str, 'oid'), # oid
    1082 : (date_in, date_out, 'date'), # date
    1083 : (time_in, time_out, 'time'), # time
    1114 : (timestamp_in, timestamp_out, 'timestamp'), # timestamp
    1184 : (timestamptz_in, timestamptz_out, 'timestamptz'), # timestamptz
    1266 : (timetz_in, timetz_out, 'timetz'), # timetz
    1186 : (interval_in, interval_out, 'interval'), # interval
    114 : (json_in, json_out, 'json'),   # json
    3802 : (json_in, json_out, 'jsonb'), # jsonb
    # range type
    3904 : (functools.partial(range_in, fin=int), range_out), # int4range
    3926 : (functools.partial(range_in, fin=int), range_out), # int8range
    3906 : (functools.partial(range_in, fin=decimal.Decimal), range_out), # numrange
    3912 : (functools.partial(range_in, fin=date_in), functools.partial(range_out, fout=date_out)), # daterange
    3908 : (functools.partial(range_in, fin=timestamp_in), functools.partial(range_out, fout=timestamp_out)), # tsrange
    3910 : (functools.partial(range_in, fin=timestamptz_in), functools.partial(range_out, fout=timestamptz_out)), # tstzrange
}
pg_arrtype_info_map = {
    # typoid : (typelem_oid, typelem_name, typdelim)
}
def _init_arrtype_info():
    for item in (L.strip() for L in _arrtype_list.split('\n') if L.strip()):
        x = item.split('|')
        if len(x) != 4:
            raise RuntimeError('wrong arrtype info:%s' % item)
        pg_arrtype_info_map[int(x[0])] = (int(x[1]), x[2], x[3])
sql_get_arrtype = r"select t1.oid::text, t1.typelem, t1.typelem::regtype, t1.typdelim from pg_type t1 join pg_type t2 on t1.typelem=t2.oid where t1.typelem <> 0 and t1.typname like '\_%' and t2.typtype in ('b','r')"
_arrtype_list = r"""
    143|142|xml|,
    199|114|json|,
    629|628|line|,
    719|718|circle|,
    791|790|money|,
    1000|16|boolean|,
    1001|17|bytea|,
    1002|18|"char"|,
    1003|19|name|,
    1005|21|smallint|,
    1006|22|int2vector|,
    1007|23|integer|,
    1008|24|regproc|,
    1009|25|text|,
    1028|26|oid|,
    1010|27|tid|,
    1011|28|xid|,
    1012|29|cid|,
    1013|30|oidvector|,
    1014|1042|character|,
    1015|1043|character varying|,
    1016|20|bigint|,
    1017|600|point|,
    1018|601|lseg|,
    1019|602|path|,
    1020|603|box|;
    1021|700|real|,
    1022|701|double precision|,
    1023|702|abstime|,
    1024|703|reltime|,
    1025|704|tinterval|,
    1027|604|polygon|,
    1034|1033|aclitem|,
    1040|829|macaddr|,
    775|774|macaddr8|,
    1041|869|inet|,
    651|650|cidr|,
    1115|1114|timestamp without time zone|,
    1182|1082|date|,
    1183|1083|time without time zone|,
    1185|1184|timestamp with time zone|,
    1187|1186|interval|,
    1231|1700|numeric|,
    1270|1266|time with time zone|,
    1561|1560|bit|,
    1563|1562|bit varying|,
    2201|1790|refcursor|,
    2207|2202|regprocedure|,
    2208|2203|regoper|,
    2209|2204|regoperator|,
    2210|2205|regclass|,
    2211|2206|regtype|,
    4097|4096|regrole|,
    4090|4089|regnamespace|,
    2951|2950|uuid|,
    3221|3220|pg_lsn|,
    3643|3614|tsvector|,
    3644|3642|gtsvector|,
    3645|3615|tsquery|,
    3735|3734|regconfig|,
    3770|3769|regdictionary|,
    3807|3802|jsonb|,
    2949|2970|txid_snapshot|,
    3905|3904|int4range|,
    3907|3906|numrange|,
    3909|3908|tsrange|,
    3911|3910|tstzrange|,
    3913|3912|daterange|,
    3927|3926|int8range|,
"""
_init_arrtype_info()
# 
def parse(v, typoid):
    if typoid in pg_arrtype_info_map:
        ti = pg_arrtype_info_map[typoid]
        return _parse_array(v, ti[0], t[2])
    ti = pg_type_info_map.get(typoid, (str, str, 'unknown'))
    return ti[0](v)
def _parse_array(v, typelem_oid, typdelim):
    return v
