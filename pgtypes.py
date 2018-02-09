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
import re

def null(f):
    def wrapper(p1, *args, **kwargs):
        if p1 is None: 
            return None
        return f(p1, *args, **kwargs)
    return wrapper
# XXX_in函数把字节串转换为python类型的对象；而XXX_out把python类型的对象转换为串(不是字节串)。
@null
def general_in(s, client_encoding, *, fin=str, need_decode=True):
    if need_decode:
        s = s.decode(client_encoding)
    return fin(s)
@null
def general_out(obj, fout=str):
    return fout(obj)
@null
def bool_in(s, client_encoding):
    if s in (b't', b'true', b'on', b'1'):
        return True
    else:
        return False
@null
def bool_out(b):
    return 't' if b else 'f'
@null
def bytea_in(s, client_encoding):
    s = s.decode(client_encoding)
    if s[:2] != r'\x':
        return s
    b = s[2:].encode('ascii')
    return codecs.decode(b, 'hex')
@null
def bytea_out(b):
    b = codecs.encode(b, 'hex')
    return (rb'\x' + b).decode('ascii')

@null
def date_in(s, client_encoding):
    y, m, d = s.split(b'-')
    return datetime.date(int(y), int(m), int(d))
@null
def date_out(d):
    return str(d)

@null
def time_in(s, client_encoding):
    x, ms = s.split(b'.')
    h, m, s = x.split(b':')
    return datetime.time(int(h), int(m), int(s), int(ms))
@null
def time_out(t):
    return str(t)

@null
def timestamp_in(s, client_encoding):
    ds, ts = s.split()
    return datetime.datetime.combine(date_in(ds, client_encoding), time_in(ts, client_encoding))
@null
def timestamp_out(dt):
    return str(dt)

@null
def timetz_in(s, client_encoding):
    return s.decode(client_encoding)
@null
def timetz_out(t):
    return t

@null
def timestamptz_in(s, client_encoding):
    return s.decode(client_encoding)
@null
def timestamptz_out(dt):
    return dt

@null
def interval_in(s, client_encoding):
    return s.decode(client_encoding)
@null
def interval_out(iv):
    return iv

@null
def json_in(s, client_encoding):
    return json.loads(s.decode(client_encoding))
@null
def json_out(js):
    return json.dumps(js)

# range type
# 目前pg自带的range类型都是用逗号分隔start/end的。
@null
def range_in(s, client_encoding, *, fin=str, delim=b',', need_decode=False):
    s = s.strip(b'()[]')
    start, end = s.split(delim)
    if need_decode:
        start, end = start.decode(client_encoding), end.decode(client_encoding)
    start = None if not start else fin(start)
    end = None if not end else fin(end)
    return (start, end)
@null
def range_out(r, *, fout=str, delim=','):
    res = ''
    if r[0] is None:
        res += '(%s' % delim
    else:
        res += '[%s%s' % (fout(r[0]), delim)
    if r[1] is None:
        res += ')'
    else:
        res += '%s)' % fout(r[1])
    return res
# typin函数接收2个参数，第一个是字节串数据，第二个是client_encoding。根据类型可能需要进行decode。
# timetz/timestamptz/interval目前还没有实现，它们其实是不需要把字节串decode成串的。
fp = functools.partial
pg_type_info_map = {
    #typoid : (typin, typout, typname)
    16 : (bool_in, bool_out, 'bool'), # bool
    21 : (fp(general_in, fin=int, need_decode=False),    general_out, 'int2'),  # int2
    23 : (fp(general_in, fin=int, need_decode=False),    general_out, 'int4'),  # int4
    20 : (fp(general_in, fin=int, need_decode=False),    general_out, 'int8'),  # int8
    26 : (fp(general_in, fin=int, need_decode=False),    general_out, 'oid'), # oid
    700 : (fp(general_in, fin=float, need_decode=False), general_out, 'float4'), # float4
    701 : (fp(general_in, fin=float, need_decode=False), general_out, 'float8'), # float8
    1700 : (fp(general_in, fin=decimal.Decimal), general_out, 'numeric'), # numeric
    18 : (general_in, general_out, 'char'),      # char whose length is 1
    1042 : (general_in, general_out, 'bpchar'),  # bpchar
    1043 : (general_in, general_out, 'varchar'), # varchar
    25 : (general_in, general_out, 'text'),      # text
    17 : (bytea_in, bytea_out, 'bytea'), # bytea
    1082 : (date_in, date_out, 'date'), # date
    1083 : (time_in, time_out, 'time'), # time
    1114 : (timestamp_in, timestamp_out, 'timestamp'), # timestamp
    1184 : (timestamptz_in, timestamptz_out, 'timestamptz'), # timestamptz
    1266 : (timetz_in, timetz_out, 'timetz'), # timetz
    1186 : (interval_in, interval_out, 'interval'), # interval
    114 : (json_in, json_out, 'json'),   # json
    3802 : (json_in, json_out, 'jsonb'), # jsonb
    # range type
    3904 : (fp(range_in, fin=int), range_out), # int4range
    3926 : (fp(range_in, fin=int), range_out), # int8range
    3906 : (fp(range_in, fin=decimal.Decimal, need_decode=True), range_out), # numrange
    3912 : (fp(range_in, fin=date_in), fp(range_out, fout=date_out)), # daterange
    3908 : (fp(range_in, fin=timestamp_in), fp(range_out, fout=timestamp_out)), # tsrange
    3910 : (fp(range_in, fin=timestamptz_in), fp(range_out, fout=timestamptz_out)), # tstzrange
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
sql_get_arrtype = r"""
    select t1.oid, t1.typelem, t1.typelem::regtype, t1.typdelim 
    from pg_type t1 join pg_type t2 on t1.typelem=t2.oid 
    where t1.typelem <> 0 and t1.typname like '\_%' and t2.typtype in ('b','r')
"""
# typoid, typelem, typname, typdelim
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
def parse(v, typoid, client_encoding):
    if typoid in pg_arrtype_info_map:
        ti = pg_arrtype_info_map[typoid]
        return _parse_array(v, ti[0], ti[2], client_encoding)
    ti = pg_type_info_map.get(typoid, (general_in, general_out, 'unknown'))
    return ti[0](v, client_encoding)
def _parse_array(v, typelem_oid, typdelim, client_encoding):
    ti = pg_type_info_map.get(typelem_oid, (general_in, general_out, 'unknown'))
    return array_split(v, ti[0], typdelim, client_encoding)
# 分析数组
def escape_array_item(s, delim=','):
    pattern = r'[{} "\\' + delim + r']'
    if not re.search(pattern, s):
        return s
    s = '"' + s + '"'
    return s.replace('\\', r'\\').replace('"', r'\"')
def unescape_array_item(s):
    if s[0] != '"':
        return s
    s = s[1:-1]
    if s == 'NULL':
        return None
    return s.replace(r'\\', '\\').replace(r'\"', '"')
def array_split(s, fin, delim, client_encoding):
    if s[0] != '{':
        return fin(unescape_array_item(s), client_encoding)
    s = s[1:-1]
    if not s:
        return []
    res = []
    sidx = idx = 0
    level = 0
    quote_open = False
    while idx < len(s):
        c = s[idx]
        if c == '{':
            if not quote_open:
                level += 1
        elif c == '}':
            if not quote_open:
                level -= 1
        elif c == '"':
            quote_open = not quote_open
        elif c == '\\':
            idx += 1
        elif c == delim:
            if not quote_open and level <= 0:
                res.append(array_split(s[sidx:idx], fin, delim, client_encoding))
                sidx = idx + 1
        idx += 1
    res.append(array_split(s[sidx:idx], fin, delim, client_encoding))
    return res
# main
if __name__ == '__main__':
    pass
