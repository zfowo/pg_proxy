#!/bin/env python3
# -*- coding: GBK -*-
# 
# postgressql type in/out map
# 
import decimal
import codecs
import datetime
import json

# XXX_in函数把串转换为python类型的对象；而XXX_out把python类型的对象转换为串。
def bytea_in(s):
    if s[:2] != r'\x':
        return s
    b = s[2:].encode('ascii')
    return codecs.decode(b, 'hex')
def bytea_out(b):
    b = codecs.encode(b, 'hex')
    return (rb'\x' + b).decode('ascii')
def date_in(s):
    y, m, d = s.split('-')
    return datetime.date(int(y), int(m), int(d))
def date_out(d):
    return str(d)
def time_in(s):
    x, ms = s.split('.')
    h, m, s = x.split(':')
    return datetime.time(int(h), int(m), int(s), int(ms))
def time_out(t):
    return str(t)
def timestamp_in(s):
    ds, ts = s.split()
    return datetime.datetime.combine(date_in(ds), time_in(ts))
def timestamp_out(dt):
    return str(dt)
def json_in(s):
    return json.loads(s)
def json_out(js):
    return json.dumps(js)
# 如果某些in/out函数需要用到pgconn的一些信息的话，可以在构造pgconn的时候deepcopy这个map，然后修改。
pg_type_info_map = {
    #typoid : (typin, typout)
    16 : (bool, str), # bool
    21 : (int, str), # int2
    23 : (int, str), # int4
    20 : (int, str), # int8
    700 : (float, str), # float4
    701 : (float, str), # float8
    1700 : (decimal.Decimal, str), # numeric
    18 : (str, str), # char whose length is 1
    1042 : (str, str), # bpchar
    1043 : (str, str), # varchar
    25 : (str, str), # text
    17 : (bytea_in, bytea_out), # bytea
    26 : (int, str), # oid
    1082 : (date_in, date_out), # date
    1083 : (time_in, time_out), # time
    1114 : (timestamp_in, timestamp_out), # timestamp
    #1184 : (), # timestamptz
    #1266 : (), # timetz
    #1186 : (), # interval
    114 : (json_in, json_out), # json
    3802 : (json_in, json_out), # jsonb
}
