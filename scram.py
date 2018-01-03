#!/bin/env python3
# -*- coding: GBK -*-
# 
import sys, os, struct
import contextlib
import random
import hmac, hashlib, base64
import pgprotocol3 as p

try:
    from passlib.utils import saslprep
except ImportError:
    saslprep = lambda x:x
# pwd如果是bytes，则认为是utf8格式，这和postgresql中pg_saslprep函数的逻辑是一样的。
def mysaslprep(pwd):
    try:
        if type(pwd) is not str:
            pwd = pwd.decode('utf8')
        pwd = saslprep(pwd)
    except (UnicodeDecodeError, ValueError):
        pass
    if type(pwd) is str:
        return pwd.encode('utf8')
    else:
        return pwd

@contextlib.contextmanager
def print_duration(prefix=''):
    st = time.time()
    yield
    et = time.time()
    print('{}{:.7f}seconds'.format(prefix, et-st))

# scram相关代码在fe-auth-scram.c里面
# pg_shadow中保存的格式为: (代码在函数 pg_be_scram_build_verifier 里面)
#     SCRAM-SHA-256$4096:salt$StoredKey:ServerKey。4096是hash次数，salt/StoredKey/ServerKey都是base64格式。
# 
# BE: SASL 包含mechanism列表
# FE: SASLInitialResponse 包含mechanism name和response:'n,,n=,r=<client_random_nonce>'
# BE: SASLContinue 包含data:'r=<client_random_nonce><server_random_nonce>,s=<salt>,i=<hash_count>'
# FE: SASLResponse 包含data:'c=biws,r=<client_random_nonce><server_random_nonce>,p=<client_proof>'
# BE: SASLFinal 包含data:'v=<server_proof>'
SCRAM_SALT_LEN = 16
SCRAM_NONCE_LEN = 18
# nonce不是base64格式
def make_SASLInitialResponse(nonce=None):
    name = b'SCRAM-SHA-256'
    nonce = gen_random_bytes(SCRAM_NONCE_LEN) if nonce is None else nonce
    client_nonce = base64.b64encode(nonce)
    response_bare = b'n=,r=' + client_nonce
    response = b'n,,' + response_bare
    x = p.SASLInitialResponse(name=name, response=response)
    x.response_bare = response_bare
    x.client_nonce = client_nonce
    return x
# msg是authtype=AT_SASLContinue的Authentication
# 其中r是client_nonce+server_nonce; s是salt; i是hash次数
def parse_SASLContinue(msg):
    items = msg.data.split(b',')
    for k, v in (item.split(b'=', maxsplit=1) for item in items):
        if k == b'r':
            msg.nonce = base64.b64decode(v)
        elif k == b's':
            msg.salt = base64.b64decode(v)
        elif k == b'i':
            msg.iter_num = int(v.decode('ascii'))
        else:
            raise ValueError('unknown info in SASLContinue(%s, %s)' % (k, v))
# msg是authtype=AT_SASLFinal的Authentication
def parse_SASLFinal(msg):
    msg.proof = base64.b64decode(msg.data[2:])
# sasl_continue_msg是authtype=AT_SASLContinue的Authentication
def make_SASLResponse(salted_pwd, sasl_init_resp_msg, sasl_continue_msg):
    sasl_resp_data_without_proof = b'c=biws,r=' + base64.b64encode(sasl_continue_msg.nonce)
    clientkey = scram_clientkey(salted_pwd)
    storedkey = sha256(clientkey)
    proof = hmac_sha256(storedkey, sasl_init_resp_msg.response_bare, b',', sasl_continue_msg.data, b',', sasl_resp_data_without_proof)
    proof = xor_bytes(proof, clientkey)
    x = p.SASLResponse(sasl_resp_data_without_proof + b',p=' + base64.b64encode(proof))
    x.data_without_proof = sasl_resp_data_without_proof
    return x
def calc_SASLFinal(salted_pwd, sasl_init_resp_msg, sasl_continue_msg, sasl_resp_msg):
    serverkey = scram_serverkey(salted_pwd)
    proof = hmac_sha256(serverkey, sasl_init_resp_msg.response_bare, b',', sasl_continue_msg.data, b',', sasl_resp_msg.data_without_proof)
    return proof
# pwd/salt都是bytes
def make_scram_verifier(pwd, salt, iter_num):
    salted_pwd = scram_salted_password(pwd, salt, iter_num)
    storedkey = sha256(scram_clientkey(salted_pwd))
    serverkey = scram_serverkey(salted_pwd)
    f = base64.b64encode
    return b'SCRAM-SHA-256$%d:%s$%s:%s' % (iter_num, f(salt), f(storedkey), f(serverkey))
def scram_salted_password(pwd, salt, iter_num):
    res = prev_d = hmac_sha256(pwd, salt, b'\x00\x00\x00\x01')
    for i in range(1, iter_num):
        d = hmac_sha256(pwd, prev_d)
        res = xor_bytes(res, d)
        prev_d = d
    return res
def scram_clientkey(salted_pwd):
    return hmac_sha256(salted_pwd, b'Client Key')
def scram_serverkey(salted_pwd):
    return hmac_sha256(salted_pwd, b'Server Key')
def gen_random_bytes(sz):
    res = b''
    while True:
        n = random.randint(1, 0xFFFFFFFF)
        res += struct.pack('>I', n)
        if len(res) >= sz:
            break
    return res[:sz]
def hmac_sha256(key, *datas):
    x = hmac.new(key, digestmod='sha256')
    for data in datas:
        x.update(data)
    return x.digest()
def sha256(*datas):
    x = hashlib.sha256()
    for data in datas:
        x.update(data)
    return x.digest()
def xor_bytes(b1, b2):
    return bytes((n1 ^ n2 for n1, n2 in zip(b1, b2)))

# main
if __name__ == '__main__':
    pass
