#!/bin/env python3
# -*- coding: GBK -*-
# 
import sys, os

all = {
    'master' : ('127.0.0.1', 5432), 
    'slaver' : [('10.10.77.100', 5432), ], 
    'conn_params' : [
        {'database':'postgres', 'user':'zhb', 'client_encoding':'GBK', 'application_name':'psql'}, 
    ], 
}
