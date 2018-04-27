#!/bin/env python3
# -*- coding: GBK -*-
# 
# 监控pg是否可用
# 
import sys, os, time
import threading, queue
import pgnet
import pgprotocol3 as p

class pgmonitor():
    def __init__(self, main_queue, fail_cnt=10, check_interval=3):
        self.main_queue = main_queue
        self.fail_cnt = fail_cnt
        self.check_interval = check_interval
        self.thr = None
    def start(self, **cnn_params):
        if self.thr:
            raise RuntimeError('thread already started')
        self.cnn_params = cnn_params
        self.thr = threading.Thread(target=self.run)
        self.thr.start()
    def run(self):
        host = self.cnn_params['host']
        port = self.cnn_params['port']
        failcnt = 0
        while True:
            cnn = None
            try:
                cnn = pgnet.pgconn(**self.cnn_params)
                failcnt = 0
                print('pgmonitor(%s:%s): SUCCESS' % (host, port))
            except pgnet.pgfatal as ex:
                if ex.cnn: # 表示连接失败不是auth失败
                    failcnt += 1
                    print('pgmonitor(%s:%s): CONNFAIL: %s' % (host, port, ex))
                else:
                    print('pgmonitor(%s:%s): ERROR: %s' % (host, port, ex))
            except Exception as ex:
                print('pgmonitor(%s:%s): ERROR: %s' % (host, port, ex))
            finally:
                if cnn: cnn.close()
            
            if failcnt >= self.fail_cnt:
                self.thr = None
                self.main_queue.put(('pgdown', host, port))
                return
            time.sleep(self.check_interval)
# main
if __name__ == '__main__':
    q = queue.Queue()
    m = pgmonitor(q)
    m.start(host='127.0.0.1', port=5432)
    m.thr.join()
    print(q.get())
