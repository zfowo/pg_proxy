#!/bin/env python3
# -*- coding: GBK -*-
# 
# 共享内存读写
# 
import sys, os
import struct, socket
import datetime

# 
# 空闲连接数读写。每个startup_msg_raw+be_addr都有一个对应的空闲连接数，key是其md5值。
# 
class idle_cnn_hash_table(object):
    KEY_SZ = 16
    VAL_SZ = 2
    ITEM_SZ = KEY_SZ + VAL_SZ
    EMPTY_KEY = b'\x00'*16
    # sidx是part中的起始位置
    def __init__(self, shm, part_idx, sidx):
        self.shm = shm
        self.part_idx = part_idx
        self.sidx = sidx 
        x = shm.get_part_bound(part_idx)
        self.ht_sz = (x[1] - x[0] - sidx) // self.ITEM_SZ # 哈希表大小
    def _hash(self, key):
        x = struct.unpack('4I', key)
        s = sum(x)
        return s % self.ht_sz
    # 检查是否存在与key对应的项，返回：
    #   .) (None, 0/1) : 不存在与key对应的项。0表示哈希表中还有空间；1表示没有空间了。
    #   .) (0, v)      : 存在与key对应的项，但其值v<=0。
    #   .) (1, v)      : 存在与key对应的项，其值>0，v是其值减1后的新值。
    # 如果指定了timeout，在指定的时间内没有获得semphore，那么抛出异常。
    # key是md5值，二进制串。
    def get(self, key, timeout=None):
        self.key = key
        self.hv = self._hash(key)
        return self.shm.get(self.sidx, -1, self.part_idx, self._get_pf, timeout)
    def _get_pf(self, mm, sidx, sz, part_bound):
        sidx += part_bound[0]
        if sz < 0:
            eidx = part_bound[1]
        else:
            eidx = part_bound[0] + sidx + sz
        
        idx = sidx + self.hv * self.ITEM_SZ
        ret = self._check_item(mm, idx)
        # 由于哈希表的key只进不出，所以ret==(None, 0)表示key还没有进入哈希表。
        if ret[0] != None or ret[1] == 0:
            return ret
        # 在self.hv位置没有找到匹配的key，则向前逐个检查。
        idx2 = idx + self.ITEM_SZ
        while idx2 + self.ITEM_SZ <= eidx:
            ret = self._check_item(mm, idx2)
            if ret[0] != None or ret[1] == 0:
                return ret
            idx2 += self.ITEM_SZ
        # 从头开始查找
        idx2 = sidx
        while idx2 + self.ITEM_SZ <= idx:
            ret = self._check_item(mm, idx2)
            if ret[0] != None or ret[1] == 0:
                return ret
            idx2 += self.ITEM_SZ
        return (None, 1)
    def _check_item(self, mm, idx):
        k = mm[idx:idx+self.KEY_SZ]
        if k == self.key:
            v = struct.unpack('h', mm[idx+self.KEY_SZ:idx+self.ITEM_SZ])[0]
            if v <= 0:
                return (0, v)
            else:
                v = v - 1
                mm[idx+self.KEY_SZ:idx+self.ITEM_SZ] = struct.pack('h', v)
                return (1, v)
        elif k == self.EMPTY_KEY:
            return (None, 0)
        else:
            return (None, 1)
    # 修改key对应的值，把val加到哈希表中已经有的值。
    # 返回新的值，如果哈希表没有空间了，则返回None。
    def put(self, key, val, timeout=None):
        self.key = key
        self.val = val
        self.hv = self._hash(key)
        return self.shm.put(val, self.sidx, self.part_idx, self._put_pf, timeout)
    def _put_pf(self, mm, data, sidx, part_bound):
        sidx += part_bound[0]
        eidx = part_bound[1]
        
        idx = sidx + self.hv * self.ITEM_SZ
        ret = self._put_item(mm, idx)
        if ret != None:
            return ret
        # 在self.hv位置被其他key占用了，则向前逐个检查。
        idx2 = idx + self.ITEM_SZ
        while idx2 + self.ITEM_SZ <= eidx:
            ret = self._put_item(mm, idx2)
            if ret != None:
                return ret
            idx2 += self.ITEM_SZ
        # 从头开始查找
        idx2 = sidx
        while idx2 + self.ITEM_SZ <= idx:
            ret = self._put_item(mm, idx2)
            if ret != None:
                return ret
            idx2 += self.ITEM_SZ
        return None
    def _put_item(self, mm, idx):
        k = mm[idx:idx+self.KEY_SZ]
        if k == self.key:
            v = struct.unpack('h', mm[idx+self.KEY_SZ:idx+self.ITEM_SZ])[0]
            v += self.val
            mm[idx+self.KEY_SZ:idx+self.ITEM_SZ] = struct.pack('h', v)
            return v
        elif k == self.EMPTY_KEY:
            mm[idx:idx+self.ITEM_SZ] = self.key + struct.pack('h', self.val)
            return self.val
        else:
            return None
# 
# 共享内存的开头8个字节分别作为idle_list/use_list的头。
# 每个item的有效大小是ITEM_SZ(用于保存实际的数据)，item头是5个字节，第一个字节表示是空闲(I)还是已被用(U)，接下来4个字节指向下一个item。
# 内部item指针指向item开头，而返回给外部的是指向保存实际数据的开头位置。
# 指针值都是相对于part_idx的起始位置的，不是相对于整个共享内存的起始位置。指针值-1表示结束。
# 
# idle_idx / use_idx是相对于整个共享内存的起始位置。
# 
class item_table(object):
    ITEM_SZ = 10 # 派生类需要定义该值
    # sidx是part_idx中的起始位置，part中sidx之前的空间不用。
    def __init__(self, shm, part_idx, sidx=0):
        self.shm = shm
        self.part_idx = part_idx
        self.sidx = sidx
        self.part_sidx, self.part_eidx = shm.get_part_bound(part_idx)
        self.idle_idx = self.part_sidx + self.sidx
        self.use_idx = self.idle_idx + 4
    # 初始化idle/use列表，返回idle item数目。
    # 共享内存的创建者调用该方法。
    @staticmethod
    def init_idle_use_list(shm, part_idx, item_sz, sidx=0):
        cnt = 0
        part_sidx, part_eidx = shm.get_part_bound(part_idx)
        mm = shm.mm
        mm[part_sidx+sidx+4:part_sidx+sidx+8] = struct.pack('i', -1) # use list
        off = sidx + 8
        mm[part_sidx+sidx:part_sidx+sidx+4] = struct.pack('i', off) # idle list
        idx = part_sidx + off
        while idx + 5 + item_sz <= part_eidx:
            mm[idx:idx+1] = b'I'
            mm[idx+1:idx+5] = struct.pack('i', off + 5 + item_sz)
            off += 5 + item_sz
            idx = part_sidx + off
            cnt += 1
        mm[idx-item_sz-4:idx-item_sz] = struct.pack('i', -1)
        return cnt
    # 查找并返回空闲的item，返回值指向item中保存实际数据的位置。如果没有空闲item，则返回-1。
    def find_idle_item(self, timeout=None):
        def pf(mm, sidx, sz, part_bound):
            x = mm[self.idle_idx:self.idle_idx+4]
            item_idx = struct.unpack('i', x)[0]
            if item_idx == -1:
                return item_idx
            
            item_pos = self.part_sidx + item_idx
            mm[self.idle_idx:self.idle_idx+4] = mm[item_pos+1:item_pos+5]
            mm[item_pos:item_pos+1] = b'U'
            mm[item_pos+1:item_pos+5] = mm[self.use_idx:self.use_idx+4]
            mm[self.use_idx:self.use_idx+4] = struct.pack('i', item_idx)
            return item_idx + 5
        return self.shm.get(part_idx=self.part_idx, pf=pf, timeout=timeout)
    # 把item_ptr放回到空闲链表中
    def put_to_idle_list(self, item_ptr, timeout=None):
        def pf(mm, sidx, sz, part_bound):
            item_pos = self.part_sidx + item_ptr
            # 从use_list删除item_ptr
            prev_idx = self.use_idx
            next_item = struct.unpack('i', mm[prev_idx:prev_idx+4])[0]
            while next_item + 5 != item_ptr:
                prev_idx = self.part_sidx + next_item + 1
                next_item = struct.unpack('i', mm[prev_idx:prev_idx+4])[0]
            mm[prev_idx:prev_idx+4] = mm[item_pos-4:item_pos]
            # 把item_ptr添加到idle_list
            mm[item_pos-5:item_pos+self.ITEM_SZ] = b'\x00' * (self.ITEM_SZ + 5)
            mm[item_pos-5:item_pos-4] = b'I'
            mm[item_pos-4:item_pos] = mm[self.idle_idx:self.idle_idx+4]
            mm[self.idle_idx:self.idle_idx+4] = struct.pack('i', item_ptr-5)
            return None
        return self.shm.get(part_idx=self.part_idx, pf=pf, timeout=timeout)
    # 读取item的值，item_ptr指向item中保存实际数据的开头。
    def get(self, item_ptr, pf=None, timeout=None):
        return self.shm.get(item_ptr, self.ITEM_SZ, self.part_idx, pf, timeout)
    # 把item_data写到item_ptr指向的位置。
    def put(self, item_ptr, item_data, pf=None, timeout=None):
        # pf可以任意解释item_data
        if pf == None and len(item_data) != self.ITEM_SZ:
            raise RuntimeError('len of item_data(%s) != %d' % (item_data, self.ITEM_SZ))
        return self.shm.put(item_data, item_ptr, self.part_idx, pf, timeout)
    # 读取所有item
    def getall(self, timeout=None):
        def pf(mm, sidx, sz, part_bound):
            res = []
            x = mm[self.use_idx:self.use_idx+4]
            item_idx = struct.unpack('i', x)[0]
            while item_idx != -1:
                item_pos = self.part_sidx + item_idx
                res.append(mm[item_pos+5:item_pos+5+self.ITEM_SZ])
                x = mm[item_pos+1:item_pos+5]
                item_idx = struct.unpack('i', x)[0]
            return res
        return self.shm.get(part_idx=self.part_idx, pf=pf, timeout=timeout)
# 
# item是连接信息，包括下面这些信息: 
#   fe_ip/fe_port    : 前端ip(4字节)和端口(2字节)。
#   be_ip/be_port    : 后端ip和端口。
#   use_num          : 使用次数(4字节)。
#   update_time      : 最后更新时间，保存为timestamp，float类型，4个字节。
#   startup_msg_raw  : 由于比较长，所以对一些常用选项名进行缩写，比如u代表user，d代表database，a代表application_name，e代表client_encoding等等，
#                      缩写由使用者处理。类型是bytes。
# 前面4项的大小是固定的，为20个字节。给startup_msg_raw分配80个字节，后面用b'\x00'填充。
# 
class cnn_info_table(item_table):
    ITEM_SZ = 20 + 80
    
    FE_IP_IDX = 0
    FE_PORT_IDX = 4
    BE_IP_IDX = 6
    BE_PORT_IDX = 10
    USE_NUM_IDX = 12
    UPDATE_TIME_IDX = 16
    STARTUP_MSG_RAW_IDX = 20
    
    def parse_item(self, item_data):
        ret = {}
        ret['fe_ip'] = socket.inet_ntoa(item_data[self.FE_IP_IDX:self.FE_IP_IDX+4])
        ret['fe_port'] = struct.unpack('H', item_data[self.FE_PORT_IDX:self.FE_PORT_IDX+2])[0]
        ret['be_ip'] = socket.inet_ntoa(item_data[self.BE_IP_IDX:self.BE_IP_IDX+4])
        ret['be_port'] = struct.unpack('H', item_data[self.BE_PORT_IDX:self.BE_PORT_IDX+2])[0]
        ret['use_num'] = struct.unpack('i', item_data[self.USE_NUM_IDX:self.USE_NUM_IDX+4])[0]
        x = struct.unpack('f', item_data[self.UPDATE_TIME_IDX:self.UPDATE_TIME_IDX+4])[0]
        ret['update_time'] = datetime.datetime.fromtimestamp(x)
        x = item_data[self.STARTUP_MSG_RAW_IDX:]
        sz = struct.unpack('>i', x[:4])[0]
        ret['startup_msg_raw'] = x[:sz]
        return ret

    def get(self, item_ptr, timeout=None):
        item_data = super().get(item_ptr, None, timeout)
        return self.parse_item(item_data)
    def getall(self, timeout=None):
        item_data_list = super().getall(timeout)
        return [self.parse_item(d) for d in item_data_list]
    def put(self, item_ptr, timeout=None, **kwargs):
        def pf(mm, item_data, item_ptr, part_bound):
            item_pos = part_bound[0] + item_ptr
            for x in item_data:
                s = item_pos + x[0]
                e = item_pos + x[0] + len(x[1])
                mm[s:e] = x[1]
            return len(item_data)
        
        item_data = [] # list of (idx, data)
        for k in kwargs:
            if k == 'fe_ip':
                data = socket.inet_aton(kwargs[k])
                item_data.append((self.FE_IP_IDX, data))
            elif k == 'fe_port':
                data = struct.pack('H', kwargs[k])
                item_data.append((self.FE_PORT_IDX, data))
            elif k == 'be_ip':
                data = socket.inet_aton(kwargs[k])
                item_data.append((self.BE_IP_IDX, data))
            elif k == 'be_port':
                data = struct.pack('H', kwargs[k])
                item_data.append((self.BE_PORT_IDX, data))
            elif k == 'use_num':
                data = struct.pack('i', kwargs[k])
                item_data.append((self.USE_NUM_IDX, data))
            elif k == 'update_time':
                pass
            elif k == 'startup_msg_raw':
                data = kwargs[k]
                if len(data) > 80:
                    raise RuntimeError('len of startup_msg_raw should not be greater than 80:(%s)' % (data, ))
                item_data.append((self.STARTUP_MSG_RAW_IDX, data))
            else:
                raise RuntimeError('unknown parameter %s' % (k, ))
        if not item_data:
            return 0
        # 总是更新update_time部分
        x = datetime.datetime.now().timestamp()
        data = struct.pack('f', x)
        item_data.append((self.UPDATE_TIME_IDX, data))
        return super().put(item_ptr, item_data, pf, timeout)

# main
if __name__ == '__main__':
    pass

