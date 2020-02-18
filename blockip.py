#!/usr/bin/python

import redis
import os
import re
import subprocess
import time
import datetime
import linecache

from settings import *
from logs import Logger


class NginxLog(object):
    def read_log(self, path):
        return linecache.getlines(path)

    def get_dt_from_line(self, s):
        # 匹配Nginx日期格式
        time_stamp = re.search('\[\d+/\w+/\d+:\d+:\d+:\d+', s).group()
        #print(time_stamp, len(time_stamp))
        return datetime.datetime.strptime(time_stamp[1:], '%d/%b/%Y:%H:%M:%S')

    def write_tmp_log(self, file_name, content):
        with open(file_name, 'w') as f:
            for c in content:
                f.write(c)

    def get_period_log(self):
        TIMEDELTA = datetime.timedelta(minutes=INTERVAL)
        LOG_START_ANALYZE_DATETIME = (datetime.datetime.today() - TIMEDELTA)
        log_file_name = '/var/log/nginx/' + time.strftime("%Y%m%d-%H%M%S",time.localtime()) + '.log'
        lines = [s for s in self.read_log(NGINX_LOG_PATH) if '/api/testblock' in s and self.get_dt_from_line(s) >= LOG_START_ANALYZE_DATETIME]
        #lines = [s for s in self.read_log(NGINX_LOG_PATH) if self.get_dt_from_line(s) >= LOG_START_ANALYZE_DATETIME] and '/api/testblock' in s
        self.write_tmp_log(log_file_name, lines)
        return log_file_name

    def get_ip_frequency(self):
        ip_dict = {}
        with open(self.get_period_log()) as f:
            for i in f:
                spec_route = i.split('"')[1].split(' ')[1]
                if spec_route == ROUTE:
                    ip_route = i.split('"')[1].split(' ')[1] + ':' + i.split(' ')[0]
                    if ip_route in ip_dict.keys():
                        ip_dict[ip_route] += 1
                    else:
                        ip_dict[ip_route] = 1
                else:
                    pass
        print(ip_dict)
        return ip_dict


class BlockIp(object):
    def __init__(self):
        self.limitation = int(FREQUENCY) * int(INTERVAL)
        self.lg = Logger("/var/log/block_log.log",level="info")
        self.nl = NginxLog()
        pool = redis.ConnectionPool(host=REDIS['host'], port=REDIS['port'], password=REDIS['password'], db=REDIS['db'])
        self.con = redis.Redis(connection_pool=pool)

    def get_all_history(self):
        return self.con.hgetall('block_ip_history')

    def get_block_ip_history(self, route_ip):
        exist_history = self.con.hget('block_ip_history', route_ip)
        #print(exist_history)
        if exist_history:
            return exist_history.decode('utf-8').split(':')
        else:
            return False

    def add_firewall(self, block_ip):
        add_cmd = 'iptables -A INPUT -s ' + block_ip + ' -j DROP'
        os.system(add_cmd)

    def delete_firewall(self, block_ip):
        del_cmd = 'iptables -D INPUT -s ' + block_ip + ' -j DROP'
        os.system(del_cmd)

    def check_firewall(self, block_ip):
        check_cmd = 'iptables -C INPUT -s ' + block_ip + ' -j DROP'
        if os.system(check_cmd) == 0:
            return True
        else:
            return False

    def clear_expire_firewall(self):
        # 查询是否在禁用列表, 不存在则已过期, 根据历史禁用列表删除已过期防火墙策略
        all_history = self.get_all_history()
        for route_ip in all_history.keys():
            ip = route_ip.decode('utf-8').split(':')[1]
            if not self.con.get(route_ip) and self.check_firewall(ip):
                self.delete_firewall(ip)
                print('删除' + ip + '的已过期防火墙策略')
            else:
                print('无遗留未删除过期防火墙策略')

    def block_ip(self):
        # 先清除已有过期防火墙策略
        self.clear_expire_firewall()
        if self.nl.get_ip_frequency():
            for k, v in self.nl.get_ip_frequency().items():
                exist_history = self.get_block_ip_history(k)
                ip = k.split(':')[1]
                # 超过访问次数限制
                if v >= FREQUENCY:
                    # 在禁用历史里可以找到, 有则在原来剩余禁用时间加上新一轮禁用周期
                    if exist_history:
                        frequency, block_time, start_time = exist_history
                        frequency = int(frequency) + v 
                        block_delta = int(time.time()) - int(start_time)
                        # 差值大于默认禁用时间但小于最大禁用时间7天, 则说明key过期了则需要延长过期
                        if int(block_time) <= block_delta <= 600000:
                            block_time = int(block_time) + BLOCK_TIME
                            block_ip_value = str(frequency) + ':' + str(block_time) + ':' + str(int(time.time()))
                            self.con.hset('block_ip_history', k, block_ip_value)
                            # 延长过期时间
                            if not self.con.get(k):
                                self.con.set(k, v)
                                self.con.expire(k, block_time)
                                print('已过期，延长过期时间')
                                # 检查防火墙禁用该ip策略是否还在, 不在则加上
                                if self.check_firewall(ip):
                                #if self.check_firewall('117.136.31.234'):
                                    #self.delete_firewall('117.136.31.234')
                                    print('已存在防火墙策略,无需重复添加')
                                else:
                                    self.add_firewall(ip)
                                    print('expired and add firewall again')
                        # 差值小于禁用时间则说明还在禁用中, 只将访问频率累加
                        elif block_delta < int(block_time):
                            block_ip_value = str(frequency) + ':' + str(block_time) + ':' + start_time
                            self.con.hset('block_ip_history', k, block_ip_value)
                            # 检查防火墙禁用该ip策略是否还在, 不在则加上
                            if self.check_firewall(ip):
                                print('已存在防火墙策略,无需重复添加')
                                #self.delete_firewall('117.136.31.234')
                            else:
                                self.add_firewall(ip)
                                print('still in firewall')
                    else:
                        block_ip_value = str(v) + ':' + str(BLOCK_TIME) + ':' + str(int(time.time()))
                        self.con.set(k, v)
                        self.con.expire(k, int(BLOCK_TIME))
                        self.con.hset('block_ip_history', k, block_ip_value)
                        # 将ip加入防火墙禁用策略
                        self.add_firewall(ip)
                        print('new ip add to firewall')

                # 没有超过访问次数限制且次数不为0的ip
                else:
                    # 在禁用历史里可以找到, 则查看是否禁用了足够时间, 够了就删除redis里该ip对应的key, 并删除防火墙策略
                    if exist_history:
                        # 将ip加入防火墙禁用策略
                        frequency, block_time, start_time = exist_history
                        delta = int(time.time()) - int(start_time)
                        # 未超过访问次数, 删除在历史记录中已过期的ip对应的防火墙策略
                        if delta >= int(block_time):
                            # 删除redis里该ip对应的key
                            self.con.delete(k)
                            # 检查防火墙禁用该ip策略是否还在, 在则删除
                            if self.check_firewall(ip):
                                print('删除未超过次数限制的已过期防火墙策略')
                                self.delete_firewall(ip)
                        else:
                            print('未超过访问限制, 无需任何操作')
                    else:
                        print('未超过访问限制, 无需任何操作')


if __name__ == '__main__':
    bi = BlockIp()
    bi.block_ip()
