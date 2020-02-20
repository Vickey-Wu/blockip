#!/usr/bin/python

import redis
import os
import re
import time
import datetime
import linecache

from settings import *
from logs import Logger


class NginxLog(object):
    def read_log(self, path):
        return linecache.getlines(path)

    def get_dt_from_line(self, s):
        # 匹配Nginx日期格式, 具体格式查看README.md
        # 如果你的Nginx日志格式不一致可以修改本函数的匹配规则及返回的时间格式
        time_stamp = re.search('\[\d+/\w+/\d+:\d+:\d+:\d+', s).group()
        return datetime.datetime.strptime(time_stamp[1:], '%d/%b/%Y:%H:%M:%S')

    def write_tmp_log(self, file_name, content):
        with open(file_name, 'w') as f:
            for c in content:
                f.write(c)

    def clear_tmp_log(self):
        log_file_name = time.strftime("%Y%m",time.localtime())
        clear_cmd = '/bin/rm /var/log/nginx/' + log_file_name + '*.log'
        os.system(clear_cmd)

    def read_whitelist(self, file_name):
        white_list = []
        with open(file_name, 'r') as f:
            for c in f:
                white_list.append(c.strip())
        return white_list

    def is_intranet_ip(self, ip):
        if re.match('^10\.', ip) or re.match('^172\.16\.', ip) or re.match('^192\.168\.', ip):
            return True
        else:
            return False

    def get_period_log(self):
        TIMEDELTA = datetime.timedelta(minutes=INTERVAL)
        LOG_START_ANALYZE_DATETIME = (datetime.datetime.today() - TIMEDELTA)
        log_file_name = '/var/log/nginx/' + time.strftime("%Y%m%d-%H%M%S",time.localtime()) + '.log'
        lines = [s for s in self.read_log(NGINX_LOG_PATH) if '/api/testblock' in s and self.get_dt_from_line(s) >= LOG_START_ANALYZE_DATETIME]
        self.write_tmp_log(log_file_name, lines)
        return log_file_name

    def get_ip_frequency(self):
        '''
        获取超过限制的IP和访问频率
        '''
        ip_dict = {}
        tmp_ip_dict = {}
        with open(self.get_period_log()) as f:
            for i in f:
                spec_route = i.split('"')[1].split(' ')[1]
                ip = i.split(' ')[0]
                # 如果IP在白名单列表或是内网地址则忽略
                if not self.is_intranet_ip(ip) and ip not in self.read_whitelist('whitelist.txt'):
                    ip_route = i.split('"')[1].split(' ')[1] + ':' + i.split(' ')[0]
                    if spec_route == ROUTE and ip_route in tmp_ip_dict.keys():
                        tmp_ip_dict[ip_route] += 1
                        # 将超过限制的ip加入字典
                        if tmp_ip_dict[ip_route] >= FREQUENCY:
                            ip_dict[ip_route] = tmp_ip_dict[ip_route]
                    else:
                        tmp_ip_dict[ip_route] = 1
        print(ip_dict)
        return ip_dict


class BlockIp(object):
    def __init__(self):
        self.limitation = int(FREQUENCY) * int(INTERVAL)
        self.lg = Logger("/var/log/nginx/block_log.log",level="info")
        self.nl = NginxLog()
        pool = redis.ConnectionPool(host=REDIS['host'], port=REDIS['port'], password=REDIS['password'], db=REDIS['db'])
        self.con = redis.Redis(connection_pool=pool)

    def get_all_history(self):
        return self.con.hgetall('block_ip_history')

    def get_block_ip_history(self, route_ip):
        exist_history = self.con.hget('block_ip_history', route_ip)
        if exist_history:
            return exist_history.decode('utf-8').split(':')
        else:
            return False

    def add_firewall(self, block_ip):
        add_cmd = '/sbin/iptables -A INPUT -s ' + block_ip + ' -j DROP'
        os.system(add_cmd)

    def delete_firewall(self, block_ip):
        del_cmd = '/sbin/iptables -D INPUT -s ' + block_ip + ' -j DROP'
        os.system(del_cmd)

    def check_firewall(self, block_ip):
        check_cmd = '/sbin/iptables -C INPUT -s ' + block_ip + ' -j DROP'
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

    def extend_block_time(self, route_ip, frequency, block_time, ip):
        # 延长过期时间并检查防火墙是否存在
        if not self.con.get(route_ip):
            self.con.set(route_ip, frequency)
            self.con.expire(route_ip, block_time)
            print('已过期，延长过期时间')
            # 检查防火墙禁用该ip策略是否还在, 不在则加上
            if self.check_firewall(ip):
                print('已存在防火墙策略,无需重复添加')
            else:
                self.add_firewall(ip)
                print('已存在历史列表的IP再次超过限制，重新加入防火墙')

    def new_ip_add_firewall(self, route_ip, frequency, ip):
        # 还未在历史列表出现过的新ip超过现在加入防火墙
        block_ip_value = str(frequency) + ':' + str(BLOCK_TIME) + ':' + str(int(time.time()))
        self.con.set(route_ip, frequency)
        self.con.expire(route_ip, int(BLOCK_TIME))
        self.con.hset('block_ip_history', route_ip, block_ip_value)
        # 将ip加入防火墙禁用策略
        self.add_firewall(ip)
        print('超过限制的新IP加入防火墙')

    def history_ip_add_firewall(self, route_ip, latest_frequency, ip):
        frequency, block_time, start_time = self.get_block_ip_history(route_ip)
        frequency = int(frequency) + latest_frequency 
        block_delta = int(time.time()) - int(start_time)
        # 差值大于默认禁用时间但小于最大禁用时间7天, 则说明key过期了则需要延长过期
        if int(block_time) <= block_delta <= 600000:
            block_time = int(block_time) + BLOCK_TIME
            block_ip_value = str(frequency) + ':' + str(block_time) + ':' + str(int(time.time()))
            self.con.hset('block_ip_history', route_ip, block_ip_value)
            self.extend_block_time(route_ip, latest_frequency, block_time, ip)
        # 差值小于禁用时间则说明还在禁用中, 只将访问频率累加
        elif block_delta < int(block_time):
            block_ip_value = str(frequency) + ':' + str(block_time) + ':' + start_time
            self.con.hset('block_ip_history', route_ip, block_ip_value)
            # 为防止未过期IP的redis键被误删，当检测到没有键时重新加入键
            if not self.con.get(route_ip):
                self.con.set(route_ip, latest_frequency)
                expire_time = int(block_time) - block_delta
                self.con.expire(route_ip, expire_time)
            # 检查防火墙禁用该ip策略是否还在, 不在则加上
            if self.check_firewall(ip):
                print('IP仍在禁用中且已存在防火墙策略,无需重复添加')
            else:
                self.add_firewall(ip)
                print('未过期但无防火墙策略，已重新添加')

    def block_ip(self):
        for k, v in self.nl.get_ip_frequency().items():
            exist_history = self.get_block_ip_history(k)
            ip = k.split(':')[1]
            if exist_history:
                self.history_ip_add_firewall(k, v, ip)
            else:
                self.new_ip_add_firewall(k, v, ip)


if __name__ == '__main__':
    nl = NginxLog()
    # 先清除临时生成的log文件
    nl.clear_tmp_log()
    bi = BlockIp()
    # 先清除已有过期防火墙策略
    bi.clear_expire_firewall()
    # 后将超过访问限制的IP加入防火墙
    bi.block_ip()
