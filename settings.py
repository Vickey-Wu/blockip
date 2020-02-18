#!/usr/bin/python

REDIS = {
    'host': 'redis_host',
    'port': 'redis_port',
    'db': 0,
    'password': ''
}

# check nginx log interval time, default 10mins, crontab interval should be the same as `INTERVAL`
INTERVAL = 10

# the same ip access the same api in 1min max time is 3
FREQUENCY = 3

# the api route that need to block ip access, NOT NULL
ROUTE = '/api/testblock'
NGINX_LOG_PATH = '/var/log/nginx/tb_access.log'

# the first time the ip over limit default block 600s (10mins)
BLOCK_TIME = 600
