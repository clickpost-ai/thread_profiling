#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime
from ctypes import c_int
from elasticsearch import Elasticsearch
from datetime import datetime, timezone
from datetime import datetime,timedelta

# import timezone

HOST_NAME = 'Host Name'
USERNAME = 'username'
PASSWORD = 'password'

import socket

hostname = socket.gethostname()
ip_Addr = socket.gethostbyname(hostname)

# Connect to Elasticsearch
es = Elasticsearch(HOST_NAME,
                   http_auth=(USERNAME, PASSWORD),
                   verify_certs=False,  # Disable SSL cert verification
                   ssl_show_warn=False  # Disable warnings for unverified SSL)
                   )

parser = argparse.ArgumentParser(
    description="Trace number of queue requests in jetty server",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-e", "--env", nargs='+',
                    help="env name")

args = parser.parse_args()
env_name=args.env[0]

print("env name "+str(env_name))

index_create = env_name.upper()+'-Jetty-Queue-Size'
server_name = env_name
f_index = env_name+'-jetty-prod-queue-size'
r_index = env_name+'-prod-request-count'
thread_index=env_name+'-prod-thread-pool-utilisation'
es.indices.create(index=index_create, ignore=400)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_ARRAY(fd_counts, u64,1024);
BPF_ARRAY(request_count, u64,1);
BPF_ARRAY(total_request, u64,1);
BPF_ARRAY(close_fd_counts,u64,1024);
BPF_ARRAY(total_time,u64,1);
BPF_ARRAY(total_request_served, u64,1);
BPF_ARRAY(threads_used, u64,100000);

TRACEPOINT_PROBE(syscalls,sys_exit_accept)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    int fd_key=args->ret;   
    u64 fd_val=1;
    u64 ts=bpf_ktime_get_ns();
    close_fd_counts.update(&fd_key,&ts);

    fd_counts.update(&fd_key,&fd_val);
    request_count.atomic_increment(0);
    total_request.atomic_increment(0);
    return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_read)
{

     u32 pid = bpf_get_current_pid_tgid() >> 32;
     u32 tid = bpf_get_current_pid_tgid();
     FILTER_PID
     int fd_key=args->fd;
     u64 *fd_addr=fd_counts.lookup(&fd_key);
     if(fd_addr!=NULL &&  *fd_addr == 1)
     {     
      	u64 fd_val=0;
     	fd_counts.update(&fd_key,&fd_val);
     	request_count.atomic_increment(0,-1);
     	u64 thread_val=1;
        threads_used.update(&tid,&thread_val);
     }

     return 0;
}


TRACEPOINT_PROBE(syscalls,sys_enter_shutdown)
{

     u32 pid = bpf_get_current_pid_tgid() >> 32;
     FILTER_PID
     int fd_key=args->fd;
     u64 *tsp=close_fd_counts.lookup(&fd_key);
     int t_key=0;
     if(tsp!=NULL && *tsp!=0)
     {     
        u64 fd_val=0;
        u64 delta_us=0;
        delta= (bpf_ktime_get_ns() - *tsp)_us /1000;
        total_time.atomic_increment(0,delta_us);
        total_request_served.atomic_increment(0);
        close_fd_counts.update(&fd_key,&fd_val);

     }
     return 0;
}







"""
S_COUNT = c_int(0)
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
                                'if (pid != %s) { return 0; }' % args.pid)
b = BPF(text=bpf_text)
import time

thread_run_time=None
while (1):
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        exit()

    request_count = b["request_count"][S_COUNT].value
    total_request = b["total_request"][S_COUNT].value
    total_request_served = b["total_request_served"][S_COUNT].value
    total_time = b["total_time"][S_COUNT].value
    if total_request_served > 0:
        total_time = (float(total_time) / total_request_served) / 1000
    b["total_request"].clear()
    b["total_time"].clear()
    b["total_request_served"].clear()
    if thread_run_time is None:
        thread_run_time=datetime.now() + timedelta(minutes=1)
    if datetime.now() > thread_run_time:
        counter = 0
        threads_used = 0
        while counter < 100000:
            threads_used += b["threads_used"][c_int(counter)].value
            counter += 1
        threads_used = round((float(threads_used) / 50) * 100,2)
        b["threads_used"].clear()
        thread_run_time = datetime.now() + timedelta(minutes=1)
        thread_doc={
            "server_name": server_name,
            "published_date": datetime.now(timezone.utc),
            "machine ip": ip_Addr,
            "threads_used": threads_used
        }
        es.index(index=thread_index, body=thread_doc)
    current_date = datetime.now()
    str_date = str(
        datetime(current_date.year, current_date.month, current_date.day, current_date.hour, current_date.minute,
                 current_date.second))
    document = {
        "server_name": server_name,
        "published_date": datetime.now(timezone.utc),
        "machine ip": ip_Addr,
        "request_queued": request_count
    }

    request_doc = {
        "server_name": server_name,
        "published_date": datetime.now(timezone.utc),
        "machine ip": ip_Addr,
        "total_request": total_request,
        "total_time": total_time,
    }
    # Indexing document
    es.index(index=f_index, body=document)
    es.index(index=r_index, body=request_doc)
