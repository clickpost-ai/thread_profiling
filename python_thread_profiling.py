#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime
from ctypes import c_int
from datetime import datetime, timezone
from datetime import datetime, timedelta
import time
import sys

HOST_NAME = 'host_link'
USERNAME = "username"
PASSWORD = "passwoed"

import socket

hostname = socket.gethostname()
ip_Addr = socket.gethostbyname(hostname)


# arguments
examples = """examples:
    sudo python3 super_final_wsgi_queued_count -p 181  ,182  # comma seprated pids
"""
parser = argparse.ArgumentParser(
    description="Trace number of queue requests in jetty server",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-p", "--pid", nargs='+',
                    help="trace this PID only")
parser.add_argument("-e", "--env", nargs='+',
                    help="env name")
args = parser.parse_args()

env_name=args.env[0]
index_create = env_name +'-QUEUE-SIZE'
server_name = env_name
f_index = env_name+'-queue-size'
r_index = env_name+'-request-count'
thread_index = env_name+'-thread-pool-utilisation'

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>


struct lock_ts
{
    u32 pid;
    u64 ts;
};

BPF_ARRAY(fd_counts, u64,4000);
BPF_ARRAY(request_queued, u64,1);
BPF_ARRAY(threads_used, u64,100000);
BPF_ARRAY(total_request, u64,1);
BPF_ARRAY(epoll_fd, u64,4000);
BPF_ARRAY(fd_request_ts, u64,4000);
BPF_ARRAY(total_time,u64,1);
BPF_ARRAY(lock_time, u64,1);
BPF_HASH(lock_details,u32,struct lock_ts);
BPF_HASH(pid_io_wait, u32);
BPF_ARRAY(io_wait_time, u64,1);
BPF_ARRAY(connection_accepted_fd, u64,4000);


TRACEPOINT_PROBE(syscalls,sys_exit_accept4)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    int fd_key=args->ret; 
    if(fd_key > 0)
    {
        int final_val;
        u64 fd_val=1;
        FD_SETUP 
        int final_fd_key=final_val + fd_key;
        fd_counts.update(&final_fd_key,&fd_val);
        request_queued.atomic_increment(0);
        
        int connection_accepted_fd_key=final_val + fd_key;
        u64 connection_accepted_fd_val=1;
        connection_accepted_fd.update(&connection_accepted_fd_key,&connection_accepted_fd_val);

    
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_epoll_ctl)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    FILTER_TID
    int fd_key=args->fd;
    int final_val;
    int op=args->op;
    FD_SETUP
    int final_epoll_key=final_val + fd_key;
    // 2 -> EPOLL_CTL_DEL
    if(fd_key > 0 && op == 2)
    {
        u64 epoll_val=1;
        epoll_fd.update(&final_epoll_key,&epoll_val);

    }
    return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_ioctl)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    FILTER_TID
    int fd_key=args->fd;
    int final_val;
    FD_SETUP
    int final_ioctll_key=final_val + fd_key;
    u64 *ioctl_addr=epoll_fd.lookup(&final_ioctll_key);
    int final_fd_key=final_val + fd_key;
    u64 fd_val = 1;
    
    int connection_accepted_fd_key=final_val + fd_key;
    u64 connection_accepted_fd_val=1;
    
    //21537 -> FION_BIO
    if(ioctl_addr!=NULL && *ioctl_addr == 1 && args->cmd == 21537)
    {
         fd_counts.update(&final_fd_key,&fd_val);
         request_queued.atomic_increment(0);
         connection_accepted_fd.update(&connection_accepted_fd_key,&connection_accepted_fd_val);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_recvfrom)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    int fd_key=args->fd; 
    int final_val;
    FD_SETUP
    int final_fd_key=final_val + fd_key;
    int fd_request_final_key=final_val + fd_key;

    u64 *fd_addr=fd_counts.lookup(&final_fd_key);
    int final_epoll_key=final_val + fd_key;
    u64 epoll_val=0;
    
    int connection_accepted_fd_key=final_val + fd_key;
    u64 connection_accepted_fd_val=0;
    u64* connection_accepted_addr=connection_accepted_fd.lookup(&connection_accepted_fd_key);
    if(fd_addr!=NULL && *fd_addr == 1 && connection_accepted_addr!=NULL && *connection_accepted_addr == 1)
    {       
            epoll_fd.update(&final_epoll_key,&epoll_val);
            request_queued.atomic_increment(0,-1);
            connection_accepted_fd.update(&connection_accepted_fd_key,&connection_accepted_fd_val);
            u64 rs_ts=bpf_ktime_get_ns();
            fd_request_ts.update(&fd_request_final_key,&rs_ts);
            total_request.atomic_increment(0);
            u64 thread_val=1;
            threads_used.update(&tid,&thread_val);
    }
 return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_sendto)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    int fd_key=args->fd; 
    int final_val;
    FD_SETUP
    int final_fd_key=final_val + fd_key;
    int fd_request_final_key=final_val + fd_key;
    u64 *fd_addr=fd_counts.lookup(&final_fd_key);
    u64 *request_ts=fd_request_ts.lookup(&fd_request_final_key);
    if(fd_addr!=NULL &&  *fd_addr == 1 && request_ts!=NULL && request_ts > 0)
    {    
        u64 api_latency= (bpf_ktime_get_ns() - *request_ts)/1000;
        total_time.atomic_increment(0,api_latency);
        fd_request_ts.delete(&fd_request_final_key);
    } 
 return 0;
}

TRACEPOINT_PROBE(syscalls,sys_enter_close)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    int fd_key=args->fd; 
    int final_val;
    FD_SETUP
    int final_fd_key=final_val + fd_key;

    u64 *fd_addr=fd_counts.lookup(&final_fd_key);
    int final_epoll_key=final_val + fd_key;
    u64 epoll_val=0;
    epoll_fd.update(&final_epoll_key,&epoll_val);
    
    u64 fd_val=0;
    fd_counts.update(&final_fd_key,&fd_val);
    
    int fd_request_final_key=final_val + fd_key;
    fd_request_ts.delete(&fd_request_final_key);
    
    int connection_accepted_fd_key=final_val + fd_key;
    u64 connection_accepted_fd_val=0;
    connection_accepted_fd.update(&connection_accepted_fd_key,&connection_accepted_fd_val);
    
    pid_io_wait.delete(&tid);
    return 0;
}

 int mutex_entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    u64 ts=bpf_ktime_get_ns();
    struct lock_ts lock ={};
    lock.pid=pid;
    lock.ts=ts;
    lock_details.update(&tid,&lock);
    return 0;
}

int mutex_exit(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    struct lock_ts *lock_obj=lock_details.lookup(&tid);
    if (lock_obj != NULL)
    {
        u64 delta_us=0;
        u64 curr_time=bpf_ktime_get_ns();
        delta_us = (curr_time - lock_obj->ts)/1000;
        lock_time.atomic_increment(0,delta_us);
        lock_details.delete(&tid);
    }    
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    FILTER_PREV_PID
    u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    u32 curr_tgid = bpf_get_current_pid_tgid();
    FILTER_CURR_PID
    u64 *tsp=pid_io_wait.lookup(&curr_tgid);
    if (tsp != NULL) {
        u64 curr_time=bpf_ktime_get_ns();
        u64 io_wait_delta = (curr_time - *tsp) / 1000;
        io_wait_time.atomic_increment(0, io_wait_delta);
        pid_io_wait.delete(&curr_tgid);
    }
    return 0;
}

"""

S_COUNT = c_int(0)
first_pid = None
if args.pid:
    pid_text = ""
    tid_text= ""
    curr_pid_text=""
    for pid in args.pid:
        if first_pid is None:
            first_pid = pid
        pid_text += "pid != %s && " % pid
        tid_text += "tid != %s && " % pid
        curr_pid_text += "curr_pid != %s && " % pid
    pid_text = pid_text.rstrip("&& ")
    tid_text = tid_text.rstrip("&& ")
    curr_pid_text=curr_pid_text.rstrip("&& ")
    bpf_text = bpf_text.replace('FILTER_PID',
                                'if (''' + pid_text + '''){ return 0; }''')
    bpf_text = bpf_text.replace('FILTER_CURR_PID',
                                'if (''' + curr_pid_text + '''){ return 0; }''')
    bpf_text = bpf_text.replace('FILTER_TID',
                                'if (''' + tid_text + '''){ return 0; }''')
    fd_counter = -1
    fd_setup_text = ""
    for pid in args.pid:
        fd_counter += 1
        pid_text = """if (pid == """ + pid + """)
            {
                final_val = """ + str(fd_counter) + """;
            }
        """
        fd_setup_text += pid_text
        fd_counter += 500
    older_pid_text=""
    for pid in args.pid:
        older_pid_text += "pid == %s || " % pid
    older_pid_text = older_pid_text.rstrip("|| ")
    bpf_text = bpf_text.replace('FILTER_PREV_PID', 'if (''' + older_pid_text + '''){  u64 ts = bpf_ktime_get_ns();
    pid_io_wait.update(&tgid, &ts); }''')
    bpf_text = bpf_text.replace('FD_SETUP', fd_setup_text)
#print(bpf_text)
b = BPF(text=bpf_text)

mutex_uprobe = "/proc/{0}/root/lib/aarch64-linux-gnu/libpthread.so.0".format(first_pid)

b.attach_uprobe(
    name=mutex_uprobe,
    sym="pthread_mutex_lock", fn_name="mutex_entry")
b.attach_uretprobe(
    name=mutex_uprobe,
    sym="pthread_mutex_lock", fn_name="mutex_exit")
b.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$',
                fn_name="oncpu")

thread_run_time = None
while (1):
    try:
        time.sleep(1)
        request_count = b["request_queued"][S_COUNT].value
        print("request queued " + str(request_count))
        if thread_run_time is None:
            thread_run_time = datetime.now() + timedelta(seconds=15)
        if datetime.now() > thread_run_time:
            counter = 0
            threads_used = 0
            while counter < 100000:
                threads_used += b["threads_used"][c_int(counter)].value
                counter += 1
            print("threads used " + str(threads_used))
            total_request = b["total_request"][S_COUNT].value
            print("total request " + str(total_request))
            total_lock_time = float(b["lock_time"][S_COUNT].value)/1000
            print("total lock time "+str(total_lock_time))
            total_time = b["total_time"][S_COUNT].value
            if total_request != 0:
                total_time = round((float(total_time) / total_request), 2)
                print("total time " + str(total_time/1000))

            io_wait_time = float(b["io_wait_time"][S_COUNT].value) / 1000
            print("io wait time final " + str(io_wait_time))
            io_wait_per_thread=0
            if threads_used!=0:
                io_wait_per_thread = float(io_wait_time) / threads_used
                io_wait_per_thread = io_wait_per_thread / 1000

            print("io wait per thread in seconds " + str(io_wait_per_thread))
            b["total_request"].clear()
            b["threads_used"].clear()
            b["lock_time"].clear()
            b["total_time"].clear()
            b["io_wait_time"].clear()
            thread_run_time = datetime.now() + timedelta(seconds=15)

    except KeyboardInterrupt:
        exit()

