#!/usr/bin/env python3
"""
eBPF Thread Profiler for Java Applications
Monitors Jetty server performance via syscall correlation
"""
from __future__ import print_function
from bcc import BPF
import argparse
import socket
import time
from ctypes import c_int
from datetime import datetime, timedelta
from time import strftime

# Get system information
hostname = socket.gethostname()
ip_addr = socket.gethostbyname(hostname)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Monitor Java application performance using eBPF syscall tracing",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-p", "--pid", required=True,
                        help="Process ID of Java application to monitor")
    parser.add_argument("-e", "--env", nargs='+', required=True,
                        help="Environment name for organizing monitoring sessions")

    return parser.parse_args()


# eBPF program for Java application monitoring
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Hash tables for tracking file descriptors and metrics
BPF_ARRAY(fd_counts, u64, 1024);           // Track active file descriptors
BPF_ARRAY(request_count, u64, 1);          // Current queue depth
BPF_ARRAY(total_request, u64, 1);          // Total requests processed
BPF_ARRAY(close_fd_counts, u64, 1024);     // Connection timestamps
BPF_ARRAY(total_time, u64, 1);             // Cumulative response time
BPF_ARRAY(total_request_served, u64, 1);   // Completed requests
BPF_ARRAY(threads_used, u64, 100000);      // Thread activity tracking

// Monitor incoming connections (Jetty accept)
TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    int fd_key = args->ret;   
    if (fd_key > 0) {
        u64 fd_val = 1;
        u64 ts = bpf_ktime_get_ns();

        // Mark FD as active and timestamp the connection
        close_fd_counts.update(&fd_key, &ts);
        fd_counts.update(&fd_key, &fd_val);

        // Increment queue depth and total request counters
        request_count.atomic_increment(0);
        total_request.atomic_increment(0);
    }
    return 0;
}

// Monitor request processing start (Jetty read)
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID

    int fd_key = args->fd;
    u64 *fd_addr = fd_counts.lookup(&fd_key);

    // If this FD is tracked (from accept), process the request
    if (fd_addr != NULL && *fd_addr == 1) {     
        u64 fd_val = 0;
        fd_counts.update(&fd_key, &fd_val);

        // Decrement queue depth (request now being processed)
        request_count.atomic_increment(0, -1);

        // Track thread activity
        u64 thread_val = 1;
        threads_used.update(&tid, &thread_val);
    }

    return 0;
}

// Monitor request completion (Jetty response sent)
TRACEPOINT_PROBE(syscalls, sys_enter_shutdown)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    int fd_key = args->fd;
    u64 *tsp = close_fd_counts.lookup(&fd_key);

    // Calculate response time if we have connection timestamp
    if (tsp != NULL && *tsp != 0) {     
        u64 fd_val = 0;
        u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

        // Accumulate response time and increment completed requests
        total_time.atomic_increment(0, delta_us);
        total_request_served.atomic_increment(0);

        // Clear the timestamp
        close_fd_counts.update(&fd_key, &fd_val);
    }
    return 0;
}
"""


def main():
    args = parse_arguments()
    env_name = args.env[0]

    print(f"Environment: {env_name}")
    print(f"Monitoring Java application PID: {args.pid}")

    # Apply PID filter to eBPF program
    filtered_bpf_text = bpf_text.replace('FILTER_PID',
                                         f'if (pid != {args.pid}) {{ return 0; }}')

    # Load eBPF program
    b = BPF(text=filtered_bpf_text)

    S_COUNT = c_int(0)
    thread_run_time = None

    print("eBPF profiler attached successfully")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 50)

    try:
        while True:
            time.sleep(1)

            # Get current metrics
            request_count = b["request_count"][S_COUNT].value
            total_request = b["total_request"][S_COUNT].value
            total_request_served = b["total_request_served"][S_COUNT].value
            total_time_val = b["total_time"][S_COUNT].value

            # Calculate average response time
            avg_response_time = 0
            if total_request_served > 0:
                avg_response_time = (float(total_time_val) / total_request_served) / 1000

            # Display metrics
            print(f"Total Requests: {total_request}")
            print(f"Requests Served: {total_request_served}")
            print(f"Average Response Time: {avg_response_time:.2f}ms")
            print(f"{strftime('%H:%M:%S')}: Queue Depth: {request_count}")

            # Reset counters for next measurement period
            b["total_request"].clear()
            b["total_time"].clear()
            b["total_request_served"].clear()

            # Calculate thread utilization every minute
            if thread_run_time is None:
                thread_run_time = datetime.now() + timedelta(minutes=1)

            if datetime.now() > thread_run_time:
                counter = 0
                threads_used = 0

                # Count active threads
                while counter < 100000:
                    threads_used += b["threads_used"][c_int(counter)].value
                    counter += 1

                # Calculate percentage utilization
                thread_utilization = round((float(threads_used) / 50) * 100, 2)
                print(f"Thread Pool Utilization: {thread_utilization}%")

                # Reset thread counters and timer
                b["threads_used"].clear()
                thread_run_time = datetime.now() + timedelta(minutes=1)
                print("-" * 50)

    except KeyboardInterrupt:
        print("\nStopping eBPF profiler...")


if __name__ == "__main__":
    main()
