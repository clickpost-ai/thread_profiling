#!/usr/bin/env python3
"""
eBPF Thread Profiler for Python Applications
Advanced syscall correlation profiler with lock contention and I/O wait analysis
"""
from __future__ import print_function
from bcc import BPF
import argparse
import socket
import time
import sys
from ctypes import c_int
from datetime import datetime, timedelta
from time import strftime

# Configuration
ELASTICSEARCH_ENABLED = False  # Set to True to enable ES integration
ES_HOST = 'your-elasticsearch-host'
ES_USERNAME = 'your-username'
ES_PASSWORD = 'your-password'

# System information
hostname = socket.gethostname()
ip_addr = socket.gethostbyname(hostname)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Advanced eBPF profiler for application performance monitoring via syscall correlation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p 1234,5678 -e production
  %(prog)s -p 9999 -e development
        """)

    parser.add_argument("-p", "--pid", nargs='+', required=True,
                        help="Process IDs to monitor (comma-separated)")
    parser.add_argument("-e", "--env", nargs='+', required=True,
                        help="Environment name for organizing monitoring sessions")

    return parser.parse_args()


def setup_elasticsearch():
    """Initialize Elasticsearch connection if enabled"""
    if ELASTICSEARCH_ENABLED:
        try:
            from elasticsearch import Elasticsearch
            es = Elasticsearch(ES_HOST,
                               http_auth=(ES_USERNAME, ES_PASSWORD),
                               verify_certs=False,
                               ssl_show_warn=False)
            return es
        except ImportError:
            print("Warning: elasticsearch library not available. Metrics will only be displayed.")
            return None
    return None


# eBPF program with comprehensive syscall correlation and lock analysis
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Structure for lock timing analysis
struct lock_ts {
    u32 pid;
    u64 ts;
};

// Hash tables and arrays for comprehensive monitoring
BPF_ARRAY(fd_counts, u64, 4000);                    // File descriptor tracking
BPF_ARRAY(request_queued, u64, 1);                  // Current queue depth
BPF_ARRAY(threads_used, u64, 100000);               // Thread activity map
BPF_ARRAY(total_request, u64, 1);                   // Total processed requests
BPF_ARRAY(epoll_fd, u64, 4000);                     // Event loop FD tracking
BPF_ARRAY(fd_request_ts, u64, 4000);                // Request timestamp tracking
BPF_ARRAY(total_time, u64, 1);                      // Cumulative response time
BPF_ARRAY(lock_time, u64, 1);                       // Total lock contention time
BPF_ARRAY(io_wait_time, u64, 1);                    // I/O wait accumulator
BPF_ARRAY(connection_accepted_fd, u64, 4000);       // Connection state tracking

// Hash maps for advanced analysis
BPF_HASH(lock_details, u32, struct lock_ts);        // Per-thread lock timing
BPF_HASH(pid_io_wait, u32);                         // I/O wait state per thread

// Syscall correlation: Step 1 - Connection acceptance
TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    int fd_key = args->ret; 
    if (fd_key > 0) {
        int final_val;
        u64 fd_val = 1;
        FD_SETUP 

        // Namespace FD by process for multi-process monitoring
        int final_fd_key = final_val + fd_key;
        fd_counts.update(&final_fd_key, &fd_val);

        // Mark connection as accepted
        int connection_accepted_fd_key = final_val + fd_key;
        u64 connection_accepted_fd_val = 1;
        connection_accepted_fd.update(&connection_accepted_fd_key, &connection_accepted_fd_val);
    }
    return 0;
}

// Syscall correlation: Step 2 - Event loop management
TRACEPOINT_PROBE(syscalls, sys_enter_epoll_ctl)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    FILTER_TID

    int fd_key = args->fd;
    int final_val;
    int op = args->op;
    FD_SETUP

    int final_epoll_key = final_val + fd_key;
    // EPOLL_CTL_DEL (2) indicates connection cleanup
    if (fd_key > 0 && op == 2) {
        u64 epoll_val = 1;
        epoll_fd.update(&final_epoll_key, &epoll_val);
    }
    return 0;
}

// Syscall correlation: Step 3 - Non-blocking setup detection
TRACEPOINT_PROBE(syscalls, sys_enter_ioctl)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID
    FILTER_TID

    int fd_key = args->fd;
    int final_val;
    FD_SETUP

    int final_ioctl_key = final_val + fd_key;
    u64 *ioctl_addr = epoll_fd.lookup(&final_ioctl_key);
    int final_fd_key = final_val + fd_key;
    u64 fd_val = 1;

    int connection_accepted_fd_key = final_val + fd_key;
    u64 connection_accepted_fd_val = 1;

    // FIONBIO (21537) - non-blocking I/O setup
    if (ioctl_addr != NULL && *ioctl_addr == 1 && args->cmd == 21537) {
        fd_counts.update(&final_fd_key, &fd_val);
        request_queued.atomic_increment(0);  // Increment queue depth
        connection_accepted_fd.update(&connection_accepted_fd_key, &connection_accepted_fd_val);
    }
    return 0;
}

// Syscall correlation: Step 4 - Request processing begins
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID

    int fd_key = args->fd; 
    int final_val;
    FD_SETUP

    int final_fd_key = final_val + fd_key;
    int fd_request_final_key = final_val + fd_key;

    // Check if this FD is from our accepted connections
    int connection_accepted_fd_key = final_val + fd_key;
    u64* connection_accepted_addr = connection_accepted_fd.lookup(&connection_accepted_fd_key);

    // Track thread activity
    u64 thread_val = 1;
    threads_used.update(&tid, &thread_val);

    if (connection_accepted_addr != NULL && *connection_accepted_addr == 1) {       
        // Clear tracking states
        int final_epoll_key = final_val + fd_key;
        u64 epoll_val = 0;
        u64 connection_accepted_fd_val = 0;

        epoll_fd.update(&final_epoll_key, &epoll_val);
        connection_accepted_fd.update(&connection_accepted_fd_key, &connection_accepted_fd_val);

        // Decrement queue depth (request now being processed)
        int zero_key = 0;
        u64 *current_count = request_queued.lookup(&zero_key);
        if (current_count != NULL && *current_count > 0) {
            request_queued.atomic_increment(0, -1);
        }

        // Start request timing
        u64 rs_ts = bpf_ktime_get_ns();
        fd_request_ts.update(&fd_request_final_key, &rs_ts);
        total_request.atomic_increment(0);
    }
    return 0;
}

// Syscall correlation: Step 5 - Response completion
TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    int fd_key = args->fd; 
    int final_val;
    FD_SETUP

    int fd_request_final_key = final_val + fd_key;
    u64 *request_ts = fd_request_ts.lookup(&fd_request_final_key);

    // Calculate end-to-end response time
    if (request_ts != NULL && *request_ts > 0) {    
        u64 api_latency = (bpf_ktime_get_ns() - *request_ts) / 1000;
        total_time.atomic_increment(0, api_latency);
        fd_request_ts.delete(&fd_request_final_key);
    } 
    return 0;
}

// Connection cleanup and resource tracking
TRACEPOINT_PROBE(syscalls, sys_enter_close)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID

    int fd_key = args->fd; 
    int final_val;
    FD_SETUP

    int final_fd_key = final_val + fd_key;
    int final_epoll_key = final_val + fd_key;
    int fd_request_final_key = final_val + fd_key;
    int connection_accepted_fd_key = final_val + fd_key;

    // Clean up all tracking states
    u64 epoll_val = 0;
    u64 fd_val = 0;
    u64 connection_accepted_fd_val = 0;

    epoll_fd.update(&final_epoll_key, &epoll_val);
    fd_counts.update(&final_fd_key, &fd_val);
    fd_request_ts.delete(&fd_request_final_key);
    connection_accepted_fd.update(&connection_accepted_fd_key, &connection_accepted_fd_val);

    // Clean up I/O wait tracking for this thread
    pid_io_wait.delete(&tid);
    return 0;
}

// Lock contention analysis: Mutex entry timing
int mutex_entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID

    u64 ts = bpf_ktime_get_ns();
    struct lock_ts lock = {};
    lock.pid = pid;
    lock.ts = ts;
    lock_details.update(&tid, &lock);
    return 0;
}

// Lock contention analysis: Mutex exit timing
int mutex_exit(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    FILTER_PID

    struct lock_ts *lock_obj = lock_details.lookup(&tid);
    if (lock_obj != NULL) {
        u64 delta_us = 0;
        u64 curr_time = bpf_ktime_get_ns();
        delta_us = (curr_time - lock_obj->ts) / 1000;
        lock_time.atomic_increment(0, delta_us);
        lock_details.delete(&tid);
    }    
    return 0;
}

// I/O wait analysis: Context switch monitoring
int oncpu(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    FILTER_PREV_PID

    u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    u32 curr_tgid = bpf_get_current_pid_tgid();
    FILTER_CURR_PID

    u64 *tsp = pid_io_wait.lookup(&curr_tgid);
    if (tsp != NULL) {
        u64 curr_time = bpf_ktime_get_ns();
        u64 io_wait_delta = (curr_time - *tsp) / 1000;
        io_wait_time.atomic_increment(0, io_wait_delta);
        pid_io_wait.delete(&curr_tgid);
    }
    return 0;
}
"""


def setup_ebpf_program(args, bpf_text):
    """Configure eBPF program with PID filtering and multi-process support"""
    first_pid = None

    if args.pid:
        pid_text = ""
        tid_text = ""
        curr_pid_text = ""

        for pid in args.pid:
            if first_pid is None:
                first_pid = pid
            pid_text += f"pid != {pid} && "
            tid_text += f"tid != {pid} && "
            curr_pid_text += f"curr_pid != {pid} && "

        pid_text = pid_text.rstrip("&& ")
        tid_text = tid_text.rstrip("&& ")
        curr_pid_text = curr_pid_text.rstrip("&& ")

        # Apply PID filters
        bpf_text = bpf_text.replace('FILTER_PID', f'if ({pid_text}){{ return 0; }}')
        bpf_text = bpf_text.replace('FILTER_CURR_PID', f'if ({curr_pid_text}){{ return 0; }}')
        bpf_text = bpf_text.replace('FILTER_TID', f'if ({tid_text}){{ return 0; }}')

        # Setup FD namespacing for multi-process monitoring
        fd_counter = -1
        fd_setup_text = ""
        for pid in args.pid:
            fd_counter += 1
            pid_text = f"""if (pid == {pid})
            {{
                final_val = {fd_counter};
            }}
        """
            fd_setup_text += pid_text
            fd_counter += 1500

        # Setup I/O wait monitoring
        older_pid_text = " || ".join([f"pid == {pid}" for pid in args.pid])
        bpf_text = bpf_text.replace('FILTER_PREV_PID',
                                    f'if ({older_pid_text}){{  u64 ts = bpf_ktime_get_ns(); pid_io_wait.update(&tgid, &ts); }}')
        bpf_text = bpf_text.replace('FD_SETUP', fd_setup_text)

    return bpf_text, first_pid


def attach_probes(b, first_pid):
    """Attach uprobe and kprobe for lock and I/O analysis"""
    if first_pid:
        try:
            mutex_uprobe = f"/proc/{first_pid}/root/lib/aarch64-linux-gnu/libpthread.so.0"
            b.attach_uprobe(name=mutex_uprobe, sym="pthread_mutex_lock", fn_name="mutex_entry")
            b.attach_uretprobe(name=mutex_uprobe, sym="pthread_mutex_lock", fn_name="mutex_exit")
            print(f"Attached mutex profiling for PID {first_pid}")
        except Exception as e:
            print(f"Warning: Could not attach mutex probes: {e}")

        try:
            b.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$', fn_name="oncpu")
            print("Attached I/O wait monitoring")
        except Exception as e:
            print(f"Warning: Could not attach I/O wait probes: {e}")


def export_metrics(es, env_name, metrics):
    """Export metrics to Elasticsearch if configured"""
    if not es:
        return

    try:
        # Define index names
        queue_index = f"{env_name}-queue-size"
        request_index = f"{env_name}-request-count"
        thread_index = f"{env_name}-thread-pool-utilisation"

        # Export metrics (implementation depends on your ES schema)
        # This is a placeholder - customize based on your needs
        pass
    except Exception as e:
        print(f"Warning: Could not export to Elasticsearch: {e}")


def main():
    args = parse_arguments()
    env_name = args.env[0]

    print(f"eBPF Thread Profiler - Environment: {env_name}")
    print(f"Monitoring PIDs: {', '.join(args.pid)}")
    print(f"Host: {hostname} ({ip_addr})")

    # Setup Elasticsearch if enabled
    es = setup_elasticsearch()

    # Configure eBPF program
    configured_bpf_text, first_pid = setup_ebpf_program(args, bpf_text)

    # Load eBPF program
    try:
        b = BPF(text=configured_bpf_text)
        attach_probes(b, first_pid)
    except Exception as e:
        print(f"Error loading eBPF program: {e}")
        sys.exit(1)

    S_COUNT = c_int(0)
    thread_run_time = None

    print("Profiler started successfully")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 60)

    try:
        while True:
            time.sleep(1)

            # Get real-time queue depth
            request_count = b["request_queued"][S_COUNT].value
            print(f"Queue Depth: {request_count}")

            # Detailed metrics every 15 seconds
            if thread_run_time is None:
                thread_run_time = datetime.now() + timedelta(seconds=15)

            if datetime.now() > thread_run_time:
                # Collect comprehensive metrics
                counter = 0
                threads_used = 0
                while counter < 100000:
                    threads_used += b["threads_used"][c_int(counter)].value
                    counter += 1

                total_request = b["total_request"][S_COUNT].value
                total_lock_time = float(b["lock_time"][S_COUNT].value) / 1000
                total_time = b["total_time"][S_COUNT].value
                io_wait_time = float(b["io_wait_time"][S_COUNT].value) / 1000

                # Calculate derived metrics
                avg_response_time = 0
                if total_request != 0:
                    avg_response_time = round((float(total_time) / total_request), 2)

                io_wait_per_thread = 0
                if threads_used != 0:
                    io_wait_per_thread = float(io_wait_time) / threads_used / 1000

                # Display comprehensive metrics
                print(f"\n=== Performance Summary ({strftime('%H:%M:%S')}) ===")
                print(f"Active Threads: {threads_used}")
                print(f"Total Requests: {total_request}")
                print(f"Avg Response Time: {avg_response_time / 1000:.3f}ms")
                print(f"Lock Contention: {total_lock_time:.2f}ms total")
                print(f"I/O Wait Time: {io_wait_time:.2f}ms total")
                print(f"I/O Wait per Thread: {io_wait_per_thread:.3f}s")

                # Export to monitoring system
                metrics = {
                    'threads_used': threads_used,
                    'total_request': total_request,
                    'avg_response_time': avg_response_time,
                    'lock_latency': total_lock_time,
                    'io_wait_time': io_wait_time,
                    'io_wait_per_thread': io_wait_per_thread
                }
                export_metrics(es, env_name, metrics)

                # Reset counters
                b["total_request"].clear()
                b["threads_used"].clear()
                b["lock_time"].clear()
                b["total_time"].clear()
                b["io_wait_time"].clear()
                thread_run_time = datetime.now() + timedelta(seconds=15)
                print("-" * 60)

    except KeyboardInterrupt:
        print("\nShutting down eBPF profiler...")


if __name__ == "__main__":
    main()
