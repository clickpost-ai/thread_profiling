# eBPF Thread Profiler

A production-ready eBPF profiler that monitors application performance through kernel syscall correlation, providing insights into queue depth, thread utilization, and response times **without any application instrumentation**.

## Key Innovation: Syscall Correlation

This profiler works by correlating Linux syscalls to understand application behavior at the kernel level:

```
accept4() → epoll_ctl() → ioctl() → recvfrom() → sendto()
    ↓           ↓          ↓         ↓           ↓
Connection   Event      Setup    Request    Response
Accept      Register   NonBlk    Start      Complete
```

By tracking this syscall sequence for each file descriptor, we derive application-level metrics:
- **Queue Depth**: Connections accepted but not yet processed
- **Thread Utilization**: Active worker threads in thread pools  
- **Response Times**: End-to-end request processing latency
- **Lock Contention**: Mutex wait times via pthread_mutex_lock profiling
- **I/O Wait**: Time spent waiting for network/disk operations
- **Lock Latency**: Detailed analysis of mutex blocking patterns

## Multi-Language Support

Works with **any application** using standard Linux networking syscalls:
- **Java**: Jetty, Tomcat, Spring Boot applications
- **Python**: Django, Flask, FastAPI web servers
- **Node.js, Go, Rust**: Any HTTP server implementation
- **Zero application code changes** required

## Production Impact

Deployed in production at Clickpost for 18+ months:
- **40% reduction** in server instances through better resource utilization
- **Early detection** of performance bottlenecks before service degradation  
- **Real-time queue monitoring** enabling automated scaling decisions
- **Cost savings** through optimized resource usage

Read more: [How We Scaled Servers While Reducing Cloud Costs Using eBPF](https://www.clickpost.ai/blog/scaled-servers-while-curtailing-our-cloud-costs-using-ebpf)

## Installation

### Prerequisites
- Linux system with BPF support (kernel 4.1+)
- Root privileges for eBPF program loading
- BCC (BPF Compiler Collection)

### Amazon Linux 2
```bash
sudo amazon-linux-extras install BCC -y
```

### Other Distributions
Follow the [BCC Installation Guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

## Usage

### Java Application Monitoring
```bash
sudo python3 java_thread_profiling.py -e production -p 1234,1235
```

### Python Application Monitoring  
```bash
sudo python3 python_thread_profiling.py -e production -p 5678,5679
```

### Parameters
- `-e, --env`: Environment name for organizing monitoring sessions
- `-p, --pid`: Comma-separated list of process IDs to monitor

## Example Output

```
Request Queue Depth: 45 requests
Thread Pool Usage: 78.5% (157/200 threads active)
Average Response Time: 245ms
Lock Latency: 12.3ms average mutex wait time
I/O Wait Time: 89ms per request

Performance Metrics:
- accept4(): 1,240 calls/sec (connection handling)
- recvfrom(): 1,180 calls/sec (request processing)  
- sendto(): 1,165 calls/sec (response delivery)
- pthread_mutex_lock: 2,340 calls with 8.7ms avg contention

Detailed Lock Analysis:
- Total lock time: 15.2 seconds over measurement period
- Lock contention events: 234 blocking occurrences
- Critical section analysis: Database operations show highest mutex wait
```

## How It Works

### eBPF Implementation
- **Syscall tracepoints** on accept4, epoll_ctl, ioctl, recvfrom, sendto
- **Uprobe/uretprobe** on pthread_mutex_lock for lock contention analysis
- **Kprobe** on finish_task_switch for I/O wait measurement
- **Hash tables** for file descriptor tracking and correlation
- **Atomic counters** for thread-safe metrics collection
- **Real-time data export** to monitoring systems

### Syscall Correlation Logic
1. **accept4()** - Track incoming connections, increment queue depth
2. **epoll_ctl()** - Monitor event loop registration patterns  
3. **ioctl()** - Detect non-blocking socket configuration
4. **recvfrom()** - Mark request processing start, decrement queue
5. **sendto()** - Calculate end-to-end response time

### Lock Contention Analysis
- **pthread_mutex_lock** uprobe - Entry point timing
- **pthread_mutex_lock** uretprobe - Exit point timing  
- **Mutex wait calculation** - Difference between entry/exit timestamps
- **Per-thread lock analysis** - Individual thread blocking patterns

### I/O Wait Monitoring
- **finish_task_switch** kprobe - Context switch detection
- **Process scheduling analysis** - Time spent off-CPU
- **I/O blocking identification** - Network and disk wait patterns

### Production Architecture
```
Application → Kernel Syscalls → eBPF Probes → Metrics Collection → Elasticsearch/Monitoring
```

## Use Cases

- **Performance bottleneck identification** at the kernel level
- **Capacity planning** based on real thread utilization
- **Automated scaling** triggered by queue depth thresholds
- **Production debugging** without application instrumentation
- **Cost optimization** through precise resource monitoring

## Contributing

Contributions welcome! This tool is actively used in production and benefits from community feedback.

## License

MIT License - see LICENSE file for details.

---

**Note**: Requires root privileges for eBPF program loading. Designed for production use with minimal overhead.
