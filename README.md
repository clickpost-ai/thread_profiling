# thread_profiling

# Thread Profiler

A lightweight profiling tool for monitoring Python and Java applications using BCC (BPF Compiler Collection).

## Features

- **Python Thread Profiling**: Monitor and analyze Python application performance
- **Java Thread Profiling**: Profile Java applications with detailed thread analysis
- **Environment-based Configuration**: Organize profiling sessions by environment
- **Process-specific Monitoring**: Target specific processes by PID

## Prerequisites

- Linux system with BPF support
- Root privileges (required for BCC operations)
- Python 3.x

## Installation

### Amazon Linux 2

```bash
sudo amazon-linux-extras install BCC -y
```

### Other Linux Distributions

Follow the comprehensive installation guide for your specific distribution:
[BCC Installation Guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

## Usage

### Python Application Profiling

Profile Python applications by specifying an environment and process IDs:

```bash
sudo python3 python_thread_profling -e <env_name> -p <pid1,pid2,...>
```

**Example:**
```bash
sudo python3 python_thread_profling -e demo -p 181,182
```

### Java Application Profiling

Profile Java applications using the dedicated Java profiler:

```bash
sudo python3 java_thread_profiling.py -e <env_name> -p <pid1,pid2,...>
```

**Example:**
```bash
sudo python3 java_thread_profiling.py -e demo -p 180,182
```

## Parameters

- `-e, --env`: Environment name for organizing profiling sessions
- `-p, --pids`: Comma-separated list of process IDs to monitor

## Requirements

- BCC (BPF Compiler Collection)
- Linux kernel with BPF support (typically 4.1+)
- Root access for BPF program loading

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

[Add your license information here]

## Support

For BCC installation issues, refer to the [official BCC documentation](https://github.com/iovisor/bcc).

---

**Note**: This tool requires root privileges to access kernel tracing capabilities through BPF.
