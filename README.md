# thread_profiling


To run this, Install BCC:
1. sudo amazon-linux-extras install BCC -y (for installing in Amazon Linux 2)
2. For other distros: Please follow this link: https://github.com/iovisor/bcc/blob/master/INSTALL.md?ref=kimsehwan96.com


To run profiling on the  Python server, run the following command:
1. sudo python3 python_thread_profling  -e `<env_name>` -p <comma separated pids>
Example: sudo python3 python_thread_profling  -e demo -p 181,182

To run profiling on a Java server, run the following command:
1. sudo python3 java_thread_profiling.py -e `<env_name>` -p <comma separated pids>
Example:  sudo python3 java_thread_profiling.py -e demo -p 180
