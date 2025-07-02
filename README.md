# thread_profiling


To run this Install BCC:
1. sudo amazon-linux-extras install BCC -y (for installing in amazon linux 2)
2. for other distro: Please follow this link:


To run profiling for python servers run below command:
1. sudo python3 python_thread_profling  -e `<env_name>` -p <comma separated pids>
Example: sudo python3 python_thread_profling  -e demo -p 181,182



