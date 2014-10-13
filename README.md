sshscan
=======
multi-threaded c++ application that can be used for penetration testing for ports (e.g. ssh port 21) for a list of servers (IP list) and generate success report for completed logins.

Features
========
- can work with large list of IP addresses and provide output within minutes
- customizable number of threads to be used (spawned) by providing command line parameters
- check provided authentication methods prior to trying user/name combination to save time
- automatic retry to avoid ssh server limitation for maximum number of connections

how to install
==============
- make sure that libssh2-dev is installed 
  On ubuntu use `sudo apt-get install libssh2-1-dev`
- then go to `src` directory
- then `make clean;make`

how to use
============
`./sshscan -H IP_FILE -U USERS_FILE -t PORT -T THREADS_COUNT`
success log will be created into the current working directory with the following format "YYYYMMDD-hhmmss.success.log"
