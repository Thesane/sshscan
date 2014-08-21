sshscan
=======
how to install
- make sure that libssh2-dev is installed 
  On ubuntu use `sudo apt-get install libssh2-1-dev`
- then go to `src` directory
- then `make clean;make`

how to use
`./sshscan -H IP_FILE -U USERS_FILE -P PASSWORDS_FILE -t PORT -T THREADS_COUNT`

Note: 
- best practice to use threads count as no more than 10 x IPs count so the it won't waste processing power lost over failed connection to the IP because of limit of new connections