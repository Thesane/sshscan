sshscan
=======
how to install
- make sure that libssh2-dev is installed 
  On ubuntu use `sudo apt-get install libssh2-1-dev`
- then go to `src` directory
- then `make clean;make`

how to use
`./sshscan -H IP_FILE -U USERS_FILE -t PORT -T THREADS_COUNT`

success log will be created into the current working directory with the following format "YYYYMMDD-hhmmss.success.log"