 #
 #	Power BY Bill Lonely
 #
all : sshscan

# Which compiler
CC = gcc

# Where are include files kept
INCLUDE=.

# Options for development
CFLAGS = -g -Wall -ansi
# Opetion for release
#CFLAGS = -O -Wall -ansi

# Local Libraries
MYLIB = mylib.a

RM=rm -rf

sshscan : main.o sshscan.o thread_pool.o gcrypt-fix.o
	$(CC) $(CFLAGS) -o sshscan main.o sshscan.o thread_pool.o gcrypt-fix.o -lpthread -lssh2 -lgcrypt

main.o : main.c
	$(CC) -I$(INCLUDE) $(CFLAGS)  -c main.c
sshscan.o : sshscan.h sshscan.c 
	$(CC) -I$(INCLUDE) $(CFLAGS)  -c sshscan.c 
thread_pool.o : thread_pool.c thread_pool.h
	$(CC) -I$(INCLUDE) $(CFLAGS)  -c thread_pool.c 
gcrypt-fix.o : gcrypt-fix.c gcrypt-fix.h
	$(CC) -I$(INCLUDE) $(CFLAGS)  -c gcrypt-fix.c 

clean-all: clean clean-bin

clean :
	$(RM) *.o
clean-bin : 
	$(RM) sshscan

