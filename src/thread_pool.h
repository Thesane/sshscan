#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_
/*work state*/
#define RUNNING 0
#define READY 1
#define IDLE 2

typedef struct worker
{
	void *(* process)(void *arg);
	void *arg;
	struct worker *next;
}CThread_worker;

typedef struct 
{
    pthread_t thread_id;
	int state;
} ThreadUnit;

typedef struct 
{
    
    CThread_worker *work_queue_head; 
    CThread_worker *work_quequ_rear; 

    int shutdown; 
    ThreadUnit *thread_unite_list;
    
    int max_thread_num;
    
    int cur_queue_size;
    
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_ready;

}CThread_pool;

int pool_init(int max_thread_num);
void *thread_routine(void *arg);
int pool_destroy(void);
int pool_add_worker(void *(*process)(void *arg), void *arg );
int pool_check_state(void);
int pool_destroy_force(void);
#endif
