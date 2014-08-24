#include  "thread_pool.h"

static CThread_pool *pool = NULL;
int pool_init(int max_thread_num)
{
    int i;

    pool = (CThread_pool *) malloc(sizeof(CThread_pool));
    if (pool == NULL)
    {
        return -1;
    }

    pool->thread_unite_list = (ThreadUnit *)malloc(sizeof(ThreadUnit) * max_thread_num);
    if (pool->thread_unite_list == NULL)
    {
        free(pool);
        return -1;
    }
    pool->max_thread_num = max_thread_num;
    
    pool->shutdown = 0;
    pool->work_quequ_rear = NULL;
    pool->work_queue_head = NULL;
    pool->cur_queue_size = 0;
    if (pthread_mutex_init(&(pool->queue_lock), NULL) != 0)
    {
        free(pool);
        return -2;
    }
    if (pthread_cond_init(&(pool->queue_ready), NULL) != 0)
    {
        pthread_mutex_destroy(&(pool->queue_lock));
        return -2;
    }

    for (i = 0; i < max_thread_num; ++i)
    {
	pool->thread_unite_list[i].state = READY;
        if (pthread_create(&(pool->thread_unite_list[i].thread_id), NULL, thread_routine, &pool->thread_unite_list[i]) != 0)
        {            
            pthread_mutex_destroy(&(pool->queue_lock));
            pthread_cond_destroy(&(pool->queue_ready));
            free(pool->thread_unite_list);
            free(pool);
            return -3;
        }		
    }
    return 0;
}

void *thread_routine(void *arg)
{
    ThreadUnit *parg = (ThreadUnit *)arg;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	
    /*printf("starting thread 0X%x \n", (unsigned int)pthread_self());*/
    while(1)
    {
        pthread_mutex_lock(&(pool->queue_lock));
        while (pool->work_queue_head == NULL && !pool->shutdown)
        {
      /*      printf("thread 0x%x is waiting \n", (unsigned int)pthread_self());*/
			parg->state = IDLE;
            pthread_cond_wait(&(pool->queue_ready), &(pool->queue_lock));
        }
        if (pool->shutdown)
        {
            /*printf("thread 0x%x will exit.\n",  (unsigned int)pthread_self());*/
            pthread_mutex_unlock(&(pool->queue_lock));
            pthread_exit(NULL);
        }
        /*printf("thread 0x%x is starting to work",  (unsigned int)pthread_self());*/
        parg->state = RUNNING;

        assert(pool->work_queue_head != NULL);

        CThread_worker *worker;
        worker = pool->work_queue_head;
        if(pool->work_quequ_rear == pool->work_queue_head)
        {
            pool->work_quequ_rear = pool->work_queue_head = NULL;
        }
        else
        {
            pool->work_queue_head = worker->next;
        }
        pthread_mutex_unlock(&(pool->queue_lock));

        (*(worker->process))(worker->arg);
        free(worker);
        worker = NULL;
    }
    pthread_exit(NULL);
}

int pool_add_worker(void *(*process)(void *arg), void *arg )
{
    CThread_worker *newworker = (CThread_worker *)malloc(sizeof(CThread_worker));
    if (newworker == NULL)
    {
        return -1;
    }
    newworker->process = process;
    newworker->arg = arg;
    newworker->next = NULL;
    
    pthread_mutex_lock(&(pool->queue_lock));
    if (pool->work_quequ_rear == NULL)
    {
        pool->work_queue_head = pool->work_quequ_rear = newworker;
    }
    else
    {
        pool->work_quequ_rear->next = newworker;
        pool->work_quequ_rear = newworker;
    }
    
    assert(pool->work_queue_head != NULL);

    pthread_mutex_unlock(&(pool->queue_lock));
    pthread_cond_signal(&(pool->queue_ready));
    return 0;
}

int pool_destroy(void)
{
    int i;
    if (pool->shutdown == 1)
    {
        return -1;
    }
    pool->shutdown = 1;
    pthread_cond_broadcast(&(pool->queue_ready));
    
    for (i = 0; i < pool->max_thread_num; ++i)
    {
        pthread_join(pool->thread_unite_list[i].thread_id, NULL);
    }
    free(pool->thread_unite_list);
    pool->thread_unite_list = NULL;
    
    pthread_mutex_destroy(&(pool->queue_lock));
    pthread_cond_destroy(&(pool->queue_ready));
    
    free(pool);
    pool = NULL;
    return 0;
}

int pool_check_state(void)
{
	int i;
	pthread_mutex_lock(&(pool->queue_lock));
	for (i = 0; i < pool->max_thread_num; ++i)
	{
		if (pool->thread_unite_list[i].state == RUNNING)
		{
		  	pthread_mutex_unlock(&(pool->queue_lock));
			return 1;
		}
	}
	pthread_mutex_unlock(&(pool->queue_lock));
	return 0;
}

int pool_destroy_force(void)
{
    int i;
    if (pool->shutdown == 1)
    {
        return -1;
    }
    pool->shutdown = 1;
    
 
    pthread_cond_broadcast(&(pool->queue_ready));
    sleep(2);

    for (i = 0; i < pool->max_thread_num; ++i)
    {
    
        pthread_cancel(pool->thread_unite_list[i].thread_id);
        pthread_join(pool->thread_unite_list[i].thread_id, NULL);
    }

    free(pool->thread_unite_list);
    pool->thread_unite_list = NULL;
    
    pthread_mutex_destroy(&(pool->queue_lock));
    pthread_cond_destroy(&(pool->queue_ready));
    
    free(pool);
    pool = NULL;
    return 0;

}

