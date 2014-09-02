/*
 * 	Updated by Ahmed Saber
 */
#include <unistd.h>   
#include <stdio.h>  
#include "sshscan.h"
#include "gcrypt-fix.h"
#include <signal.h>
#include <time.h>
#include <list>

using namespace std;

Setting setting;
struct ip_list IP_List;
struct user_list User_List;
int recive = 0;
list<pthread_t> thread_list;
pthread_mutex_t list_mutex;
pthread_mutex_t file_mutex;

/*SIGINT*/
void ouch(int sig)
{   
    recive = 1;
    (void) signal(SIGINT, SIG_DFL);
    printf("Recived SIGINT\n");
    
    libssh2_exit();
    
    free_ip_list(&IP_List);
    free_user_list(&User_List);
    free_setting(&setting);
    sleep(2);
    printf("END! BYE.......\n");
    exit(0);
}

void show_help(void)
{
	printf("-H Host File\n");
	printf("-U User File\n");
	printf("-t port\n");
	printf("-T threads count\n");
	printf("-D Log file\n");
	
}

int main(int argc, char **argv)
{
    int i,j, rc;
    struct Try_login_arg_by_pwd *workarg = NULL;
    
    struct ip_node  *pIP = NULL;
    struct user_node *pUser = NULL;
    struct  workarg_queue *record_node = NULL;
    
    if (strcmp(argv[1],"-help") == 0)
    {
	show_help();
	return 0;
    }
    
    if (checkSetting(argc, argv, &setting) < 0)
    {
        fprintf(stderr, "Options Error \n");
        return -1;
    }
    
    if (analysisSetting(&setting, &IP_List, &User_List) < 0)
    {
        return -1;
    }
    
    if (IP_List.count <= 0)
    {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        
        free_setting(&setting);
        return -1;
    }
	/*
    if (pool_init(setting.thread_num) < 0)
    {
	free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_setting(&setting);
		fprintf(stderr,"Init thread pool error!!\n");
		return -2;
    }	
	*/
	  
    (void)signal(SIGINT, ouch);
    gcrypt_fix();
    rc = libssh2_init (0);
    if (rc != 0) {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_setting(&setting);
        fprintf (stderr, "libssh2 initialization failed (%d)\n", rc);       
	return -1;
    }
    workarg = (struct Try_login_arg_by_pwd *)malloc(sizeof(struct Try_login_arg_by_pwd) * IP_List.count* User_List.count);
    
    
    record_node = (struct  workarg_queue *)malloc(sizeof(struct workarg_queue));
    if (record_node == NULL)
    {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_setting(&setting);;
	return -1;
    }
    record_node->level = 1; 
    record_node->point = (void *)workarg;

    pthread_mutex_lock(&(setting.setting_mutex));
    
    record_node->next = setting.workarg_list_head;
    setting.workarg_list_head = record_node;

    pthread_mutex_unlock(&(setting.setting_mutex));
    
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "Start Current local time and date: %s\n", asctime (timeinfo) );  
//     int max_conn = 0;
    pIP = IP_List.head;
    
    for (j = 0; j < IP_List.count; ++j)
    {
	 pUser = User_List.head;
   
	  for (i = 0; i < User_List.count; ++i)
	{
	  while (thread_list.size() >= setting.thread_num)
	    {
	      
		sleep(1);
	    }
	    
	   pthread_t temp_thread;
	     struct Try_login_arg_by_pwd * pWorkarg_node = new Try_login_arg_by_pwd();
	     
	  pWorkarg_node->port  = setting.port;
	  pWorkarg_node->user = (*pUser).user;
	  pWorkarg_node->password = (*pUser).password;
	  pWorkarg_node->ip = (*pIP).ip;
	  pWorkarg_node->setting = &setting;
	  pWorkarg_node->thread_list = &thread_list;
	
	  pthread_create(&temp_thread,NULL,&try_login_pwd,(void *)  pWorkarg_node);
	  pthread_mutex_lock(&setting.complete_mutex);
// 	  printf("");
	  thread_list.push_back(temp_thread);
	  pthread_mutex_unlock(&setting.complete_mutex);
//     	  if(max_conn++ > 9)
// 	  {
// 	    sleep(1);
// 	    max_conn = 0;
// 	  }
	  pUser = pUser->next;
	         
	}
	pIP = pIP->next;
	
      
    }
    
    while (thread_list.size() > 0)
    {
        sleep(6);
    }
        
    if (recive == 0)
    {
        //pool_destroy();    
        libssh2_exit();
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_setting(&setting);
	
    }
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "Finish Current local time and date: %s", asctime (timeinfo) );    
    	
    return 0;
}
