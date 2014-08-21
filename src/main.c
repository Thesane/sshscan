/*
 *	Power BY Bill Lonely
 * 	Updated by Ahmed Saber
 */
#include <unistd.h>   
#include <stdio.h>  
#include "sshscan.h"
#include "thread_pool.h"
#include "gcrypt-fix.h"
#include <signal.h>
#include <time.h>

Setting setting;
struct ip_list IP_List;
struct user_list User_List;
struct password_list Pwd_List;
int recive = 0;

/*SIGINT*/
void ouch(int sig)
{   
    recive = 1;
    (void) signal(SIGINT, SIG_DFL);
    printf("Recived SIGINT\n");
    pool_destroy_force();
    
    libssh2_exit();
    
    free_ip_list(&IP_List);
    free_user_list(&User_List);
    free_password_list(&Pwd_List);
    free_setting(&setting);
    sleep(2);
    printf("END! BYE.......\n");
    exit(0);
}

void show_help(void)
{
	printf("-h Host IP\n");
	printf("-H Host File\n");
	printf("-u UserName\n");
	printf("-U User File\n");
	printf("-p password\n");
	printf("-P Password File\n");
	printf("-t port\n");
	printf("-T threads count\n");
	printf("-D Log file\n");
	printf("-N Password Group Number\n");
	
}

int main(int argc, char **argv)
{
    int i, rc;
    struct Test_ssh_Arg_by_IP *workarg = NULL;
    struct ip_node  *pIP = NULL;
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
    if (analysisSetting(&setting, &IP_List, &User_List, &Pwd_List) < 0)
    {
        return -1;
    }
    
    if (IP_List.count <= 0)
    {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_password_list(&Pwd_List);
        free_setting(&setting);
        return -1;
    }
	
    if (pool_init(setting.thread_num) < 0)
    {
	free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_password_list(&Pwd_List);
        free_setting(&setting);
		fprintf(stderr,"Init thread pool error!!\n");
		return -2;
    }	
		
    (void)signal(SIGINT, ouch);
    gcrypt_fix();
    rc = libssh2_init (0);
    if (rc != 0) {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_password_list(&Pwd_List);
        free_setting(&setting);
        fprintf (stderr, "libssh2 initialization failed (%d)\n", rc);       

        return -1;
    }
    workarg = (struct Test_ssh_Arg_by_IP *)malloc(sizeof(struct Test_ssh_Arg_by_IP) * IP_List.count);
    
    
    record_node = (struct  workarg_queue *)malloc(sizeof(struct workarg_queue));
    if (record_node == NULL)
    {
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_password_list(&Pwd_List);
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
    printf ( "Start Current local time and date: %s", asctime (timeinfo) );    
    pIP = IP_List.head;
    for (i = 0; i < IP_List.count; ++i)
    {
        workarg[i].port  = setting.port;
        workarg[i].users = User_List;
        workarg[i].passwords = Pwd_List;
        workarg[i].ip = *pIP;
        workarg[i].setting = &setting;

        pool_add_worker (ssh_test,(void *)(&workarg[i]));
        pIP = pIP->next;        
    }
    sleep(2);
    
    while (pool_check_state())
    {
        sleep(6);
    }
        
    if (recive == 0)
    {
        pool_destroy();    
        libssh2_exit();
        free_ip_list(&IP_List);
        free_user_list(&User_List);
        free_password_list(&Pwd_List);
        free_setting(&setting);
	
    }
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "Finish Current local time and date: %s", asctime (timeinfo) );    
    	
    return 0;
}
