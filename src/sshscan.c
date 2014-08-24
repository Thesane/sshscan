#include "sshscan.h"
#include "thread_pool.h"
#include "gcrypt-fix.h"
#include <error.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void* ssh_test(void *arg)
{
    int i;
    struct Test_ssh_Arg_by_IP *test_arg = (struct Test_ssh_Arg_by_IP *)arg;
    struct user_node *puser = NULL;
    struct Try_login_arg_by_pwd *workarg; 
    struct  workarg_queue *record_node = NULL;

    if (test_connect(test_arg->ip.ip, test_arg->port, test_arg->setting->connect_test_count) <= 0)
    {
        test_arg->ret = -1;
        return NULL;
    }
    printf("Connect %s : %d success! \n",test_arg->ip.ip, test_arg->port);
    sleep(2); 
    workarg = (struct Try_login_arg_by_pwd *)malloc(sizeof(struct Try_login_arg_by_pwd ) * test_arg->users.count);
    if (workarg == NULL)
    {
        test_arg->ret = -1;
        return NULL;
    }
    record_node = (struct  workarg_queue *)malloc(sizeof(struct workarg_queue));
    if (record_node == NULL)
    {
        free(workarg);
        test_arg->ret = -1;
        return NULL;
    }
    i = 0;
    for (puser = test_arg->users.head; puser != NULL; puser = puser->next)
    {
      
        workarg[i].setting = test_arg->setting;
        workarg[i].port = test_arg->port;
        workarg[i].ip = test_arg->ip.ip;
        workarg[i].user = puser->user;
        workarg[i].password = puser->password;
	workarg[i].complete = 0;
	pthread_mutex_init(&workarg[i].complete_mutex, NULL);
        pool_add_worker (try_login_pwd, (void *)(&workarg[i]));
        ++i;
    }  
    test_arg->ret = 0;
    
    /*
    workarg = (struct Try_login_arg_by_user *)malloc(sizeof(struct Try_login_arg_by_user ) * test_arg->users.count);
    if (workarg == NULL)
    {
        test_arg->ret = -1;
        return NULL;
    }
    record_node = (struct  workarg_queue *)malloc(sizeof(struct workarg_queue));
    if (record_node == NULL)
    {
        free(workarg);
        test_arg->ret = -1;
        return NULL;
    }
    record_node->level = 2;
    record_node->point = (void *)workarg;

    pthread_mutex_lock(&(test_arg->setting->setting_mutex));
    
    record_node->next = test_arg->setting->workarg_list_head;
    test_arg->setting->workarg_list_head = record_node;

    pthread_mutex_unlock(&(test_arg->setting->setting_mutex));

    i = 0;
    for (puser = test_arg->users.head; puser != NULL; puser = puser->next)
    {
        workarg[i].setting = test_arg->setting;
        workarg[i].port = test_arg->port;
        workarg[i].ip = test_arg->ip.ip;
        workarg[i].user = puser->user;
        workarg[i].passwords = &test_arg->passwords;
	workarg[i].complete = 0;
	pthread_mutex_init(&workarg[i].complete_mutex, NULL);
        pool_add_worker (try_login_user, (void *)(&workarg[i]));
        ++i;
    }  
    
    test_arg->ret = 0;*/
    return NULL;
} 

void *try_login_pwd(void *arg)
{
    int sockfd;
    int flag_connect_success = 0;
    int i;
    /*, j;*/
    int count_num;
    LIBSSH2_SESSION *session;
    struct Try_login_arg_by_pwd *parg = (struct Try_login_arg_by_pwd *)arg;
    struct sockaddr_in address;
    FILE *fp;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(parg->port);
    address.sin_addr.s_addr = inet_addr(parg->ip);

    
    count_num = 0;
    try_again:
    if (count_num >= 10)
    {
	printf("Failed to connect %s, Will END\n", parg->ip);
	return NULL;
    }
    
    pthread_mutex_lock(&(parg->complete_mutex));
    if (parg->complete == 1)
    {
	pthread_mutex_unlock(&(parg->complete_mutex));
	parg->ret = 1;
	return NULL;
    }
    pthread_mutex_unlock(&(parg->complete_mutex));

    /* We could authenticate via password */
    /*printf("Try Authentication. IP:%s:%d Username:%s Password:%s \n",
		parg->lastLevArg->ip, parg->lastLevArg->port ,parg->lastLevArg->user , ppass->password);*/
	    flag_connect_success = 0;
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
	perror("socket() error:");
	parg->ret = -1;
	return NULL;
    }

    for (i = 1; i <= parg->setting->connect_test_count; ++i)
    {
	if (connect(sockfd, (struct sockaddr *)(&address), sizeof(address)) == 0)
	{
	    flag_connect_success = 1;
	    break;            
	}     
	sleep(2);
    }

    if (flag_connect_success == 0)
    {
	parg->ret = -2;
	printf("Failed to connect %s, Will Try Again\n", parg->ip);
	close(sockfd);
	sleep(rand() % 30 + 1);
	count_num++;
	goto try_again;
      }
    count_num = 0;
    session = libssh2_session_init();gcrypt_fix();
    if (libssh2_session_handshake(session, sockfd))
    {
	/*fprintf(stderr, "Failure establishing SSH session\n");*/
	close(sockfd);
	parg->ret = -1;
	sleep(rand() % 10 + 1);
	goto try_again;
    }
    if (libssh2_userauth_password(session, parg->user, parg->password))
    {
	/*printf("\tAuthentication by password failed! IP:%s:%d Username:%s Password:%s \n",
	    parg->ip, parg->port ,parg->user,  parg->password );*/
    } 
    else 
    {
	printf("\tAuthentication by password succeeded.IP:%s:%d Username:%s Password:%s \n",
	parg->ip, parg->port ,parg->user, parg->password );
	libssh2_session_disconnect(session,
		"Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);
	close(sockfd);
		
	pthread_mutex_lock(&(parg->setting->success_log_mutex));
	if ((fp = fopen(parg->setting->path_log, "a")) == NULL)
	{
	      pthread_mutex_unlock(&(parg->setting->success_log_mutex));
	      parg->ret = -2;
	      return NULL;
	}

	fprintf(fp, "%s:%d  User:%s  Password:%s  \n",  parg->ip, parg->port ,parg->user, parg->password);
	fclose(fp);
	pthread_mutex_unlock(&(parg->setting->success_log_mutex));

	pthread_mutex_lock(&(parg->complete_mutex));
	parg->complete = 1;
	pthread_mutex_unlock(&(parg->complete_mutex));
	
	return NULL;
    }
    libssh2_session_disconnect(session,
		"Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    close(sockfd); 
      /*sleep(2);*/
    
    parg->ret = 0;
    
    return NULL;
}

/* Done */
int test_connect(char *ip, short port, int test_count)
{
    int i;
    int flag_connect_success = 0;
    int sockfd;
    struct sockaddr_in address;
    struct timeval timeo;
    timeo.tv_sec = 30;  

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket() error:");
        return -1;
    }
    
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
    
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr(ip);


    flag_connect_success = 0;
    for (i = 1; i <= test_count; ++i)
    {
        printf("Try connect %s : %d  (%d / %d)\n", ip, port, i, test_count);
        if (connect(sockfd, (struct sockaddr *)(&address), sizeof(address)) == 0)
        {
            
            flag_connect_success = 1;
            break;            
        }
        else
        {
            if (errno == EINPROGRESS)
            {
                fprintf(stderr, "connect %s:%d time out \n", ip, port);
            }
            else
            {
                printf("connect %s:%d : %s\n", ip, port, strerror(errno));
                break;
            }
        }
        sleep(2);
    }

    if (flag_connect_success == 0)
    {
        close(sockfd);
        return 0;
    }
    close(sockfd);
    return 1;
}


/* Done */
int checkSetting(int argc, char **argv, Setting *setting)
{
	int opt;
	extern char *optarg;
	int ret;

    char time_buf[MAX_LEN_TIME_STR];
    char *home_path = NULL;
    time_t the_time;
    struct tm *tm_ptr;
    
    
    if (argc <= 3)
    {
        return -1;
    }
    
    setting->Host_File = NULL;
    setting->User_File = NULL;
    setting->port = 22;     
    setting->workarg_list_head = NULL;
    setting->connect_test_count = 3;  
    setting->thread_num = 6;  
    
    home_path = getenv("PWD");  
    if (home_path == NULL)
    {
        fprintf(stderr, "can find home directory.\n");
        return -1;
    }
    
    strncpy(setting->path_log, home_path, MAX_LEN_PATH);

    if (pthread_mutex_init(&(setting->success_log_mutex), NULL) != 0)
    {
        return -1;
    }
    
    if (pthread_mutex_init(&(setting->setting_mutex), NULL) != 0)
    {
        pthread_mutex_destroy(&(setting->success_log_mutex));
        return -1;
    }
    
    ret = 0;
    
    while ((opt = getopt(argc, argv, "H:U:t:D:T:")) != EOF)
    {
        switch (opt)
        {
            case 'H':
		setting->Host_File = (char *)malloc(strlen(optarg + 1));
		memset(setting->Host_File, 0, strlen(optarg) + 1);
		strncpy(setting->Host_File, optarg, strlen(optarg));
                break;
            case 'U':
                setting->User_File = (char *)malloc(strlen(optarg) + 1);
		memset(setting->User_File, 0, strlen(optarg) + 1);
		strncpy(setting->User_File, optarg, strlen(optarg));
                break;
            case 't':
                setting->port = atoi(optarg);
				break;
	    case 'T':
		setting->thread_num = atoi(optarg);
		break;
	    case 'D':
	        memset(setting->path_log, 0, MAX_LEN_PATH);
	        strncpy(setting->path_log, optarg, MAX_LEN_PATH - 1);
	        break;
            default:
                fprintf(stderr, "Unknown error processing command-line options.\n");
                ret = -1;
		break;
        }
    }

    if (setting->User_File == NULL || setting->Host_File == NULL)
    {
        fprintf(stderr, "Must enter the IP address, username files!!\n");
        ret = -1;
    }

    if (ret == -1)
    {
        free_setting(setting);
    }
    else
    {
        
        (void) time(&the_time);
        tm_ptr = localtime(&the_time);
        strftime(time_buf, MAX_LEN_TIME_STR, "%Y%m%d-%H%M%S", tm_ptr);
        strncpy(setting->success_log_filename, time_buf,MAX_LEN_FILENAME);
        strncat(setting->success_log_filename,".success.log", MAX_LEN_FILENAME);
    }
    
    return ret;
}
/* Done */
void free_setting(Setting *setting)
{

/*    struct workarg_queue *p1, *p2;*/
    
    if (setting->Host_File != NULL)
    {
        free(setting->Host_File);
		setting->Host_File = NULL;
    }
    if (setting->User_File != NULL)
    {
        free(setting->User_File);
		setting->User_File = NULL;
    }
    
    pthread_mutex_destroy(&(setting->success_log_mutex));
    pthread_mutex_destroy(&(setting->setting_mutex));
    
    
    /*free worker arg queue*/
    /*p1 = setting->workarg_list_head;
    while (p1 != NULL)
    {
        if (p1->level == 1 || p1->level == 3)
        {
            free(p1->point);
            p1->point = NULL;
            p2 = p1;
            p1 = p2->next;
            free(p2);  
        }
        else if (p1->level == 2)
        {
            parg_user = (struct Try_login_arg_by_user *)p1->point;
			pthread_mutex_destroy(&(parg_user->complete_mutex));
			free(p1->point);
            p1->point = NULL;
            p2 = p1;
            p1 = p2->next;
            free(p2);  
        }
    }*/
    setting->workarg_list_head = NULL;
}
/* Done */
#define MAX_BUF 500
int analysisSetting(Setting *setting, struct ip_list *IPs, 
        struct user_list *Users)
{
    /*int i, j;
    int flag;*/
    char buf[MAX_BUF];
    struct ip_node *pIP1, *pIP2;
    struct user_node *pUser1, *pUser2;
    
    FILE *fp;

    IPs->count = 0;
    IPs->head = NULL;
    Users->count = 0;
    Users->head = NULL;
    struct stat file_stat;
    
    
    if (stat(setting->path_log, &file_stat) < 0)
    {
        fprintf(stderr, "%s:%s\n", setting->path_log, strerror(errno));
        return -1;
    }
    strncat(setting->path_log, "/", MAX_LEN_PATH);
    strncat(setting->path_log, setting->success_log_filename, MAX_LEN_PATH);
    
    if (setting->Host_File != NULL)
    {
        fp = fopen(setting->Host_File, "rt");
        if (fp == NULL)
        {
            fprintf(stderr, "FILE '%s' can't open ! \n", setting->Host_File);
            return -1;
        }
        memset(buf, 0, MAX_BUF);
        if (fgets(buf, MAX_BUF, fp) != NULL)
		{
			pIP1 = (struct ip_node *)malloc(sizeof(struct ip_node));
       		pIP1->next = NULL;
        	pIP1->ip = (char *)malloc(strlen(buf) + 1);
        	memset(pIP1->ip, 0, strlen(buf)+1);
        	strncpy(pIP1->ip, buf, strlen(buf) - 1);

       		IPs->head = pIP2 = pIP1;
        	IPs->count++;
		}

        while (!feof(fp))
        {
            memset(buf, 0, MAX_BUF);
            if (fgets(buf, MAX_BUF, fp) != NULL)
			{
				pIP1 = (struct ip_node *)malloc(sizeof(struct ip_node));
				pIP1->next = NULL;
            	pIP1->ip = (char *)malloc(strlen(buf) + 1);
            	memset(pIP1->ip, 0, strlen(buf)+1);
            	strncpy(pIP1->ip, buf, strlen(buf) - 1);

            	pIP2->next = pIP1;
				pIP2 = pIP1;
				IPs->count++;
			}           
        }
        fclose(fp);
    }
  
    if (setting->User_File != NULL)
    {
        fp = fopen(setting->User_File, "rt");
        if (fp == NULL)
        {
            free_ip_list(IPs);
            fprintf(stderr, "FILE '%s' can't open ! \n", setting->User_File);
            return -1;
        }
        memset(buf, 0, MAX_BUF);
        if (fgets(buf, MAX_BUF, fp) != NULL)
        {
	  	pUser1 = (struct user_node *)malloc(sizeof(struct user_node));
       	 	pUser1->next = NULL;
		
		char *username,*userpassword;
		username= strtok(buf," ");
		pUser1->user = (char *)malloc(strlen(username) + 1);
	
        	memset(pUser1->user, 0, strlen(username) + 1);
        	strncpy(pUser1->user, username, strlen(username));
	
		userpassword = strtok(NULL," ");
		
		pUser1->password = (char *)malloc(strlen(userpassword) + 1);
        	memset(pUser1->password, 0, strlen(userpassword) + 1);
        	strncpy(pUser1->password, userpassword, strlen(userpassword) - 1);
        	
		pUser2 = Users->head = pUser1;
			Users->count++;
        }
        
        while (!feof(fp))
        {
            memset(buf, 0, MAX_BUF);
            if (fgets(buf, MAX_BUF, fp) != NULL)
            {
            	pUser1 = (struct user_node *)malloc(sizeof(struct user_node));
		pUser1->next = NULL;
       		char *username,*userpassword;
		
		username = strtok(buf," ");
       		pUser1->user = (char *)malloc(strlen(username) + 1);
        	memset(pUser1->user, 0, strlen(username) + 1);
        	strncpy(pUser1->user, username, strlen(username));
		userpassword = strtok(NULL," ");
       		pUser1->password = (char *)malloc(strlen(userpassword) + 1);
        	memset(pUser1->password, 0, strlen(userpassword) + 1);
        	strncpy(pUser1->password, userpassword, strlen(userpassword) - 1);
        	
		pUser2->next = pUser1;
                pUser2 = pUser1;
			Users->count++;
            }            
        }   
        fclose(fp);       
    }
    /*assert(pPassword1 != NULL);*/
    
    return 0;    
}
/* Done */
void free_ip_list(struct ip_list *IPs)
{
    struct ip_node *p1,*p2;
    
    p1 = IPs->head;
    IPs->count = 0;
    IPs->head = 0;
    while (p1 != NULL)
    {
        p2 = p1;
        p1 = p1->next;
        free(p2->ip);
        free(p2);
    }
}
/* Done */
void free_user_list(struct user_list *Users)
{
    struct user_node *p1,*p2;
    
    p1 = Users->head;
    Users->count = 0;
    Users->head = NULL;
    while (p1 != NULL)
    {
        p2 = p1;
        p1 = p1->next;
        free(p2->user);
        free(p2->password);
        free(p2);
    }
}
