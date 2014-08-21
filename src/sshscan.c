#include "sshscan.h"
#include "thread_pool.h"
#include "gcrypt-fix.h"
#include <error.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

void* ssh_test(void *arg)
{
    int i;
    struct Test_ssh_Arg_by_IP *test_arg = (struct Test_ssh_Arg_by_IP *)arg;
    struct user_node *puser = NULL;
    struct Try_login_arg_by_user *workarg; 
    struct  workarg_queue *record_node = NULL;

    if (test_connect(test_arg->ip.ip, test_arg->port, test_arg->setting->connect_test_count) <= 0)
    {
        test_arg->ret = -1;
        return NULL;
    }
    printf("Connect %s : %d success! \n",test_arg->ip.ip, test_arg->port);
    sleep(2); 
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
    test_arg->ret = 0;
    return NULL;
} 

void *try_login_pwd(void *arg)
{
    int sockfd;
    int flag_connect_success = 0;
    int i, j;
    int count_num;
    LIBSSH2_SESSION *session;
    struct Try_login_arg_by_pwd *parg = (struct Try_login_arg_by_pwd *)arg;
    struct sockaddr_in address;
    struct password_node *ppass;
    FILE *fp;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(parg->lastLevArg->port);
    address.sin_addr.s_addr = inet_addr(parg->lastLevArg->ip);

    j = 1;
    
    count_num = 0;
    for (ppass = parg->passwords;
            ppass != NULL && j <= parg->lastLevArg->setting->per_pwd_num;
            ppass = ppass->next)
    {
	try_again:
	if (count_num >= 10)
	{
	    printf("Failed to connect %s, Will END\n", parg->lastLevArg->ip);
	    return NULL;
	}
	
        pthread_mutex_lock(&(parg->lastLevArg->complete_mutex));
        if (parg->lastLevArg->complete == 1)
        {
            pthread_mutex_unlock(&(parg->lastLevArg->complete_mutex));
	    parg->ret = 1;
            return NULL;
        }
        pthread_mutex_unlock(&(parg->lastLevArg->complete_mutex));

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
    
   	for (i = 1; i <= parg->lastLevArg->setting->connect_test_count; ++i)
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
	    /*printf("Failed to connect %s, Will Try Again\n", parg->lastLevArg->ip);*/
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
        if (libssh2_userauth_password(session, parg->lastLevArg->user, ppass->password))
        {
            /*printf("\tAuthentication by password failed! IP:%s:%d Username:%s Password[%d/%d]:%s \n",
               parg->lastLevArg->ip, parg->lastLevArg->port ,parg->lastLevArg->user, j, parg->lastLevArg->setting->per_pwd_num, ppass->password );*/
        } 
        else 
        {
            /*printf("\tAuthentication by password succeeded.IP:%s:%d Username:%s Password[%d/%d]:%s \n",
            parg->lastLevArg->ip, parg->lastLevArg->port ,parg->lastLevArg->user, j, parg->lastLevArg->setting->per_pwd_num, ppass->password );*/
            libssh2_session_disconnect(session,
                   "Normal Shutdown, Thank you for playing");
  	    libssh2_session_free(session);
 	    close(sockfd);
 		    
 	    pthread_mutex_lock(&(parg->lastLevArg->setting->success_log_mutex));
 	    if ((fp = fopen(parg->lastLevArg->setting->path_log, "a")) == NULL)
 	    {
 	         pthread_mutex_unlock(&(parg->lastLevArg->setting->success_log_mutex));
 	         parg->ret = -2;
 	         return NULL;
 	    }

	    fprintf(fp, "%s:%d  User:%s  Password:%s  \n",  parg->lastLevArg->ip, parg->lastLevArg->port ,parg->lastLevArg->user, ppass->password);
	    fclose(fp);
	    pthread_mutex_unlock(&(parg->lastLevArg->setting->success_log_mutex));

            pthread_mutex_lock(&(parg->lastLevArg->complete_mutex));
            parg->lastLevArg->complete = 1;
            pthread_mutex_unlock(&(parg->lastLevArg->complete_mutex));
	    return NULL;
        }
	libssh2_session_disconnect(session,
                   "Normal Shutdown, Thank you for playing");
  	libssh2_session_free(session);
 	close(sockfd); 
        j++;
	/*sleep(2);*/
    }
    parg->ret = 0;
    return NULL;
}

void *try_login_user(void *arg)
{
    struct Try_login_arg_by_user *parg;
    struct Try_login_arg_by_pwd *workarg;
    struct workarg_queue *record_node;
    
    int i;

    parg = (struct Try_login_arg_by_user *)arg;
    workarg = (struct Try_login_arg_by_pwd *)malloc(sizeof(struct Try_login_arg_by_user) * parg->setting->pwd_group_num);
    
    if (workarg == NULL)
    {

        parg->ret = -1;
        return NULL;
    }

    record_node = (struct  workarg_queue *)malloc(sizeof(struct workarg_queue));
    if (record_node == NULL)
    {
        free(workarg);
        parg->ret = -1;
        return NULL;
    }
    record_node->level = 1; 
    record_node->point = (void *)workarg;

    pthread_mutex_lock(&(parg->setting->setting_mutex));
    
    record_node->next = parg->setting->workarg_list_head;
    parg->setting->workarg_list_head = record_node;

    pthread_mutex_unlock(&(parg->setting->setting_mutex));


    for (i = 0; i < parg->setting->pwd_group_num; ++i)
    {
        workarg[i].lastLevArg = parg;
        workarg[i].passwords = parg->setting->pwd_groups[i];
        pool_add_worker (try_login_pwd, (void *)(&workarg[i])); 
    }
    parg->ret = 0;
    return NULL;
    
}

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
    
    setting->Host_IP = NULL;
    setting->Host_File = NULL;
    setting->Username = NULL;
    setting->User_File = NULL;
    setting->Password = NULL;
    setting->Password_File = NULL;
    setting->port = 22;     
    setting->workarg_list_head = NULL;
    setting->connect_test_count = 3;  
    setting->pwd_group_num = 4; 
    setting->pwd_groups = NULL;  
    setting->per_pwd_num = 0;    
    setting->thread_num = 6;  
    
    home_path = getenv("HOME");  
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
    
    while ((opt = getopt(argc, argv, "h:H:u:U:p:P:t:D:T:N:")) != EOF)
    {
        switch (opt)
        {
            case 'h':
                if (setting->Host_IP == NULL && setting->Host_File == NULL)
                {
                    setting->Host_IP = (char *)malloc( strlen(optarg) + 1);
                    memset(setting->Host_IP, 0, strlen(optarg)+1);
                    strncpy(setting->Host_IP, optarg, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Options 'h' and 'H' are mutally exclusive.\n");
                    ret = -1;
                }
                break;
            case 'H':
                if (setting->Host_IP == NULL && setting->Host_File == NULL)
                {
                    setting->Host_File = (char *)malloc(strlen(optarg + 1));
                    memset(setting->Host_File, 0, strlen(optarg) + 1);
                    strncpy(setting->Host_File, optarg, strlen(optarg));
                }
                else
                {                    
                    fprintf(stderr, "Options 'h' and 'H' are mutally exclusive.\n");
                    ret = -1;
                }
                break;
            case 'u':
                if (setting->Username == NULL && setting->User_File == NULL)
                {
                    setting->Username = (char *)malloc(strlen(optarg + 1));
                    memset(setting->Username, 0, strlen(optarg) + 1);
                    strncpy(setting->Username, optarg, strlen(optarg));
                }
                else
                {
                
                    fprintf(stderr, "Options 'u' and 'U' are mutally exclusive.\n");
                    ret = -1;
                }
                break;
            case 'U':
                if (setting->Username == NULL && setting->User_File == NULL)
                {
                    setting->User_File = (char *)malloc(strlen(optarg) + 1);
                    memset(setting->User_File, 0, strlen(optarg) + 1);
                    strncpy(setting->User_File, optarg, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Options 'u' and 'U' are mutally exclusive.\n");
                    ret = -1;
                }
                break;
            case 'p':
                if (setting->Password == NULL && setting->Password_File == NULL)
                {
                    setting->Password = (char *)malloc(strlen(optarg) + 1);
                    memset(setting->Password, 0, strlen(optarg) + 1);
                    strncpy(setting->Password, optarg, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Options 'p' and 'P' are mutally exclusive.\n");
                    ret = -1;
                }
				break;
            case 'P':
                if (setting->Password == NULL && setting->Password_File == NULL)
                {
                    setting->Password_File = (char *)malloc(strlen(optarg) + 1);
                    memset(setting->Password_File, 0, strlen(optarg) + 1);
                    strncpy(setting->Password_File, optarg, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Options 'p' and 'P' are mutally exclusive.\n");
                    ret = -1;
                }
				break;
            case 't':
                setting->port = atoi(optarg);
				break;
	    case 'T':
		setting->thread_num = atoi(optarg);
		break;
	    case 'N' :
		setting->pwd_group_num = atoi(optarg);
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

    if ((setting->Password_File  == NULL && setting->Password == NULL) ||
        (setting->Username == NULL && setting->User_File == NULL) || 
        (setting->Host_File == NULL && setting->Host_IP == NULL))
    {
        fprintf(stderr, "Must enter the IP address, username and password!!\n");
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

void free_setting(Setting *setting)
{

    struct workarg_queue *p1, *p2;
    struct Try_login_arg_by_user *parg_user;  /*level2*/

 
    if (setting->Host_IP != NULL)
    {
        free(setting->Host_IP);
		setting->Host_IP = NULL;
    }
    if (setting->Host_File != NULL)
    {
        free(setting->Host_File);
		setting->Host_File = NULL;
    }
    if (setting->Username != NULL)
    {
        free(setting->Username);
    }
    if (setting->User_File != NULL)
    {
        free(setting->User_File);
		setting->User_File = NULL;
    }
    if (setting->Password != NULL)
    {
        free(setting->Password);
		setting->Password = NULL;
    }
    if (setting->Password_File != NULL)
    {
        free(setting->Password_File);
		setting->Password_File = NULL;
    }
    if (setting->pwd_groups != NULL)
    {
        free(setting->pwd_groups);
        setting->pwd_groups = NULL;
    }
    
    pthread_mutex_destroy(&(setting->success_log_mutex));
    pthread_mutex_destroy(&(setting->setting_mutex));
    
    
    /*free worker arg queue*/
    p1 = setting->workarg_list_head;
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
    }
    setting->workarg_list_head = NULL;
}

#define MAX_BUF 500
int analysisSetting(Setting *setting, struct ip_list *IPs, 
        struct user_list *Users, struct password_list *Passwords)
{
    int i, j;
    int flag;
    char buf[MAX_BUF];
    struct ip_node *pIP1, *pIP2;
    struct user_node *pUser1, *pUser2;
    struct password_node *pPassword1, *pPassword2;
    
    FILE *fp;
    int per_pwd_num;  

    IPs->count = 0;
    IPs->head = NULL;
    Users->count = 0;
    Users->head = NULL;
    Passwords->count = 0;
    Passwords->head = NULL;
    struct stat file_stat;
    
    
    if (stat(setting->path_log, &file_stat) < 0)
    {
        fprintf(stderr, "%s:%s\n", setting->path_log, strerror(errno));
        return -1;
    }
    strncat(setting->path_log, "/", MAX_LEN_PATH);
    strncat(setting->path_log, setting->success_log_filename, MAX_LEN_PATH);
    
    if (setting->Host_IP != NULL)
    {
        pIP1 = (struct ip_node *)malloc(sizeof(struct ip_node));
        pIP1->next = NULL;
        pIP1->ip = (char *)malloc(strlen(setting->Host_IP)+1);
        memset(pIP1->ip, 0, strlen(setting->Host_IP) + 1);
        strncpy(pIP1->ip, setting->Host_IP, strlen(setting->Host_IP));
        IPs->count++;
        IPs->head = pIP1;
    }
    else if (setting->Host_File != NULL)
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
  
    if (setting->Username != NULL)
    {
        pUser1 = (struct user_node *)malloc(sizeof(struct user_node));
        pUser1->next = NULL;
        pUser1->user = (char *)malloc(strlen(setting->Username) + 1);
        memset(pUser1->user, 0, strlen(setting->Username) + 1);
        strncpy(pUser1->user, setting->Username, strlen(setting->Username));
        
        Users->head = pUser1;
        Users->count++;
    }
    else if (setting->User_File != NULL)
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
       		pUser1->user = (char *)malloc(strlen(buf) + 1);
        	memset(pUser1->user, 0, strlen(buf) + 1);
        	strncpy(pUser1->user, buf, strlen(buf) - 1);
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
       	    	pUser1->user = (char *)malloc(strlen(buf) + 1);
				memset(pUser1->user, 0, strlen(buf) + 1);
            	strncpy(pUser1->user, buf, strlen(buf) - 1);
				pUser2->next = pUser1;
                pUser2 = pUser1;
			Users->count++;
            }            
        }   
        fclose(fp);       
    }
    if (setting->Password != NULL)
    {
        pPassword1 = (struct password_node *)malloc(sizeof(struct password_node));
        pPassword1->next = NULL;
        pPassword1->password = (char *)malloc(strlen(setting->Password) + 1);
        memset(pPassword1->password, 0, strlen(setting->Password) + 1);
        strncpy(pPassword1->password, setting->Password, strlen(setting->Password));

        Passwords->head = pPassword1;
        Passwords->count++;
    }
    else if (setting->Password_File != NULL)
    {
        fp = fopen(setting->Password_File, "rt");
        if (fp == NULL)
        {
            free_ip_list(IPs);
            free_user_list(Users);
            fprintf(stderr,"FILE '%s' can't open!\n", setting->Password_File);
			return -1;
        }
        memset(buf, 0, MAX_BUF);
        if (fgets(buf, MAX_BUF, fp))
        {
            pPassword1 = (struct password_node *)malloc(sizeof(struct password_node));
            pPassword1->next = NULL;
            pPassword1->password = (char *)malloc(strlen(buf) + 1);
            memset(pPassword1->password, 0, strlen(buf) + 1);
            strncpy(pPassword1->password, buf, strlen(buf) - 1);

            Passwords->head = pPassword2 = pPassword1;
            Passwords->count++;
        }
        while (!feof(fp))
        {
             memset(buf, 0, MAX_BUF);
             if (fgets(buf, MAX_BUF, fp))
             {
                pPassword1 = (struct password_node *)malloc(sizeof(struct password_node));
                pPassword1->next = NULL;
                pPassword1->password = (char *)malloc(strlen(buf) + 1);
                memset(pPassword1->password, 0, strlen(buf) + 1);
                strncpy(pPassword1->password, buf, strlen(buf) - 1);

                pPassword2->next = pPassword1;
                pPassword2 = pPassword1;
                Passwords->count++;
            }
        }
        fclose(fp);
    }
    
    per_pwd_num = Passwords->count / setting->pwd_group_num ;
    if ((Passwords->count % setting->pwd_group_num) != 0)
    {
         per_pwd_num++;
    }
    setting->per_pwd_num = per_pwd_num;
    setting->pwd_groups = (struct password_node **)malloc(sizeof(struct password_node*) * setting->pwd_group_num);
    if (setting->pwd_groups == NULL)
    {
        return -4;
    }   
    pPassword1 =  Passwords->head;

    i = 0;   
    flag = 0;
    while(1)
    {
        setting->pwd_groups[i] = pPassword1;
        i++;       
        if (i >= setting->pwd_group_num)
        {
            break;
        }
        for (j = 0; j < per_pwd_num ; ++j)
        {
            pPassword1 = pPassword1->next;
			if (pPassword1 == NULL)
			{
				flag = 1;
				break;
			}
        }
		if (flag)
		{
			break;
		}
    }
    /*assert(pPassword1 != NULL);*/
    
    return 0;    
}

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
        free(p2);
    }
}

void free_password_list(struct password_list *Passwords)
{
    struct password_node *p1,*p2;
    
    p1 = Passwords->head;
    Passwords->count = 0;
    Passwords->head = NULL;

    while (p1 != NULL)
    {
        p2 = p1;
        p1 = p1->next;
        free(p2->password);
        free(p2);
    }
}
