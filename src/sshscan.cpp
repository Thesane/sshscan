#include "sshscan.h"
#include "gcrypt-fix.h"
#include <error.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <list>
using namespace std;

void* try_login_pwd(void *arg)
{
  int sockfd;
  int flag_connect_success = 0;
  int i;
  /*, j;*/
  int count_num,h_count_num,auth_pw = 0;
  LIBSSH2_SESSION *session;
  char *userauthlist;
  struct Try_login_arg_by_pwd *parg = (struct Try_login_arg_by_pwd *)arg;
  struct sockaddr_in address;
  FILE *fp;
  //printf("current %i,%i,%i,%i,%i  %i %s\n",(*parg->conn_cnt)[0],(*parg->conn_cnt)[1],(*parg->conn_cnt)[2],(*parg->conn_cnt)[3],(*parg->conn_cnt)[4],parg->ip_ind,parg->ip);
  while((*parg->conn_cnt)[parg->ip_ind] > 8)
  {
    //printf("waiting for max_conn %i for ip %s\n",(*parg->conn_cnt),parg->ip);
    sleep(1);
  }
  pthread_mutex_lock(&(parg->setting->complete_mutex));
  (*parg->conn_cnt)[parg->ip_ind]++;
  pthread_mutex_unlock(&(parg->setting->complete_mutex));
      
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(parg->port);
  address.sin_addr.s_addr = inet_addr(parg->ip);
  
  
  count_num = 0;
  h_count_num = 0;
  flag_connect_success = 0;
  try_again:
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket() error:");
    parg->ret = -1;
    goto exit_it;
  }
  struct timeval timeout;      
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  
  if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
    sizeof(timeout)) < 0)
    printf("setsockopt failed\n");
  
  if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
    sizeof(timeout)) < 0)
    printf("setsockopt failed\n");
  
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
    close(sockfd);
    count_num++;
    if(count_num < 2)
    {
	sleep( 2);
       goto try_again;
    }
     
    else
    {
//       printf("connect to %s failed\n",parg->ip);
      goto exit_it;
    }
    
  }
  
  session = libssh2_session_init();gcrypt_fix();
  libssh2_session_set_timeout(session,2000);
  if (libssh2_session_handshake(session, sockfd))
  {
    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    
    close(sockfd);
    parg->ret = -1;
    h_count_num++;
    if(h_count_num < 2)
    {
       goto try_again;
    }
     
    else
    {
//       printf("handshake %s failed\n",parg->ip);
      goto exit_it;
    }
    
  }
  userauthlist = libssh2_userauth_list(session, parg->user, strlen(parg->user));
  if(userauthlist == NULL)
  {
    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    close(sockfd); 
    
    goto exit_it;
  }
  if (strstr(userauthlist, "password") != NULL) {
    auth_pw = 1;
  }
  if(auth_pw == 0)
  {
    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    close(sockfd); 
    goto exit_it;
    
  }
  if (libssh2_userauth_password(session, parg->user, parg->password))
  {
    //printf("\tAuthentication by password failed! IP:%s:%d Username:%s Password:%s \n",
    //    parg->ip, parg->port ,parg->user,  parg->password );
    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    close(sockfd); 
    /*sleep(2);*/
    
    parg->ret = 0;
    goto exit_it;
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
      goto exit_it;
    }
    
    fprintf(fp, "%s:%d  User:%s  Password:%s  \n",  parg->ip, parg->port ,parg->user, parg->password);
    fclose(fp);
    
    pthread_mutex_unlock(&(parg->setting->success_log_mutex));
    exit_it:
    pthread_mutex_lock(&(parg->setting->complete_mutex));
    parg->thread_list->remove(pthread_self());
	  (*parg->conn_cnt)[parg->ip_ind]--;
    pthread_mutex_unlock(&(parg->setting->complete_mutex));
//     printf("ip %s user %s password %s\n",parg->ip,parg->user,parg->password);
    pthread_exit(0);
    return NULL;
  }
  
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
  setting->connect_test_count = 2;  
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
  if (pthread_mutex_init(&(setting->complete_mutex), NULL) != 0)
  {
    return -1;
  }
  
  if (pthread_mutex_init(&(setting->setting_mutex), NULL) != 0)
  {
    pthread_mutex_destroy(&(setting->success_log_mutex));
    pthread_mutex_destroy(&(setting->complete_mutex));
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
  pthread_mutex_destroy(&(setting->complete_mutex));
  
  
  /*free worker arg queue*/
  /*p1 = setting->workarg_list_head;
   *    while (p1 != NULL)
   *    {
   *	if (p1->level == 1 || p1->level == 3)
   *	{
   *	    free(p1->point);
   *	    p1->point = NULL;
   *	    p2 = p1;
   *	    p1 = p2->next;
   *	    free(p2);  
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
   *    int flag;*/
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
