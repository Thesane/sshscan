#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <libssh2.h>
#include <time.h>
#include <pthread.h>

#ifndef _SSHSCAN_H_
#define _SSHSCAN_H_

#define FROM_UNKNOWN -1
#define FROM_KEYBOARD 0
#define FROM_FILE 1

#define MAX_LEN_FILENAME 256
#define MAX_LEN_TIME_STR 256


#define MAX_LEN_PATH    2048
#include <list>
#include <vector>
using namespace std;
typedef  struct _Setting
{
    char *Host_File;
    char *User_File;
    short port;
    int     connect_test_count;   
    char success_log_filename[MAX_LEN_PATH];  
    char path_log[MAX_LEN_PATH];  
    pthread_mutex_t success_log_mutex;  
    pthread_mutex_t complete_mutex; 
    pthread_mutex_t setting_mutex;  
    struct password_node **pwd_groups; 
    int per_pwd_num;     
    struct workarg_queue *workarg_list_head ;
    int pwd_group_num;  
    unsigned int thread_num;  
}Setting;

struct ip_node
{
    char *ip;
    struct ip_node *next;
};
struct ip_list
{
    struct ip_node *head;
    int count;
};

struct user_node
{
    char *user;
    char *password;
    struct user_node *next;
};
struct user_list
{
    struct user_node *head;
    int count;
};


/*Level 3*/
struct Try_login_arg_by_pwd
{
    char *ip;
    char *user;
    short port;
    char *password;
    int complete;
    vector<int> *conn_cnt;
    int ip_ind;
    Setting *setting;
    list<pthread_t> *thread_list;
    int ret;
};

struct workarg_queue
{
    void *point;
    int level;
    struct workarg_queue *next;
};

struct threads
{
  pthread_t *pThread;
  struct threads *next;
};
int checkSetting(int argc, char **argv, Setting *setting);
void free_setting(Setting *setting);
int analysisSetting(Setting *setting, struct ip_list *IPs, 
        struct user_list *Users);
void free_ip_list(struct ip_list *IPs);
void free_user_list(struct user_list *Users);
void* try_login_pwd(void *arg);


#endif
