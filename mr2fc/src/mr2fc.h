/************************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-10-29
# 
# Unless you and I-MOVE execute a separate written software license 
# agreement governing use of this software, this software is licensed 
# to you under the terms of the GNU General Public License version 2 
# (the "GPL"), with the following added to such license:
# 
#    As a special exception, the copyright holders of this software give 
#    you permission to link this software with independent modules, and 
#    to copy and distribute the resulting executable under terms of your 
#    choice, provided that you also meet, for each linked independent 
#    module, the terms and conditions of the license of that module. 
#    An independent module is a module which is not derived from this
#    software.  The special exception does not apply to any modifications 
#    of the software.  
# 
# Not withstanding the above, under no circumstances may you combine 
# this software in any way with any other I-MOVE software provided 
# under a license other than the GPL, without I-MOVE's express prior 
# written consent. 
#
# Revision Table
#
# Version   | Name             |Date           |Description
# ----------|------------------|---------------|-------------------
#  0.1.0    |lishengming       |2014-10-29     |Trial Version
#  1.1.0    |lishengming       |2015-01-14     |Version for Test
#
*************************************************************************/

#ifndef __MR2FC_H__
#define __MR2FC_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

/*############################## Includes ####################################*/
#include <sys/stat.h>      
#include <unistd.h>      
#include <stdio.h>      
#include <stdlib.h>      
#include <sys/socket.h>      
#include <sys/types.h>      
#include <string.h>      
#include <asm/types.h>      
#include <linux/netlink.h>      
#include <linux/socket.h>      
#include <stddef.h>   
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/queue.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

#include <msg.h>
#include <json.h>
#include <event.h>
#include <evhttp.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <shm.h>
#include <per_auth.h>
#include <prc_mgt.h>

/*############################## Macros ######################################*/
//#define SSL_SURPPORT

#define MR2FC_VER           "1.1.0"

#ifdef SSL_SURPPORT
#define TSL_CACERT          "/etc/tsl/ca.crt"
#define TSL_MYCERTF         "/etc/tsl/client.crt"
#define TSL_MYKEY           "/etc/tsl/client.key.unsecure"

#define SSL_CIPHER_RC4_MD5  "RC4-MD5"
#endif

#define gettid() syscall(__NR_gettid)
  
#define RECV_TIMEOUT        (10 * 1000)
#define DEST_MODULE         "msg_server"
//#define DEST_MODULE         "router_client"


#define HTTP_REQ_TIMEOUT            10
#define HTTP_MAX_QUERY_VARS         64
#define HTTP_VAR_NAME_LEN           64
#define HTTP_VAR_VALUE_LEN          64
#define HTPP_CLB_LEN                64
#define MAX_HEAD_ITEMS              16
#define MAX_DATA_ITEMS              48
#define MAX_RECV_RETRY_TIMES        5
#define HTTP_SERVER_THREAD_NUM      10
#define HTTP_SERVER_BACKLOG         1024
#define HTTP_REQ_PRC_TIMEOUT        10

/* Mr2fc debug macro. */
#define IM_MR2FC_LOG_ERR              0x00000001
#define IM_MR2FC_LOG_WARN             0x00000002
#define IM_MR2FC_LOG_INFO             0x00000004
#define IM_MR2FC_LOG_TRACE            0x00000008

/* Default, print the first three levels log */
#define IM_MR2FC_LOG_FLAG             0x00000007

#define IM_MR2FC_LOG(IMLogFlag, IMLogLevel, fmt, args...) do { \
    if ((IMLogFlag) & (IMLogLevel)) { \
        FILE *fp = fopen("/dev/console", "w"); \
    	if (fp) { \
            fprintf(fp, "[IM_MR2FC][%s]-%d ", __FUNCTION__, __LINE__); \
    		fprintf(fp, fmt, ## args); \
    		fprintf(fp, "\n"); \
    		fclose(fp); \
    	} \
    } \
} while (0)

#ifndef IM_FREE_JSON_OBJ
#define IM_FREE_JSON_OBJ(ptr) if(ptr){json_object_put(ptr); ptr = NULL;}
#endif

#ifndef NTOHL
#define NTOHL(x) (x) = ntohl(x)
#endif

#ifndef HTONL
#define HTONL(x) (x) = htonl(x)
#endif

#ifndef NTOHS
#define NTOHS(x) (x) = ntohs(x)
#endif

#ifndef HTONS
#define HTONS(x) (x) = htons(x)
#endif

#define K_CONTENT_LEN       "Content-Length"
#define K_IMOVE_TYPE        "Imove-Type"
#define ARIA2_URL           "http://192.168.222.254:6800/jsonrpc"

#define HTTP_RESP_CODE_OK       200
#define HTTP_CMM_TIME_OUT       (10 * 60)
#define INVALID_SOCKET          -1
#define SERVER_NAME_LEN         64
#define MAX_TCP_CONN_FALI_CNT   5
#define SYNC_LEN                4
#define TCP_REPLY_BUF_LEN       (129 * 1024)
#define TCP_RECV_BUF_LEN        (65 * 1024)
#define DEV_ID_LEN              64
#define SESSION_ID_LEN          8
#define MAC_STR_LEN             17
#define SEND_TIME_OUT           5
#define RECV_TIME_OUT           5
#define MAX_TCP_FAIL_CNT        5
#define MAX_HTTP_RESP_DATA_LEN  (128 * 1024)
#define MAX_HTTP_GET_PARAS_LEN  1024
#define MAX_HB_FAIL_CNT         6
#define MAX_USR_NAME_LEN        64
#define MAX_PWD_LEN             64
#define MAX_HOST_NAME_LEN       64
#define MAX_IP_LEN              15
#define MAX_SESSION_STR_LEN     64
#define MAX_ONLINE_CLIENT_CNT   32

#define DEFAULT_SYNC            "SSID"
#define MR2FC_CONFIG_FILE       "/etc/mr2fc.conf"
#define FORMAT_STRING           "%s"
#define FORMAT_UNINT            "%u"
#define FORMAT_INT              "%d"
#define DEV_IF_NAME             "eth0"

#define K_USR_NAME              "usr_name"
#define K_PWD                   "password"
#define K_LOGIN_TYPE            "login_type"
#define DEFAULT_PWD             "imove"
#define K_CALLBACK              "callback"

#define K_DEV_NAME              "router_name"
#define K_DEV_ID                "dev_id"
#define K_ROUTER_STAT           "router_status"
#define K_ROUTER_ID             "router_id"
#define K_BIND_STATE            "bind_state"
#define K_SESS_KEY              "secret_key"

#define DHCP_RELEASE_FILE       "/var/dhcp.leases"
#define ARP_FILE                "/proc/net/arp"

#define SPECIAL_STR_5B          "%5B"
#define SPECIAL_STR_5b          "%5b"
#define SPECIAL_STR_5D          "%5D"
#define SPECIAL_STR_5d          "%5d"
#define SPECIAL_STR_22          "%22"

/*############################## Enums ######################################*/

/*############################## Structs #####################################*/

typedef struct
{
    int socket_fd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int fail_count;
} socket_manage_info;

typedef struct
{
    char server_name[SERVER_NAME_LEN];
    unsigned int server_port;
    unsigned int heart_beat_interval;
    char mac_str[MAC_STR_LEN + 1];
    unsigned int http_port;
} mr2fc_config_info;

/* network packet, one byte aligned */
#pragma pack(1)
typedef struct
{
    char sync[SYNC_LEN];
    unsigned short cmd;
    unsigned int msg_len;
    unsigned int seq_no;
} tcp_msg_head;

typedef struct
{
    unsigned long long session_id;
    char msg_type;
    unsigned int head_len;
} tcp_normal_msg_sub_head;

typedef struct
{
    char sync[SYNC_LEN];
    unsigned short cmd;
    unsigned int msg_len;
    unsigned int seq_no;
    unsigned long long session_id;
    char msg_type;
    unsigned int head_len;
} tcp_normal_whole_msg_head;

typedef struct
{
    char dev_id[DEV_ID_LEN];
} dev_login_info;

typedef struct
{
    char dev_id[DEV_ID_LEN];
    unsigned long long session_id;;
} dev_heart_beat_info;

typedef struct
{
    unsigned long long session_id;
    unsigned char sate;
} dev_login_ret;

typedef struct
{
    unsigned long long session_id;
    unsigned char sate;
} dev_logout_ret;

typedef struct
{
    unsigned long long session_id;
    unsigned char sate;
} heart_beat_info;

typedef struct
{
    unsigned long long session_id;
    unsigned char usr_name_len;
} usr_bind_dev_info;

typedef struct
{
    unsigned long long session_id;
    unsigned char state;
} usr_bind_state_ret;

typedef struct
{
    unsigned long long session_id;
    unsigned char state;
    unsigned int router_idx;
} usr_bind_ret;
#pragma pack()

typedef struct
{
    char name[HTTP_VAR_NAME_LEN];
    char value[HTTP_VAR_VALUE_LEN];
} http_query_var;

typedef struct
{
    int count;
    http_query_var query_vars[HTTP_MAX_QUERY_VARS];
} http_query_var_tbl;

typedef struct
{
    char type;
    char name[HTTP_VAR_NAME_LEN];
    char value[HTTP_VAR_VALUE_LEN];
} var_item;

typedef struct
{
    char call_back[HTPP_CLB_LEN];
    int head_itm_cnt;
    var_item head_vars[MAX_HEAD_ITEMS];
    int data_itm_cnt;
    var_item data_vars[MAX_DATA_ITEMS];
} query_vars;

typedef struct
{
    char name[MAX_HOST_NAME_LEN + 1];
    char mac[MAC_STR_LEN + 1];
    char ip[MAX_IP_LEN + 1];
    unsigned short port;
    char session[MAX_SESSION_STR_LEN + 1];
    unsigned int last_time;
} http_client;

typedef struct
{
    char name[MAX_USR_NAME_LEN];
    char pwd[MAX_PWD_LEN];
    int login_type;
} usr_login_info;

typedef struct
{
    char usr_name[MAX_USR_NAME_LEN];
    char dev_pwd[MAX_PWD_LEN];
    char dev_name[MAX_USR_NAME_LEN];
    char dev_id[DEV_ID_LEN];
} usr_bind_info;

typedef struct
{
    char usr_name[MAX_USR_NAME_LEN];
    char dev_id[DEV_ID_LEN];
} bind_state_info;

typedef enum
{
    MSG_IMOVE = 1,
    MSG_OTHER = 2,
}msg_type;

typedef enum
{
    STAGE_REPORT_DEV_FOR_AUTH,  //auth
    STAGE_HEART_BEAT,           //heart beat
    STAGE_NORMAL,               //normal
} run_stage_type;

typedef enum
{
    SSID_SEND                   = 0x0101,
    SSID_RECIEVE                = 0x0102,
    ROUTER_LOGIN                = 0x0103,
    ROUTER_LOGIN_RET            = 0x0104,
    ROUTER_LOGINOUT             = 0x0105,
    ROUTER_LOGINOUT_RET         = 0x0106,
    ROUTER_HEARBEAT             = 0x0107,    
    ROUTER_HEARBEAT_RET         = 0x0108,
    ROUTER_USER_BIND            = 0x0109,
    ROUTER_USER_BIND_RET        = 0x010a,
    ROUTER_USER_BIND_STATE      = 0x010b,
    ROUTER_USER_BIND_STATE_RET  = 0x010c,
} tcp_msg_cmd_id;

typedef enum
{
    HTTP_GET        = 0,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
} http_req_method;

typedef enum
{
    TYPE_JSON       = 0,    // application/json;charset=UTF-8
    TYPE_TXT_HTML,          // text/html;charset=UTF-8
    TYPE_APP_XML,           // application/xml;charset=UTF-8
    TYPE_OCT_STREAM,        // application/octet-stream;charset=UTF-8
} http_content_type;

typedef enum
{
    CMD_USR_LOGIN       = 0x0100,
    CMD_USR_LOGOUT      = 0x0101,
    CMD_USR_BIND        = 0x0104,
    CMD_GET_BIND_STATE  = 0x010c,
} msg_cmd;

typedef enum
{
    LOGIN_ANONYMOUS = 1,
    LOGIN_PWD       = 2,
} usr_login_type;

typedef enum
{
    TYPE_INT = 1,
    TYPE_STR = 2,
} http_var_type;

typedef enum
{
    LOGOUT_SUCC     = -1,
    LOGIN_TYPE_ERR  = -2,
    PWD_ERR         = -3,
    SESSION_ERR     = -4,
    LOGOUT_ERR      = -5,
    EXCEED_MAX_CLI  = -6,
    INTERNAL_ERR    = -7,
    AUTH_SUCC       = -100,
    BIND_SUCC       = -200,
    BIND_FAIL       = -201,
    DEFAULTE_CODE   = -999,
} auth_code;

typedef enum
{
    CODE_SUCC       = 0,
    CODE_NO_PERM    = 7,
} err_code;

#define RET_MSG_AUTH_SUCC       "auth success"
#define RET_MSG_LOGOUT_SUCC     "logout success"
#define RET_MSG_INTERNAL_ERR    "internal err"
#define RET_MSG_LOGINTYPE_ERR   "not support login type"
#define RET_MSG_PWD_ERR         "password err"
#define RET_MSG_SESSION_ERR     "wrong session"
#define RET_MSG_LOGOUT_ERR      "logout err, no such dev"
#define RET_MSG_EXCEED_MAX_CLI  "login failed, cause of exceed max client count"
#define RET_MSG_UNKOWN          "unkown"

typedef int (*msg_prcs_func)(char *, unsigned int, unsigned int);

typedef struct
{
    tcp_msg_cmd_id msg_type;
    char *msg_desc;
    msg_prcs_func msg_handl;
} tcp_msg_prcs_tbl_item;

typedef struct
{
    long status;
    int content_type;
    size_t content_len;
    char data[0];

} http_resp_msg;

typedef struct
{
    char *msg;
    int len;
    run_stage_type stage;
} tcp_msg_prc_paras;

typedef struct
{
    char *msg;
    int len;
    unsigned int seq;
    int index;
    run_stage_type stage;
} tcp_msg_prc_paras_new;

/*############################## Prototypes ##################################*/

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __MR2FC_H__ */
