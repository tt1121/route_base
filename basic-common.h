/*##############################################################################
** 文 件 名: basic-common.h
** Copyright (c), 2013-2016, T&W ELECTRONICS(SHENTHEN) Co., Ltd.
** 日    期: 2013-11-16
** 描    述:
** 版    本:
** 修改历史:
** 2013-11-16   创建本文件；
##############################################################################*/
#ifndef __BASIC-COMMON_H__
#define __BASIC-COMMON_H__

#if __cplusplus
extern "C" {
#endif

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
#include <json.h>
#include <msg.h>
#include <http_client.h>

/*############################## Macros ######################################*/
#define MAX_NAME_LEN    32
#define IP_ADDR_LEN     18
#define MAC_STR_LEN     20
#define STATUS_LEN      4
#define BUFF_LEN        128
#define TIME_OUT        30
#define MAX_LEN_OF_BUF  2048
#define DEFAULT_VALUE   0
#define DEFAULT_ERROR   (-1)
#define MEM_STATS_NUM   4
#define CPU_STATS_NUM   7

#define SYSTEM_TIME_OUT     30
#define DOWNLOAD_TIME_OUT   66  /*8M/125kbps,66 seconds time out */
#define MAX_STAS_LEN        (18*64)

#define MAX_LEN_OF_ONLINE_STA_TABLE     64
#define DOWNLOAD_PATH_LEN               256

#define RESULT_CODE_SUCCESS             0
#define RESULT_CODE_WRONG_PARAMETER     1
#define RESULT_CODE_MSG_SHORT           2
#define RESULT_CODE_INTERNAL_ERR        3
#define RESULT_CODE_SYSTEM_CMD_ERR      4
#define RESULT_CODE_SYSTEM_CMD_TIMEOUT  5
#define RESULT_CODE_DOWNLOADING_IMG     6

#define FIRMWARE_DOWNLOAD_PATH          "/tmp/"
#define PATH_CPU_RATE_SH                "/www/cpu-rate.sh"

#define DHCP_LEASE_FILE             "/tmp/dhcp.leases"
#define CMD_BRCTL_SHOW_MACS         "brctl showmacs br-lan"
#define MODULE_NAME_OF_THIS         "Basic"
#define MODULE_NAME_OF_WIFI1        "Basic.WifiInfo2G"
#define MODULE_NAME_OF_WIFI2        "Basic.WifiInfo5G"
#define MODULE_NAME_OF_SYSTEM       "Basic.SystemInfo"
#define MODULE_NAME_OF_CLILIST      "Basic.ClientList"
#define MODULE_NAME_OF_BLACKLIST    "Basic.BlackList"
#define MODULE_NAME_OF_REBOOT       "Basic.Reboot"
#define MODULE_NAME_OF_IMGUPDATE    "Basic.ImgUpdate"
#define MODULE_NAME_OF_SYNACCOUNT   "Basic.sync_account"

#define OPTION_BLACK_STA            "BlackSta"

#define DEVICE_NAME_OF_2G       "mt7620"
#define DEVICE_NAME_OF_5G       "mt7610"
#define IF_NAME_OF_2G           "@wifi-iface[1]"
#define IF_NAME_OF_5G           "@wifi-iface[0]"
#define APPLY_COMMIT            "uci commit"
#define APPLY_WIFI              "wifi"

#define OBJECT_SYSTEM_CPU       "cpuinfo"
#define OBJECT_SYSTEM_MEM_USED  "mem_used"
#define OBJECT_SYSTEM_MEM_TOTAL "mem_total"
#define OBJECT_SYSTEM_UP_RATE   "up_rate"
#define OBJECT_SYSTEM_DOWN_RATE "down_rate"

#define OBJECT_WIFI_DISABLED     "disabled"
#define OBJECT_WIFI_SSID         "ssid"
#define OBJECT_WIFI_ENCRYPT      "encryption"
#define OBJECT_WIFI_KEY          "key"

#define OBJECT_BLACKLIST_TITLE          "blacklist"
#define OBJECT_CLILIST_TITLE            "clistlist"
#define OBJECT_CLILIST_MAC              "mac"
#define OBJECT_CLILIST_IP               "ip_address"
#define OBJECT_CLILIST_HOST_NAME        "host_name"
#define OBJECT_CLILIST_LINK_TYPE        "link_type"
#define OBJECT_CLILIST_LINK_STATUS      "black_status"
#define OBJECT_CLILIST_ONLINE_STATUS    "online_status"


#define OBJECT_ERROR_CODE        "error_code"
#define OBJECT_ERROR_MSG         "error_msg"


#define MSG_DESC_CONFIG         "basic config msg from cloud client"
#define MSG_DESC_SYSINFO        "msg of system information"
#define MSG_DESC_2G_INFO        "msg of 2g information"
#define MSG_DESC_5G_INFO        "msg of 5g information"
#define MSG_DESC_CLI_LIST       "msg of online sta list"
#define MSG_DESC_BLACK_LIST     "msg of black table sta list"
#define MSG_DESC_2G_SET_REPLY   "msg of replying 2g config"
#define MSG_DESC_5G_SET_REPLY   "msg of replying 5g config"
#define MSG_DESC_MAC_SET_REPLY  "msg of replying mac config"
#define MSG_DESC_SYS_REB_REPLY  "msg of replying system reboot"
#define MSG_DESC_SYS_UPD_REPLY  "msg of replying system updatet"
#define MSG_DESC_IMG_UPDATE     "post msg for img update"

#define RESULT_SUCCESS                  "config success"
#define RESULT_WRONG_PARAMETER          "wrong parameter"  
#define RESULT_MSG_SHORT                "msg is too short"
#define RESULT_INTERNAL_ERR             "internal error"
#define RESULT_SYSTEM_CMD_ERR           "system command error"
#define RESULT_MSG_SYSTEM_CMD_TIMEOUT   "system command timeout"
#define RESULT_UPDATING                 "downloading img file and will update system"
#define RESULT_UNKOWN                   "unkown"

#define OBJECT_TITLE        "title"        
#define OBJECT_DESC         "desc"
#define OBJECT_MSG          "rst_msg"
#define MSG_TITLE           "Firmware upgrade"
#define MSG_DESC            "Firmware upgrade results"
#define MSG_RST             "Upgrade success"
#define MODULE_URL          "https://oc.openrouter.cc/push/notification/imgupdate.json"

#define BC_LOG_FILE_NAME         "/overlay/basic-common.log"
#define BC_LOG_MAX_SIZE          (4*1024)


#define PWD_KEY             "new_pwd"
#define USER_KEY            "account"
#define SET_MD5PWD2FLASH    "protest --cloud_pwd_md5 -w"
#define SET_PWD2FLASH       "protest --cloud_pwd_ori -w"
#define SET_CRYPWD2FLASH    "protest --cloud_pwd_cry -w"
#define GET_USERNAME_CMD    "protest --cloud_name -r"
#define CRYPT_KEY_STRING    "$1$TW"
#define CHANGE_PWD          "change password"

/*############################## Structs #####################################*/
typedef struct {
    char hostname[MAX_NAME_LEN];    //主机名
    char ipaddr[IP_ADDR_LEN];       //ip
    char macstr[MAC_STR_LEN];       //mac
    int link_type;                  //连接类型，有线，2.4g，或5g,分别为0，1，2
    int line_status;                //上网的状态，0，断线；1，在线
} online_sta_entry, *p_online_sta_entry;

typedef struct {
    int   		sta_num;			//STA个数
    online_sta_entry  online_sta_info[MAX_LEN_OF_ONLINE_STA_TABLE];
} online_sta_table, *p_online_sta_table;         //在线用户列表

typedef struct {
    int port_no;    //端口号，对应每个接口
    char macstr[MAC_STR_LEN];       //mac
    char local_status[STATUS_LEN];  //是否属于本地mac，yes为是，no为非本地mac，即用户mac
} brctl_mac_entry, *p_brctl_mac_entry;

typedef struct {
    int   		mac_num;			//MAC个数
    brctl_mac_entry  brctl_mac_info[MAX_LEN_OF_ONLINE_STA_TABLE];
} brctl_mac_table, *p_brctl_mac_table;         //桥里接口mac列表

typedef struct PACKED         //定义一个cpu occupy的结构体
{
    char name[20];      //定义一个char类型的数组名name有20个元素
    unsigned int user; //定义一个无符号的int类型的user
    unsigned int nice; //定义一个无符号的int类型的nice
    unsigned int system;//定义一个无符号的int类型的system
    unsigned int idle; //定义一个无符号的int类型的idle
}cpu_occupy;

typedef int (*wifi_msg_prcs_func_ptr)(MsgHeader *, int, int);
typedef int (*clilist_msg_prcs_func_ptr)(MsgHeader *, int);
typedef int (*blacklist_msg_prcs_func_ptr)(MsgHeader *, int);
typedef int (*sysinfo_msg_prcs_func_ptr)(MsgHeader *, int);
typedef int (*imgupdate_msg_prcs_func_ptr)(MsgHeader *, int);
typedef int (*sysreboot_msg_prcs_func_ptr)(MsgHeader *, int);
typedef int (*synaccount_msg_prcs_func_ptr)(MsgHeader *, int);

/*############################## Prototypes ##################################*/
int bc_prcs_wifi_set(MsgHeader *msg, int wifi_idx, int fd);
int bc_prcs_wifi_get(MsgHeader *msg, int wifi_idx, int fd);
int bc_prcs_clilist_add(MsgHeader *msg, int fd);
int bc_prcs_clilist_del(MsgHeader *msg, int fd);
int bc_prcs_clilist_get(MsgHeader *msg, int fd);
int bc_prcs_blacklist_get(MsgHeader *msg, int fd);
int bc_prcs_sysinfo_get(MsgHeader *msg, int fd);
int bc_prcs_imgupdate_set(MsgHeader *msg, int fd);
int bc_prcs_sysreboot_set(MsgHeader *msg, int fd);
void cmdline_to_argcv(char *cmd, int *argc, char *argv[]);
void bc_execvp(const char *fmt, ...);
int download_file(char *cmd, int time_out);
static void bc_create_reply_msg(MsgHeader *request_msg_head, char *my_string, int len);
static int bc_find_str_in_file(const char *fileName, const char *str);
static void bc_create_rst_msg(char *rst_msg, int ret);
void bc_set_reply(int ret, char *desc, MsgHeader *request_msg_head, int fd);
void bc_log(const char *fmt, ...);
static void get_cpu_info(int *cpu_percent);
void get_cpuoccupy (cpu_occupy *cpust);
int cal_cpuoccupy (cpu_occupy *o, cpu_occupy *n);
static void get_mem_info(float *mem_total, float *mem_used);
void converter_string_with_special_character(char *str);
int del_substr(char *str, char *substr);
char *skip_white(char *ptr);
char *skip_not_white(char *ptr);
char *skip_token(char *ptr);
static void get_wan_info(float *up_rate, float *down_rate);
int cmd_read(const char* command, const char* ifname, const char *pszPrefix, const char* itemname, const char* seperator, char* value, size_t size);
static int bc_system(char *command, int printFlag);
static void sta_table_init(online_sta_table *tab);
static void mac_table_init(brctl_mac_table *tab);
static void online_sta_set_entry(online_sta_entry *p_entry, char *name, char *ipstr, char *macstr, int type, int status);
static void brctl_mac_set_entry(brctl_mac_entry *p_entry, int port, char *macstr, char *localstr);
static int brctl_mac_table_search(brctl_mac_table *tab, char *macstr);
static int sta_mac_table_search(online_sta_table *tab, char *macstr);
static int online_sta_table_set_entry(online_sta_table *sta_tab, brctl_mac_table *mac_tab);
int get_uci_option_value(char *name, char *option, char *value);
int get_cmd_value(char *name, char *value);
int bc_prcs_sysaccount_set(MsgHeader *msg, int fd);


#if __cplusplus
}
#endif

#endif /* __BASIC-COMMON_H__ */

