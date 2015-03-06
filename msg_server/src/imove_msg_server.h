#ifndef __IMOVE_MSG_SERVER_H__
#define __IMOVE_MSG_SERVER_H__
#include <errno.h>
#include <stdlib.h>             /* malloc, free, etc. */
#include <stdio.h>              /* stdin, stdout, stderr */
#include <string.h>             /* strdup */
#include <ctype.h>
#include <time.h>               /* localtime, time */
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>             /* OPEN_MAX */
#include <setjmp.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/types.h>          /* socket, bind, accept */
#include <sys/socket.h>         /* socket, bind, accept, setsockopt, */
#include <sys/stat.h> 
#include <assert.h>

#include <uci.h>
#include "json.h"
#include <msg.h>
#include <per_auth.h>
#include <imove_api.h>
#include <speedtest.h>
#include <wizard.h>
#include <logic.h>
#include "./fw_upgrade/im_download.h"

typedef unsigned int UINT;
typedef int			INT;


#define ERROR_LOG_FILE	"/var/log/msg_server.log"
#define ERROR_LOG_FILE_BK	"/var/log/msg_server.log.bk"

#define BRIDGE_MODE 			0
#define REPEATER_MODE 			1
#define SPEED_LIST_LEN 			256

#define SYS_CMD				0x02
#define STORAGE_CMD		0X03
#define SPEED_CHECK_CMD	0X04
#define GET_UPLOAD_CMD	0X05

/**** System set operation cmd *****************/
#define FN_CREATE_GROUP            		0x200
#define FN_GET_GROUP_LIST         	 	0x201
#define FN_GET_GROUP_SETTINGS_INFO 	0x202
#define FN_DELETE_GROUP            		0x203
#define FN_AMEND_GROUP             		0x204
#define FN_ADD_GROUP_DEV           		0x205
#define FN_DELETE_GROUP_DEV        		0x206
#define FN_GET_GROUP_DEV_LIST      		0x207
#define FN_QUERY_DEV_INFO          		0x208 
#define FN_ROUTER_SWITCH_STATUS  		0x209
#define FN_WIFI_SET_WIRELESS       		0x20A
#define FN_WIFI_GET_WIRELESS_STATUS 	0X20B
#define FN_SET_VWAN_MODE_PPPOE      	0X20C 
#define FN_GET_VWAN_MODE_PPPOE      	0X20D
#define FN_SET_VWAN_MODE_STATIC     	0X20E
#define FN_GET_VWAN_MODE_STATIC     	0X20F
#define FN_CLIENT_CONNECT_TO_AP     	0X210
#define FN_GET_REPEATER_STATUS      	0X211
#define FN_SET_PASSWORD			    	0X212

#define FN_CLOSE_ROUTER_TYPE        		0X219
#define FN_RESET_FACTORY            		0X21A

#define FN_GET_FW_VERSION           		0X21C
#define FN_GET_FW_UPGADE_STATUS     	0X21D
#define FN_GET_ROUTER_INIT_STATUS   	0X21F

#define FN_GET_SCAN_RESULT          			0X220
#define FN_GET_ROUTER_CUR_SPEED     		0X221
#define FN_SET_DEV_UPLOAD_MAXSPEED  		0X223
#define FN_SET_DEV_DOWNLOAD_MAXSPEED 	0X224
#define FN_FORMAT_DISK               			0X225
#define FN_GET_ROUTER_CONNECT_STATUS 	0X227
#define FN_PASSWORD_EXIST            			0X228
#define FN_GET_USR_DEV_ACCESS_PER    		0X229
#define FN_WLAN_GET_CONNECT_TYPE     		0X22A
#define FN_WLAN_GET_REPEATER_STATUS  	0X22B
#define FN_GET_SSID_AND_ROUTE_ID     		0X22D
#define FN_PASSWORD_MODIFICATION     		0X22E
#define FN_FW_UPGRADE                			0X24F

#define FN_SET_DHCP_CONNCT				0x256
#define FN_GET_ROUTER_STATUS				0x230
#define FN_GET_ROUTER_NETWORK_STATUS 	0x231
#define FN_GET_ROUTER_CONNECT_DEVRATE 	0x232	// 562
#define FN_GET_DEV_CON_INFO 				0x233	// 563
#define FN_GET_ROUTER_MAC					0x234	// 564
#define FN_CLONE_MAC						0x236	// 566
#define FN_GET_DHCP_INFO 					0X238	// 568
#define FN_SET_DHCP_INFO					0x239	// 569
#define FN_GET_IP_BINDING_INFO				0x23A	// 570
#define FN_BIND_IP							0x23B	// 571
#define FN_DEL_IP_BIND						0x23C	// 572
#define FN_GET_WIFI_SETTINGS				0x23D	// 573
#define FN_SET_WIFI_SETTINGS				0x23E	// 574
#define FN_GET_WIFI_ACCESS_CTR_MAK		0x23F	// 575
#define FN_SET_WIFI_ACCESS_STR_MAK		0x240	// 576
#define FN_SET_WIFI_ACCESS_CTRL			0x241	// 577
#define FN_SET_GROUP						0x242	// 578
#define FN_SET_HDSIK						0x243	// 579
#define FN_GET_LIMIT_DEV_INFO				0x245	// 581
#define FN_SET_LIMIT_SPEED					0x246	// 582
#define FN_SET_UPNP							0x247	// 583
#define FN_GET_UPNP						0x248	// 584
#define FN_GET_PORT_FORWARD_INFO		0x249	// 585
#define FN_GET_DMZ_INFO					0x24A	// 586
#define FN_SET_DMZ_INFO					0x24B	// 587
#define FN_GET_WEB_FW_VERSION			0x24E	// 590
#define FN_SYSTEM_BACKUPS					0x250	// 592
#define FN_RECOVER_BACKUP_SYSTEM			0x251	// 593
#define FN_GET_WAN_STATUS					0x252	// 594
#define FN_GET_LAN_STATUS					0x253	// 595
#define FN_GET_MAMAGEPC_MAC				0x254	// 596
#define FN_GET_ACCESS_INTERNET_STATUS	0x255	// 597
#define FN_SET_DHCP_CONNECT				0x256	// 598
#define FN_GET_HDISK_SETTINGS				0x257	// 599
#define FN_START_UPGRADE					0x259	// 601
#define FN_RESUME_MAC						0x25A	// 602
#define FN_ADD_PORT_FORWARDING			0x25D	// 605
#define FN_PORT_AMEND_FORWARDING		0x25E	// 606
#define FN_DEL_PORT_FORWARDING			0x25F	// 607
#define FN_GET_SAMBA_INFO					0x260	// 608
#define FN_ADD_DDNS						0x261	// 609
#define FN_DEL_DDNS							0x262	// 610
#define FN_GET_DDNS_LIST					0x263	// 611
/**** Storage operation cmd ****/
#define FN_GET_STORAGE_INFO          			0x300
#define FN_FILE_LS_FILE_DIR          			0x301
#define FN_FILE_LS_R_FILE_DIR        			0x302
#define FN_FILE_MAKE_DIR             			0x303
#define FN_FILE_COPY_FILE_DIR        			0x304
#define FN_FILE_COPY_CANCEL          			0x305
#define FN_FILE_MOVE_FILE_DIR        			0x306
#define FN_FILE_MOVE_CANCEL          			0x307
#define FN_FILE_RM_FILE_DIR          			0x308
#define FN_FILE_RM_CANCEL            			0x309
#define FN_FILE_RENAME_FILE_DIR      		0x30A
#define FN_FILE_QUERY_STATUS         			0x30B
#define FN_FILE_RM_DIR 						0x320

/**** Speed check cmd ****/
#define FN_GET_TEST_DOWNLOAD_SPEED   	0X400
#define FN_GET_TEST_UPLOAD_SPEED     		0X401
#define FN_GET_WIFI_PASSWD_STRENGTH  	0X402
#define FN_GET_ADMIN_PASSWD_STRENGTH 	0X404

/*** bandwidth cmd ***/
#define FN_SETUP_UPLOAD_FLOW_SPEED   		0X500

/**** unknow  ***/
#define FN_FILE_PWD_FILE_DIR 				311
#define FN_FILE_TOUCH_FILE_DIR 				312

/************************ error code defined ******************************/
#define ERROR_CODE_SUCCESS 				0
#define ERROR_CODE_UNKNOW 				1
#define ERROR_CODE_TIMEOUT 				2
#define ERROR_CODE_PORT 					3
#define ERROR_CODE_FORM 					4
#define ERROR_CODE_ATTRI 					5
#define ERROR_CODE_AUTH 					7
#define ERROR_CODE_SRC_NOT_EXIST 		8
#define ERROR_CODE_DES_NOT_EXIST 		9
#define ERROR_CODE_PARA_INVALID 			10
#define ERROR_CODE_NO_DRIVE 				11
#define ERROR_CODE_JSON_INVALID 			12
#define PLEASE_REINPUT_PASSWORD 			13
#define ERROR_NO_DES_DEV_INFO 			14 //没有获取到指定设备的信息
#define ERROR_CREATE_FILE 					15

#define ERROR_CREATE_GROUP 				30
#define ERROR_GET_GROUP_LIST 				31
#define ERROR_GET_GROUP_SETTINGS_INFO 	32
#define ERROR_DELETE_GROUP 				33
#define ERROR_AMEND_GROUP 				34
#define ERROR_ADD_GROUP_DEV 				35
#define ERROR_DELETE_GROUP_DEV 			36
#define ERROR_GET_GROUP_DEV_LIST 		37
#define ERROR_GET_USR_DEV_PERMISSION 	38
#define ERROR_GET_DEV_INFO 				39


#define ERROR_PARA_LENGTH_LONG 			50 //参数长度过长
#define ERROR_GET_ROOT_PWD  				51
#define ERROR_ADMIN_PWD_NULL 			52
#define ERROR_SET_REPEATER_FAIL 			53
#define ERROR_GET_REPEATER_STATUS 		54
#define ERROR_GET_PPPOE_STATUS 			55
#define ERROR_GET_STATIC_STATUS 			56
#define ERROR_FORMAT_DISK_FAIL 			57
#define ERROR_GET_SN_FAIL 					58
#define ERROR_GET_CUR_SPEED_ERROR 		59
#define ERROR_SET_VWAN_MODE_DHCP 		60
#define ERROR_GET_MAX_SPEED 				61
#define ERROR_GET_DEV_CONNECT_TIME 		62
#define ERROR_DEV_NOT_ONLINE 				63
#define ERROR_PARA_INVALIDE 				64
#define ERROR_GET_DEV_CONTIME 			65
#define ERROR_NO_FUNC_MODULE_DEFINED	66
#define ERROR_SYN_RESOURCE_LIMIT			67

#define ERROR_GET_AP_LSIT 					77
#define ERROR_SRC_FILE_LARGE 				78
#define ERROR_NO_SUPPORT_FORMAT 		79

#define ERROR_GET_ROUTER_STATUS 			100
#define ERROR_GET_ROUTER_NETWORK_STATUS 101
#define ERROR_GET_ROUTER_MAC 			102
#define ERROR_GET_DHCP_INFO 				103
#define ERROR_SET_DHCP_INFO 				104
#define ERROR_SET_WIFI_MARK 				105
#define ERROR_GET_IP_BINDING_INFO 		106
#define ERROR_ISVALID_FALSE 				107
#define ERROR_BIND_IP 						108
#define ERROR_DEL_BIND_IP 					109
#define ERROR_SET_DMZ_INFO 				110
#define ERROR_CLONE_MAC 					111
#define ERROR_RESUME_MAC 					112
#define ERROR_ADD_PORT_FORWORD 			113
#define ERROR_DEL_DDNS 					114
#define ERROR_ADD_DDNS 					115
#define ERROR_DEL_PORT_FORWORD 			116
#define ERROR_ADD_BLACK_LIST 				117
#define ERROR_DEL_BLACK_LIST 				118
#define ERROR_GET_WIFI_CTR 				119
#define ERROR_RECOVERY_SYSTEM 			120
#define ERROR_SYSTEM_BACKUPS 				121
#define ERROR_GET_LAN_STATUS 				122
#define ERROR_GET_DDNS_LIST 				123
#define ERROR_GET_DMZ_STATUS 				124
#define ERROR_PORT_FORWARD_SAME_NAME 	125
#define ERROR_GET_MANAGE_MAC 			126
#define ERROR_PORT_FORWARD_EXIST 		127
#define ERROR_GET_SAMBA_INFO 				128
#define ERROR_GET_WAN_INFO 				129
/***********************************************************/
#define HAVE_PERMISSION_OPRATION 			1
#define HAVE_NO_PERMISSION 				0
#define GROUP_SUCCESS 					0
#define MAX_GROUP_COUNT 				8
#define DEV_FILE_NAME_TOTAL 				64
#define MAC_LEN 					32
#define IPADDR_STR_LEN 					32
#define IP_LIST_LEN 2*1024
#define MSG_SERVER_UNCONSUME_RET_LEN 10*1024
#define MSG_SERVER_CONSUME_RET_LEN 5*1024
#define MSG_SERVER_TRUE 1
#define MSG_SERVER_FALSE 0
#define MAX_GROUP_USR_COUNT 100
#define MAX_GROUP_COUNT 8
#define WAN_MODE_TYPE 16
#define PPPOE_TYPE 1
#define DHCP_TYPE 2
#define STATIC_TYPE 3
#define REPEATER_TYPE 4
#define UPGRADE_FW_PATH 		"/tmp/update.bin"
#define TOTALLOADSIZE 			32

#define LS_MOUNT 	3
#define CP_MOUNT 	4
#define RM_MOUNT 	3
#define MKDIR_COUNT 	3
#define MV_COUNT 	4
#define RENAME_COUNT 	4
#define MAX_SRC_COUNT 	5
#define EVENT_ID 	123456

#define INIT_SETUP_COMPLETED 	0
#define WIFI_NOT_COMPLETED 	1

#define GET_WLAN_IP_FAIL 	2
#define GET_WLAN_IP_SUCCESS 	4
#define ZERO_PASSWORD_POINT 	0
#define WEAK_PASSWORD_POINT 5
#define MEDIUM_PASSWORD_POINT 15
#define INTENSITY_PASSWORD_POINT 25

#define FILE_HANDLE_RET_STR_LEN 256
#define FULL_FILE_PATH_LENGTH   1024
#define HD_DISK 	"Hdisk"
#define HD_DISK1 	"Hdisk1"
#define U_DISK 		"Udisk"
#define SD_DISK 		"sdcard"
#define HD_DISK2 	"Hdisk2"

#define U_DISK1 		"Udisk1"
#define U_DISK2 		"Udisk2"

#define SD_DISK1 	"sdcard1"
#define SD_DISK2 	"sdcard2"
#define IMOVE_PRIVATE_NAME "iMove_Private"
#define PRIVATE_FULL_PATH "/tmp/mnt/Hdisk1/iMove_Private"

#define NTFS_TYPE 1
#define EXT4_TYPR 2

/** status of connection **/
#define MSG_READ		0
#define MSG_HANDLE		1
#define MSG_HANDLE_2	2
#define MSG_WRITE		3
#define PIPE_WRITE		4
#define PIPE_READ		5
#define DONE			6
#define TIME_OUT 		7


/***************** file operation ********************/
typedef struct IM_ST_file_op_rd
{
	unsigned int i_radom;		// radom data
	int status;				// 0:success 1: failed  2:handling
	char *addr_file;			// 保存的是地址 
	struct IM_ST_file_op_rd *prev;
	struct IM_ST_file_op_rd *next;
}IM_ST_file_op_rd;

typedef struct{
    uint8_t thread_cancel_flag;//consume thread switch 
    uint16_t total_file_number;//the total number of files for consume operation
    uint16_t complete_file_number;//the completed files for consume operation
    uint32_t complete_fw_len;
	uint32_t total_fw_len;
	int32_t upgrade_ret;
	uint8_t sleep_flag;// 0 sleep;1 normal
}thread_info;

typedef struct file_info {
	char file_name[256];
	uint32_t file_size;
}file_info_t;

typedef struct src_files{
	file_info_t file_t[1024];
	char dst_dir[256];
	uint32_t count;
	uint32_t total_size;
	unsigned int i_radom;
	thread_info th_info;
}src_files_t;

/** msg header option ****************************/
#define JSON_SESSION_LEN 	33
#define JSON_SIGN_LEN		32
#define KEY_HEADER			"header"
#define KEY_CMD				"cmd"
#define KEY_VER				"ver"
#define KEY_SEQ				"seq"
#define KEY_APPID			"appid"
#define KEY_DEVICE			"device"
#define KEY_CODE			"code"
#define KEY_SESSIONID		"sessionid"
#define KEY_SIGN			"sign"
#define KEY_DATA			"data"

typedef struct IM_ST_msg_header
{
	int i_cmd;
    int i_ver;
    int i_seq;
    int i_device;
    int i_appid;
    int i_code;
    char s_session[JSON_SESSION_LEN];
    char s_sign[JSON_SIGN_LEN];
}IM_ST_msg_header;

/*** connection request **************************/
#define SOCKETBUF_SIZE 8192
#define CLIENT_STREAM_SIZE SOCKETBUF_SIZE
typedef struct IM_ST_request
{
	int fd; 				// client's socket fd
	unsigned short cmd;	// command
	int status;			// connect handle status,I.E: READ, see define.h
	time_t time_last;		// time of last success operation
	unsigned int interval;	//set or get interval, for all users at one command operation 
	int data_fd;			// fd of data,for folk child process to handle need much time do 
	struct IM_ST_request *next;       /* next */
    	struct IM_ST_request *prev;       /* previous */
	int buffer_start;		// where buffer start
	int buffer_end;		// where buffer end
	unsigned char is_cache;				// 1: need cache, 0: no; used with member interval
	struct IM_ST_msg_header msg_header;	// communication message header
	char buffer[SOCKETBUF_SIZE];			// send data buffer
	char client_stream[CLIENT_STREAM_SIZE];	//client's msg
}IM_ST_request;

/*** call back function define and struct ***/
typedef int (*IM_api_func)(json_object *obj, IM_ST_msg_header *hd, IM_ST_request *requset);
typedef struct IM_ST_handle_func
{
	unsigned short cmd;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned char combine:1,	// 标记是否可以将多个用户的请求合并，
				  reverse:7; 	// reversed
#else
	unsigned char	reverse:7, 
				combine:1;
#endif
	IM_api_func func;
}IM_ST_handle_func;

#define DIE(mesg) imove_log_error_mesg(__FILE__, __LINE__, mesg), exit(1)
#define WARN(mesg) imove_log_error_mesg(__FILE__, __LINE__, mesg)

#define FREE_MEM(ptr)	\
		if (ptr)	{free(ptr);ptr = NULL;}

#define IMOVE_FD_SET(fd, where) { FD_SET(fd, where); \
    if (fd > max_fd) max_fd = fd; \
    }		

#define IMOVE_CLOSE_FD(fd)	\
	{if (fd > 0) close(fd); fd = -1;}

#define DEBUG 1
#ifdef DEBUG
#define p_debug(args...) do { \
	fprintf(stderr, ##args); \
	}while(0);
#else
#define p_debug(...)
#endif
/*******************************************/
typedef struct{
    char mac[MAC_LEN];
	char ipaddr[IPADDR_STR_LEN];
	uint8_t  dev_contype;
	uint32_t total_uploadsize;
	uint32_t total_downloadsize;
	uint32_t upload_speed;
	uint32_t download_speed;
	uint8_t	 is_online;
}dev_info;

typedef struct{
   	uint32_t MaxUpSpeed;
	uint32_t MaxDownSpeed;
	uint32_t contime;
	uint32_t total_down;
	uint32_t total_up;
	char ip[32];
	uint8_t is_online;
	uint8_t con_type;
}devbackupinfo;

/*****  json object define *****/
typedef struct json_object JObj;
// typedef struct json_object * PJObj;
//boolean json_object_get_boolean

#define JSON_PARSE(json_str) json_tokener_parse(json_str)
#define JSON_GET_OBJECT(r_json, member) json_object_object_get(r_json, member)  
#define JSON_GET_OBJECT_VALUE(p_json, type) json_object_get_##type(p_json)
#define JSON_TO_STRING(p_json) json_object_to_json_string(p_json)
#define JSON_NEW_EMPTY_OBJECT() json_object_new_object()
#define JSON_NEW_OBJECT(member, type) json_object_new_##type(member)
#define JSON_NEW_ARRAY() json_object_new_array()
#define JSON_ADD_OBJECT(p_json, member, member_json) json_object_object_add(p_json, member, member_json) 
#define JSON_ARRAY_ADD_OBJECT(p_json, member_json) json_object_array_add(p_json, member_json)
#define JSON_PUT_OBJECT(jo) do{\
	if((jo) != NULL)\
	{\
		json_object_put((jo));\
		(jo) = NULL;\
	}\
	}while(0)

#define JSON_IS_JOBJ(p_json) json_object_is_type((p_json), json_type_object) 

// for json array
#define JSON_IS_ARRAY(p_json) json_object_is_type((p_json), json_type_array)
#define JSON_GET_ARRAY_LIST(p_json) json_object_get_array((p_json))
#define JSON_GET_ARRAY_LEN(p_json) json_object_array_length((p_json))
#define JSON_GET_ARRAY_MEMBER_BY_ID(p_json, idx) json_object_array_get_idx((p_json), idx)
#define JSON_ADD_ARRAY_MEMBER_BY_ID(p_json, idx, member) json_object_array_put_idx((p_json), idx, (member))

/*********** global define ****************/
#if 0
IM_ST_request *request_cache_list = NULL;	// cacha list head, cacha for some reqeust
IM_ST_request *request_free_list = NULL;	// free list head
IM_ST_request *request_ready_list = NULL; 	// ready list head
IM_ST_request *request_block_list = NULL;	// block list head
#endif
#if 0
extern IM_ST_handle_func system_cmd_func;
extern IM_ST_handle_func storage_manage_cmd_func;
extern IM_ST_handle_func speed_check_cmd_func;
extern IM_ST_handle_func ge_upload_speed_cmd_func;
extern IM_ST_handle_func unknow_cmd_funcs;
#endif

/***********************  imove defined funcs **********************/
void inline IM_free_json_object(struct json_object *ptr);
struct json_object* imove_create_json_msg_header(IM_ST_msg_header *str_hd);
IM_ST_handle_func *imove_find_fun_by_cmd(int cmd);
void imove_free_requests(void);
/****************** function defined *************/
int get_test_download_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request);
int get_test_upload_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request);
int get_wifi_passwd_strength(JObj * rpc_json,  IM_ST_msg_header *header,IM_ST_request *request);
int get_admin_passwd_streagth(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request);
int set_upload_flow_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request);
int create_group(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request);
int get_group_list(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request);
int get_group_settings_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int delete_group(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request);
int amend_group(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int add_group_dev(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int delete_group_dev(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int get_group_dev_list(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int query_dev_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _Route_switch_status(JObj * rpc_json,IM_ST_msg_header *header, IM_ST_request *request);
int _WiFi_setwireless(JObj * rpc_json,IM_ST_msg_header *header, IM_ST_request *request);
int _WiFi_getwirelessstatus(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_set_vwan_mode_dhcp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int get_usr_dev_permission(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _get_vwan_dhcp_status(char *hostname,char *dns_list,char *macaddr);
int _set_vwan_mode_pppoe(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _Wlan_getPPPoEstatus(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _set_vwan_mode_static(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _get_vwan_mode_static(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _client_connect_to_ap(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _get_repeater_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_password_modification(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_set_password(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_close_route_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _Reset_factory(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_reset_getversion(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_get_fw_upgrade_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_fw_upgrade();
int dm_upgrade_firmware(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_wlan_getaccesspointlist(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _Wlan_get_cur_speed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_set_dev_upload_maxspeed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_set_dev_download_maxspeed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_format_disk(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_wlan_get_connect_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_password_exist(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_wlan_get_connect_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_wlan_get_repeater_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _unload_opk(JObj * rpc_json);
int _start_app(JObj * rpc_json);
int _stop_app(JObj * rpc_json);
int handle_getStorageInfo(JObj* rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_handle_cp_cancel(JObj *rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_handle_cp(JObj *rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_rm_cancel(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_handle_rm(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_rmdir(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request);
int imove_handle_mv_cancel(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_mv(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int imove_handle_rn(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_ls(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_ls_r(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_pwd(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_mkdir(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_touch(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int _handle_query_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int get_ssid_and_route_id(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int get_router_init_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);

/*************** WEB interface *****************/
typedef struct total_rate{
   	uint32_t total_down;
	uint32_t total_up;
	uint32_t total_count;
	double total_down_speed;
	double total_up_speed;
}total_rate_t;

typedef struct {
	unsigned int cur_downloadspeed;
	unsigned int avg_downloadspeed;
	unsigned int max_downloadspeed;
	unsigned int total_downloadsize;
	unsigned int total_uploadsize;
}router_network_info_t;

typedef struct{
	uint8_t isdhcp;
	char sip[32];
	char eip[32];
	uint32_t dhcptime;
}dhcp_info_t;

typedef struct ddns_info {
	char domain_name[32];
	char isp_name[32];
	int ddns_status;
}ddns_info_t;

typedef struct ddns_list{
	ddns_info_t ddns_t[4];
	int count;
}ddns_list_t;

#define NETWORK_NET_FLOW_LEVEL 	1024
#define NETWORK_NET_MAX_SPEED 	12*1024
#define MSG_SERVER_VERSION_LEN 	32

int dm_get_router_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_router_network_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_router_connect_dev_rate_statistics(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_dev_con_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_router_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_clone_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_dhcp_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_dhcp_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_ip_binding_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_bind_ip(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_del_ip_bind(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_wifi_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_wifi_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_wifi_access_ctr_mark(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_wifi_access_ctr_mark(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_wifi_access_ctrl(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_group(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_hdisk(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_limit_dev_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_limit_speed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_upnp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_upnp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_port_forward_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_dmz_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_dmz_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_fw_version(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_web_fw_upgrade(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_system_backups(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_recover_backup_system(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_wan_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_lan_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_managepc_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_access_internet_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_set_dhcp_connect(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_hdisk_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_start_upgrade(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_resume_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_add_port_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_port_amend_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_del_port_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_samba_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_add_ddns(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_del_ddns(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
int dm_get_ddns_list(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request);
#endif
