/*
 * =============================================================================
 *
 *       Filename:  api_process.c
 *
 *    Description:  longsys sever module.
 *
 *        Version:  1.0
 *        Created:  2014/10/29 14:51:25
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Oliver (), 515296288jf@163.com
 *   Organization:  
 *
 * =============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <mntent.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>     /*Unix 鏍囧噯鍑芥暟瀹氫箟*/
#include <sys/types.h>  
#include <locale.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include "msg_server.h"

typedef int (*API_FUNC)(JObj *rpc_json,char *retstr,header_info *header,thread_info *threadStatus);

typedef struct _tag_handle
{
 uint16_t tag;
 API_FUNC tagfun;
}tag_handle;

tag_handle all_tag_handle[]=
{
 {FN_CREATE_GROUP,create_group},
 {FN_GET_GROUP_LIST,get_group_list},
 {FN_GET_GROUP_SETTINGS_INFO,get_group_settings_info},
 {FN_DELETE_GROUP,delete_group},
 {FN_AMEND_GROUP,amend_group},
 {FN_ADD_GROUP_DEV,add_group_dev},
 {FN_GET_GROUP_DEV_LIST,get_group_dev_list},
 {FN_QUERY_DEV_INFO,query_dev_info},
 {FN_GET_ROUTER_INIT_STATUS,get_router_init_status},	
 {FN_FILE_COPY_FILE_DIR,_handle_cp},
 {FN_FILE_COPY_CANCEL,_handle_cp_cancel},	
 {FN_FILE_RM_FILE_DIR,_handle_rm},
 {FN_FILE_RM_CANCEL,_handle_rm_cancel},
 {FN_FILE_RM_DIR,_handle_rmdir},
 {FN_FILE_MOVE_FILE_DIR,_handle_mv},
 {FN_FILE_MOVE_CANCEL,_handle_mv_cancel},
 {FN_FILE_RENAME_FILE_DIR,_handle_rn},
 {FN_FILE_LS_FILE_DIR,_handle_ls},
 {FN_FILE_LS_R_FILE_DIR,_handle_ls_r},
 {FN_FILE_MAKE_DIR,_handle_mkdir},
 {FN_FILE_TOUCH_FILE_DIR,_handle_touch},
 {FN_FILE_PWD_FILE_DIR,_handle_pwd},
 {FN_GET_STORAGE_INFO,handle_getStorageInfo},
 {FN_FILE_QUERY_STATUS,_handle_query_status},
 {FN_ROUTER_SWITCH_STATUS,_Route_switch_status},
 {FN_WIFI_SET_WIRELESS,_WiFi_setwireless},
 {FN_WIFI_GET_WIRELESS_STATUS,_WiFi_getwirelessstatus},
 {FN_SET_VWAN_MODE_PPPOE,_set_vwan_mode_pppoe},
 	{FN_GET_VWAN_MODE_PPPOE,_Wlan_getPPPoEstatus},
 	{FN_SET_VWAN_MODE_STATIC,_set_vwan_mode_static},
 	{FN_GET_VWAN_MODE_STATIC,_get_vwan_mode_static},
 	{FN_CLIENT_CONNECT_TO_AP,_client_connect_to_ap},
 	{FN_GET_REPEATER_STATUS,_get_repeater_status},
 	{FN_PASSWORD_MODIFICATION,_Password_modification},
 	{FN_CLOSE_ROUTER_TYPE,_close_route_type},
 	{FN_RESET_FACTORY,_Reset_factory},
 	{FN_GET_FW_VERSION,_Reset_getversion},
 	{FN_GET_FW_UPGADE_STATUS,_Get_fw_upgrade_status},
 	{FN_GET_SCAN_RESULT,_Wlan_getaccesspointlist},
 	{FN_GET_ROUTER_CUR_SPEED,_Wlan_get_cur_speed},
 	{FN_SET_DEV_UPLOAD_MAXSPEED,_set_dev_upload_maxspeed},
 	{FN_SET_DEV_DOWNLOAD_MAXSPEED,_set_dev_download_maxspeed},
 	{FN_FORMAT_DISK,_Format_disk},
 	{FN_GET_ROUTER_CONNECT_STATUS,_Wlan_get_connect_status},
 	{FN_PASSWORD_EXIST,_Password_exist},
 	{FN_WLAN_GET_CONNECT_TYPE,_Wlan_get_connect_type},
 	{FN_WLAN_GET_REPEATER_STATUS,_Wlan_get_repeater_type},
 	{FN_GET_USR_DEV_ACCESS_PER,get_usr_dev_permission},
 	{FN_GET_SSID_AND_ROUTE_ID,get_ssid_and_route_id},
 	{FN_GET_TEST_DOWNLOAD_SPEED,get_test_download_speed},
 	{FN_GET_TEST_UPLOAD_SPEED,get_test_upload_speed},
 	{FN_GET_WIFI_PASSWD_STRENGTH,get_wifi_passwd_strength},
 	{FN_GET_ADMIN_PASSWD_STRENGTH,get_admin_passwd_streagth},
 	{FN_SETUP_UPLOAD_FLOW_SPEED,set_upload_flow_speed},
 	{FN_FW_UPGRADE,dm_upgrade_firmware},
 	{FN_SET_DHCP_CONNCT,_set_vwan_mode_dhcp},
};
#define TAGHANDLE_NUM (sizeof(all_tag_handle)/sizeof(all_tag_handle[0]))

int calculate_pwd_strenglth(char *rootpwd)
{
    uint8_t pwd_len = strlen(rootpwd);
	uint8_t digit_point = 0;
	uint8_t group_point = 0;
	uint8_t contain_char_flag = 0;
	uint8_t contain_digit_flag = 0;
	uint8_t contain_symbol_flag = 0;
	uint8_t total_contain = 0;
	uint8_t password_stren_point = 0;
	uint8_t i = 0;
	uint8_t admin_pwdlevel =0;
	
    if(pwd_len <= 6)
    {
		digit_point = 1;
	}else if(pwd_len >= 7&&pwd_len <= 12)
	{
		digit_point = 2;
	}else if(pwd_len >= 13)
	{
		digit_point = 3;
	}
	 for(i=0;i<pwd_len;i++)
	 {
	 	p_debug("rootpwd :%d",(unsigned char)*(rootpwd+i));
		if(((unsigned char)*(rootpwd+i) >= 97&&(unsigned char)*(rootpwd+i) <= 122)||
			((unsigned char)*(rootpwd+i) >= 65&&(unsigned char)*(rootpwd+i) <= 90))
		{
			contain_char_flag = 1;
		}else if((unsigned char)*(rootpwd+i) >= 48&&(unsigned char)*(rootpwd+i) <= 57)
		{
			contain_digit_flag = 1;
		}else{
			contain_symbol_flag = 1;
		}
	 }
     total_contain = contain_char_flag + contain_digit_flag + contain_symbol_flag;
     if(total_contain == 1)
     {
		group_point = 1;
	 }else if(total_contain == 2)
	 {
		group_point = 2;
	 }else if(total_contain == 3)
	 {
		group_point = 3;
	 }
	 password_stren_point = digit_point + group_point;
	if(password_stren_point == 2)
	{
		admin_pwdlevel = WEAK_PASSWORD_POINT;
	}else if(password_stren_point == 3||password_stren_point == 4)
	{
		admin_pwdlevel = MEDIUM_PASSWORD_POINT;
	}else if(password_stren_point == 5||password_stren_point == 6)
	{
		admin_pwdlevel = INTENSITY_PASSWORD_POINT;
	}
	return admin_pwdlevel;
}
int set_upload_flow_speed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *max_uploadspeed_json = JSON_GET_OBJECT(para_json,"max_uploadspeed");//KB/S
	uint32_t max_uploadspeed = JSON_GET_OBJECT_VALUE(max_uploadspeed_json,int);
	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_test_download_speed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *testspeed_status_json = JSON_GET_OBJECT(para_json,"testspeed_status");
	uint8_t testspeed_status = JSON_GET_OBJECT_VALUE(testspeed_status_json,int);
	//invoking  imove function
	uint32_t  download_speed = 100;//KB/S
	JSON_ADD_OBJECT(response_para_json, "download_speed", JSON_NEW_OBJECT(download_speed,int));
	JSON_ADD_OBJECT(response_para_json, "testspeed_status", JSON_NEW_OBJECT(testspeed_status,int));

	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int get_test_upload_speed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *testspeed_status_json = JSON_GET_OBJECT(para_json,"testspeed_status");
	uint8_t testspeed_status = JSON_GET_OBJECT_VALUE(testspeed_status_json,int);
	//invoking  imove function
	uint32_t  upload_speed = 200;//KB/S
	JSON_ADD_OBJECT(response_para_json, "upload_speed", JSON_NEW_OBJECT(upload_speed,int));
	JSON_ADD_OBJECT(response_para_json, "testspeed_status", JSON_NEW_OBJECT(testspeed_status,int));

	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int get_wifi_passwd_strength(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t wifi_pwdlevel = 0;
	int32_t wifi_ret = -1;
    char wifipwd[32] = {0};
	struct wirelessInfo info;
	char *str_fre = "24G";
	char *str_hot = "HOSTAP";
	memset(&info,0,sizeof(struct wirelessInfo));
	WiFi_getwirelessstatus(str_fre,str_hot,&info);
	if(info.password && *info.password)
		strcpy(wifipwd,info.password);
	if(wifi_ret != 0)
	{
		header->code = ERROR_GET_ROOT_PWD;
	}
	if (wifipwd && *wifipwd) {
		wifi_pwdlevel = calculate_pwd_strenglth(wifipwd);
	}else{
		wifi_pwdlevel = ZERO_PASSWORD_POINT;
	}
	JSON_ADD_OBJECT(response_para_json, "wifi_pwdlevel", JSON_NEW_OBJECT(wifi_pwdlevel,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int get_admin_passwd_streagth(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t is_same = MSG_SERVER_FALSE;
	uint8_t admin_pwdlevel = 0;
	int32_t root_ret = -1;
    char rootpwd[32] = {0};
	uint8_t wifi_pwdlevel = 0;
	int32_t wifi_ret = -1;
    char wifipwd[32] = {0};
	struct wirelessInfo info;
	char *str_fre = "24G";
	char *str_hot = "HOSTAP";
	memset(&info,0,sizeof(struct wirelessInfo));
	WiFi_getwirelessstatus(str_fre,str_hot,&info);
	if(info.password && *info.password)
		strcpy(wifipwd,info.password);
	if(wifi_ret != 0)
	{
		header->code = ERROR_GET_ROOT_PWD;
	}
	if (wifipwd && *wifipwd) {
		wifi_pwdlevel = calculate_pwd_strenglth(wifipwd);
	}else{
		wifi_pwdlevel = ZERO_PASSWORD_POINT;
	}
	root_ret = IM_RootPwdGet(rootpwd);
	if(root_ret != 0)
	{
		header->code = ERROR_GET_ROOT_PWD;
	}
	if (rootpwd && *rootpwd) {
		admin_pwdlevel = calculate_pwd_strenglth(rootpwd);
	}else{
		header->code = ERROR_ADMIN_PWD_NULL;
	}
	if(!strcmp(wifipwd,rootpwd))
	{
		is_same = MSG_SERVER_TRUE;
	}
	JSON_ADD_OBJECT(response_para_json, "admin_pwdlevel", JSON_NEW_OBJECT(admin_pwdlevel,int));
	JSON_ADD_OBJECT(response_para_json, "wifi_pwdlevel", JSON_NEW_OBJECT(wifi_pwdlevel,int));
	JSON_ADD_OBJECT(response_para_json, "is_same", JSON_NEW_OBJECT(is_same,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_ssid_and_route_id(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* route_id_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
    char router_id[64] = {0};
	int id = -1;
	id = get_cfg_sn_status(router_id);
	if(id < 0)
	{
		header->code = ERROR_GET_SN_FAIL;
	}
	JSON_ADD_OBJECT(route_id_json, "router_id",JSON_NEW_OBJECT(atoi(router_id),int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,route_id_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_usr_dev_permission(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t internet_access_flag = 0;
	uint8_t router_ctrl_flag = 0;
	uint8_t routedisc_access_flag = 0;
	uint8_t routedisc_ctrl_flag = 0;
	uint8_t pridisk_access_flag = 0;
	uint8_t pridisk_ctrl_flag = 0;

	//invoking  imove function
	stPermsInfo  *mStPermsInfo = NULL;
	mStPermsInfo = IM_GetObjPermBySess(header->sessionid);
	if(mStPermsInfo != NULL)
	{
		internet_access_flag = mStPermsInfo->ucInternetAccEnable;
		router_ctrl_flag = mStPermsInfo->ucRouterCtrlEnable;
		routedisc_access_flag = mStPermsInfo->ucRouterDiscAccEnable;
		routedisc_ctrl_flag = mStPermsInfo->ucRouterDiscCtrlEnable;
		pridisk_access_flag = mStPermsInfo->ucPrivateDiscAccEnable;
		pridisk_ctrl_flag = mStPermsInfo->ucPrivateDiscCtrlEnable;
	}else{
		header->code = ERROR_GET_USR_DEV_PERMISSION;
	}
	JSON_ADD_OBJECT(response_para_json, "internet_access", JSON_NEW_OBJECT(internet_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "router_ctrl", JSON_NEW_OBJECT(router_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_access", JSON_NEW_OBJECT(routedisc_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_ctrl", JSON_NEW_OBJECT(routedisc_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_access", JSON_NEW_OBJECT(pridisk_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_ctrl", JSON_NEW_OBJECT(pridisk_ctrl_flag,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}


/*return < 0 :can not get ip*/
int get_wlan_ip_status()
{
	FILE *read_fp; 
	int chars_read; 
	char buffer[8]={0};
	int ret=-1;
	read_fp = popen("route | grep eth1 | wc -l", "r");
	if(read_fp!=NULL)
	{
		chars_read = fread(buffer, sizeof(char), sizeof(buffer)-1, read_fp); 
		if (chars_read > 0&&atoi(buffer) == 2) 
		{ 
			ret = 0;
		} 
	}
	pclose(read_fp);
	return ret;
}
int get_router_init_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int router_initstatus = -1;
	//set_init_status(2);
	p_debug("DM send:  %s, get_init_status(): %d",retstr, get_init_status());
	if(get_init_status() == 3)
	{
	   router_initstatus = INIT_SETUP_COMPLETED;
	}else if(get_init_status() == 2)
	{
	   router_initstatus = WIFI_NOT_COMPLETED;
	}else if(get_init_status() == 0)
	{
		if(get_wlan_ip_status() < 0)
		{
		   router_initstatus = GET_WLAN_IP_FAIL;
		}
		else{
		   router_initstatus = GET_WLAN_IP_SUCCESS;
		}
	}
    JSON_ADD_OBJECT(response_para_json, "router_initstatus", JSON_NEW_OBJECT(router_initstatus,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}

int create_group(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
   JObj *group_name_json = JSON_GET_OBJECT(para_json,"group_name");
   char *group_name = JSON_GET_OBJECT_VALUE(group_name_json,string);
   
   JObj *Internet_access_json = JSON_GET_OBJECT(para_json,"internet_access");
   uint8_t Internet_access_flag = JSON_GET_OBJECT_VALUE(Internet_access_json,int);

   JObj *router_ctrl_json = JSON_GET_OBJECT(para_json,"router_ctrl");
   uint8_t router_ctrl_flag = JSON_GET_OBJECT_VALUE(router_ctrl_json,int);

   JObj *routedisc_access_json = JSON_GET_OBJECT(para_json,"routedisc_access");
   uint8_t routedisc_access_flag = JSON_GET_OBJECT_VALUE(routedisc_access_json,int);

   JObj *routedisc_ctrl_json = JSON_GET_OBJECT(para_json,"routedisc_ctrl");
   uint8_t routedisc_ctrl_flag = JSON_GET_OBJECT_VALUE(routedisc_ctrl_json,int);

   JObj *pridisk_access_json = JSON_GET_OBJECT(para_json,"pridisk_access");
   uint8_t pridisk_access_flag = JSON_GET_OBJECT_VALUE(pridisk_access_json,int);

   JObj *pridisk_ctrl_json = JSON_GET_OBJECT(para_json,"pridisk_ctrl");
   uint8_t pridisk_ctrl_flag = JSON_GET_OBJECT_VALUE(pridisk_ctrl_json,int);
   int32_t group_id = -1; 
   uint8_t ucGrpType = 1;//usr 1,process 2
   
   uint32_t nPermissions = Internet_access_flag|
   	                       router_ctrl_flag<<1|
   	                       routedisc_access_flag<<2|
   	                       routedisc_ctrl_flag<<3|
   	                       pridisk_access_flag<<4|
   	                       pridisk_ctrl_flag<<5;
   group_id = IM_AddGrp(group_name, ucGrpType, nPermissions);//200
   if(group_id <= 0)
   {
      header->code = ERROR_CREATE_GROUP;
   }else{
		header->code = GROUP_SUCCESS;
   }
   
   JSON_ADD_OBJECT(response_para_json, "group_id", JSON_NEW_OBJECT(group_id,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
   return 0;
}
int get_group_list(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint32_t i= 0;
	uint32_t group_id = 0;
	char group_name[DEV_FILE_NAME_TOTAL+1];
    stGroupBrief * group_brief = IM_GetGrpBrief();//201
    JObj *group_info[MAX_GROUP_COUNT];
	if(group_brief->nCount > MAX_GROUP_COUNT)
	{
		group_brief->nCount = MAX_GROUP_COUNT;
	}
    if(group_brief != NULL)
	{
		for(i = 0;i < group_brief->nCount;i++)
        {
            group_info[i] = JSON_NEW_EMPTY_OBJECT();
			group_id = group_brief->stGrpCot[i].nId;
			strcpy(group_name,group_brief->stGrpCot[i].szName);
			JSON_ADD_OBJECT(group_info[i], "group_name", JSON_NEW_OBJECT(group_name,string));
		    JSON_ADD_OBJECT(group_info[i], "group_id", JSON_NEW_OBJECT(group_id,int));
			p_debug("DM %d:group_id =%d,group_name =%s", i,group_id,group_name);
			JSON_ARRAY_ADD_OBJECT(response_data_array,group_info[i]);
	    }
	    free(group_brief);
		header->code = GROUP_SUCCESS;
	}else{
 		header->code = ERROR_GET_GROUP_LIST;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int get_group_settings_info(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
   JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
   uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);

   uint8_t internet_access_flag = 0;
   uint8_t router_ctrl_flag = 0;
   uint8_t routedisc_access_flag = 0;
   uint8_t routedisc_ctrl_flag = 0;
   uint8_t pridisk_access_flag = 0;
   uint8_t pridisk_ctrl_flag = 0;
   uint32_t number = 0;
   
   //invoking  imove function
    stGrpDetailInfo *mStGrpDetailInfo = IM_GetObjsInfoInGroup(group_id);//207
	if(mStGrpDetailInfo != NULL)
	{
	    number = mStGrpDetailInfo->nObjCnt;
		internet_access_flag = mStGrpDetailInfo->stPermissons.ucInternetAccEnable;
		router_ctrl_flag = mStGrpDetailInfo->stPermissons.ucRouterCtrlEnable;
		routedisc_access_flag = mStGrpDetailInfo->stPermissons.ucRouterDiscAccEnable;
		routedisc_ctrl_flag = mStGrpDetailInfo->stPermissons.ucRouterDiscCtrlEnable;
		pridisk_access_flag = mStGrpDetailInfo->stPermissons.ucPrivateDiscAccEnable;
		pridisk_ctrl_flag = mStGrpDetailInfo->stPermissons.ucPrivateDiscCtrlEnable;
		free(mStGrpDetailInfo);
		header->code = GROUP_SUCCESS;
	}else{
	    header->code = ERROR_GET_GROUP_SETTINGS_INFO;
	}
    JSON_ADD_OBJECT(response_para_json, "internet_access", JSON_NEW_OBJECT(internet_access_flag,boolean));
    JSON_ADD_OBJECT(response_para_json, "router_ctrl", JSON_NEW_OBJECT(router_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_access", JSON_NEW_OBJECT(routedisc_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_ctrl", JSON_NEW_OBJECT(routedisc_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_access", JSON_NEW_OBJECT(pridisk_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_ctrl", JSON_NEW_OBJECT(pridisk_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "number", JSON_NEW_OBJECT(number,int));

	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
	return 0;
}
int delete_group(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);

	int32_t group_ret = -1;
	group_ret = IM_DelGrp(group_id);//203
	if(group_ret != 0)
	{
		header->code = ERROR_DELETE_GROUP;
	}else{
		header->code = GROUP_SUCCESS;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int amend_group(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
   JObj *group_name_json = JSON_GET_OBJECT(para_json,"group_name");
   char *group_name = JSON_GET_OBJECT_VALUE(group_name_json,string);

   JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
   uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);
   JObj *Internet_access_json = JSON_GET_OBJECT(para_json,"internet_access");
   uint8_t Internet_access_flag = JSON_GET_OBJECT_VALUE(Internet_access_json,int);

   JObj *router_ctrl_json = JSON_GET_OBJECT(para_json,"router_ctrl");
   uint8_t router_ctrl_flag = JSON_GET_OBJECT_VALUE(router_ctrl_json,int);

   JObj *routedisc_access_json = JSON_GET_OBJECT(para_json,"routedisc_access");
   uint8_t routedisc_access_flag = JSON_GET_OBJECT_VALUE(routedisc_access_json,int);

   JObj *routedisc_ctrl_json = JSON_GET_OBJECT(para_json,"routedisc_ctrl");
   uint8_t routedisc_ctrl_flag = JSON_GET_OBJECT_VALUE(routedisc_ctrl_json,int);

   JObj *pridisk_access_json = JSON_GET_OBJECT(para_json,"pridisk_access");
   uint8_t pridisk_access_flag = JSON_GET_OBJECT_VALUE(pridisk_access_json,int);

   JObj *pridisk_ctrl_json = JSON_GET_OBJECT(para_json,"pridisk_ctrl");
   uint8_t pridisk_ctrl_flag = JSON_GET_OBJECT_VALUE(pridisk_ctrl_json,int);
    int32_t group_ret =-1;
    uint32_t nPermissions = Internet_access_flag|
   	                       router_ctrl_flag<<1|
   	                       routedisc_access_flag<<2|
   	                       routedisc_ctrl_flag<<3|
   	                       pridisk_access_flag<<4|
   	                       pridisk_ctrl_flag<<5;
    p_debug("DM group_id = %d,group_name = %s,nPermissions = %d", group_id,group_name,nPermissions);
	group_ret = IM_SetGrp(group_id, group_name,nPermissions);//204
    if(group_ret != 0)
	{
		header->code = ERROR_AMEND_GROUP;
	}else{
		header->code = GROUP_SUCCESS;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
	return 0;
}
int add_group_dev(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);

	JObj *dev_name_json = JSON_GET_OBJECT(para_json,"dev_name");
	char * dev_name = JSON_GET_OBJECT_VALUE(dev_name_json,string);

	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char * mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	int32_t group_ret = -1;
	group_ret = IM_DelObjFromGrp(mac);//205
	if(group_ret != 0)
	{
		header->code = ERROR_DELETE_GROUP_DEV;
	}else{
		header->code = GROUP_SUCCESS;
	}
   p_debug("DM group_id = %d,dev_name = %s,pMacStr = %s",group_id,dev_name,mac);
   group_ret = IM_AddObj2Grp(group_id,dev_name,mac);//205
    if(group_ret != 0)
	{
		header->code = ERROR_ADD_GROUP_DEV;
	}else{
		header->code = GROUP_SUCCESS;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
 	return 0;
}
int delete_group_dev(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char * mac = JSON_GET_OBJECT_VALUE(mac_json,string);
    int32_t group_ret = -1;
	p_debug("pMacStr = %s",mac);
    group_ret = IM_DelObjFromGrp(mac);//205
    if(group_ret != 0)
	{
		header->code = ERROR_DELETE_GROUP_DEV;
	}else{
		header->code = GROUP_SUCCESS;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
 	return 0;
}

int get_group_dev_list(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	int32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);
	uint32_t i =0;
	char ip_list[IP_LIST_LEN] = {0};
	char group_name[DEV_FILE_NAME_TOTAL] = {0};
	char mac[MAC_LEN] = {0};//mac地址
	char ipaddr[IPADDR_STR_LEN] = {0};//ip地址
	char dev_name[DEV_FILE_NAME_TOTAL] = {0};
	char dev_contime_str[DEV_FILE_NAME_TOTAL] = {0};
	uint32_t dev_contime_size = 0;
	JObj *ip_info[MAX_GROUP_USR_COUNT];
	uint8_t j = 0;
	uint8_t total_count = 0;
	stGrpDetailInfo *mStGrpDetailInfo = NULL;
	stGroupBrief * group_brief = NULL;
	uint32_t ip_count = 0;
	char upper_mac[MAC_LEN] = {0};
	dev_info mDevInfo;
	uint8_t paserList_ret = 0;
	int time_ret = 0;
	get_dev_info(ip_list,IP_LIST_LEN);
    p_debug("ip_list1 = %s,groupid = %d",ip_list,group_id);
	if(group_id >= 0 )
	{
		mStGrpDetailInfo = IM_GetObjsInfoInGroup(group_id);//207
		ip_count = mStGrpDetailInfo->nObjCnt;
		p_debug("ip_count = %d", ip_count);
		if(mStGrpDetailInfo != NULL&&ip_count<=MAX_GROUP_USR_COUNT)
		{
			for(i = 0;i < ip_count;i++)
			{
				memset(dev_name,0,DEV_FILE_NAME_TOTAL);
				memset(upper_mac,0,MAC_LEN);
				memset(&mDevInfo,0,sizeof(dev_info));
				ip_info[i] = JSON_NEW_EMPTY_OBJECT();
				p_debug("mStGrpDetailInfo->stObjInfo[i].szMacStr = %s", mStGrpDetailInfo->stObjInfo[i].szMacStr);
				strcpy(upper_mac,mStGrpDetailInfo->stObjInfo[i].szMacStr);
				if(upper_mac!=NULL&&*upper_mac)
				{
					p_debug("mStGrpDetailInfo->stObjInfo[i].szName = %s",  mStGrpDetailInfo->stObjInfo[i].szName);
					strcpy(dev_name,mStGrpDetailInfo->stObjInfo[i].szName);
					if(ip_list != NULL&&*ip_list)
					{
						my_toupper(upper_mac);
						paserList_ret = paserList2DevInfo(ip_list,upper_mac,&mDevInfo);
						my_tolower(upper_mac);
					}
				}
				time_ret = getDevConTimefromDhcp(upper_mac,dev_contime_str);
				if(time_ret >= 0)
				{
					dev_contime_size = atoi(dev_contime_str);
				}else{
					dev_contime_size = 0;
				}
				JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(upper_mac,string));
				JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(dev_name,string));	
				JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(dev_contime_size,int));
				JSON_ADD_OBJECT(ip_info[i], "upload_speed", JSON_NEW_OBJECT(mDevInfo.upload_speed,int));
				JSON_ADD_OBJECT(ip_info[i], "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
				JSON_ADD_OBJECT(ip_info[i], "is_online", JSON_NEW_OBJECT(mDevInfo.is_online,boolean));
				JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
			}
			free(mStGrpDetailInfo);
			header->code = GROUP_SUCCESS;
		}
		else{
			header->code = ERROR_GET_GROUP_DEV_LIST;
		}
	}else if(group_id == -1)
	{
		p_debug("group_id = %d",group_id);
		group_brief = IM_GetGrpBrief();//201
		if(group_brief->nCount > MAX_GROUP_COUNT)
		{
			group_brief->nCount = MAX_GROUP_COUNT;
		}
	    if(group_brief != NULL)
		{
			for(i = 0;i < group_brief->nCount;i++)
	        {
				group_id = group_brief->stGrpCot[i].nId;
				mStGrpDetailInfo = IM_GetObjsInfoInGroup(group_id);//207
				  ip_count = mStGrpDetailInfo->nObjCnt;
				  p_debug("ip_count = %d", ip_count);
				  if(mStGrpDetailInfo != NULL&&ip_count<=MAX_GROUP_USR_COUNT)
				  {
				   	for(j = 0;j < ip_count;j++)
				   	{
				   		memset(&mDevInfo,0,sizeof(dev_info));
						memset(dev_name,0,DEV_FILE_NAME_TOTAL);
						ip_info[total_count] = JSON_NEW_EMPTY_OBJECT();
						p_debug("mStGrpDetailInfo->stObjInfo[%d].szMacStr = %s", j,mStGrpDetailInfo->stObjInfo[j].szMacStr);
						memset(upper_mac,0,MAC_LEN);
						strcpy(upper_mac,mStGrpDetailInfo->stObjInfo[j].szMacStr);
						p_debug("mStGrpDetailInfo->stObjInfo[%d].szName = %s", j,mStGrpDetailInfo->stObjInfo[j].szName);
						memset(dev_name,0,DEV_FILE_NAME_TOTAL);
						strcpy(dev_name,mStGrpDetailInfo->stObjInfo[j].szName);
						if(upper_mac!=NULL&&*upper_mac)
						{
							if(ip_list != NULL&&*ip_list)
							{
								my_toupper(upper_mac);
								paserList_ret = paserList2DevInfo(ip_list,upper_mac,&mDevInfo);
								my_tolower(upper_mac);
							}
						}
						
						time_ret = getDevConTimefromDhcp(upper_mac);
						if(time_ret >= 0)
						{
							dev_contime_size = time_ret;
						}else{
							dev_contime_size = 0;
						}
						JSON_ADD_OBJECT(ip_info[total_count], "mac", JSON_NEW_OBJECT(upper_mac,string));
						JSON_ADD_OBJECT(ip_info[total_count], "dev_name", JSON_NEW_OBJECT(dev_name,string));	
						JSON_ADD_OBJECT(ip_info[total_count], "dev_contime", JSON_NEW_OBJECT(dev_contime_size,int));
						JSON_ADD_OBJECT(ip_info[total_count], "upload_speed", JSON_NEW_OBJECT(mDevInfo.upload_speed,int));
						JSON_ADD_OBJECT(ip_info[total_count], "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
						JSON_ADD_OBJECT(ip_info[total_count], "is_online", JSON_NEW_OBJECT(mDevInfo.is_online,boolean));
						JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[total_count]);
						total_count++;
				 	}
					free(mStGrpDetailInfo);
				}
		    }
		    free(group_brief);
			header->code = GROUP_SUCCESS;
		}else{
	 		header->code = ERROR_GET_GROUP_LIST;
		}
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int query_dev_info(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char *mac_str = JSON_GET_OBJECT_VALUE(mac_json,string);
   char group_name[DEV_FILE_NAME_TOTAL] = {0};
   char lower_mac[MAC_LEN] = {0};//mac地址
   char ipaddr[IPADDR_STR_LEN] = {0};//ip地址
   char dev_name[DEV_FILE_NAME_TOTAL] = {0};
   char ip_list[IP_LIST_LEN] = {0};
   stObjBrief *mStObjBrief = NULL;
   uint8_t paserList_ret = 0;
   char upper_mac[MAC_LEN] = {0};
   char dev_contime_str[DEV_FILE_NAME_TOTAL] = {0};
   uint32_t dev_contime_size = 0;
   int time_ret = 0;
   int maxspeed_ret = 0;
   char max_uploadspeed_str[32] = {0};
   char max_downloadspeed_str[32] = {0};
   int max_uploadspeed = -1;
   int max_downloadspeed = -1;
   dev_info mDevInfo;
   memset(&mDevInfo,0,sizeof(dev_info));
   strcpy(lower_mac,mac_str);
   my_tolower(lower_mac);
   mStObjBrief = IM_GetObjBrief(lower_mac);
   	if(mStObjBrief != NULL)
  	{
		strcpy(group_name,mStObjBrief->szGrpName);
	   strcpy(dev_name,mStObjBrief->szName);
	   p_debug("group_name = %s\n",group_name);
	   p_debug("dev_name = %s\n",dev_name);
	   p_debug("mac_str = %s",mac_str);
	   get_dev_info(ip_list,IP_LIST_LEN);
	   //{<mac>,<ip>,< total_upbytes >,<total_downloadsize>,< up_bps>,< down_bps >, <update time >}
	   p_debug("ip_list2 = %s",ip_list);
	   strcpy(upper_mac,mac_str);
	   if(ip_list&&*ip_list&&mac_str!=NULL)
	   {	
		    my_toupper(upper_mac);
	   		paserList_ret = paserList2DevInfo(ip_list,upper_mac,&mDevInfo);
			my_tolower(upper_mac);
	   }
	   free(mStObjBrief);
   }else{
		header->code = ERROR_GET_DEV_INFO;
   }
	time_ret = getDevConTimefromDhcp(upper_mac,dev_contime_str);
	if(time_ret >= 0)
	{
		dev_contime_size = time_ret;
	}else{
		dev_contime_size = 0;
	}
	maxspeed_ret = getDevMaxUpSpeed(upper_mac);
	if(maxspeed_ret >= 0)
	{
		max_uploadspeed = maxspeed_ret;
		
	}
	maxspeed_ret = getDevMaxDownSpeed(upper_mac);
	if(maxspeed_ret >= 0)
	{
		max_downloadspeed = maxspeed_ret;
	}
	JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(mac_str,string));
	JSON_ADD_OBJECT(response_para_json, "group_name", JSON_NEW_OBJECT(group_name,string));
	JSON_ADD_OBJECT(response_para_json, "dev_contype", JSON_NEW_OBJECT(mDevInfo.dev_contype,int));
	JSON_ADD_OBJECT(response_para_json, "dev_contime", JSON_NEW_OBJECT(dev_contime_size,int));
	JSON_ADD_OBJECT(response_para_json, "dev_name", JSON_NEW_OBJECT(dev_name,string));
	JSON_ADD_OBJECT(response_para_json, "total_downloadsize", JSON_NEW_OBJECT(mDevInfo.total_downloadsize,int));
	JSON_ADD_OBJECT(response_para_json, "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
	JSON_ADD_OBJECT(response_para_json, "is_online", JSON_NEW_OBJECT(mDevInfo.is_online,boolean));
	JSON_ADD_OBJECT(response_para_json, "max_uploadspeed", JSON_NEW_OBJECT(max_uploadspeed,int));
	JSON_ADD_OBJECT(response_para_json, "max_downloadspeed", JSON_NEW_OBJECT(max_downloadspeed,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _Route_switch_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t sleep_status = NULL;
	uint8_t hiber_ret = 0;
	//hiber_ret = Route_get_hibernation_status();
	if(threadStatus->sleep_flag == 0)
	{
		sleep_status = 0;
	}else{
		sleep_status = 1;
	}
	JSON_ADD_OBJECT(response_para_json, "sleep_status", JSON_NEW_OBJECT(sleep_status,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
/*20A*/
int _WiFi_setwireless(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	
	JObj *para_24G_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *para_5G_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,1);
	
	JObj *fre_24G_json = JSON_GET_OBJECT(para_24G_json,"wifi_type");
	JObj *ssid_24G_json = JSON_GET_OBJECT(para_24G_json,"ssid");
	JObj *encrypt_24G_json = JSON_GET_OBJECT(para_24G_json,"wifi_isencrypt");
	JObj *password_24G_json = JSON_GET_OBJECT(para_24G_json,"wifi_password");

	JObj *hide_24G_json = JSON_GET_OBJECT(para_24G_json,"wifi_ishide");
	JObj *online_24G_json = JSON_GET_OBJECT(para_24G_json,"wifi_isonline");
	
	
	uint8_t fre_24G_flag = JSON_GET_OBJECT_VALUE(fre_24G_json,int);
	char *str_24G_ssid = JSON_GET_OBJECT_VALUE(ssid_24G_json,string);
	uint8_t encrypt_24G_flag = JSON_GET_OBJECT_VALUE(encrypt_24G_json,boolean);
	char *password_24G = JSON_GET_OBJECT_VALUE(password_24G_json,string);
    uint8_t hide_24G_flag = JSON_GET_OBJECT_VALUE(hide_24G_json,boolean);
	uint8_t online_24G_flag = JSON_GET_OBJECT_VALUE(online_24G_json,boolean);
	
	JObj *fre_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_type");
	JObj *ssid_5G_json = JSON_GET_OBJECT(para_5G_json,"ssid");
	JObj *encrypt_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_isencrypt");
	JObj *password_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_password");
	JObj *hide_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_ishide");
	JObj *online_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_isonline");
	
	uint8_t fre_5G_flag = JSON_GET_OBJECT_VALUE(fre_5G_json,int);
	char *str_5G_ssid = JSON_GET_OBJECT_VALUE(ssid_5G_json,string);
	uint8_t encrypt_5G_flag = JSON_GET_OBJECT_VALUE(encrypt_5G_json,boolean);
	char *password_5G = JSON_GET_OBJECT_VALUE(password_5G_json,string);
	uint8_t hide_5G_flag = JSON_GET_OBJECT_VALUE(hide_5G_json,boolean);
	uint8_t online_5G_flag = JSON_GET_OBJECT_VALUE(online_5G_json,boolean);

	p_debug("fre_flag_24G = %d\n,str_ssid = %s\n,encrypt_flag = %d\n,password = %s,online_24G_flag = %d",\
		fre_24G_flag,str_24G_ssid,encrypt_24G_flag,password_24G,online_24G_flag);
	p_debug("fre_flag_5G = %d\n,str_ssid = %s\n,encrypt_flag = %d\n,password = %s,online_5G_flag = %d",\
		fre_5G_flag,str_5G_ssid,encrypt_5G_flag,password_5G,online_5G_flag);
	header->code = 0;
	char encrypt[32] = {0};
	char *str_hot = "HOSTAP";
	char *str_24G_fre = "24G";
	char *str_5G_fre = "5G";
	char *str_on = "on";
	char *str_off = "off";
	if(encrypt_24G_flag == 0)
	{
       strcpy(encrypt,"none");
	}else if(encrypt_24G_flag == 1){
       strcpy(encrypt,"psk2+ccmp");
	}
	if(hide_24G_flag == 0)
	{
       WiFi_hidewireless(str_24G_fre,str_hot,str_off);
	}else if(hide_24G_flag == 1)
	{
       WiFi_hidewireless(str_24G_fre,str_hot,str_on);
	}
	if(online_24G_flag == 0)
	{
       wifi_switch_hot(str_24G_fre,str_hot,str_off);
	}else if(online_24G_flag == 1)
	{
       wifi_switch_hot(str_24G_fre,str_hot,str_on);
	}
	WiFi_setwireless(str_24G_fre,str_hot,str_24G_ssid,encrypt,password_24G);

	memset(encrypt,0,32);
	if(encrypt_5G_flag == 0)
	{
       strcpy(encrypt,"none");
	}else if(encrypt_5G_flag == 1){
       strcpy(encrypt,"psk2+ccmp");
	}
	if(hide_5G_flag == 0)
	{
       WiFi_hidewireless(str_5G_fre,str_hot,str_off);
	}else if(hide_5G_flag == 1)
	{
       WiFi_hidewireless(str_5G_fre,str_hot,str_on);
	}
	if(online_5G_flag == 0)
	{
	   
       wifi_switch_hot(str_5G_fre,str_hot,str_off);
	}else if(online_5G_flag == 1)
	{
       wifi_switch_hot(str_5G_fre,str_hot,str_on);
	}
	WiFi_setwireless(str_5G_fre,str_hot,str_5G_ssid,encrypt,password_5G);
	p_debug("get_init_status()1 = %d",get_init_status());
	uint8_t pppoe_flag = (get_init_status()&2) >> 1;
	uint8_t wifi_flag = get_init_status()&1;
	p_debug("pppoe_flag = %d",pppoe_flag);
	p_debug("wifi_flag = %d",wifi_flag);
	if(pppoe_flag == 1 && wifi_flag == 0)
	{
       set_init_status(3);
	   p_debug("get_init_status()2 = %d",get_init_status());
	}
	restart_wifi();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
/*20B*/
int _WiFi_getwirelessstatus(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
    
	char *str_fre = NULL;
	char *str_hot = NULL;
	char wifi_name[64] = {0};
	JObj* wifi_info[2];
    wifi_info[0] = JSON_NEW_EMPTY_OBJECT();
    wifi_info[1] = JSON_NEW_EMPTY_OBJECT();
	struct wirelessInfo info[2];
	str_fre = "24G";
	str_hot = "HOSTAP";
	memset(&info[0],0,sizeof(struct wirelessInfo));
	memset(&info[1],0,sizeof(struct wirelessInfo));
	header->code = 0;
	WiFi_getwirelessstatus(str_fre,str_hot,&info[0]);
	info[0].wifi_type = 1;
	p_debug("2.4G info[0].name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d",info[0].name,info[0].wifi_type,info[0].encrypt,info[0].wifi_hide,\
		info[0].wifi_switch);
	strcpy(wifi_name,info[0].name);
	if(info[0].wifi_switch == 0)
	{
	   info[0].wifi_switch = 1;
	}else
	{
       info[0].wifi_switch = 0;
	}
	if(info[0].wifi_hide == 0)
	{
	   info[0].wifi_hide = 1;
	}else
	{
       info[0].wifi_hide = 0;
	}
	JSON_ADD_OBJECT(wifi_info[0], "wifi_type",JSON_NEW_OBJECT(info[0].wifi_type,int));
	JSON_ADD_OBJECT(wifi_info[0], "ssid",JSON_NEW_OBJECT(wifi_name,string));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_isencrypt",JSON_NEW_OBJECT(info[0].encrypt,boolean));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_password", JSON_NEW_OBJECT(info[0].password,string));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_ishide", JSON_NEW_OBJECT(info[0].wifi_hide,boolean));
    JSON_ADD_OBJECT(wifi_info[0], "wifi_isonline", JSON_NEW_OBJECT(info[0].wifi_switch,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,wifi_info[0]);
	str_fre = "5G";
	WiFi_getwirelessstatus(str_fre,str_hot,&info[1]);
	info[1].wifi_type = 2;
	p_debug("5G info[1].name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d",info[1].name,info[1].wifi_type,info[1].encrypt,info[1].wifi_hide,info[1].wifi_switch);
	if(info[1].wifi_switch == 0)
	{
	   info[1].wifi_switch = 1;
	}else
	{
       info[1].wifi_switch = 0;
	}
	if(info[1].wifi_hide == 0)
	{
	   info[1].wifi_hide = 1;
	}else
	{
       info[1].wifi_hide = 0;
	}
	memset(wifi_name,0,64);
	strcpy(wifi_name,info[1].name);
	JSON_ADD_OBJECT(wifi_info[1], "wifi_type",JSON_NEW_OBJECT(info[1].wifi_type,int));
	JSON_ADD_OBJECT(wifi_info[1], "ssid",JSON_NEW_OBJECT(wifi_name,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_isencrypt",JSON_NEW_OBJECT(info[1].encrypt,boolean));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_password", JSON_NEW_OBJECT(info[1].password,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_ishide", JSON_NEW_OBJECT(info[1].wifi_hide,boolean));
    JSON_ADD_OBJECT(wifi_info[1], "wifi_isonline", JSON_NEW_OBJECT(info[1].wifi_switch,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,wifi_info[1]);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
    return 0;
}
int _set_vwan_mode_dhcp(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t dhcp_flag = 0;
	uint8_t wifi_flag = 0;
	char r_status[4] = {0};
	int dhcp_ret = -1;
	char hostname[32] = {0};
	char dns_list[32] = {0};
	char macaddr[32] = {0};
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		set_to_bridge();	
	}
	dhcp_flag = (get_init_status()&2) >> 1;
	wifi_flag = get_init_status()&1;
	if(dhcp_flag == 0 && wifi_flag == 0)
	{
       set_init_status(2);
	}
	dhcp_ret = set_vwan_mode_dhcp(hostname,dns_list,macaddr);
	if(dhcp_ret < 0)
	{
		header->code = ERROR_SET_VWAN_MODE_DHCP;
	}
	restart_network();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
   return 0;
}
int _get_vwan_dhcp_status(char *hostname,char *dns_list,char *macaddr)
{
   return 0;
}
int _set_vwan_mode_pppoe(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *name_json = JSON_GET_OBJECT(para_json,"adsl_name");
	char *username = JSON_GET_OBJECT_VALUE(name_json,string);
	JObj *password_json = JSON_GET_OBJECT(para_json,"adsl_password");
	char *password = JSON_GET_OBJECT_VALUE(password_json,string);
	char *dns_list=NULL;
	char r_status[4] = {0};
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		set_to_bridge();	
	}
    set_vwan_mode_pppoe(username ,password,dns_list);
	uint8_t pppoe_flag = 0;
	uint8_t wifi_flag = 0;
	pppoe_flag = (get_init_status()&2) >> 1;
	wifi_flag = get_init_status()&1;
	if(pppoe_flag == 0 && wifi_flag == 0)
	{
       set_init_status(2);
	}
	restart_network();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Wlan_getPPPoEstatus(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* pppoe_info = JSON_NEW_EMPTY_OBJECT();
    char adsl_name[64] = {0};
	char adsl_password[64] = {0};
	char dns_list[64] = {0};
	int32_t pppoe_status = -1;
	get_vwan_pppoe_status(adsl_name,adsl_password,dns_list);
	if(!*adsl_name)
	{
		p_debug("adsl_name1 = %s,adsl_password = %s,dns_list = %s",adsl_name,adsl_password,dns_list);
		pppoe_status = get_cfg_pppoe_status(adsl_name,adsl_password);
		p_debug("adsl_name2 = %s,adsl_password = %s,dns_list = %s",adsl_name,adsl_password,dns_list);
		if(pppoe_status < 0)
		{
			header->code = ERROR_GET_PPPOE_STATUS;
		}
	}

	p_debug("adsl_name3 = %s,adsl_password = %s,dns_list = %s",adsl_name,adsl_password,dns_list);
	JSON_ADD_OBJECT(pppoe_info, "adsl_name",JSON_NEW_OBJECT(adsl_name,string));
	JSON_ADD_OBJECT(pppoe_info, "adsl_password",JSON_NEW_OBJECT(adsl_password,string));
	JSON_ARRAY_ADD_OBJECT (response_data_array,pppoe_info);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
/**/
int _set_vwan_mode_static(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
   char *ipaddr = JSON_GET_OBJECT_VALUE(ip_json,string);
   JObj *dns1_json = JSON_GET_OBJECT(para_json,"dns1_ip");
   JObj *dns2_json = JSON_GET_OBJECT(para_json,"dns2_ip");

   char *dns_list1 = JSON_GET_OBJECT_VALUE(dns1_json,string);
   char *dns_list2 = JSON_GET_OBJECT_VALUE(dns2_json,string);

   JObj *netmask_json = JSON_GET_OBJECT(para_json,"netmask");
   char *netmask = JSON_GET_OBJECT_VALUE(netmask_json,string);
   JObj *gateway_json = JSON_GET_OBJECT(para_json,"gateway");
   char *gateway = JSON_GET_OBJECT_VALUE(gateway_json,string);
   char dns_list[64] = {0};
   uint8_t static_flag = 0;
   uint8_t wifi_flag = 0;
   if(dns_list1 != NULL&&dns_list2 != NULL)
   {
      sprintf(dns_list,"\'%s %s\'",dns_list1,dns_list2);
   }else if(dns_list1 != NULL&&dns_list2 == NULL)
   	{
      strcpy(dns_list,dns_list1);
   }else if(dns_list2 != NULL&&dns_list1 == NULL)
   	{
      strcpy(dns_list,dns_list2);
   }
	p_debug("dns_list = %s",dns_list);
	char r_status[4] = {0};
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		set_to_bridge();	
	}
    set_vwan_mode_static(ipaddr,netmask,gateway ,dns_list);
	static_flag = (get_init_status()&2) >> 1;
	wifi_flag = get_init_status()&1;
	if(static_flag== 0 && wifi_flag == 0)
	{
       set_init_status(2);
	}
	restart_network();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
  return 0;
}
/**/
int _get_vwan_mode_static(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* static_info = JSON_NEW_EMPTY_OBJECT();
    char ipaddr[32] = {0};
	char dns_list[64] = {0};
    char netmask[32] = {0};
    char gateway[32] = {0};
	char dns1_ip[32] = {0};
    char dns2_ip[32] = {0};
	char *tmp = NULL;
	int32_t static_ret = -1;
	uint8_t ret = get_vwan_static_status (ipaddr,netmask,gateway,dns_list);
	p_debug("ipaddr = %s,netmask=%s,gateway=%s,dns_list=%s", ipaddr,netmask,gateway,dns_list);
	tmp = strstr(dns_list," ");
	if(tmp!=NULL)
	{
      memcpy(dns1_ip,dns_list,tmp-dns_list);
	  strcpy(dns2_ip,tmp); 
	}else{
      strcpy(dns1_ip,dns_list);  
	}
	if(!*ipaddr)
	{
		memset(ipaddr,0,32);
		memset(dns_list,0,64);
		memset(netmask,0,32);
		memset(gateway,0,32);
		memset(dns1_ip,0,32);
		memset(dns2_ip,0,32);
		static_ret = get_cfg_static_status(ipaddr,netmask,gateway,dns_list);
		if(static_ret < 0)
		{
			header->code = ERROR_GET_STATIC_STATUS;
		}else{
			tmp = strstr(dns_list," ");
			if(tmp!=NULL)
			{
				if(strstr(dns_list,"'"))
				{
					memcpy(dns1_ip,dns_list+1,tmp-dns_list-1);
					memcpy(dns2_ip,tmp,strlen(tmp)-1); 
				}
			}else{
				strcpy(dns1_ip,dns_list);  
			}
		}
	}
	JSON_ADD_OBJECT(static_info, "ip",JSON_NEW_OBJECT(ipaddr,string));
	JSON_ADD_OBJECT(static_info, "dns1_ip",JSON_NEW_OBJECT(dns1_ip,string));
	JSON_ADD_OBJECT(static_info, "dns2_ip",JSON_NEW_OBJECT(dns2_ip,string));
	JSON_ADD_OBJECT(static_info, "netmask",JSON_NEW_OBJECT(netmask,string));
	JSON_ADD_OBJECT(static_info, "gateway",JSON_NEW_OBJECT(gateway,string));
	
	JSON_ARRAY_ADD_OBJECT (response_data_array,static_info);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _client_connect_to_ap(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *is_uselocal_json = JSON_GET_OBJECT(para_json,"is_uselocal");
	JObj *local_ssid_json = JSON_GET_OBJECT(para_json,"local_ssid");
	JObj *local_password_json = JSON_GET_OBJECT(para_json,"local_password");
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	JObj *ssid_json = JSON_GET_OBJECT(para_json,"ssid");
	JObj *password_json = JSON_GET_OBJECT(para_json,"password");
	JObj *channel_json = JSON_GET_OBJECT(para_json,"channel");
	JObj *encrypt_json = JSON_GET_OBJECT(para_json,"encrypt");
	
	uint8_t is_uselocal = JSON_GET_OBJECT_VALUE(is_uselocal_json,boolean);
	char *local_ssid = JSON_GET_OBJECT_VALUE(local_ssid_json,string);
	char *local_password = JSON_GET_OBJECT_VALUE(local_password_json,string);
	char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	char *ap_ssid = JSON_GET_OBJECT_VALUE(ssid_json,string);
	uint8_t channel = JSON_GET_OBJECT_VALUE(channel_json,int);
	char *encrypt = JSON_GET_OBJECT_VALUE(encrypt_json,string);
	char *password = JSON_GET_OBJECT_VALUE(password_json,string);
	int32_t repeater_ret = 0;
	Repeater_Param rep_param;
	memset(&rep_param,0,sizeof(Repeater_Param));
	char is_uselocal_str[2] = {0};
	sprintf(rep_param.is_uselocal,"%d",is_uselocal);
	sprintf(rep_param.channel,"%d",channel);
	sprintf(rep_param.is_connect,"%d",0);
    p_debug("local_ssid=%s,local_password=%s", local_ssid,local_password);
	if(local_ssid&&*local_ssid)
	{
		p_debug("access local_ssid");
		strcpy(rep_param.local_ssid,local_ssid);
	}
	if(local_password&&*local_password)
	{
		strcpy(rep_param.local_password,local_password);
	}
	if(mac&&*mac)
	{
		strcpy(rep_param.mac,mac);
	}
    if(ap_ssid&&*ap_ssid)
    {
		strcpy(rep_param.ssid,ap_ssid);
	}
	if(password&&*password)
	{
		strcpy(rep_param.password,password);
	}
    if(encrypt&&encrypt)
    {
		strcpy(rep_param.encrypt,encrypt);
	}
	p_debug("rep_param.local_ssid=%s,rep_param.local_password=%s", rep_param.local_ssid,rep_param.local_password);
	repeater_ret = set_to_repeart(&rep_param);
	if(repeater_ret < 0)
	{
		header->code = ERROR_SET_REPEATER_FAIL;
	}
    //client_connect_to_ap(ap_ssid,channel,encrypt,password);
	uint8_t repeater_flag = 0;
	uint8_t wifi_flag = 0;
	repeater_flag = (get_init_status()&2) >> 1;
	wifi_flag = get_init_status()&1;
	if(repeater_flag == 0 && wifi_flag == 0)
	{
       set_init_status(2);
	}
	restart_network();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
    return 0;
}
int _get_repeater_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* rep_bri_info = JSON_NEW_EMPTY_OBJECT();
	uint8_t is_uselocal = 0;
	char local_ssid[SSID_LENGTH+1] = {0};
	char local_password[PASSOWRD_LENGTH+1] = {0};
	char mac[MAC_LEN+1] = {0};
    char ssid[SSID_LENGTH+1] = {0};
    char password[PASSOWRD_LENGTH+1] = {0};
	uint8_t channel = 0;
	char encrypt[ENCRYPY_LEN+1] = {0};
	uint8_t is_connect = 0;
	int32_t repeater_ret = 0;
	Repeater_Param rep_param;
    repeater_ret = get_repeart_status(&rep_param);
	if(repeater_ret > 0 )
	{
		is_uselocal = atoi(rep_param.is_uselocal);
		strcpy(local_ssid,rep_param.local_ssid);
		strcpy(local_password,rep_param.local_password);
		strcpy(mac,rep_param.mac);
		strcpy(ssid,rep_param.ssid);
		strcpy(password,rep_param.password);
		channel = atoi(rep_param.channel);
		strcpy(encrypt,rep_param.encrypt);
		is_connect = atoi(rep_param.is_connect);
	}
	else{
		header->code = ERROR_GET_REPEATER_STATUS;
	}
	JSON_ADD_OBJECT(rep_bri_info, "is_uselocal",JSON_NEW_OBJECT(password,boolean));
	JSON_ADD_OBJECT(rep_bri_info, "local_ssid",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "local_password",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "mac",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "ssid",JSON_NEW_OBJECT(ssid,string));
	JSON_ADD_OBJECT(rep_bri_info, "password",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "channel",JSON_NEW_OBJECT(password,int));
	JSON_ADD_OBJECT(rep_bri_info, "encrypt",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "is_connect",JSON_NEW_OBJECT(is_connect,boolean));
	JSON_ARRAY_ADD_OBJECT (response_data_array,rep_bri_info);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}

int _Password_modification(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

    JObj *old_pass_json = JSON_GET_OBJECT(para_json,"router_password");
    char *old_password = JSON_GET_OBJECT_VALUE(old_pass_json,string);
	JObj *new_pass_json = JSON_GET_OBJECT(para_json,"router_newpassword");
    char *new_password = JSON_GET_OBJECT_VALUE(new_pass_json,string);
	char *username = "root";
	uint8_t pass_ret =  IM_RootPwdAuth(old_password);
	p_debug("pass_ret = %d",pass_ret);
	if(pass_ret != 0)
	{
       header->code = PLEASE_REINPUT_PASSWORD;
	}
	else{
		p_debug("new_password = %s",new_password);
       IM_RootPwdSet(new_password);
	}

	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
    JSON_ADD_OBJECT(response_json, "header", header_json);
    strcpy(retstr,JSON_TO_STRING(response_json));
    JSON_PUT_OBJECT(response_json);
  return 0;
}
int _close_route_type(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	
	JObj *close_json = JSON_GET_OBJECT(para_json,"close_type");
	uint8_t close_type = JSON_GET_OBJECT_VALUE(close_json,int);

	char *switch_off = "off";
	char *switch_on = "on";
	char *str_fre_24G = "24G";
	char *str_fre_5G = "5G";
	char *str_hot = "ALLAP";
	if(close_type == 1){
	  wifi_switch_hot(str_fre_24G,str_hot,switch_off);
	  wifi_switch_hot(str_fre_5G,str_hot,switch_off);
	  restart_wifi();
	}else if(close_type ==2 ){
	   wifi_switch_hot(str_fre_24G,str_hot,switch_on);
	   wifi_switch_hot(str_fre_5G,str_hot,switch_on);
	   restart_wifi();
	}else if(close_type ==3 ){
		threadStatus->sleep_flag = 1;
	   	Reset_Sleep();
	}else if(close_type ==4 ){
		threadStatus->sleep_flag = 0;
	   	Reset_wakeup();
	}else if(close_type ==5 ){
		Reset_system();
	}else if(close_type ==6 ){
		Reset_Halt();
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Reset_factory(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
  Reset_factory();
  return 0;
}

int _Reset_getversion(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
    char version[MSG_SERVER_VERSION_LEN] = {0};
	char newversion[MSG_SERVER_VERSION_LEN] = {0};
	uint8_t is_update = MSG_SERVER_FALSE;
    Reset_getversion(version);
	//ms_get_new_version(newversion);//获取服务器版本接口
	if(!strcmp(version,newversion))
	{
		is_update = MSG_SERVER_FALSE;
	}else{
 		is_update = MSG_SERVER_TRUE;
	}
	p_debug("the longsys fw newest version : %s",version);
    JSON_ADD_OBJECT(response_para_json, "kernel_ver", JSON_NEW_OBJECT(version,string));
	JSON_ADD_OBJECT(response_para_json, "kernel_newver", JSON_NEW_OBJECT(newversion,string));
	JSON_ADD_OBJECT(response_para_json, "is_update", JSON_NEW_OBJECT(is_update,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Get_fw_upgrade_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	uint32_t fw_file_size = threadStatus->total_fw_len;
	uint32_t fw_down_size = threadStatus->complete_fw_len;
	uint8_t update_state = 0;
	if(threadStatus->upgrade_ret == 0)
	{
		if(fw_down_size != fw_file_size)
		{
			update_state = 1;
		}else {
			update_state = 3;
		}
	}else if(threadStatus->upgrade_ret == -1){
		update_state = 2;
	}
    JSON_ADD_OBJECT(response_para_json, "file_size", JSON_NEW_OBJECT(fw_file_size,int));
	JSON_ADD_OBJECT(response_para_json, "download_size", JSON_NEW_OBJECT(fw_down_size,int));
	JSON_ADD_OBJECT(response_para_json, "update_state", JSON_NEW_OBJECT(update_state,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int dm_fw_upgrade()
{
    Reset_fwupgrade(UPGRADE_FW_PATH);
	return 0;
}
int dm_upgrade_firmware(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	/*JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	
	JObj *url_json = JSON_GET_OBJECT(para_json,"im_url");
	char *fw_url = JSON_GET_OBJECT_VALUE(url_json,string);
	JObj *md5_json = JSON_GET_OBJECT(para_json,"im_md5");
	char *fw_md5 = JSON_GET_OBJECT_VALUE(url_json,string);
	S_IM_MSG_FIRMWARE firmware ;
	memset(&firmware,0,sizeof(S_IM_MSG_FIRMWARE));
	if(fw_url!=NULL&&fw_md5!=NULL&&strlen(fw_url) < MAX_URL_LEN&&strlen(fw_md5) < MAX_STRING)
	{
		memcpy(firmware.im_url,fw_url,MAX_URL_LEN);
		memcpy(firmware.im_md5,fw_md5,MAX_STRING);
		firmware.dlen = (int32_t *)&(threadStatus->complete_fw_len);
		firmware.tlen = (int32_t *)&(threadStatus->total_fw_len);
		//threadStatus->upgrade_ret = im_upgrade_firmware(&firmware, dm_fw_upgrade);
	}else{
		header->code = ERROR_PARA_LENGTH_LONG;
	}*/
	char version[MSG_SERVER_VERSION_LEN] = {0};
	 Reset_getversion(version);
	 p_debug("the longsys fw newest version : %s",version);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}

int _Wlan_getaccesspointlist(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
    char *fre = "24G";
    char scan_result[5*1024];
    get_scan_result(fre,scan_result);
	p_debug("scan_result = %s",scan_result);

	JObj *ap_info[50];
	uint8_t i = 0;
	char mac[32] = {0};
	char ssid[32] = {0};
	char channel[8] = {0};
	char flag[4] = {0};
	char encrypt[16] = {0};
	char tkip_aes[16] = {0};
	char power[16] = {0};
	char *start = scan_result;
	char *end = NULL;
	while(strstr(start,"{")&&i<40)
	{
		ap_info[i] = JSON_NEW_EMPTY_OBJECT();
		memset(mac,0,32);
		memset(ssid,0,32);
		memset(channel,0,8);
		memset(flag,0,4);
		memset(encrypt,0,16);
		memset(tkip_aes,0,16);
		memset(power,0,16);
		start = strstr(start,"{");
		end = strstr(start,",");
		start ++;
        memcpy(mac,start,end-start);
		p_debug("mac = %s",mac);
		end ++;
		start = end;
		end = strstr(end,",");
		memcpy(ssid,start,end-start);
		p_debug("ssid = %s",ssid);
		end ++;
		start = end;
		end = strstr(end,",");
		memcpy(channel,start,end-start);
		end ++;
		start = end;
		end = strstr(end,",");
		memcpy(flag,start,end-start);
		end ++;
		start = end;
		end = strstr(end,",");
		memcpy(encrypt,start,end-start);
		end ++;
		start = end;
		end = strstr(end,",");
		memcpy(tkip_aes,start,end-start);
		end ++;
		start = end;
		end = strstr(end,"}");
		memcpy(power,start,end-start);
		p_debug("power = %s",power);
		//JSON_ADD_OBJECT(ap_info[i], "mac",JSON_NEW_OBJECT(mac,string));
		JSON_ADD_OBJECT(ap_info[i], "ssid",JSON_NEW_OBJECT(ssid,string));
		JSON_ADD_OBJECT(ap_info[i], "channel",JSON_NEW_OBJECT(atoi(channel),int));
		JSON_ADD_OBJECT(ap_info[i], "Is_encrypt",JSON_NEW_OBJECT(atoi(flag),boolean));
		JSON_ADD_OBJECT(ap_info[i], "encrypt",JSON_NEW_OBJECT(encrypt,string));
		JSON_ADD_OBJECT(ap_info[i], "tkip_aes",JSON_NEW_OBJECT(tkip_aes,string));
		JSON_ADD_OBJECT(ap_info[i], "wifi_signal",JSON_NEW_OBJECT(atoi(power),int));;
		JSON_ARRAY_ADD_OBJECT (response_data_array,ap_info[i]);
		i++;
	}
	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));

	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	p_debug("retstr = %s",retstr);
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Wlan_get_cur_speed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	char route_speed[SPEED_LIST_LEN] ={0};
	int ret_speed = -1;
	uint32_t route_speed_size = 0;
	ret_speed = Wlan_get_cur_speed(route_speed);
	if(ret_speed <0)
	{
		header->code == ERROR_GET_CUR_SPEED_ERROR;
	}
	route_speed_size = atoi(route_speed);
	p_debug("route_speed_size = %d",route_speed_size);
	route_speed_size = route_speed_size/1000;
    JSON_ADD_OBJECT(response_para_json, "net_speed", JSON_NEW_OBJECT(route_speed_size,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _set_dev_upload_maxspeed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* rate_limmit = JSON_NEW_EMPTY_OBJECT();
	JObj* dev_rate_limit_info = JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	JObj *max_speed_json = JSON_GET_OBJECT(para_json,"max_uploadspeed");
	uint32_t max_speed = JSON_GET_OBJECT_VALUE(max_speed_json,int);//KB/S
    uint64_t max_speed_bit = max_speed*1000;
	char speed_limit[64];
	char *prio = "6";
	sprintf(speed_limit, "%lld", max_speed_bit);
	p_debug("mac = %s,speed_limit = %s",mac,speed_limit);
	
	/*start_speed_limit();
	set_up_speed_limit(mac,speed_limit,prio);
	stop_speed_limit();*/

	JSON_ADD_OBJECT(rate_limmit, "upload_maxspeed", JSON_NEW_OBJECT(speed_limit,string));
	JSON_ADD_OBJECT(dev_rate_limit_info, mac, rate_limmit);
	json_object_to_file(RATE_LIMIT_UP_CONFIG, dev_rate_limit_info);
	JSON_PUT_OBJECT(dev_rate_limit_info);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _set_dev_download_maxspeed(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	JObj *max_speed_json = JSON_GET_OBJECT(para_json,"max_downloadspeed");
	uint16_t max_speed = JSON_GET_OBJECT_VALUE(max_speed_json,int);
	uint64_t max_speed_bit = max_speed*1000;
	char speed_limit[64];
	char *prio = "6";

	JObj* rate_limmit = JSON_NEW_EMPTY_OBJECT();
	JObj* dev_rate_limit_info = JSON_NEW_EMPTY_OBJECT();
	
	sprintf(speed_limit, "%lld", max_speed_bit);
	/*start_speed_limit();
	set_down_speed_limit(mac,speed_limit,prio);
	stop_speed_limit();*/

	JSON_ADD_OBJECT(rate_limmit, "download_maxspeed", JSON_NEW_OBJECT(speed_limit,string));
	JSON_ADD_OBJECT(dev_rate_limit_info, mac, rate_limmit);
	json_object_to_file(RATE_LIMIT_DOWN_CONFIG, dev_rate_limit_info);
	JSON_PUT_OBJECT(dev_rate_limit_info);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
    return 0;
}
int _Format_disk(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	
	JObj *disk_json = JSON_GET_OBJECT(para_json,"disk");
	char *drivname = NULL;
	drivname = JSON_GET_OBJECT_VALUE(disk_json,string);
	JObj *drivedev_json = JSON_GET_OBJECT(para_json,"dev_node");
	char *drivedev = NULL;
	drivedev = JSON_GET_OBJECT_VALUE(drivedev_json,string);  
	JObj *format_json = JSON_GET_OBJECT(para_json,"is_format");
	uint8_t format_flag = JSON_GET_OBJECT_VALUE(format_json,int); 
	p_debug("drivname = %s,format_flag = %d,drivedev = %s\n",drivname,format_flag,drivedev);
	int format_ret = -1;
	if(drivname != NULL&&drivedev!=NULL&&format_flag == MSG_SERVER_TRUE&&strcmp(drivname,IMOVE_PRIVATE_NAME))
	{
		if(strlen(drivname)<5)
		{
			p_debug("Format_formatall\n");
			format_ret = Format_formatall(NTFS_TYPE);
			if(format_ret==0)
			{
				header->code = 0;
			}else{
				header->code = ERROR_FORMAT_DISK_FAIL;
			}
		}else{
			p_debug("Format_formatdisk\n");
			format_ret = Format_formatdisk(drivname, drivedev, NTFS_TYPE);
			if(format_ret==0)
			{
				header->code = 0;
			}else{
				header->code = ERROR_FORMAT_DISK_FAIL;
			}
		}
		
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Wlan_get_connect_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_pppoe_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_dhcp_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_static_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_repeater_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	char wan_mode[WAN_MODE_TYPE] = {0};
	uint8_t pppoe_is_connect = MSG_SERVER_FALSE;
	uint8_t dhcp_is_connect = MSG_SERVER_FALSE;
	uint8_t static_is_connect = MSG_SERVER_FALSE;
	uint8_t repeater_is_connect = MSG_SERVER_FALSE;
	
	uint8_t enable_pppoe = MSG_SERVER_TRUE;
	uint8_t enable_dhcp = MSG_SERVER_TRUE;
	uint8_t enable_static = MSG_SERVER_TRUE;
	uint8_t enable_repeater = MSG_SERVER_TRUE;
	char r_status[4] = {0};
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		repeater_is_connect = MSG_SERVER_TRUE;	
	}else{
		get_wan_mode(wan_mode);
		p_debug("wan_mode = %s",wan_mode);
		if(!strcmp(wan_mode,"pppoe"))
		{
	       pppoe_is_connect = MSG_SERVER_TRUE;
		}
		else if(!strcmp(wan_mode,"dhcp"))
		{
	       dhcp_is_connect = MSG_SERVER_TRUE;
		}
		else if(!strcmp(wan_mode,"static"))
		{
	       static_is_connect = MSG_SERVER_TRUE;
		   
		}
	}
    JSON_ADD_OBJECT(response_pppoe_json, "con_type", JSON_NEW_OBJECT(PPPOE_TYPE,int));
	JSON_ADD_OBJECT(response_pppoe_json, "enable", JSON_NEW_OBJECT(enable_pppoe,boolean));
	JSON_ADD_OBJECT(response_pppoe_json, "is_connect", JSON_NEW_OBJECT(pppoe_is_connect,boolean));
	JSON_ADD_OBJECT(response_dhcp_json, "con_type", JSON_NEW_OBJECT(DHCP_TYPE,int));
	JSON_ADD_OBJECT(response_dhcp_json, "enable", JSON_NEW_OBJECT(enable_dhcp,boolean));
	JSON_ADD_OBJECT(response_dhcp_json, "is_connect", JSON_NEW_OBJECT(dhcp_is_connect,boolean));

	JSON_ADD_OBJECT(response_static_json, "con_type", JSON_NEW_OBJECT(STATIC_TYPE,int));
	JSON_ADD_OBJECT(response_static_json, "enable", JSON_NEW_OBJECT(enable_static,boolean));
	JSON_ADD_OBJECT(response_static_json, "is_connect", JSON_NEW_OBJECT(static_is_connect,boolean));

	JSON_ADD_OBJECT(response_repeater_json, "con_type", JSON_NEW_OBJECT(REPEATER_TYPE,int));
	JSON_ADD_OBJECT(response_repeater_json, "enable", JSON_NEW_OBJECT(enable_repeater,boolean));
	JSON_ADD_OBJECT(response_repeater_json, "is_connect", JSON_NEW_OBJECT(repeater_is_connect,boolean));
	
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_pppoe_json);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_dhcp_json);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_static_json);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_repeater_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	p_debug("retstr = %s",retstr);
    return 0;
}
int _Password_exist(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* sign_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t is_password = Password_exist();
    JSON_ADD_OBJECT(response_para_json, "is_password", JSON_NEW_OBJECT(is_password,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Wlan_get_connect_type(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t is_internet =MSG_SERVER_FALSE;
	//is_internet =   Wlan_get_connect_type();
    JSON_ADD_OBJECT(response_para_json, "is_internet", JSON_NEW_OBJECT(is_internet,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
  return 0;
}
int _Wlan_get_repeater_type(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t is_connect =MSG_SERVER_FALSE;
	//is_connect =    Wlan_get_repeater_type();
    JSON_ADD_OBJECT(response_para_json, "is_connect", JSON_NEW_OBJECT(is_connect,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
    return 0;
}


uint8_t get_length_from_info(char *retstr)
{
  char *start = strstr(retstr,"<nfiles>");
  char *end = strstr(retstr,"</nfiles>");
  char count_str[32];
  memset(count_str,0,32);
  uint8_t len = strlen("<nfiles>");
  memcpy(count_str,start+len,end-start-len);
  p_debug("length_str = %d",atoi(count_str));
  return atoi(count_str);
}
uint8_t get_total_from_info(char *retstr)
{
  char *start = strstr(retstr,"<page_total>");
  char *end = strstr(retstr,"</page_total>");
  char count_str[32];
  memset(count_str,0,32);
  uint8_t len = strlen("<page_total>");
  memcpy(count_str,start+len,end-start-len);
  p_debug("total_str = %d",atoi(count_str));
  return atoi(count_str);
}

uint8_t get_member(char *retstr,uint8_t i,char *_start,char *_end,char *member)
{
   char section[16]={0};
   sprintf(section,"Section[%d]",i);
   char *sectionstr = strstr(retstr,section);  
   if(sectionstr != NULL)
   {
       char *start = strstr(sectionstr,_start);
	   char *end = strstr(sectionstr,_end);
	   uint8_t len = strlen(_start);
	   memcpy(member,start+len,end-start-len);
	   return 0;
   }
   return -1;
}

int _unload_opk(JObj * rpc_json)
{
  return 0;
}
int _start_app(JObj * rpc_json)
{
  return 0;
}
int _stop_app(JObj * rpc_json)
{
  return 0;
}
int handle_getStorageInfo(JObj* rpc_json, char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *disk_info_array = JSON_NEW_ARRAY();
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	all_disk_t mAll_disk_t;
	uint8_t drive_count = 0;
	int i=0;
	int private_exist = 0;
	char drive_name[32] = {0};
    char full_path[FULL_FILE_PATH_LENGTH] = {0};
	char private_full_path[FULL_FILE_PATH_LENGTH] = {0};
    char dev[32] = {0};
	uint32_t total_size = 0;
	uint32_t free_size = 0;
	char total_size_str[32] = {0};
	char free_size_str[32] = {0};
	int32_t isformat = MSG_SERVER_FALSE;

	char private_total_size_str[32] = {0};
	char private_free_size_str[32] = {0};
	char private_dev[32] = {0};
	int32_t private_isformat = MSG_SERVER_TRUE;
	uint8_t type = 0;
	memset(&mAll_disk_t,0,sizeof(all_disk_t));
	int32_t storage_ret = Format_getstorage (&mAll_disk_t);
	if(storage_ret != 0)
	{
		header->code = ERROR_CODE_NO_DRIVE;
	}
	drive_count = mAll_disk_t.count;
	JObj *drive_info[drive_count];
	for(i=0;i < drive_count;i++)
    {
		drive_info[i] = JSON_NEW_EMPTY_OBJECT();
		memset(drive_name,0,32);
		memset(full_path,0,FULL_FILE_PATH_LENGTH);
		memset(dev,0,32);
		memset(private_full_path,0,FULL_FILE_PATH_LENGTH);
		strcpy(drive_name,mAll_disk_t.disk[i].name);
		strcpy(full_path,mAll_disk_t.disk[i].path);
		strcpy(dev,mAll_disk_t.disk[i].dev);
		total_size = mAll_disk_t.disk[i].total_size;
		free_size = mAll_disk_t.disk[i].free_size;
		isformat = mAll_disk_t.disk[i].is_format;
		sprintf(total_size_str,"%d",total_size);
		sprintf(free_size_str,"%d",free_size);
		
		p_debug("drive_name = %s,full_path = %s,total_size_str = %s,free_size_str =%s\n",\
			drive_name,full_path,total_size_str,free_size_str);
		
		if(strstr(mAll_disk_t.disk[i].name,HD_DISK))
		{
			if(!strcmp(mAll_disk_t.disk[i].name,HD_DISK1))
			{
				sprintf(private_full_path,"%s/%s",full_path,IMOVE_PRIVATE_NAME);
				if(access(private_full_path,F_OK)!=-1)
				{
					private_exist = 1;
					strcpy(private_total_size_str,total_size_str);
					strcpy(private_free_size_str,free_size_str);
					strcpy(private_dev,dev);
					private_isformat = MSG_SERVER_TRUE;
				}
			}
			type = 1;
		}else if(strstr(mAll_disk_t.disk[i].name,U_DISK))
		{
			type = 3;
		}else if(strstr(mAll_disk_t.disk[i].name,SD_DISK))
		{
			type = 2;
		}
		JSON_ADD_OBJECT(drive_info[i], "disk",JSON_NEW_OBJECT(drive_name,string));
		JSON_ADD_OBJECT(drive_info[i], "full_path",JSON_NEW_OBJECT(full_path,string));
		JSON_ADD_OBJECT(drive_info[i], "total_size",JSON_NEW_OBJECT(total_size_str,string));
		JSON_ADD_OBJECT(drive_info[i], "free_size",JSON_NEW_OBJECT(free_size_str,string));
		JSON_ADD_OBJECT(drive_info[i], "dev_node",JSON_NEW_OBJECT(dev,string));
		JSON_ADD_OBJECT(drive_info[i], "type",JSON_NEW_OBJECT(type,int));
		JSON_ADD_OBJECT(drive_info[i], "is_format", JSON_NEW_OBJECT(isformat,boolean));
		JSON_ARRAY_ADD_OBJECT (disk_info_array,drive_info[i]);
	}
	if(private_exist == 1)
	{
		drive_info[i] = JSON_NEW_EMPTY_OBJECT();
		JSON_ADD_OBJECT(drive_info[i], "disk",JSON_NEW_OBJECT(IMOVE_PRIVATE_NAME,string));
		JSON_ADD_OBJECT(drive_info[i], "full_path",JSON_NEW_OBJECT(private_full_path,string));
		JSON_ADD_OBJECT(drive_info[i], "total_size",JSON_NEW_OBJECT(private_total_size_str,string));
		JSON_ADD_OBJECT(drive_info[i], "free_size",JSON_NEW_OBJECT(private_free_size_str,string));
		JSON_ADD_OBJECT(drive_info[i], "dev_node",JSON_NEW_OBJECT(private_dev,string));
		JSON_ADD_OBJECT(drive_info[i], "is_format", JSON_NEW_OBJECT(private_isformat,boolean));
		JSON_ARRAY_ADD_OBJECT (disk_info_array,drive_info[i]);
	}
	JSON_ADD_OBJECT(response_para_json, "disk_info", disk_info_array);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int _handle_cp_cancel(JObj *rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
  
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_data_array = JSON_NEW_ARRAY();
   JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
   uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
   header->code = 0;
    threadStatus->thread_cancel_flag = 0;
	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_cp(JObj *rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	uint8_t count = 0;
	uint8_t i =0;
	char *des_path = NULL;
	char *src_path = NULL;
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
	JObj *des_json = JSON_GET_OBJECT(file_json,"target_dir");
	des_path=JSON_GET_OBJECT_VALUE(des_json,string);
	count = JSON_GET_ARRAY_LEN(src_json);
	char cp_retstr[FILE_HANDLE_RET_STR_LEN];
	header->code = 0;
	char src_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	if(access(des_path,F_OK)!=-1)
	{
		for(i=0;i<count;i++)
		{  
		   src_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(src_json,i),"fileordir_name"),string);
			p_debug("src_path1 = %s",src_path);
		   if(access(src_path,F_OK)!=-1)
		   {  	
		   		/*strcpy(des_full_path,dm_concat_path_file(des_path, bb_get_last_path_component_strip(src_path)));
				p_debug("des_full_path = %s",des_full_path);
				if(access(des_full_path,F_OK)!=-1)	
				{
				    strcat(des_full_path,"1");
					if(access(des_full_path,F_OK)!=-1)
					{
						replace_last_char(des_full_path,'2');
						if(access(des_full_path,F_OK)!=-1)
						{
							replace_last_char(des_full_path,'3');
							if(access(des_full_path,F_OK)!=-1)
							{
								replace_last_char(des_full_path,'3');
							}
						}
					}
					des_path = des_full_path;
				}*/
				p_debug("des_path = %s",des_path);
			   threadStatus->thread_cancel_flag = 1;
		       char *file_argv[]={"cp","-rf",src_path,des_path};
		       handle_cp(CP_MOUNT,file_argv,cp_retstr,threadStatus);
			   p_debug("cancel threadStatus->thread_cancel_flag = %d", threadStatus->thread_cancel_flag);
		   }
		   else{
		       header->code = ERROR_CODE_SRC_NOT_EXIST;
		   }
		}
	}else{
		header->code = ERROR_CODE_DES_NOT_EXIST;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	p_debug("retstr = %s",retstr);
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int _handle_rm_cancel(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
	header->code = 0;
	threadStatus->thread_cancel_flag = 0;
	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
   return 0;
}

int _handle_rm(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   uint8_t count = 0;
   uint8_t i =0;
   char *des_path = NULL;
   char rm_retstr[FILE_HANDLE_RET_STR_LEN];
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data"); 
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *des_json = JSON_GET_OBJECT(file_json,"fileordir_list");
   count = JSON_GET_ARRAY_LEN(des_json);
   header->code = 0;
   for(i=0;i<count;i++)
   { 
       des_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(des_json,i),"fileordir_name"),string);
       if(access(des_path,F_OK)!=-1)
	   {
          p_debug("des_path = %s",des_path);
	      char *file_argv[]={"rm","-rf",des_path};
          handle_rm(RM_MOUNT,file_argv,rm_retstr,threadStatus);
	   }else{
	      header->code = ERROR_CODE_DES_NOT_EXIST;
	   }
   }
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int _handle_rmdir(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	return 0;
}
int _handle_rename(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	return 0;
}
int _handle_mv_cancel(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
	header->code = 0;
	threadStatus->thread_cancel_flag = 0;
	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_mv(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   uint8_t count = 0;
   uint8_t i =0;
   char mv_retstr[FILE_HANDLE_RET_STR_LEN];
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *src_json = NULL;
   JObj *des_json = NULL;
   char *des_path = NULL;
   char *src_path = NULL; 
   header->code = 0;
   	char src_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	
   if(header->cmd == 774)
   {
       src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
	   JObj *des_json = JSON_GET_OBJECT(file_json,"target_dir");
	   des_path=JSON_GET_OBJECT_VALUE(des_json,string);
	   count = JSON_GET_ARRAY_LEN(src_json);
	   if(access(des_path,F_OK)!=-1)
	   {
	       for(i=0;i<count;i++)
		   { 
			   p_debug("i=%d",i);
		       src_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(src_json,i),"fileordir_name"),string);
			   if(access(src_path,F_OK)!=-1)
			   {
			   		strcpy(des_full_path,dm_concat_path_file(des_path, bb_get_last_path_component_strip(src_path)));
					p_debug("des_full_path = %s",des_full_path);
					if(access(des_full_path,F_OK)!=-1)	
					{
						char *extension_start = NULL;
						char comma = '.';
						extension_start = strrchr(des_full_path,comma);
						if(extension_start!=NULL)
						{
							char extersion_filename[64] = {0};
							strcpy(extersion_filename,extension_start);
							*extension_start = 0;
							strcat(des_full_path,"1");
							p_debug("des_full_path1 = %s",des_full_path);
							strcat(des_full_path,extersion_filename);
							p_debug("des_full_path2 = %s",des_full_path);
							if(access(des_full_path,F_OK)!=-1)
							{
								*extension_start = '2';
								if(access(des_full_path,F_OK)!=-1)
								{
									*extension_start = '3';
									if(access(des_full_path,F_OK)!=-1)
									{
										*extension_start = '3';
									}
								}
							}
						}else{
							strcat(des_full_path,"1");
							if(access(des_full_path,F_OK)!=-1)
							{
								replace_last_char(des_full_path,'2');
								if(access(des_full_path,F_OK)!=-1)
								{
									replace_last_char(des_full_path,'3');
									if(access(des_full_path,F_OK)!=-1)
									{
										replace_last_char(des_full_path,'3');
									}
								}
							}
						}
						
						des_path = des_full_path;
					}
				  p_debug("des_path = %s",des_path);
			      char *file_argv[]={"mv","-f",src_path,des_path};
		          handle_mv(MV_COUNT,file_argv,mv_retstr,threadStatus);
				  p_debug("finished1");
			   }else{
			      header->code = ERROR_CODE_SRC_NOT_EXIST;
			   }
		   }
	   }else{
	      header->code = ERROR_CODE_DES_NOT_EXIST;
	   }
    }
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}
int _handle_rn(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   uint8_t count = 0;
   uint8_t i =0;
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *src_json = NULL;
   JObj *des_json = NULL;
   
   char *des_path = NULL;
   char *src_path = NULL; 
   char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	src_json = JSON_GET_OBJECT(file_json,"fileordir_name");
	des_json = JSON_GET_OBJECT(file_json,"fileordir_newname");
	src_path = JSON_GET_OBJECT_VALUE(src_json,string);
	des_path = JSON_GET_OBJECT_VALUE(des_json,string);
	header->code = 0;
    strcpy(des_full_path,des_path);
	if(access(des_full_path,F_OK)!=-1)	
	{
		char *extension_start = NULL;
		char comma = '.';
		extension_start = strrchr(des_full_path,comma);
		if(extension_start!=NULL)
		{
			char extersion_filename[64] = {0};
			strcpy(extersion_filename,extension_start);
			*extension_start = 0;
			strcat(des_full_path,"1");
			p_debug("des_full_path1 = %s",des_full_path);
			strcat(des_full_path,extersion_filename);
			p_debug("des_full_path2 = %s",des_full_path);
			if(access(des_full_path,F_OK)!=-1)
			{
				*extension_start = '2';
				if(access(des_full_path,F_OK)!=-1)
				{
					*extension_start = '3';
					if(access(des_full_path,F_OK)!=-1)
					{
						*extension_start = '3';
					}
				}
			}
		}
	    else {
			strcat(des_full_path,"1");
			if(access(des_full_path,F_OK)!=-1)
			{
				replace_last_char(des_full_path,'2');
				if(access(des_full_path,F_OK)!=-1)
				{
					replace_last_char(des_full_path,'3');
					if(access(des_full_path,F_OK)!=-1)
					{
						replace_last_char(des_full_path,'3');
					}
				}
			}
	    }
	}
    
	if(access(src_path,F_OK)!=-1)
	{
	  if (rename(src_path, des_full_path) < 0)
	  {
	     header->code = ERROR_CODE_SRC_NOT_EXIST;
	  }
	}else{
	  header->code = ERROR_CODE_SRC_NOT_EXIST;
	}
	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));

	JSON_ADD_OBJECT(response_json, "header", header_json);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_ls(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   char ls_info[MSG_SERVER_UNCONSUME_RET_LEN] = {0};
   uint8_t file_count = 0;
   uint8_t total_page = 0;
   uint8_t i =0;
   uint8_t file_mode = 0;
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_data_array = JSON_NEW_ARRAY();
   JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
   JObj *fileordir_info_array = JSON_NEW_ARRAY();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *dir_json = JSON_GET_OBJECT(file_json,"dir_name");
   JObj *pageno_json = JSON_GET_OBJECT(file_json,"page_no");
   JObj *pagenum_json = JSON_GET_OBJECT(file_json,"page_num");
   JObj *mode_json = JSON_GET_OBJECT(file_json,"get_mode");
   
   char *des_path = JSON_GET_OBJECT_VALUE(dir_json,string);
   uint8_t page_no = JSON_GET_OBJECT_VALUE(pageno_json,int);
   uint8_t page_num = JSON_GET_OBJECT_VALUE(pagenum_json,int);
   file_mode = JSON_GET_OBJECT_VALUE(mode_json,int);
   file_count = page_num;
   char fileordir_name[FILE_NAME_LENGTH] = {0};
   char file_type[4] = {0};
   uint8_t file_type_flag = 0;
   char create_time[64] = {0};
   char file_size[64] = {0};
   header->code = 0;
   if(page_no >0&&page_num>0)
   {
      if(access(des_path,F_OK)!=-1)	
	   {  
		   char *file_argv[]={"ls","-t",des_path};//sort by change time
		   handle_ls(LS_MOUNT,file_argv,ls_info,page_no,page_num); 
		   file_count = get_length_from_info(ls_info);
		   JObj *file_info[file_count];
		   total_page = get_total_from_info(ls_info);
		   char *start = ls_info;
		   char *end = NULL;
		   //p_debug("[%s]-%d ls_info: %s\n", __FUNCTION__, __LINE__, ls_info);
		  while(strstr(start,"{")&&i<file_count)
		  {
			file_info[i] = JSON_NEW_EMPTY_OBJECT();
			memset(fileordir_name,0,FILE_NAME_LENGTH);
			memset(file_type,0,4);
			memset(create_time,0,64);
			memset(file_size,0,64);
			start = strstr(start,"{");
			end = strstr(start,"type:");
			start ++;
			end--;
	        memcpy(fileordir_name,start,end-start);
			end = end + 6;
			start = end;
			end = strstr(end,",");
			memcpy(file_type,start,end-start);
			end ++;
			start = end;
			end = strstr(end,",");
			memcpy(create_time,start,end-start);
			end ++;
			start = end;
			end = strstr(end,"}");
			memcpy(file_size,start,end-start);
			file_type_flag = atoi(file_type);
			if( file_mode == 0)
			{
				JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(fileordir_name,string));
				JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(file_type_flag,int));
				JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(atoi(create_time),int));
				JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(atoi(file_size),int));
				JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
			}else if(file_mode == 1 && file_type_flag==0)
			{
				JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(fileordir_name,string));
				JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(file_type_flag,int));
				JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(atoi(create_time),int));
				JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(atoi(file_size),int));
				JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
			}
			i++;
		}
	   }else	
	   {
	          header->code = ERROR_CODE_DES_NOT_EXIST;
	   }  
   }else{
      header->code = ERROR_CODE_PARA_INVALID;
   }
   JSON_ADD_OBJECT(response_file_json, "page_total", json_object_new_int(total_page));
   JSON_ADD_OBJECT(response_file_json, "page_no", json_object_new_int(page_no));
   JSON_ADD_OBJECT(response_file_json, "page_num", json_object_new_int(page_num));
   JSON_ADD_OBJECT(response_file_json, "fileordir_info", fileordir_info_array);
   JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
  return 0;
}
int _handle_ls_r(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	char ls_info[MSG_SERVER_UNCONSUME_RET_LEN] = {0};
	int total_count = 0;
	uint8_t i =0;
	uint8_t file_mode = 0;
	char fileordir_name[FULL_FILE_PATH_LENGTH] = {0};
    char file_type[4] = {0};
    char create_time[64] = {0};
    char file_size[64] = {0};
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
	JObj *fileordir_info_array = JSON_NEW_ARRAY();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *dir_json = JSON_GET_OBJECT(file_json,"dir_name");
	char *des_path = JSON_GET_OBJECT_VALUE(dir_json,string);
	JObj *pageno_json = JSON_GET_OBJECT(file_json,"page_no");
	JObj *pagenum_json = JSON_GET_OBJECT(file_json,"page_num");
	JObj *mode_json = JSON_GET_OBJECT(file_json,"get_mode");
	uint8_t page_no = JSON_GET_OBJECT_VALUE(pageno_json,int);
	uint8_t page_num = JSON_GET_OBJECT_VALUE(pagenum_json,int);
	file_mode = JSON_GET_OBJECT_VALUE(mode_json,int);
	uint8_t file_start = 0;
	uint8_t file_end = 0;
	uint8_t page_total = 0;
	uint8_t info_size = 0;
	uint8_t file_type_flag = 0;
	char *start = NULL;
	char *end = NULL;
	/*total_count = 59
   [DM_SERVER][_handle_ls_r]-2838total_count = 59,file_start = 0,file_end = 20*/
   if(page_no > 0&&page_num > 0)	
   {
		if(access(des_path,F_OK)!=-1)
		{
		    char *file_count_argv[]={"ls","-Rt",des_path};
		    get_total_files_count(LS_MOUNT,file_count_argv,&total_count); 
			p_debug("total_count = %d",total_count);
		    file_start = (page_no-1)*page_num;
			if(total_count%page_num == 0)
			{
		       page_total = total_count/page_num;
			}else{
		       page_total = total_count/page_num + 1;
			}
			if(page_no <= page_total)
			{
		       	if(page_no == page_total)
				{
			       file_end = total_count;
				}else{
			       file_end = file_start + page_num;
				}
		   }
			info_size = file_end - file_start;
			if(info_size > 0)
			{
               JObj *file_info[info_size];
			   char *file_argv[]={"ls","-R",des_path};
			   p_debug("total_count = %d,file_start = %d,file_end = %d",total_count,file_start,file_end);
			   handle_ls_r(LS_MOUNT,file_argv,ls_info,file_start,file_end); 
			   p_debug("lr:ls_info = %s",ls_info);
			   start = ls_info;
			  while(strstr(start,"{")&&i<info_size)
			  {
				file_info[i] = JSON_NEW_EMPTY_OBJECT();
				memset(fileordir_name,0,FULL_FILE_PATH_LENGTH);
				memset(file_type,0,4);
				memset(create_time,0,64);
				memset(file_size,0,64);
				start = strstr(start,"{");
				end = strstr(start,"type:");
				start ++;
				end--;
		        memcpy(fileordir_name,start,end-start);
				end = end + 6;
				start = end;
				end = strstr(end,",");
				memcpy(file_type,start,end-start);
				end ++;
				start = end;
				end = strstr(end,",");
				memcpy(create_time,start,end-start);
				end ++;
				start = end;
				end = strstr(end,"}");
				memcpy(file_size,start,end-start);
				file_type_flag = atoi(file_type);
				p_debug("%d:fileordir_name = %s",i,fileordir_name);
				if( file_mode == 0)
				{
					JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(fileordir_name,string));
					JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(file_type_flag,int));
					JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(atoi(create_time),int));
					JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(atoi(file_size),int));
					JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
				}else if(file_mode == 1 && file_type_flag==0)
				{
					JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(fileordir_name,string));
					JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(file_type_flag,int));
					JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(atoi(create_time),int));
					JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(atoi(file_size),int));
					JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
				}
				i++;
			}
			}
		}else{
		   header->code = ERROR_CODE_DES_NOT_EXIST;
		}
   }else	
   { 
           header->code = ERROR_CODE_PARA_INVALID;
   }  
   
   JSON_ADD_OBJECT(response_file_json, "page_total", JSON_NEW_OBJECT(page_total,int));
   JSON_ADD_OBJECT(response_file_json, "page_no", JSON_NEW_OBJECT(page_no,int));
   JSON_ADD_OBJECT(response_file_json, "page_num", JSON_NEW_OBJECT(page_num,int));
   JSON_ADD_OBJECT(response_file_json, "fileordir_info", fileordir_info_array);
   JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
  return 0;
}

int _handle_pwd(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
  return 0;
}
int _handle_mkdir(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *dir_json = JSON_GET_OBJECT(file_json,"dir_name");
	char *des_path = JSON_GET_OBJECT_VALUE(dir_json,string);
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char mkdir_retstr[FILE_HANDLE_RET_STR_LEN] = {0};
	strcpy(des_full_path,des_path);
	header->code = 0;
	if(access(des_full_path,F_OK)!=-1)	
	{
	    strcat(des_full_path,"1");
		if(access(des_full_path,F_OK)!=-1)
		{
			replace_last_char(des_full_path,'2');
			if(access(des_full_path,F_OK)!=-1)
			{
				replace_last_char(des_full_path,'3');
				if(access(des_full_path,F_OK)!=-1)
				{
					replace_last_char(des_full_path,'3');
				}
			}
		}
	}
	p_debug("des_full_path: %s", des_full_path);
	char *file_argv[]={"mkdir","-p",des_full_path};
	handle_mkdir(MKDIR_COUNT,file_argv,mkdir_retstr);
	sleep(1);
	if(access(des_path,F_OK) < 0)	
	{
		header->code = ERROR_CREATE_FILE;
	}
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
   JSON_ADD_OBJECT(response_json, "header", header_json);
   strcpy(retstr,JSON_TO_STRING(response_json));
   JSON_PUT_OBJECT(response_json);
  return 0;
}

int _handle_touch(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
  return 0;
}
int _handle_query_status(JObj * rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{
   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_data_array = JSON_NEW_ARRAY();
   JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
   uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
   uint8_t event_result = 0;
   p_debug("DM event_id =  0x%x",(unsigned int)event_id);
   header->code = 0;
    /*uint8_t total_file = threadStatus->total_file_number;
      uint8_t finished_file = threadStatus->complete_file_number;
      JSON_ADD_OBJECT(response_file_json, "file_total", JSON_NEW_OBJECT(total_file,int));
	JSON_ADD_OBJECT(response_file_json, "file_finished", JSON_NEW_OBJECT(finished_file,int));*/

	if(threadStatus->thread_cancel_flag == 1)
	{
		event_result = 2;
	}else if(threadStatus->thread_cancel_flag == 0)
	{
		event_result = 0;
	}
	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(threadStatus->thread_cancel_flag,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(retstr,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}


int api_response(char *retstr,header_info *header)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
    JSON_ADD_OBJECT(response_json, "header", header_json);
    strcpy(retstr,JSON_TO_STRING(response_json));
    JSON_PUT_OBJECT(response_json);
	p_debug("retstr = %s",retstr);
	return 0;
}


int api_process(JObj *rpc_json,char *retstr,header_info *header,thread_info *threadStatus)
{ 
	uint8_t i = 0;
	uint8_t switch_flag = 0;
	for(i = 0; i<TAGHANDLE_NUM; i++)
	{
		if(header->cmd == all_tag_handle[i].tag)
		{
	       	 all_tag_handle[i].tagfun(rpc_json,retstr,header,threadStatus);
		     switch_flag = 1;

		}
	}
	if(switch_flag == 0)
	{
	    strcpy(retstr,"input cmd is not finished!");
	}
	return 0;
}



