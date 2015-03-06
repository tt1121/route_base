#include "imove_msg_server.h"

static IM_ST_file_op_rd *g_file_op_rd = NULL;
static IM_ST_file_op_rd *g_file_op_freelist = NULL;
S_IM_MSG_FIRMWARE g_firmware_info;
#if 0
/** 0x01--**/
IM_ST_handle_func gen_cmd_func[]={
		
}; 
#endif

/** 0x02-- **/
IM_ST_handle_func system_cmd_func[] = {
		{.cmd=FN_CREATE_GROUP, .combine = 0, .func= create_group},
		{.cmd=FN_GET_GROUP_LIST, .combine = 0, .func= get_group_list},
		{.cmd=FN_GET_GROUP_SETTINGS_INFO, .combine= 0,.func=get_group_settings_info},
		{.cmd=FN_DELETE_GROUP, .combine=0,  .func=delete_group},
		{.cmd=FN_AMEND_GROUP, .combine=0, .func=amend_group},
		{.cmd=FN_ADD_GROUP_DEV, .combine=0, .func=add_group_dev},
 		{.cmd=FN_GET_GROUP_DEV_LIST, .combine=0, .func=get_group_dev_list},
 		{.cmd=FN_QUERY_DEV_INFO, .combine=0, .func=query_dev_info},
 		{.cmd=FN_GET_ROUTER_INIT_STATUS, .combine=0, .func=get_router_init_status},
 		{.cmd = FN_ROUTER_SWITCH_STATUS, .combine = 0, .func = _Route_switch_status},
 		{.cmd = FN_WIFI_SET_WIRELESS,.combine = 0, .func = _WiFi_setwireless},
 		{.cmd = FN_WIFI_GET_WIRELESS_STATUS, .combine = 0, .func = _WiFi_getwirelessstatus},
 		{.cmd = FN_SET_VWAN_MODE_PPPOE, .combine = 0, .func = _set_vwan_mode_pppoe},
 		{.cmd = FN_GET_VWAN_MODE_PPPOE, .combine = 0, .func = _Wlan_getPPPoEstatus},
	 	{.cmd = FN_SET_VWAN_MODE_STATIC,.combine = 0, .func = _set_vwan_mode_static},
	 	{.cmd = FN_GET_VWAN_MODE_STATIC, .combine = 0, .func= _get_vwan_mode_static},
	 	{.cmd = FN_CLIENT_CONNECT_TO_AP, .combine = 0, .func= _client_connect_to_ap},
	 	{.cmd = FN_GET_REPEATER_STATUS, .combine = 0, .func= _get_repeater_status},
	 	{.cmd = FN_PASSWORD_MODIFICATION, .combine = 0, .func= imove_password_modification},
	 	{.cmd = FN_SET_PASSWORD, .combine = 0, .func= imove_set_password},
	 	{.cmd = FN_CLOSE_ROUTER_TYPE, .combine = 0, .func= imove_close_route_type},
	 	{.cmd = FN_RESET_FACTORY, .combine = 0, .func= _Reset_factory},
	 	{.cmd = FN_GET_FW_VERSION, .combine = 0, .func= imove_reset_getversion},
	 	{.cmd = FN_GET_FW_UPGADE_STATUS, .combine = 0, .func= imove_get_fw_upgrade_status},
	 	{.cmd = FN_GET_SCAN_RESULT, .combine = 0, .func= imove_wlan_getaccesspointlist},
	 	{.cmd = FN_GET_ROUTER_CUR_SPEED, .combine = 0, .func= _Wlan_get_cur_speed},
	 	{.cmd = FN_SET_DEV_UPLOAD_MAXSPEED, .combine = 0, .func= imove_set_dev_upload_maxspeed},
	 	{.cmd = FN_SET_DEV_DOWNLOAD_MAXSPEED, .combine = 0, .func= imove_set_dev_download_maxspeed},
	 	{.cmd = FN_FORMAT_DISK, .combine = 0, .func= imove_format_disk},
	 	{.cmd = FN_GET_ROUTER_CONNECT_STATUS, .combine = 0, .func= imove_wlan_get_connect_status},
	 	{.cmd = FN_PASSWORD_EXIST, .combine = 0, .func= imove_password_exist},
	 	{.cmd = FN_WLAN_GET_CONNECT_TYPE, .combine = 0, .func= imove_wlan_get_connect_type},
	 	{.cmd = FN_WLAN_GET_REPEATER_STATUS, .combine = 0, .func= imove_wlan_get_repeater_type},
	 	{.cmd = FN_GET_USR_DEV_ACCESS_PER, .combine = 0, .func= get_usr_dev_permission},
	 	{.cmd = FN_GET_SSID_AND_ROUTE_ID, .combine = 0, .func= get_ssid_and_route_id},
	 	{.cmd = FN_FW_UPGRADE, .combine = 0, .func= dm_upgrade_firmware},
 		{.cmd = FN_SET_DHCP_CONNCT, .combine = 0, .func= imove_set_vwan_mode_dhcp},
		{.cmd = FN_GET_ROUTER_STATUS, .combine = 0, .func = dm_get_router_status},
		{.cmd = FN_GET_ROUTER_NETWORK_STATUS, .combine = 0, .func = dm_get_router_network_status},
		{.cmd = FN_GET_ROUTER_CONNECT_DEVRATE, .combine = 0, .func = dm_get_router_connect_dev_rate_statistics},
		{.cmd = FN_GET_DEV_CON_INFO, .combine = 0, .func = dm_get_dev_con_info},
		{.cmd = FN_GET_ROUTER_MAC, .combine = 0, .func = dm_get_router_mac},
		{.cmd = FN_CLONE_MAC, .combine = 0, .func = dm_clone_mac},
		{.cmd = FN_GET_DHCP_INFO, .combine = 0, .func = dm_get_dhcp_info},
		{.cmd = FN_SET_DHCP_INFO, .combine = 0, .func = dm_set_dhcp_info},
		{.cmd = FN_GET_IP_BINDING_INFO, .combine = 0, .func = dm_get_ip_binding_info},
		{.cmd = FN_BIND_IP, .combine = 0, .func = dm_bind_ip},
		{.cmd = FN_DEL_IP_BIND, .combine = 0, .func = dm_del_ip_bind},
		{.cmd = FN_GET_WIFI_SETTINGS, .combine = 0, .func = dm_get_wifi_settings},
		{.cmd = FN_SET_WIFI_SETTINGS, .combine = 0, .func = dm_set_wifi_settings},
		{.cmd = FN_GET_WIFI_ACCESS_CTR_MAK, .combine = 0, .func = dm_get_wifi_access_ctr_mark},
		{.cmd = FN_SET_WIFI_ACCESS_STR_MAK, .combine = 0, .func = dm_set_wifi_access_ctr_mark},
		{.cmd = FN_SET_WIFI_ACCESS_CTRL, .combine = 0, .func = dm_set_wifi_access_ctrl},
		{.cmd = FN_SET_GROUP, .combine = 0, .func = dm_set_group},
		{.cmd = FN_SET_HDSIK, .combine = 0, .func = dm_set_hdisk},
		{.cmd = FN_GET_LIMIT_DEV_INFO, .combine = 0, .func = dm_get_limit_dev_info},
		{.cmd = FN_SET_LIMIT_SPEED, .combine = 0, .func = dm_set_limit_speed},
		{.cmd = FN_SET_UPNP, .combine = 0, .func = dm_set_upnp},
		{.cmd = FN_GET_UPNP, .combine = 0, .func = dm_get_upnp},
		{.cmd = FN_GET_PORT_FORWARD_INFO, .combine = 0, .func = dm_get_port_forward_info},
		{.cmd = FN_GET_DMZ_INFO, .combine = 0, .func = dm_get_dmz_info},
		{.cmd = FN_SET_DMZ_INFO, .combine = 0, .func = dm_set_dmz_info},
		{.cmd = FN_GET_WEB_FW_VERSION, .combine = 0, .func = dm_get_fw_version},
		{.cmd = FN_FW_UPGRADE, .combine = 0, .func = dm_web_fw_upgrade},
		{.cmd = FN_SYSTEM_BACKUPS, .combine = 0, .func = dm_system_backups},
		{.cmd = FN_RECOVER_BACKUP_SYSTEM, .combine = 0, .func = dm_recover_backup_system},
		{.cmd = FN_GET_WAN_STATUS, .combine = 0, .func = dm_get_wan_status},
		{.cmd = FN_GET_LAN_STATUS, .combine = 0, .func = dm_get_lan_status},
		{.cmd = FN_GET_MAMAGEPC_MAC, .combine = 0, .func = dm_get_managepc_mac},
		{.cmd = FN_GET_ACCESS_INTERNET_STATUS, .combine = 0, .func = dm_get_access_internet_status},
		{.cmd = FN_SET_DHCP_CONNECT, .combine = 0, .func = dm_set_dhcp_connect},
		{.cmd = FN_GET_HDISK_SETTINGS, .combine = 0, .func = dm_get_hdisk_settings},
		{.cmd = FN_START_UPGRADE, .combine = 0, .func = dm_start_upgrade},
		{.cmd = FN_RESUME_MAC, .combine = 0, .func = dm_resume_mac},
		{.cmd = FN_ADD_PORT_FORWARDING, .combine = 0, .func = dm_add_port_forwarding},
		{.cmd = FN_PORT_AMEND_FORWARDING, .combine = 0, .func = dm_port_amend_forwarding},
		{.cmd = FN_DEL_PORT_FORWARDING, .combine = 0, .func = dm_del_port_forwarding},
		{.cmd = FN_GET_SAMBA_INFO, .combine = 0, .func = dm_get_samba_info},
		{.cmd = FN_ADD_DDNS, .combine = 0, .func = dm_add_ddns},
		{.cmd = FN_DEL_DDNS, .combine = 0, .func = dm_del_ddns},
		{.cmd = FN_GET_DDNS_LIST, .combine = 0, .func = dm_get_ddns_list}
};

/** 0x03--**/
IM_ST_handle_func storage_manage_cmd_func[] = {
	{.cmd = FN_FILE_COPY_FILE_DIR, .combine = 0, .func = imove_handle_cp},
 	{.cmd = FN_FILE_COPY_CANCEL, .combine = 0, .func = imove_handle_cp_cancel},	
 	{.cmd = FN_FILE_RM_FILE_DIR, .combine = 0, .func = imove_handle_rm},
 	{.cmd = FN_FILE_RM_CANCEL, .combine = 0, .func = _handle_rm_cancel},
 	{.cmd = FN_FILE_RM_DIR, .combine = 0, .func = _handle_rmdir},
 	{.cmd = FN_FILE_MOVE_FILE_DIR, .combine = 0, .func = _handle_mv},
 	{.cmd = FN_FILE_MOVE_CANCEL, .combine = 0, .func = imove_handle_mv_cancel},
 	{.cmd = FN_FILE_RENAME_FILE_DIR, .combine = 0, .func = imove_handle_rn},
 	{.cmd = FN_FILE_LS_FILE_DIR, .combine = 0, .func = _handle_ls},
 	{.cmd = FN_FILE_LS_R_FILE_DIR, .combine = 0, .func = _handle_ls_r},
 	{.cmd = FN_FILE_MAKE_DIR, .combine = 0, .func = _handle_mkdir},
 	{.cmd = FN_GET_STORAGE_INFO, .combine = 0, .func = handle_getStorageInfo},
 	{.cmd = FN_FILE_QUERY_STATUS, .combine = 0, .func = _handle_query_status},
};

/** 0x04-- **/
IM_ST_handle_func speed_check_cmd_func[] = {
	{.cmd = FN_GET_TEST_DOWNLOAD_SPEED, .combine = 0, .func= get_test_download_speed},
 	{.cmd = FN_GET_TEST_UPLOAD_SPEED, .combine = 0, .func= get_test_upload_speed},
 	{.cmd = FN_GET_WIFI_PASSWD_STRENGTH, .combine = 0, .func= get_wifi_passwd_strength},
 	{.cmd = FN_GET_ADMIN_PASSWD_STRENGTH, .combine = 0, .func= get_admin_passwd_streagth},
	
};

/** 0x05-- **/
IM_ST_handle_func ge_upload_speed_cmd_func[] = {
	{.cmd = FN_SETUP_UPLOAD_FLOW_SPEED, .combine = 0, .func= set_upload_flow_speed},
};

/*** unknow cmd func defined ***/
IM_ST_handle_func unknow_cmd_funcs[] = {
	{.cmd = FN_FILE_TOUCH_FILE_DIR, .combine = 0, .func= _handle_touch},		// 这两个命令并不知道在哪定义
 	{.cmd = FN_FILE_PWD_FILE_DIR, .combine = 0, .func= _handle_pwd},
};

char* dm_concat_path_file(const char *path, const char *filename);
char* bb_get_last_path_component_strip(char *path);

/****
创建线程的封装接口函数
params:
	start_routine: 	[IN] 函数指针
	arg: 				[IN] 传递给start_routine 所运行的线程的参数
	is_detache:		[IN] 是否开启PTHREAD_CREATE_DETACHED属性
return:
	0: 	success
	!0: failed
****/
int imove_create_thread_gen(void *(*start_routine)(void *), void *arg, int is_detache)
{
	pthread_t pth_id;
	pthread_attr_t attr;
	int ret = 0;

	if (start_routine == NULL)
	{
		return -1;
	}
	
	ret = pthread_attr_init(&attr);
	if (ret != 0)
	{
		p_debug("errno:%d msg:%s\b", errno, strerror(errno));
		goto ERR_OUT;
	}
		
	if (is_detache)
	{
		ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (ret != 0)
		{
			p_debug("errno:%d pthread setdetachestate failed\n", errno);
			goto ERR_OUT;
		}
	}
	
	/*************  create pthread to handle upgrade ***********/
	ret = pthread_create(&pth_id, &attr, start_routine, arg);
	
ERR_OUT:	
	return ret;
}

int  replace_last_char(char *s, int c)
{
	if (s && *s) {
		size_t sz = strlen(s) - 1;
		 p_debug("tmp :%d\n",(unsigned char)*(s+sz));
		if ( (unsigned char)*(s+sz) == c-1)
		{
		    p_debug("last char :%d\n",(unsigned char)*(s+sz));
            *(s+sz) =(unsigned char)c;
		}
	}else{
		return -1;
	}
	return 0;
}

int rename_process(char *des_full_path)
{
	char *extension_start = NULL;
	char comma = '.';
	extension_start = strrchr(des_full_path,comma);
	if(extension_start!=NULL)
	{
		char extersion_filename[64] = {0};
		strcpy(extersion_filename,extension_start);
		*extension_start = 0;
		//memset(des_full_path,0,sizeof(des_full_path));
		strcat(des_full_path,"(1)");
		strcat(des_full_path,extersion_filename);
		p_debug("des_full_path2 = %s",des_full_path);
		if(access(des_full_path,F_OK)!=-1)
		{
			*(extension_start + 1) = '2';
			if(access(des_full_path,F_OK)!=-1)
			{
				*(extension_start + 1) = '3';
				if(access(des_full_path,F_OK)!=-1)
				{
					*(extension_start + 1) = '4';
					if(access(des_full_path,F_OK)!=-1)
					{
						*(extension_start + 1) = '5';
						if(access(des_full_path,F_OK)!=-1)
						{
							*(extension_start + 1) = '6';
							if(access(des_full_path,F_OK)!=-1)
							{
								*(extension_start + 1) = '7';
								if(access(des_full_path,F_OK)!=-1)
								{
									*(extension_start + 1) = '8';
									if(access(des_full_path,F_OK)!=-1)
									{
										*(extension_start + 1) = '9';
										if(access(des_full_path,F_OK)!=-1)
										{
											*(extension_start + 1) = '9';
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}else{
		strcat(des_full_path,"(1)");
		if(access(des_full_path,F_OK)!=-1)
		{
			replace_last_char(des_full_path,'2');
			if(access(des_full_path,F_OK)!=-1)
			{
				replace_last_char(des_full_path,'3');
				if(access(des_full_path,F_OK)!=-1)
				{
					replace_last_char(des_full_path,'4');
					if(access(des_full_path,F_OK)!=-1)
					{
						replace_last_char(des_full_path,'5');
						if(access(des_full_path,F_OK)!=-1)
						{
							replace_last_char(des_full_path,'6');
							if(access(des_full_path,F_OK)!=-1)
							{
								replace_last_char(des_full_path,'7');
								if(access(des_full_path,F_OK)!=-1)
								{
									replace_last_char(des_full_path,'8');
									if(access(des_full_path,F_OK)!=-1)
									{
										replace_last_char(des_full_path,'9');
										if(access(des_full_path,F_OK)!=-1)
										{
											replace_last_char(des_full_path,'9');
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}

char*  my_toupper(char *upper_mac)
{
	uint8_t i = 0;
	for(i=0;i< strlen(upper_mac);i++)
	{
		upper_mac[i] = toupper(upper_mac[i]);
	}
	return NULL;
}
char*  my_tolower(char *lower_mac)
{
	uint8_t i = 0;
	for(i=0;i< strlen(lower_mac);i++)
	{
		lower_mac[i] = tolower(lower_mac[i]);
	}
	return NULL;
}

/***
产生随机数
params:
	none
return:
	radom data
***/
static unsigned int imove_generate_radom(void)
{
	int i_radom = 0;

	srand((unsigned)time(NULL));

	i_radom = rand();
	
	return (unsigned int)i_radom;
}

/***
将新节点添加到队列中
***/
static void add_new2queue(IM_ST_file_op_rd **head, IM_ST_file_op_rd *req)
{
	if (*head)
	{
		(*head)->prev = req;
	}

	req->next = *head;
	req->prev = NULL;
	*head = req;
}

/****
将节点从队列中删除 
***/
static void del_node_from_queue(IM_ST_file_op_rd **header, IM_ST_file_op_rd *node)
{
	if (*header == node)	// the first or the last node
		*header = node->next;

	if (node->prev)
		node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;

	node->next = NULL;
	node->prev = NULL;	
}

/****
分配新节点
***/
static IM_ST_file_op_rd *create_new_node(void)
{
	IM_ST_file_op_rd *req;
	
	if (g_file_op_freelist)
	{
		req = g_file_op_freelist;
		del_node_from_queue(&g_file_op_freelist, g_file_op_freelist);
	}
	else
	{
		req = (IM_ST_file_op_rd *)malloc(sizeof(IM_ST_file_op_rd));
		if (!req)
		{
			p_debug("malloc for new request");
			return NULL;
		}
	}

	return req;
}

/*****
根据event_id 获取对应的文件操作单元

*****/
IM_ST_file_op_rd *imove_find_fileop_by_id(unsigned int event_id)
{
	IM_ST_file_op_rd *tmp = NULL;
	IM_ST_file_op_rd *next = NULL;
	if (event_id < 0)
	{
		return NULL;
	}

	if (g_file_op_rd == NULL)
	{
		return NULL;
	}

	tmp = g_file_op_rd;
	while (tmp)
	{
		next = tmp->next;
		if (tmp->i_radom == event_id)
			break;
		tmp = next;
	}
	
	return tmp;	
}

int paserList2DevInfo(char *ip_list,char *upper_mac,dev_info *mDevInfo)
{
	char mac[MAC_LEN] = {0};
	char ipaddr[IPADDR_STR_LEN] = {0};
	char total_upload_str[TOTALLOADSIZE] = {0};
	char total_download_str[TOTALLOADSIZE]={0};
	char up_bps[TOTALLOADSIZE] = {0};
	char down_bps[TOTALLOADSIZE] = {0};
	char update_time[TOTALLOADSIZE] = {0};
	char *start = NULL;
	char *end = NULL;
	uint32_t total_download_size = 0;
	uint32_t total_upload_size = 0;
	uint32_t up_bps_size = 0;
	uint32_t down_bps_size = 0;
	char *target_dev = NULL;
	my_toupper(upper_mac);
	target_dev = strstr(ip_list,upper_mac);
	my_tolower(upper_mac);
    if(target_dev != NULL)
    {
		 start = target_dev;
		 end = strstr(start,",");
		  memcpy(mac,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(ipaddr,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_upload_str,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_download_str,start,end-start);//total_downloadsize
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(up_bps,start,end-start);//上传速度
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(down_bps,start,end-start);//下载速度
		 end ++;
		 start = end;
		 end = strstr(end,"}");
		 memcpy(update_time,start,end-start);//连接时间
		  p_debug("total_download_str = %s,total_upload_str=%s,up_bps=%s,down_bps=%s",total_download_str,\
		  	total_upload_str,up_bps,down_bps);
		 total_download_size = atoi(total_download_str);
		 total_upload_size = atoi(total_upload_str);
		 up_bps_size = atoi(up_bps);
		 down_bps_size = atoi(down_bps);
		
		 mDevInfo->total_downloadsize = total_download_size/NETWORK_NET_FLOW_LEVEL;
		 mDevInfo->total_uploadsize = total_upload_size/NETWORK_NET_FLOW_LEVEL;
		 mDevInfo->download_speed = down_bps_size/NETWORK_NET_FLOW_LEVEL;
		 if(mDevInfo->download_speed >= NETWORK_NET_MAX_SPEED)
		 {
			mDevInfo->download_speed == NETWORK_NET_MAX_SPEED;
		 }
		 mDevInfo->upload_speed = up_bps_size/NETWORK_NET_FLOW_LEVEL;
    }
    else{
         mDevInfo->total_downloadsize = 0;
		 mDevInfo->total_uploadsize = 0;
		 mDevInfo->download_speed = 0;
		 mDevInfo->upload_speed = 0;
		 return -1;
    }
	return 0;	
}

int getDevBackUpInfo(char *mac,devbackupinfo *mDev_backup)
{
	JObj* rate_limmit_json = NULL;
	JObj* upspeed_json = NULL;
	JObj* downspeed_json = NULL;
	JObj* connecttime_json = NULL;
	JObj* ip_json = NULL;
	JObj *dev_total_down_josn = NULL;
	JObj *con_type_json = NULL;
	int is_online = 0;
	uint8_t con_type = 0;
		
	rate_limmit_json = json_object_from_file(RATE_LIMIT_UP_CONFIG);
	if(rate_limmit_json != NULL)
	{
		json_object_object_foreach(rate_limmit_json,key,value){ //这是一个宏定义，所以可以这么使用
			if(strstr(key,mac))
			{ 
				upspeed_json = JSON_GET_OBJECT(value,"upload_maxspeed");
				if(upspeed_json != NULL)
					mDev_backup->MaxUpSpeed = JSON_GET_OBJECT_VALUE(upspeed_json,int);
				downspeed_json = JSON_GET_OBJECT(value,"download_maxspeed");
				if(downspeed_json != NULL)
					mDev_backup->MaxDownSpeed = JSON_GET_OBJECT_VALUE(downspeed_json,int);
				connecttime_json = JSON_GET_OBJECT(value,"connect_time");
				if(connecttime_json != NULL)
					mDev_backup->contime = JSON_GET_OBJECT_VALUE(connecttime_json,int);
				ip_json = JSON_GET_OBJECT(value,"ip");
				if(ip_json != NULL)
					strcpy(mDev_backup->ip,JSON_GET_OBJECT_VALUE(ip_json,string));
				dev_total_down_josn = JSON_GET_OBJECT(value,"total_down");
				if(dev_total_down_josn != NULL)
					mDev_backup->total_down = JSON_GET_OBJECT_VALUE(dev_total_down_josn,int);

				con_type_json = JSON_GET_OBJECT(value,"con_type");
				if(con_type_json != NULL)
					con_type = JSON_GET_OBJECT_VALUE(con_type_json,int);
				p_debug("mac = %s,connect_time = %d,ip = %s,total_down = %d",mac,mDev_backup->contime,mDev_backup->ip,mDev_backup->total_down);
			}
		}
		JSON_PUT_OBJECT(rate_limmit_json);

		is_online = is_dev_online(mac);
		if(is_online > 0)
		{
			mDev_backup->is_online = is_online;
			mDev_backup->con_type = con_type;
		}
	}
	else{
		return -1;
	}
	return 0;
}
	
/******************************** 0x04-- speed check cmd function **********************************************/
int get_test_download_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *testspeed_status_json = JSON_GET_OBJECT(para_json,"testspeed_status");
	uint8_t testspeed_status = JSON_GET_OBJECT_VALUE(testspeed_status_json,int);
	SPEED_DOWNLOAD_ST st_download;


	speed_test_download(testspeed_status, &st_download);
	JSON_ADD_OBJECT(response_para_json, "download_speed", JSON_NEW_OBJECT(st_download.download_speed,double));
	JSON_ADD_OBJECT(response_para_json, "testspeed_status", JSON_NEW_OBJECT(st_download.testspeed_status,int));
	

	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_test_upload_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *testspeed_status_json = JSON_GET_OBJECT(para_json,"testspeed_status");
	uint8_t testspeed_status = JSON_GET_OBJECT_VALUE(testspeed_status_json,int);
	SPEED_UPLOAD_ST st_upload;


	speed_test_upload(testspeed_status, &st_upload);
	JSON_ADD_OBJECT(response_para_json, "upload_speed", JSON_NEW_OBJECT(st_upload.upload_speed,double));
	JSON_ADD_OBJECT(response_para_json, "testspeed_status", JSON_NEW_OBJECT(st_upload.testspeed_status,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	
	return 0;
}

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

int get_wifi_passwd_strength(JObj * rpc_json,  IM_ST_msg_header *header,IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t wifi_24G_pwdlevel = 0;
	uint8_t wifi_5G_pwdlevel = 0;
	uint8_t wifi_pwdlevel = 0;
	int32_t wifi_ret = -1;
    	char wifipwd[32] = {0};
	struct wirelessInfo info;
	char *str_24G_fre = "24G";
	char *str_5G_fre = "5G";
	char *str_hot = "HOSTAP";
	
	memset(&info,0,sizeof(struct wirelessInfo));
	WiFi_getwirelessstatus(str_24G_fre, str_hot, &info);
	
	if(info.password && *info.password)
		strcpy(wifipwd,info.password);
	if(wifi_ret != 0)
	{
		header->i_code = ERROR_GET_ROOT_PWD;
	}
	
	if (wifipwd && *wifipwd) 
	{
		wifi_24G_pwdlevel = calculate_pwd_strenglth(wifipwd);
	}
	else
	{
		wifi_24G_pwdlevel = ZERO_PASSWORD_POINT;
	}

	memset(&info,0,sizeof(struct wirelessInfo));

	WiFi_getwirelessstatus(str_5G_fre,str_hot,&info);
	if(info.password && *info.password)
		strcpy(wifipwd,info.password);
	if(wifi_ret != 0)
	{
		header->i_code = ERROR_GET_ROOT_PWD;
	}
	
	if (wifipwd && *wifipwd) 
	{
		wifi_5G_pwdlevel = calculate_pwd_strenglth(wifipwd);
	}
	else
	{
		wifi_5G_pwdlevel = ZERO_PASSWORD_POINT;
	}
	
	if(wifi_24G_pwdlevel < wifi_5G_pwdlevel)
	{
		wifi_pwdlevel = wifi_24G_pwdlevel;
	}
	else
	{
		wifi_pwdlevel = wifi_5G_pwdlevel;
	}
	
	JSON_ADD_OBJECT(response_para_json, "wifi_pwdlevel", JSON_NEW_OBJECT(wifi_pwdlevel,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_admin_passwd_streagth(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request)
{
	JObj* header_json = NULL;
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
	
	if (wifipwd && *wifipwd) {
		wifi_pwdlevel = calculate_pwd_strenglth(wifipwd);
	}else{
		wifi_pwdlevel = ZERO_PASSWORD_POINT;
	}
	root_ret = IM_RootPwdGet(rootpwd);
	p_debug("rootpwd = %s",rootpwd);
	if(root_ret != 0)
	{
		header->i_code = ERROR_GET_ROOT_PWD;
	}
	
	if (rootpwd && *rootpwd) {
		admin_pwdlevel = calculate_pwd_strenglth(rootpwd);
	}else{
		header->i_code = ERROR_ADMIN_PWD_NULL;
	}

	if(!strcmp(wifipwd,rootpwd))
	{
		is_same = MSG_SERVER_TRUE;
	}
	JSON_ADD_OBJECT(response_para_json, "admin_pwdlevel", JSON_NEW_OBJECT(admin_pwdlevel,int));
	JSON_ADD_OBJECT(response_para_json, "wifi_pwdlevel", JSON_NEW_OBJECT(wifi_pwdlevel,int));
	JSON_ADD_OBJECT(response_para_json, "is_same", JSON_NEW_OBJECT(is_same,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/**************************** 0x05-- get upload speed cmd function ***********************************************/
int set_upload_flow_speed(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *max_uploadspeed_json = JSON_GET_OBJECT(para_json,"max_uploadspeed");//KB/S
	uint32_t max_uploadspeed = JSON_GET_OBJECT_VALUE(max_uploadspeed_json,int);
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/***************************** 0x02-- 0x03-- cmd function ***********************************/
int create_group(JObj * rpc_json, IM_ST_msg_header *header,IM_ST_request *request)
{
 //  JObj* header_json=JSON_NEW_EMPTY_OBJECT();
   JObj* header_json = NULL;
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *response_data_array = JSON_NEW_ARRAY();
   JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
   JObj *group_name_json = JSON_GET_OBJECT(para_json,"group_name");
   const char *group_name = JSON_GET_OBJECT_VALUE(group_name_json,string);
   
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
      header->i_code = ERROR_CREATE_GROUP;
   }else{
		header->i_code = GROUP_SUCCESS;
   }
   
   JSON_ADD_OBJECT(response_para_json, "group_id", JSON_NEW_OBJECT(group_id,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif   
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
//   strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

   JSON_PUT_OBJECT(header_json);
   JSON_PUT_OBJECT(response_data_array);
   JSON_PUT_OBJECT(response_json);
   return 0;
}

int get_group_list(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request)
{
    	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj *header_json = NULL;
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
			fprintf(stderr, "szName:len:%d \t %s\n", strlen(group_brief->stGrpCot[i].szName), group_brief->stGrpCot[i].szName);
			strcpy(group_name,group_brief->stGrpCot[i].szName);
			JSON_ADD_OBJECT(group_info[i], "group_name", JSON_NEW_OBJECT(group_name,string));
		    JSON_ADD_OBJECT(group_info[i], "group_id", JSON_NEW_OBJECT(group_id,int));
			p_debug("DM %d:group_id =%d,group_name =%s", i,group_id,group_name);
			JSON_ARRAY_ADD_OBJECT(response_data_array,group_info[i]);
	    }
	    free(group_brief);
		header->i_code = GROUP_SUCCESS;
	}else{
 		header->i_code = ERROR_GET_GROUP_LIST;
	}
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		fprintf(stderr, "imove_create_json_msg_header return NULL\n");
	}
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
   	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_group_settings_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//    JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
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
		header->i_code = GROUP_SUCCESS;
	}else{
	    header->i_code = ERROR_GET_GROUP_SETTINGS_INFO;
	}
    JSON_ADD_OBJECT(response_para_json, "internet_access", JSON_NEW_OBJECT(internet_access_flag,boolean));
    JSON_ADD_OBJECT(response_para_json, "router_ctrl", JSON_NEW_OBJECT(router_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_access", JSON_NEW_OBJECT(routedisc_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_ctrl", JSON_NEW_OBJECT(routedisc_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_access", JSON_NEW_OBJECT(pridisk_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_ctrl", JSON_NEW_OBJECT(pridisk_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "number", JSON_NEW_OBJECT(number,int));

	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	header_json = imove_create_json_msg_header(header);
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif   
   JSON_ADD_OBJECT(response_json, "header", header_json);
   JSON_ADD_OBJECT(response_json, "data", response_data_array);
//   strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

   JSON_PUT_OBJECT(header_json);
   JSON_PUT_OBJECT(response_data_array);
   JSON_PUT_OBJECT(response_json);
	return 0;
}

int delete_group(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);

	int32_t group_ret = -1;
	group_ret = IM_DelGrp(group_id);//203
	if(group_ret != 0)
	{
		header->i_code = ERROR_DELETE_GROUP;
	}else{
		header->i_code = GROUP_SUCCESS;
	}
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int amend_group(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//   JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
   JObj *group_name_json = JSON_GET_OBJECT(para_json,"group_name");
   const char *group_name = JSON_GET_OBJECT_VALUE(group_name_json,string);

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
		header->i_code = ERROR_AMEND_GROUP;
	}else{
		header->i_code = GROUP_SUCCESS;
	}
	
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
   JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
   JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif   
	header_json = imove_create_json_msg_header(header);
   JSON_ADD_OBJECT(response_json, "header", header_json);
//   strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

   JSON_PUT_OBJECT(header_json);
   JSON_PUT_OBJECT(response_json);
	return 0;
}

int add_group_dev(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	uint32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);

	JObj *dev_name_json = JSON_GET_OBJECT(para_json,"dev_name");
	const char * dev_name = JSON_GET_OBJECT_VALUE(dev_name_json,string);

	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	const char * mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	int32_t group_ret = -1;
	group_ret = IM_DelObjFromGrp(mac);//205
	if(group_ret != 0)
	{
		header->i_code = ERROR_DELETE_GROUP_DEV;
	}else{
		header->i_code = GROUP_SUCCESS;
	}
    p_debug("DM group_id = %d,dev_name = %s,pMacStr = %s",group_id,dev_name,mac);
    group_ret = IM_AddObj2Grp(group_id,dev_name,mac);//205
    if(group_ret != 0)
	{
		header->i_code = ERROR_ADD_GROUP_DEV;
	}else{
		header->i_code = GROUP_SUCCESS;
	}

	/* usr type black,it's cannot access internel */
	if(group_id == USR_TYPE_BLACK)
	{
		IM_ApplyInternetAcc(mac,DISENABLE);
	}
	

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
 	return 0;
}

int delete_group_dev(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	const char * mac = JSON_GET_OBJECT_VALUE(mac_json,string);
    int32_t group_ret = -1;
	p_debug("pMacStr = %s",mac);
    group_ret = IM_DelObjFromGrp(mac);//205
    if(group_ret != 0)
	{
		header->i_code = ERROR_DELETE_GROUP_DEV;
	}else{
		header->i_code = GROUP_SUCCESS;
	}
#if 	0
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
 	return 0;
}

int get_group_dev_list(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	int32_t group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);
	uint32_t i =0;
	char ip_list[IP_LIST_LEN] = {0};
	char mac[MAC_LEN] = {0};//mac地址
	uint32_t dev_contime_size = 0;
	JObj *ip_info[MAX_GROUP_USR_COUNT];
	stGrpDetailInfo *mStGrpDetailInfo = NULL;
	stGroupBrief * group_brief = NULL;
	dev_info mDevInfo;
	uint8_t paserList_ret = 0;
	int is_online = MSG_SERVER_FALSE;
	devbackupinfo mdevbackupinfo;
	stObjSample *mstobjSample = NULL;
	int dev_ret = -1;
	get_dev_info(ip_list,IP_LIST_LEN);
    p_debug("ip_list = %s,groupid = %d\n",ip_list,group_id);
	if(group_id >= 0 )
	{
		mStGrpDetailInfo = IM_GetObjsInfoInGroup(group_id);//207
		if(mStGrpDetailInfo != NULL)
		{
			for(i = 0;i < mStGrpDetailInfo->nObjCnt;i++)
			{
				if(check_valid_mac(mStGrpDetailInfo->stObjInfo[i].szMacStr) >= 0&&mStGrpDetailInfo->stObjInfo[i].szName !=NULL)
				{
					memset(mac,0,MAC_LEN);
					p_debug("mStGrpDetailInfo->stObjInfo[i].szMacStr = %s\n", mStGrpDetailInfo->stObjInfo[i].szMacStr);
					strcpy(mac,mStGrpDetailInfo->stObjInfo[i].szMacStr);
					memset(&mDevInfo,0,sizeof(dev_info));
					memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
					ip_info[i] = JSON_NEW_EMPTY_OBJECT();
					if(ip_list != NULL&&*ip_list)
					{
						paserList_ret = paserList2DevInfo(ip_list,mac,&mDevInfo);
					}
					dev_ret = getDevBackUpInfo(mac,&mdevbackupinfo);
					if(dev_ret >= 0)
					{
						JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mac,string));
						JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mStGrpDetailInfo->stObjInfo[i].szName,string));	
						JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
						JSON_ADD_OBJECT(ip_info[i], "upload_speed", JSON_NEW_OBJECT(mDevInfo.upload_speed,int));
						JSON_ADD_OBJECT(ip_info[i], "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
						JSON_ADD_OBJECT(ip_info[i], "is_online", JSON_NEW_OBJECT(mdevbackupinfo.is_online,boolean));
						JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
					}else{
						header->i_code = ERROR_GET_DEV_INFO;
					}
				}else{
					p_debug("ERROR_MAC_PARA_INVALIDE");//header->code = ERROR_PARA_INVALIDE;
				}
			}
			free(mStGrpDetailInfo);
		}
		else{
			header->i_code = ERROR_GET_GROUP_DEV_LIST;
		}
	}
	else if(group_id == -1)
	{
		p_debug("group_id1 = %d",group_id);
		mstobjSample = IM_GetObjSample();
		if(mstobjSample != NULL)
		{
			for(i = 0; i < mstobjSample->nCount; i++)
			{
				p_debug("i:%d szmacstr:%s szname:%s\n", i, mstobjSample->stObjCot[i].szMacStr, mstobjSample->stObjCot[i].szName);
				  if(check_valid_mac(mstobjSample->stObjCot[i].szMacStr) >= 0 && mstobjSample->stObjCot[i].szName != NULL)
				  {
					memset(mac,0,MAC_LEN);
					strcpy(mac,mstobjSample->stObjCot[i].szMacStr);
					ip_info[i] = JSON_NEW_EMPTY_OBJECT();
					memset(&mDevInfo,0,sizeof(dev_info));
					if(ip_list != NULL&&*ip_list)
					{
						paserList_ret = paserList2DevInfo(ip_list,mac,&mDevInfo);
					}
					memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
					dev_ret = getDevBackUpInfo(mac,&mdevbackupinfo);
					if(dev_ret >= 0)
					{
						JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mac,string));
						JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string)); 
						JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
						JSON_ADD_OBJECT(ip_info[i], "upload_speed", JSON_NEW_OBJECT(mDevInfo.upload_speed,int));
						JSON_ADD_OBJECT(ip_info[i], "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
						JSON_ADD_OBJECT(ip_info[i], "is_online", JSON_NEW_OBJECT(mdevbackupinfo.is_online,boolean));
						JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
					}else{
						header->i_code = ERROR_GET_DEV_INFO;
					}
				  }else{
					p_debug("ERROR_MAC_PARA_INVALIDE\n");//header->code = ERROR_PARA_INVALIDE;
				  }
			}
			free(mstobjSample);
		}
	}
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		fprintf(stderr, "imove_create_json_msg_header return NULL\n");
	}
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int query_dev_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	const char *mac_str = JSON_GET_OBJECT_VALUE(mac_json,string);
   char group_name[DEV_FILE_NAME_TOTAL] = {0};
   char mac[MAC_LEN] = {0};//mac地址
   char ipaddr[IPADDR_STR_LEN] = {0};//ip地址
   char dev_name[DEV_FILE_NAME_TOTAL] = {0};
   char ip_list[IP_LIST_LEN] = {0};
   stObjBrief *mStObjBrief = NULL;
   uint8_t paserList_ret = 0;
   uint32_t dev_contime_size = 0;
   int dev_ret = -1;
   int max_uploadspeed = -1;
   int max_downloadspeed = -1;
   dev_info mDevInfo;
   int is_online = 0;
   devbackupinfo mdevbackupinfo;
   if(check_valid_mac(mac_str) >= 0)
   {
		strcpy(mac,mac_str);
		memset(&mDevInfo,0,sizeof(dev_info));
		mStObjBrief = IM_GetObjBrief(mac);
		if(mStObjBrief != NULL)
		{
			strcpy(group_name,mStObjBrief->szGrpName);
			strcpy(dev_name,mStObjBrief->szName);
			p_debug("group_name = %s,dev_name = %s,mac = %s",group_name,dev_name,mac);
			get_dev_info(ip_list,IP_LIST_LEN);
			if(ip_list&&*ip_list)
			{	
				paserList_ret = paserList2DevInfo(ip_list,mac,&mDevInfo);
			}
			memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
			dev_ret = getDevBackUpInfo(mac,&mdevbackupinfo);
			if(dev_ret < 0)
			{
				header->i_code = ERROR_GET_DEV_INFO;
			}
			free(mStObjBrief);
		}else{
			header->i_code = ERROR_GET_DEV_INFO;
		}
   }else{
		header->i_code = ERROR_PARA_INVALIDE;		
   }
   
	JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(mac_str,string));
	JSON_ADD_OBJECT(response_para_json, "group_name", JSON_NEW_OBJECT(group_name,string));
	JSON_ADD_OBJECT(response_para_json, "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type, int));
	JSON_ADD_OBJECT(response_para_json, "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime, int));
	JSON_ADD_OBJECT(response_para_json, "dev_name", JSON_NEW_OBJECT(dev_name,string));
	JSON_ADD_OBJECT(response_para_json, "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
	JSON_ADD_OBJECT(response_para_json, "download_speed", JSON_NEW_OBJECT(mDevInfo.download_speed,int));
	JSON_ADD_OBJECT(response_para_json, "is_online", JSON_NEW_OBJECT(mdevbackupinfo.is_online,boolean));
	JSON_ADD_OBJECT(response_para_json, "max_uploadspeed", JSON_NEW_OBJECT(mdevbackupinfo.MaxUpSpeed,int));
	JSON_ADD_OBJECT(response_para_json, "max_downloadspeed", JSON_NEW_OBJECT(mdevbackupinfo.MaxDownSpeed,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);

	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _Route_switch_status(JObj * rpc_json,IM_ST_msg_header *header, IM_ST_request *request)
{
    JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=NULL;
	uint8_t sleep_status = 0;
	uint8_t hiber_ret = 0;
	//hiber_ret = Route_get_hibernation_status();
#if 0	
	if(threadStatus->sleep_flag == 0)
	{
		sleep_status = 0;
		p_debug("_Route_switch_status sleep_flag = %d",threadStatus->sleep_flag);
	}else{
		sleep_status = 1;
		p_debug("_Route_switch_status sleep_flag = %d",threadStatus->sleep_flag);
	}
#endif
	JSON_ADD_OBJECT(response_para_json, "sleep_status", JSON_NEW_OBJECT(sleep_status,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	header_json = imove_create_json_msg_header(header);

	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
  return 0;
}

int _WiFi_setwireless(JObj * rpc_json,IM_ST_msg_header *header, IM_ST_request *request)
{
 //   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
 	 JObj* response_json = JSON_NEW_EMPTY_OBJECT();
	JObj* header_json= NULL;
	
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
	const char *str_24G_ssid = JSON_GET_OBJECT_VALUE(ssid_24G_json,string);
	uint8_t encrypt_24G_flag = JSON_GET_OBJECT_VALUE(encrypt_24G_json,boolean);
	const char *password_24G = JSON_GET_OBJECT_VALUE(password_24G_json,string);
    uint8_t hide_24G_flag = JSON_GET_OBJECT_VALUE(hide_24G_json,boolean);
	uint8_t online_24G_flag = JSON_GET_OBJECT_VALUE(online_24G_json,boolean);
	
	JObj *fre_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_type");
	JObj *ssid_5G_json = JSON_GET_OBJECT(para_5G_json,"ssid");
	JObj *encrypt_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_isencrypt");
	JObj *password_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_password");
	JObj *hide_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_ishide");
	JObj *online_5G_json = JSON_GET_OBJECT(para_5G_json,"wifi_isonline");
	
	uint8_t fre_5G_flag = JSON_GET_OBJECT_VALUE(fre_5G_json,int);
	const char *str_5G_ssid = JSON_GET_OBJECT_VALUE(ssid_5G_json,string);
	uint8_t encrypt_5G_flag = JSON_GET_OBJECT_VALUE(encrypt_5G_json,boolean);
	const char *password_5G = JSON_GET_OBJECT_VALUE(password_5G_json,string);
	uint8_t hide_5G_flag = JSON_GET_OBJECT_VALUE(hide_5G_json,boolean);
	uint8_t online_5G_flag = JSON_GET_OBJECT_VALUE(online_5G_json,boolean);

	header->i_code = 0;
	char encrypt[32] = {0};
	char *str_hot = "HOSTAP";
	char *str_24G_fre = "24G";
	char *str_5G_fre = "5G";
	char *str_on = "on";
	char *str_off = "off";
	int statue = -1;

	p_debug("fre_flag_24G = %d\n,str_ssid = %s\n,encrypt_flag = %d\n,password = %s,online_24G_flag = %d",\
		fre_24G_flag,str_24G_ssid,encrypt_24G_flag,password_24G,online_24G_flag);
	p_debug("fre_flag_5G = %d\n,str_ssid = %s\n,encrypt_flag = %d\n,password = %s,online_5G_flag = %d",\
		fre_5G_flag,str_5G_ssid,encrypt_5G_flag,password_5G,online_5G_flag);
	
	if(encrypt_24G_flag == 0)
	{
       strcpy(encrypt,"none");
	}else if(encrypt_24G_flag == 1){
       strcpy(encrypt,"psk2+ccmp");
	}
	if(hide_24G_flag == 0)
	{
       WiFi_hidewireless(str_24G_fre,str_hot,str_on);
	}else if(hide_24G_flag == 1)
	{
       WiFi_hidewireless(str_24G_fre,str_hot,str_off);
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
       WiFi_hidewireless(str_5G_fre,str_hot,str_on);
	}else if(hide_5G_flag == 1)
	{
       WiFi_hidewireless(str_5G_fre,str_hot,str_off);
	}
	if(online_5G_flag == 0)
	{
	   
       wifi_switch_hot(str_5G_fre,str_hot,str_off);
	}else if(online_5G_flag == 1)
	{
       wifi_switch_hot(str_5G_fre,str_hot,str_on);
	}
	WiFi_setwireless(str_5G_fre,str_hot,str_5G_ssid,encrypt,password_5G);
	
	/* 获取路由初始化状态 */
	get_wizard_init_status(&statue);	
	if(statue != WIZARD_OK)
	{
		set_wizard_init_status(WIZARD_OK);
	}

	restart_wifi();
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*20B*/
int _WiFi_getwirelessstatus(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
 //   JObj* response_json=JSON_NEW_EMPTY_OBJECT();
 	JObj* response_json = JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json= NULL;
    
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
	header->i_code = 0;
	WiFi_getwirelessstatus(str_fre,str_hot,&info[0]);
	info[0].wifi_type = 1;
	fprintf(stderr, "2.4G info[0].name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d\n",info[0].name,info[0].wifi_type,info[0].encrypt,info[0].wifi_hide,\
		info[0].wifi_switch);
//	strcpy(wifi_name,info[0].name);
	snprintf(wifi_name ,sizeof(wifi_name), "%s", info[0].name);
	if(info[0].wifi_switch == 0)
	{
	   info[0].wifi_switch = 1;
	}else
	{
       info[0].wifi_switch = 0;
	}
	if (wifi_info[0] == NULL)
	{
		fprintf(stderr, "wifi_info[0] is NULL\n");
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
	fprintf(stderr, "5G info[1].name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d\n",info[1].name,info[1].wifi_type,info[1].encrypt,info[1].wifi_hide,info[1].wifi_switch);
	if(info[1].wifi_switch == 0)
	{
	   info[1].wifi_switch = 1;
	}else
	{
       info[1].wifi_switch = 0;
	}
	/*if(info[1].wifi_hide == 0)
	{
	   info[1].wifi_hide = 1;
	}else
	{
       info[1].wifi_hide = 0;
	}*/
	memset(wifi_name,0,64);
	strcpy(wifi_name,info[1].name);
	JSON_ADD_OBJECT(wifi_info[1], "wifi_type",JSON_NEW_OBJECT(info[1].wifi_type,int));
	JSON_ADD_OBJECT(wifi_info[1], "ssid",JSON_NEW_OBJECT(wifi_name,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_isencrypt",JSON_NEW_OBJECT(info[1].encrypt,boolean));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_password", JSON_NEW_OBJECT(info[1].password,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_ishide", JSON_NEW_OBJECT(info[1].wifi_hide,boolean));
    JSON_ADD_OBJECT(wifi_info[1], "wifi_isonline", JSON_NEW_OBJECT(info[1].wifi_switch,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,wifi_info[1]);
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	fprintf(stderr, "is goting to create response json object\n");
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		fprintf(stderr, "imove_create_json_msg_header return NULL\n");
	}
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	fprintf(stderr, "success create response msg \n");
//	JSON_PUT_OBJECT(header_json);
//	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
    return 0;
}

int imove_set_vwan_mode_dhcp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
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
		header->i_code = ERROR_SET_VWAN_MODE_DHCP;
	}
	restart_network();
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	header_json = imove_create_json_msg_header(header);
   JSON_ADD_OBJECT(response_json, "header", header_json);
//   strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

    JSON_PUT_OBJECT(header_json);
   JSON_PUT_OBJECT(response_json);
   return 0;
}

/**************
获取路由器的状态
params:
	rpc_json: [IN] json object of receive msg
	header:	[IN] msg header
	request:  [IN|OUT] reqeust structer
return:
	0:	success
	-1:	failed
**************/
int dm_get_router_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	router_info_t dm_router_info;
	int get_router_ret = -1;

	memset(&dm_router_info,0,sizeof(router_info_t));
	get_router_ret = getrouterinfo(&dm_router_info);
	
	if(get_router_ret >= 0)
	{
		JSON_ADD_OBJECT(response_para_json, "router_name", JSON_NEW_OBJECT(dm_router_info.name,string));
		JSON_ADD_OBJECT(response_para_json, "dev_runtime", JSON_NEW_OBJECT(dm_router_info.runtime,int));
		JSON_ADD_OBJECT(response_para_json, "dev_num", JSON_NEW_OBJECT(dm_router_info.devnum,int));
		JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(dm_router_info.mac,string));
		JSON_ADD_OBJECT(response_para_json, "router_ver", JSON_NEW_OBJECT(dm_router_info.ver,string));
		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	}else{
		header->i_code = ERROR_GET_ROUTER_STATUS;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_router_network_status(router_network_info_t *dm_router_network_info)
{
	char router_network_list[SPEED_LIST_LEN] = {0};
	int ret_speed = -1;
	char *start = NULL;
	char *end = NULL;
	char *total_down[32] = {0};
	char total_down_speed[32] = {0};
	char total_up[32] = {0};
	char total_count[32] = {0};
	char total_up_speed[32] = {0};
	ret_speed = get_speed_info(router_network_list,SPEED_LIST_LEN);
	if(ret_speed < 0)
	{
		return -1;
	}
	if(router_network_list!=NULL&&*router_network_list)
	{
		start = router_network_list;
		 end = strstr(start,",");
		  memcpy(total_down,start,end-start);
		  dm_router_network_info->total_downloadsize = (unsigned int)atoi(total_down);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_up,start,end-start);
		 dm_router_network_info->total_uploadsize = atoi(total_up);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_count,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_down_speed,start,end-start);//total_downloadsize
		 end ++;
		 start = end;
		 end = strstr(end,"}");
		 memcpy(total_up_speed,start,end-start);//上传速度
		 dm_router_network_info->cur_downloadspeed = atoi(total_down_speed);
	}else
	{
		return -1;
	}
	return 0;
}

/***********
获取路由器网络状态
params:
	rpc_json: [IN] json object of receive msg
	header:	[IN] msg header
	request:  [IN|OUT] reqeust structer
return:
	0:	success
	-1:	failed
***********/
int dm_get_router_network_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int get_router_network_ret = -1;
	int flow_ret = -1;
	router_network_info_t dm_router_network_info;
	total_rate_t total_flow;

	memset(&dm_router_network_info,0,sizeof(router_network_info_t));
	get_router_network_ret = get_router_network_status(&dm_router_network_info);
	
	memset(&total_flow,0,sizeof(total_rate_t));
	flow_ret = get_total_flow_fro_back(&total_flow);
	
	if(get_router_network_ret >= 0&&flow_ret >= 0)
	{
		JSON_ADD_OBJECT(response_para_json, "cur_downloadspeed", JSON_NEW_OBJECT(dm_router_network_info.cur_downloadspeed,int));
		JSON_ADD_OBJECT(response_para_json, "avg_downloadspeed", JSON_NEW_OBJECT(dm_router_network_info.avg_downloadspeed,int));
		JSON_ADD_OBJECT(response_para_json, "max_downloadspeed", JSON_NEW_OBJECT(dm_router_network_info.max_downloadspeed,int));
		JSON_ADD_OBJECT(response_para_json, "total_downloadsize", JSON_NEW_OBJECT(total_flow.total_down,int));
		JSON_ADD_OBJECT(response_para_json, "total_uploadsize", JSON_NEW_OBJECT(total_flow.total_up,int));
		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	}else{
		header->i_code = ERROR_GET_ROUTER_NETWORK_STATUS;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_total_flow_fro_back(total_rate_t *total_flow)
{
	JObj* dev_info_json = NULL;
	JObj* total_down_json = NULL;
	JObj* total_up_json = NULL;
	dev_info_json = json_object_from_file(FLOW_TOTAL_DOWN);
	if(dev_info_json != NULL)
	{
		total_down_json = JSON_GET_OBJECT(dev_info_json,"total_down");
		total_flow->total_down= JSON_GET_OBJECT_VALUE(total_down_json,int);
		total_up_json = JSON_GET_OBJECT(dev_info_json,"total_up");
		total_flow->total_up= JSON_GET_OBJECT_VALUE(total_up_json,int);
		p_debug("total_down = %d,total_up = %d\n",total_flow->total_down,total_flow->total_up);
	}
	else{
		return -1;
	}
	return 0;
}

/*************
获取路由器连接终端的流量统计
params:
	rpc_json: [IN] json object of receive msg
	header:	[IN] msg header
	request:  [IN|OUT] reqeust structer
return:
	0:	success
	-1:	failed
**************/
int dm_get_router_connect_dev_rate_statistics(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_para_array=JSON_NEW_ARRAY();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *page_no_json = JSON_GET_OBJECT(para_json,"page_no");
	uint8_t page_no = JSON_GET_OBJECT_VALUE(page_no_json,int);
	JObj *page_num_json = JSON_GET_OBJECT(para_json,"page_num");
	uint8_t page_num = JSON_GET_OBJECT_VALUE(page_num_json,int);
	dev_info mDevInfo;
	int i =0;
	int paserList_ret = -1;
	char dev_name[DEV_FILE_NAME_TOTAL] = {0};
	char ip_list[IP_LIST_LEN] = {0};
	int file_start = 0;
	int file_end = 0;
	int page_total = 0;
	int cur_num = 0;
	stObjSample *mstobjSample = NULL;
	devbackupinfo mdevbackupinfo;
	int dev_ret = -1;
	p_debug("page_no = %d,page_num = %d\n",page_no,page_num);

	if(page_no >0&&page_num>0)
	{
		file_start = (page_no-1)*(page_num);
		
		mstobjSample = IM_GetObjSample();
		if(mstobjSample != NULL)
		{
			p_debug("mstobjSample->nCount = %d\n",mstobjSample->nCount);
			if(mstobjSample->nCount%page_num == 0 )
			{
		       	page_total = mstobjSample->nCount/page_num;
			}
			else
			{
		      	 	page_total = mstobjSample->nCount/page_num + 1;
			}
			
			if(page_no <= page_total)
			{
		       	if(page_no == page_total)
				{
			       	file_end = mstobjSample->nCount;
				}
				else
				{
			       	file_end = file_start + page_num;	// 这里的page_num应该是表示为每一页有多少条目
				}
			}

			if (file_end <= file_start)
			{
				p_debug("file_end:%d file_start:%d\n", file_end, file_start);
				goto par_err;
			}
			cur_num = file_end - file_start;
			
			JObj *ip_info[cur_num];
			
			p_debug("file_start = %d\n",file_start);
			p_debug("file_end = %d\n",file_end);
			
			for(i = file_start;i < file_end;i++)
			{
				if(check_valid_mac(mstobjSample->stObjCot[i].szMacStr) >= 0&&mstobjSample->stObjCot[i].szName != NULL)
				{
					p_debug("mstobjSample->stObjCot[%d].szMacStr = %s\n", i,mstobjSample->stObjCot[i].szMacStr);
					ip_info[i] = JSON_NEW_EMPTY_OBJECT();
					memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
					dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
					if(dev_ret >= 0)
					{
						JSON_ADD_OBJECT(ip_info[i-file_start], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string));	
						JSON_ADD_OBJECT(ip_info[i-file_start], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
						JSON_ARRAY_ADD_OBJECT(response_para_array,ip_info[i-file_start]);
					}
				}
				else
				{
					p_debug("ERROR_MAC_PARA_INVALIDE\n");
				}
			}
			
			free(mstobjSample);
		}
	}
	else
	{	
		header->i_code = ERROR_CODE_PARA_INVALID;
	}
	
	int flow_ret = -1;
	uint32_t total_downloadsize = 0; 
	total_rate_t total_flow;
	memset(&total_flow,0,sizeof(total_rate_t));
	flow_ret = get_total_flow_fro_back(&total_flow);

	if(flow_ret >= 0)
	{
		total_downloadsize = total_flow.total_down;
	}
	
	p_debug("total_downloadsize = %d\n",total_downloadsize);

	if (response_para_json == NULL)
	{
		p_debug("response_para_json is NULL\n");
		return -1;
	}

par_err:		
	JSON_ADD_OBJECT(response_para_json, "total_downloadsize", JSON_NEW_OBJECT(total_downloadsize,int));
	JSON_ADD_OBJECT(response_para_json, "page_total", JSON_NEW_OBJECT(page_total,int));
	JSON_ADD_OBJECT(response_para_json, "dev_flowlist", response_para_array);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}

	p_debug("is to construct response msg\n");
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/***********
获取设备连接信息
params:
	rpc_json: [IN] json object of receive msg
	header:	[IN] msg header
	request:  [IN|OUT] reqeust structer
return:
	0:	success
	-1:	failed
**********/
int dm_get_dev_con_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *namelist_type_json = JSON_GET_OBJECT(para_json,"namelist_type");
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	uint32_t i =0;
	stGrpDetailInfo *mStGrpDetailInfo = NULL;
	stGroupBrief * group_brief = NULL;
	int is_online = MSG_SERVER_FALSE;
	devbackupinfo mdevbackupinfo;
	stObjSample *mstobjSample = NULL;
	stObjBrief *mStObjBrief = NULL;
	int dev_ret = -1;
	JObj *ip_info[MAX_GROUP_USR_COUNT];
	
	if(group_id_json != NULL)
	{
		int group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);
		if(group_id >= 0 )
		{
			mStGrpDetailInfo = IM_GetObjsInfoInGroup(group_id);//207
			if(mStGrpDetailInfo != NULL)
			{
				p_debug("mStGrpDetailInfo->nObjCnt = %d",mStGrpDetailInfo->nObjCnt);
				for(i = 0;i < mStGrpDetailInfo->nObjCnt;i++)
				{
					if(check_valid_mac(mStGrpDetailInfo->stObjInfo[i].szMacStr) >= 0&&mStGrpDetailInfo->stObjInfo[i].szName != NULL)
					{
						mStObjBrief = IM_GetObjBrief(mStGrpDetailInfo->stObjInfo[i].szMacStr);
						memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
						dev_ret = getDevBackUpInfo(mStGrpDetailInfo->stObjInfo[i].szMacStr,&mdevbackupinfo);
						if(dev_ret >= 0&&mStObjBrief != NULL)
						{
							ip_info[i] = JSON_NEW_EMPTY_OBJECT();
							JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mStGrpDetailInfo->stObjInfo[i].szName,string));
							JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string)); 
							JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mStGrpDetailInfo->stObjInfo[i].szMacStr,string));
							JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
							JSON_ADD_OBJECT(ip_info[i], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
							JSON_ADD_OBJECT(ip_info[i], "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type,int));
							JSON_ADD_OBJECT(ip_info[i], "group_name", JSON_NEW_OBJECT(mStObjBrief->szGrpName,string));
							JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
							free(mStObjBrief);
						}
					}else{
						p_debug("ERROR_MAC_PARA_INVALIDE");//header->code = ERROR_PARA_INVALIDE;
					}
				}
				free(mStGrpDetailInfo);
			}
			else{
				header->i_code = ERROR_GET_GROUP_DEV_LIST;
			}
		}else if(group_id == -1)
		{
			mstobjSample = IM_GetObjSample();
			if(mstobjSample != NULL)
			{
				for(i = 0;i < mstobjSample->nCount;i++)
				{
					  if(check_valid_mac(mstobjSample->stObjCot[i].szMacStr) >= 0&&mstobjSample->stObjCot[i].szName != NULL)
					  {
					  	  p_debug("mstobjSample->stObjCot[%d].szMacStr = %s", i,mstobjSample->stObjCot[i].szMacStr);
							mStObjBrief = IM_GetObjBrief(mstobjSample->stObjCot[i].szMacStr);
							memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
							dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
							if(dev_ret >= 0&&mStObjBrief != NULL)
							{
								ip_info[i] = JSON_NEW_EMPTY_OBJECT();
								JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string));
								JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string)); 
								JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szMacStr,string));
								JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
								JSON_ADD_OBJECT(ip_info[i], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
								JSON_ADD_OBJECT(ip_info[i], "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type,int));
								JSON_ADD_OBJECT(ip_info[i], "group_name", JSON_NEW_OBJECT(mStObjBrief->szGrpName,string));
								JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
								free(mStObjBrief);
							}
					  }else{
						p_debug("ERROR_MAC_PARA_INVALIDE");//header->code = ERROR_PARA_INVALIDE;
					  }
				}
				free(mstobjSample);
			}
		}
	}
	else if(namelist_type_json != NULL)
		{ //获取设备类别 0全部 1白名单 2黑名单
		uint8_t namelist_type = JSON_GET_OBJECT_VALUE(namelist_type_json,int);
		char ip_mac_list[1024] = {0};
		get_dhcp_backlist(ip_mac_list);
		mstobjSample = IM_GetObjSample();
			if(mstobjSample != NULL)
			{
				for(i = 0;i < mstobjSample->nCount;i++)
				{
					  if(check_valid_mac(mstobjSample->stObjCot[i].szMacStr) >= 0&&mstobjSample->stObjCot[i].szName != NULL)
					  {
					  	  p_debug("mstobjSample->stObjCot[%d].szMacStr = %s", i,mstobjSample->stObjCot[i].szMacStr);
						    if(namelist_type == 0)
							{
								mStObjBrief = IM_GetObjBrief(mstobjSample->stObjCot[i].szMacStr);
								memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
								dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
								if(dev_ret >= 0&&mStObjBrief != NULL)
								{
									ip_info[i] = JSON_NEW_EMPTY_OBJECT();
									JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string));
									JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string)); 
									JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szMacStr,string));
									JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
									JSON_ADD_OBJECT(ip_info[i], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
									JSON_ADD_OBJECT(ip_info[i], "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type, int));
									JSON_ADD_OBJECT(ip_info[i], "group_name", JSON_NEW_OBJECT(mStObjBrief->szGrpName,string));
									JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
									free(mStObjBrief);
								}
							}else if(namelist_type == 1)
							{
								if(ip_mac_list != NULL)
								{
									if(!strstr(ip_mac_list,mstobjSample->stObjCot[i].szMacStr))
									{
										memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
										dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
										mStObjBrief = IM_GetObjBrief(mstobjSample->stObjCot[i].szMacStr);
										if(dev_ret >= 0&&mStObjBrief != NULL)
										{
											ip_info[i] = JSON_NEW_EMPTY_OBJECT();
											JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string));
											JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string)); 
											JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szMacStr,string));
											JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
											JSON_ADD_OBJECT(ip_info[i], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
											JSON_ADD_OBJECT(ip_info[i], "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type, int));
											JSON_ADD_OBJECT(ip_info[i], "group_name", JSON_NEW_OBJECT(mStObjBrief->szGrpName,string));
											JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
											free(mStObjBrief);
										}
									}
								}
							}else if(namelist_type == 2)
							{
								if(ip_mac_list != NULL&&*ip_mac_list)
								{
									if(strstr(ip_mac_list,mstobjSample->stObjCot[i].szMacStr))
									{
										memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
										dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
										mStObjBrief = IM_GetObjBrief(mstobjSample->stObjCot[i].szMacStr);
										if(dev_ret >= 0&&mStObjBrief != NULL)
										{
											ip_info[i] = JSON_NEW_EMPTY_OBJECT();
											JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string));
											JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string)); 
											JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szMacStr,string));
											JSON_ADD_OBJECT(ip_info[i], "dev_contime", JSON_NEW_OBJECT(mdevbackupinfo.contime,int));
											JSON_ADD_OBJECT(ip_info[i], "total_downloadsize", JSON_NEW_OBJECT(mdevbackupinfo.total_down,int));
											JSON_ADD_OBJECT(ip_info[i], "dev_contype", JSON_NEW_OBJECT(mdevbackupinfo.con_type, int));
											JSON_ADD_OBJECT(ip_info[i], "group_name", JSON_NEW_OBJECT(mStObjBrief->szGrpName,string));
											JSON_ARRAY_ADD_OBJECT(response_data_array,ip_info[i]);
											free(mStObjBrief);
										}
									}
								}
							}
					  }else{
						p_debug("ERROR_MAC_PARA_INVALIDE");//header->code = ERROR_PARA_INVALIDE;
					  }
				}
				free(mstobjSample);
			}
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*****
获取路由器MAC地址
params:
	rpc_json: [IN] json object of receive msg
	header:	[IN] msg header
	request:  [IN|OUT] reqeust structer
return:
	0:	success
	-1:	failed
*****/
int dm_get_router_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int get_router_mac_ret = -1;
	router_info_t dm_router_info;
	memset(&dm_router_info,0,sizeof(router_info_t));
	get_router_mac_ret = getrouterinfo(&dm_router_info);
	if(get_router_mac_ret >= 0)
	{
		JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(dm_router_info.mac,string));
		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	}else{
		header->i_code = ERROR_GET_ROUTER_MAC;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*****
克隆MAC地址
*****/
int dm_clone_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	char* mac = NULL;
	int clone_ret = 0;
	
	if(mac_json != NULL)
	{
		mac = JSON_GET_OBJECT_VALUE(mac_json,string);
		if(check_valid_mac(mac) >=0 )
		{
			clone_ret = set_ghost_mac(mac);
			if(clone_ret < 0)
			{
				header->i_code = ERROR_CLONE_MAC;
			}
		}else{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}


int get_dhcp_info(dhcp_info_t *dhcp_info)
{
	int ret = 0;
	char leasetime[32] = {0};
	char sip[32] = {0};
	char eip[32] = {0};
	char wan_mode[WAN_MODE_TYPE] = {0};
	get_wan_mode(wan_mode);
	p_debug("wan_mode = %s",wan_mode);
	
	if(!strcmp(wan_mode,"dhcp"))
	{
		if(is_dnsmasq_exist() >= 0)
       		dhcp_info->isdhcp = MSG_SERVER_TRUE;
	}
	
	ret = get_dhcp_leasetime(leasetime);
	if(ret >= 0)
	{
		dhcp_info->dhcptime = atoi(leasetime)/60;
	}
	else
	{
		return -1;
	}
	
	ret = get_dhcp_start_ip(sip);
	if(ret >= 0)
	{
		strcpy(dhcp_info->sip,sip);
	}else{
		return -1;
	}
	
	ret = get_dhcp_end_ip(eip);
	if(ret >= 0)
	{
		strcpy(dhcp_info->eip,eip);
	}else{
		return -1;
	}
	
	return 0;
}

/****
获取DHCP 的信息

****/
int dm_get_dhcp_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int dhcp_ret = -1;
	dhcp_info_t dm_dhcp_info;
	char mac[32] = {0};
	char ip[32] = {0};
	char netmask[32] = {0};
	char lan_ip[32] = {0};
	char *comma_l = NULL;
	char sip[32] = {0};
	char eip[32] = {0};
	
	memset(&dm_dhcp_info,0,sizeof(dhcp_info_t));
	dhcp_ret = get_dhcp_info(&dm_dhcp_info);
	if(dhcp_ret >= 0)
	{
		dhcp_ret = get_len_status(mac,ip,netmask);
		if(dhcp_ret >= 0)
		{
			comma_l = strrchr(ip,'.');
			memcpy(lan_ip,ip,comma_l-ip);
			p_debug("lan_ip = %s",lan_ip);
			sprintf(sip,"%s.%s",lan_ip,dm_dhcp_info.sip);
			sprintf(eip,"%s.%s",lan_ip,dm_dhcp_info.eip);
		}
		
		JSON_ADD_OBJECT(response_para_json, "isdhcp", JSON_NEW_OBJECT(dm_dhcp_info.isdhcp,boolean));
		JSON_ADD_OBJECT(response_para_json, "sip", JSON_NEW_OBJECT(dm_dhcp_info.sip,string));
		JSON_ADD_OBJECT(response_para_json, "eip", JSON_NEW_OBJECT(dm_dhcp_info.eip,string));
		JSON_ADD_OBJECT(response_para_json, "dhcptime", JSON_NEW_OBJECT(dm_dhcp_info.dhcptime,int));
		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	}
	else
	{
		header->i_code = ERROR_GET_DHCP_INFO;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	


int set_dhcp_info(dhcp_info_t *dhcp_info)
{
	int ret = -1;
	char leasetime[32] = {0};
	char *switch_on = "on";
	char *switch_off = "off";
	char wan_mode[WAN_MODE_TYPE] = {0};
	
	sprintf(leasetime,"%d",dhcp_info->dhcptime*60);
	ret = set_dhcp_leasetime(leasetime);
	if(ret < 0)
	{
		p_debug("leasetime = %s",leasetime);
		return -1;
	}
	ret = set_dhcp_start_ip(dhcp_info->sip);
	if(ret < 0)
	{
		return -1;
	}
	ret = set_dhcp_end_ip(dhcp_info->eip);
	if(ret < 0)
	{
		return -1;
	}
	system("uci commit dhcp");

	if(dhcp_info->isdhcp == MSG_SERVER_TRUE)
	{
		ret = switch_dhcp(switch_on);
		if(ret < 0)
		{
			return -1;
		}
	}else{
		ret = switch_dhcp(switch_off);
		if(ret < 0)
		{
			return -1;
		}
	}
	
	return 0;
}

/****
设置LAN侧的DHCP的相关信息
****/
int dm_set_dhcp_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *isdhcp_json = JSON_GET_OBJECT(para_json,"isdhcp");
	JObj *sip_json = JSON_GET_OBJECT(para_json,"sip");
	JObj *eip_json = JSON_GET_OBJECT(para_json,"eip");
	JObj *dhcptime_json = JSON_GET_OBJECT(para_json,"dhcptime");
	const char *sip = NULL;
	const char *eip = NULL;
	int dhcp_ret = -1;
	dhcp_info_t dm_dhcp_info;
	unsigned char sip_int = 0;
	unsigned char eip_int = 0;
	struct in_addr s_ip;
	struct in_addr e_ip;
	int ret = 0;
	char *p = NULL;
	
	memset(&dm_dhcp_info,0,sizeof(dhcp_info_t));
	
	if((isdhcp_json != NULL) && (sip_json != NULL) && (eip_json != NULL) && (dhcptime_json != NULL))
	{
		dm_dhcp_info.isdhcp = JSON_GET_OBJECT_VALUE(isdhcp_json,boolean);
		dm_dhcp_info.dhcptime = JSON_GET_OBJECT_VALUE(dhcptime_json,int);
		sip = JSON_GET_OBJECT_VALUE(sip_json,string);
		eip = JSON_GET_OBJECT_VALUE(eip_json,string);

		p_debug("dm_set_dhcp_info \n");
		if(sip && eip)
		{
			p_debug("dm_set_dhcp_info sip:%s eip:%s \n", sip, eip);
			ret = inet_pton(AF_INET, sip, &s_ip);
			if (!ret)
				goto err_param;
			sip_int = (unsigned char)(((char *)&s_ip)[3]);

			ret = inet_pton(AF_INET, eip, &e_ip);
			if (!ret)
				goto err_param;
			eip_int =  (unsigned char)(((char *)&e_ip)[3]);

			p_debug("sip_int:%d eip_int:%d\n", sip_int, eip_int);
			if(sip_int > 0 && sip_int < 254 && eip_int > 0 && eip_int <= 254 && eip_int > sip_int)
			{
				p = strrchr(eip, '.');
				snprintf(dm_dhcp_info.eip, 4, "%s", p + 1);	// 2,the first 3 bytes for 1~254 and the last byte is \0

				p = strrchr(sip, '.');
				snprintf(dm_dhcp_info.sip, 4, "%s", p + 1);
				
				p_debug("eip:%s sip:%s\n", dm_dhcp_info.eip, dm_dhcp_info.sip);
				dhcp_ret = set_dhcp_info(&dm_dhcp_info);
				if(dhcp_ret < 0)
				{
					header->i_code = ERROR_SET_DHCP_INFO;
				}
			}
			else
			{
				header->i_code = ERROR_PARA_INVALIDE;
			}
		}
		else
		{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	}
	else
	{
err_param:	
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

int dm_get_ip_binding_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int bind_ret = -1;
	uint8_t i = 0;
	ip_binding_group_t ip_binding_group;
	memset(&ip_binding_group,0,sizeof(ip_binding_group_t));
	p_debug("bind_ret1");
	
	bind_ret = get_dhcp_bind_t(&ip_binding_group);
	if(bind_ret >= 0)
	{
		JObj *ip_binding_info[MAX_GROUP_USR_COUNT];
		for(i = 0;i < ip_binding_group.count;i++)
		{
			ip_binding_info[i] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(ip_binding_info[i], "ip", JSON_NEW_OBJECT(ip_binding_group.ip_binding_info[i].ip,string)); 
			JSON_ADD_OBJECT(ip_binding_info[i], "mac", JSON_NEW_OBJECT(ip_binding_group.ip_binding_info[i].mac,string));
			JSON_ADD_OBJECT(ip_binding_info[i], "isvalid", JSON_NEW_OBJECT(ip_binding_group.ip_binding_info[i].isvalid,int));
			JSON_ARRAY_ADD_OBJECT(response_data_array,ip_binding_info[i]);
		}
	}else{
		header->i_code = ERROR_GET_IP_BINDING_INFO;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/***
绑定IP
***/
int dm_bind_ip(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	JObj *isvalid_json = JSON_GET_OBJECT(para_json,"isvalid");
	int bind_ret = -1;
	const char *ip = NULL;
	const char *mac = NULL;
	uint8_t isvalid = MSG_SERVER_FALSE;
	
	if(ip_json != NULL && mac_json != NULL && isvalid_json != NULL)
	{
		ip = JSON_GET_OBJECT_VALUE(ip_json,string);
		mac = JSON_GET_OBJECT_VALUE(mac_json,string);
		isvalid = JSON_GET_OBJECT_VALUE(isvalid_json,boolean);
	
		bind_ret = add_dhcp_ip_mac(ip,mac);
		if(bind_ret < 0)
		{
			header->i_code = ERROR_BIND_IP;
		}
		else
		{
			dhcp_restart();
		}
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*******
删除绑定的IP
******/
int dm_del_ip_bind(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	int bind_ret = -1;
	char *ip = NULL;
	const char *mac = NULL;
	
	if (mac_json != NULL)
	{
		mac = JSON_GET_OBJECT_VALUE(mac_json,string);
		if(check_valid_mac(mac) >= 0)
		{
			bind_ret = del_dhcp_ip_mac(mac);
			p_debug("bind_ret = %d",bind_ret);
			if(bind_ret < 0)
			{
				header->i_code = ERROR_DEL_BIND_IP;
			}
			else
			{
				dhcp_restart();
			}
		}
		else
		{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/************
获取无线相关参数
**********/
int dm_get_wifi_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	
	char *str_fre = NULL;
	char *str_hot = NULL;
	JObj* wifi_info[2];
    	wifi_info[0] = JSON_NEW_EMPTY_OBJECT();
	wifi_info[1] = JSON_NEW_EMPTY_OBJECT();
	struct wirelessInfo info;
	str_fre = "24G";
	str_hot = "HOSTAP";
	int wps_type = 0;
	memset(&info,0,sizeof(struct wirelessInfo));
	WiFi_getwirelessstatus(str_fre,str_hot,&info);
	info.wifi_type = 1;
	p_debug("2.4G info.name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d\n",info.name,info.wifi_type,info.encrypt,info.wifi_hide,info.wifi_switch);
	if(info.wifi_switch == 0)
	{
	   info.wifi_switch = 1;
	}else
	{
       info.wifi_switch = 0;
	}
	if(!strcmp(info.wps_type,WPS_TYPE_PIN)){
		wps_type = 1;
	}else if(!strcmp(info.wps_type,WPS_TYPE_PBC))
	{
		wps_type = 2;
	}
	JSON_ADD_OBJECT(wifi_info[0], "wifi_type",JSON_NEW_OBJECT(info.wifi_type,int));
	JSON_ADD_OBJECT(wifi_info[0], "ssid",JSON_NEW_OBJECT(info.name,string));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_isencrypt",JSON_NEW_OBJECT(info.encrypt,boolean));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_password", JSON_NEW_OBJECT(info.password,string));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_ishide", JSON_NEW_OBJECT(info.wifi_hide,boolean));
    JSON_ADD_OBJECT(wifi_info[0], "wifi_isonline", JSON_NEW_OBJECT(info.wifi_switch,boolean));
	
	JSON_ADD_OBJECT(wifi_info[0], "channel", JSON_NEW_OBJECT(info.channel,int));
	JSON_ADD_OBJECT(wifi_info[0], "wifi_sign", JSON_NEW_OBJECT(info.wifi_sign,int));
	JSON_ADD_OBJECT(wifi_info[0], "is_wps", JSON_NEW_OBJECT(info.is_wps,boolean));
	JSON_ADD_OBJECT(wifi_info[0], "wps_type", JSON_NEW_OBJECT(wps_type,int));
	JSON_ADD_OBJECT(wifi_info[0], "is_autochannel", JSON_NEW_OBJECT(info.is_autochannel,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,wifi_info[0]);
	str_fre = "5G";
	memset(&info,0,sizeof(struct wirelessInfo));
	WiFi_getwirelessstatus(str_fre,str_hot,&info);
	info.wifi_type = 2;
	p_debug("5G info.name = %s,info.wifi_type = %d,info.encrypt = %d,info.wifi_hide = %d,\
		info.wifi_switch = %d\n",info.name,info.wifi_type,info.encrypt,info.wifi_hide,info.wifi_switch);
	if(info.wifi_switch == 0)
	{
	   info.wifi_switch = 1;
	}else
	{
       info.wifi_switch = 0;
	}
	if(!strcmp(info.wps_type,WPS_TYPE_PIN)){
		wps_type = 1;
	}else if(!strcmp(info.wps_type,WPS_TYPE_PBC))
	{
		wps_type = 2;
	}
	JSON_ADD_OBJECT(wifi_info[1], "wifi_type",JSON_NEW_OBJECT(info.wifi_type,int));
	JSON_ADD_OBJECT(wifi_info[1], "ssid",JSON_NEW_OBJECT(info.name,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_isencrypt",JSON_NEW_OBJECT(info.encrypt,boolean));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_password", JSON_NEW_OBJECT(info.password,string));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_ishide", JSON_NEW_OBJECT(info.wifi_hide,boolean));
    JSON_ADD_OBJECT(wifi_info[1], "wifi_isonline", JSON_NEW_OBJECT(info.wifi_switch,boolean));

	JSON_ADD_OBJECT(wifi_info[1], "channel", JSON_NEW_OBJECT(info.channel,int));
	JSON_ADD_OBJECT(wifi_info[1], "wifi_sign", JSON_NEW_OBJECT(info.wifi_sign,int));
	JSON_ADD_OBJECT(wifi_info[1], "is_wps", JSON_NEW_OBJECT(info.is_wps,boolean));
	JSON_ADD_OBJECT(wifi_info[1], "wps_type", JSON_NEW_OBJECT(wps_type,int));
	JSON_ADD_OBJECT(wifi_info[1], "is_autochannel", JSON_NEW_OBJECT(info.is_autochannel,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,wifi_info[1]);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
    return 0;
}

/******
无线参数设置
*******/
int dm_set_wifi_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_first_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *para_second_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,1);
	struct wirelessInfo wifi_info;
	int wps_type =0;
	uint8_t wifi_type = 0;
	int statue = -1;
	
	if(para_first_json != NULL)
	{
		JObj *fre_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_type");
		JObj *wifi_ap_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_ap");
		JObj *online_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_isonline");
		JObj *ssid_fisrt_json = JSON_GET_OBJECT(para_first_json,"ssid");
		JObj *hide_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_ishide");
		JObj *encrypt_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_isencrypt");
		JObj *password_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_password");
		JObj *is_autochannel_fisrt_json = JSON_GET_OBJECT(para_first_json,"is_autochannel");
		JObj *channel_fisrt_json = JSON_GET_OBJECT(para_first_json,"channel");
		JObj *wifi_signal_fisrt_json = JSON_GET_OBJECT(para_first_json,"wifi_signal");
		JObj *is_wps_fisrt_json = JSON_GET_OBJECT(para_first_json,"is_wps");
		JObj *wps_type_fisrt_json = JSON_GET_OBJECT(para_first_json,"wps_type");
		
		if(fre_fisrt_json != NULL&&wifi_ap_fisrt_json != NULL&&online_fisrt_json != NULL
		&&ssid_fisrt_json != NULL&&hide_fisrt_json != NULL&&encrypt_fisrt_json != NULL
		&&password_fisrt_json != NULL&&is_autochannel_fisrt_json != NULL
		&&channel_fisrt_json != NULL&&wifi_signal_fisrt_json != NULL&&is_wps_fisrt_json != NULL
		&&wps_type_fisrt_json != NULL)
		{
			memset(&wifi_info,0,sizeof(struct wirelessInfo));
			wifi_type = JSON_GET_OBJECT_VALUE(fre_fisrt_json,int);
			if(wifi_type == 1)
			{
				wifi_info.wifi_type = 3;
			}else{
				wifi_info.wifi_type = 0;
			}
			wifi_info.wifi_ap = 1;
			wifi_info.wifi_switch = JSON_GET_OBJECT_VALUE(online_fisrt_json,boolean);
			wifi_info.wifi_hide = JSON_GET_OBJECT_VALUE(hide_fisrt_json,boolean);
			wifi_info.encrypt = JSON_GET_OBJECT_VALUE(encrypt_fisrt_json,boolean);
			strcpy(wifi_info.name,JSON_GET_OBJECT_VALUE(ssid_fisrt_json,string));
			strcpy(wifi_info.password,JSON_GET_OBJECT_VALUE(password_fisrt_json,string));
			wifi_info.is_autochannel = JSON_GET_OBJECT_VALUE(is_autochannel_fisrt_json,boolean);
			if(wifi_info.is_autochannel == 1)
			{
				wifi_info.channel = 6;
			}else{
				wifi_info.channel = JSON_GET_OBJECT_VALUE(password_fisrt_json,int);
			}
			wifi_info.channel = JSON_GET_OBJECT_VALUE(channel_fisrt_json,int);
			wifi_info.wifi_sign = JSON_GET_OBJECT_VALUE(wifi_signal_fisrt_json,int);;
			wifi_info.is_wps = JSON_GET_OBJECT_VALUE(is_wps_fisrt_json,boolean);
			wps_type = JSON_GET_OBJECT_VALUE(wps_type_fisrt_json,boolean);
			if(wps_type == 1)
			{
				strcpy(wifi_info.wps_type,WPS_TYPE_PIN);
			}else{
				strcpy(wifi_info.wps_type,WPS_TYPE_PBC);
			}
			p_debug("wifi_info.wifi_hide = %d",wifi_info.wifi_hide);
			p_debug("wifi_info.name = %s",wifi_info.name);
			set_wireless(&wifi_info);
		}
	}

	if(para_second_json != NULL)
	{
		memset(&wifi_info,0,sizeof(struct wirelessInfo));
		JObj *fre_second_json = JSON_GET_OBJECT(para_second_json,"wifi_type");
		JObj *wifi_ap_second_json = JSON_GET_OBJECT(para_second_json,"wifi_ap");
		JObj *online_second_json = JSON_GET_OBJECT(para_second_json,"wifi_isonline");
		JObj *ssid_second_json = JSON_GET_OBJECT(para_second_json,"ssid");
		JObj *hide_second_json = JSON_GET_OBJECT(para_second_json,"wifi_ishide");
		JObj *encrypt_second_json = JSON_GET_OBJECT(para_second_json,"wifi_isencrypt");
		JObj *password_second_json = JSON_GET_OBJECT(para_second_json,"wifi_password");
		JObj *is_autochannel_second_json = JSON_GET_OBJECT(para_second_json,"is_autochannel");
		JObj *channel_second_json = JSON_GET_OBJECT(para_second_json,"channel");
		JObj *wifi_signal_second_json = JSON_GET_OBJECT(para_second_json,"wifi_signal");
		JObj *is_wps_second_json = JSON_GET_OBJECT(para_second_json,"is_wps");
		JObj *wps_type_second_json = JSON_GET_OBJECT(para_second_json,"wps_type");
		if(fre_second_json != NULL&&wifi_ap_second_json != NULL&&online_second_json != NULL
		&&ssid_second_json != NULL&&hide_second_json != NULL&&encrypt_second_json != NULL
		&&password_second_json != NULL&&is_autochannel_second_json != NULL
		&&channel_second_json != NULL&&wifi_signal_second_json != NULL&&is_wps_second_json != NULL
		&&wps_type_second_json != NULL)
		{
			wifi_type = JSON_GET_OBJECT_VALUE(fre_second_json,int);
			if(wifi_type == 1)
			{
				wifi_info.wifi_type = 3;
			}else{
				wifi_info.wifi_type = 0;
			}
			wifi_info.wifi_ap = 1;
			wifi_info.wifi_switch = JSON_GET_OBJECT_VALUE(online_second_json,boolean);
			wifi_info.wifi_hide = JSON_GET_OBJECT_VALUE(hide_second_json,boolean);
			wifi_info.encrypt = JSON_GET_OBJECT_VALUE(encrypt_second_json,boolean);
			strcpy(wifi_info.name,JSON_GET_OBJECT_VALUE(ssid_second_json,string));
			strcpy(wifi_info.password,JSON_GET_OBJECT_VALUE(password_second_json,string));
			wifi_info.is_autochannel = JSON_GET_OBJECT_VALUE(is_autochannel_second_json,boolean);
			if(wifi_info.is_autochannel == 1)
			{
				wifi_info.channel = 40;
			}else{
				wifi_info.channel = JSON_GET_OBJECT_VALUE(channel_second_json,int);
			}
			wifi_info.wifi_sign = JSON_GET_OBJECT_VALUE(wifi_signal_second_json,int);;
			wifi_info.is_wps = JSON_GET_OBJECT_VALUE(is_wps_second_json,boolean);
			wps_type = JSON_GET_OBJECT_VALUE(wps_type_second_json,boolean);
			if(wps_type == 1)
			{
				strcpy(wifi_info.wps_type,WPS_TYPE_PIN);
			}else{
				strcpy(wifi_info.wps_type,WPS_TYPE_PBC);
			}
			set_wireless(&wifi_info);
		}
	}

	if(para_first_json != NULL||para_second_json != NULL)
	{
		/* 获取路由初始化状态 */
		get_wizard_init_status(&statue);	
		if(statue != WIZARD_OK)
		{
			set_wizard_init_status(WIZARD_OK);
		}
		restart_wifi();		
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/*************打开 black control  **********************/
int set_black_ctrl_open()
{
	int ctrl_ret = -1;
	stGrpDetailInfo *mStGrpDetailInfo = NULL;
	int i =0;
	p_debug("ctrl_ret0 = %d",ctrl_ret);
	ctrl_ret = set_cfg_wifictrl_status(1);
	p_debug("ctrl_ret1 = %d",ctrl_ret);
	if (ctrl_ret >= 0)
	{
		mStGrpDetailInfo = IM_GetObjsInfoInGroup(4);//207
		p_debug("ctrl_ret2 = %d",ctrl_ret);
		if(mStGrpDetailInfo != NULL)
		{
			for(i = 0;i < mStGrpDetailInfo->nObjCnt;i++)
			{
				p_debug("ctrl_ret4 = %d",ctrl_ret);
				if(check_valid_mac(mStGrpDetailInfo->stObjInfo[i].szMacStr) >= 0)
				{
					p_debug("mStGrpDetailInfo->stObjInfo[%d].szMacStr = %s",i,mStGrpDetailInfo->stObjInfo[i].szMacStr);
					ctrl_ret = add_dhcp_backlist(mStGrpDetailInfo->stObjInfo[i].szMacStr);
					if(ctrl_ret < 0)
					{
						return ERROR_SET_WIFI_MARK;
					}
				}else{
					return ERROR_SET_WIFI_MARK;
				}
			}
			free(mStGrpDetailInfo);
		}
		p_debug("ctrl_ret3 = %d",ctrl_ret);
	}else{
		return ERROR_SET_WIFI_MARK;
	}
	return 0;
}

/******************** 关闭block control *********************/
int set_black_ctrl_close()
{
	int ctrl_ret = -1;
	stGrpDetailInfo *mStGrpDetailInfo = NULL;
	int i =0;
	ctrl_ret = set_cfg_wifictrl_status(0);
	if(ctrl_ret >= 0)
	{
		mStGrpDetailInfo = IM_GetObjsInfoInGroup(4);//207
		if(mStGrpDetailInfo != NULL)
		{
			for(i = 0;i < mStGrpDetailInfo->nObjCnt;i++)
			{
				if(check_valid_mac(mStGrpDetailInfo->stObjInfo[i].szMacStr) >= 0)
				{
					ctrl_ret = del_dhcp_backlist(mStGrpDetailInfo->stObjInfo[i].szMacStr);
					if(ctrl_ret < 0)
					{
						return ERROR_SET_WIFI_MARK;
					}
				}else{
					return ERROR_SET_WIFI_MARK;
				}
			}
			free(mStGrpDetailInfo);
		}
	}else{
		return ERROR_SET_WIFI_MARK;
	}
	return 0;
}

/******
获取无线访问控制标志
******/
int dm_get_wifi_access_ctr_mark(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int wifi_ctrl = 0;
	wifi_ctrl = get_cfg_wifictrl_status();
	if(wifi_ctrl != 1)
	{
		wifi_ctrl = 0;
	}
	JSON_ADD_OBJECT(response_para_json, "wifi_ctrl", JSON_NEW_OBJECT(wifi_ctrl,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*******
设置无线访问控制标志
*******/
int dm_set_wifi_access_ctr_mark(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *wifi_ctrl_json = JSON_GET_OBJECT(para_json,"wifi_ctrl");
	uint8_t wifi_ctrl = MSG_SERVER_FALSE;
	int access_ctrl_ret = 0;
	
	if(wifi_ctrl_json != NULL)
	{
		p_debug("wifi_ctrl = %d",wifi_ctrl);
		wifi_ctrl = JSON_GET_OBJECT_VALUE(wifi_ctrl_json,boolean);
		p_debug("wifi_ctrl2 = %d",wifi_ctrl);
		//让黑名单生效或者失效
		if(wifi_ctrl == MSG_SERVER_TRUE)
		{
			header->i_code = set_black_ctrl_open();//生效
		}else{
			header->i_code = set_black_ctrl_close();//无效
		}
		dhcp_restart();
		
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*******
设置无线控制黑名单
******/
int dm_set_wifi_access_ctrl(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	JObj *namelist_type_json = JSON_GET_OBJECT(para_json,"namelist_type");
	JObj *op_type_json = JSON_GET_OBJECT(para_json,"op_type");
	int access_ctrl_ret = -1;
	const char *mac = NULL;
	int namelist_type = 0;
	int group_del_ret = -1;
	int group_add_ret = -1;
	int op_type = 0;//操作方式 1增加 2删除
	
	if(mac_json != NULL&&namelist_type_json != NULL&&op_type_json != NULL)
	{
		mac = JSON_GET_OBJECT_VALUE(mac_json,string);
		op_type = JSON_GET_OBJECT_VALUE(op_type_json,int);
		if(check_valid_mac(mac) >= 0)
		{
			stObjBrief *mStObjBrief = NULL;
			mStObjBrief = IM_GetObjBrief(mac);
			if(mStObjBrief != NULL)
			{
				if(op_type == 1)
				{
					group_del_ret = IM_DelObjFromGrp(mac);//205
					if(group_del_ret != 0)
					{
						header->i_code = ERROR_DELETE_GROUP_DEV;
					}else{
						group_add_ret = IM_AddObj2Grp(4,mStObjBrief->szName,mac);//205
						access_ctrl_ret = add_dhcp_backlist(mac);
						if(access_ctrl_ret < 0 || group_add_ret < 0)
						{
							header->i_code = ERROR_ADD_BLACK_LIST;
						}
					}
				}else if(op_type == 2)
				{
					access_ctrl_ret = del_dhcp_backlist(mac);
					group_del_ret = IM_DelObjFromGrp(mac);//205
					group_add_ret = IM_AddObj2Grp(3,mStObjBrief->szName,mac);//205
					if(access_ctrl_ret < 0||group_del_ret < 0||group_add_ret < 0)
					{
						header->i_code = ERROR_DEL_BLACK_LIST;				
					}
				}
				if(header->i_code == 0)
				{
					dhcp_restart();
				}
			}
		}else{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*********
设置分组
********/
int dm_set_group(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json= NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	JObj *group_id_json = JSON_GET_OBJECT(para_json,"group_id");
	JObj *op_type_json = JSON_GET_OBJECT(para_json,"op_type");
	JObj *dev_name_json = JSON_GET_OBJECT(para_json,"dev_name");
	int group_ret = -1;
	if(mac_json != NULL&&group_id_json != NULL&&op_type_json != NULL&&dev_name_json != NULL)
	{
		const char* mac = JSON_GET_OBJECT_VALUE(mac_json,string);
		int group_id = JSON_GET_OBJECT_VALUE(group_id_json,int);
		int op_type = JSON_GET_OBJECT_VALUE(op_type_json,int);// 1:add,2:del
		const char * dev_name = JSON_GET_OBJECT_VALUE(dev_name_json,string);
		if(op_type == 1)
		{
			group_ret = IM_DelObjFromGrp(mac);//205
			if(group_ret != 0)
			{
				header->i_code = ERROR_DELETE_GROUP_DEV;
			}else{
				header->i_code = GROUP_SUCCESS;
			}
		   p_debug("DM group_id = %d,dev_name = %s,pMacStr = %s",group_id,dev_name,mac);
		   group_ret = IM_AddObj2Grp(group_id,dev_name,mac);//205
		    if(group_ret != 0)
			{
				header->i_code = ERROR_ADD_GROUP_DEV;
			}else{
				header->i_code = GROUP_SUCCESS;
			}
		}else if(op_type == 2)
		{
			group_ret = IM_DelObjFromGrp(mac);//205
			if(group_ret != 0)
			{
				header->i_code = ERROR_DELETE_GROUP_DEV;
			}else{
				header->i_code = GROUP_SUCCESS;
			}			
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/******
硬盘设置
*******/
int dm_set_hdisk(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *is_format_json = JSON_GET_OBJECT(para_json,"is_format");
	JObj *dev_node_json = JSON_GET_OBJECT(para_json,"dev_node");
	
	uint8_t is_format = 0;
	int format_ret = -1;
	char *dev_node = NULL;
	char *drivname = NULL;
	
	if (is_format_json != NULL)
	{
		is_format = JSON_GET_OBJECT_VALUE(is_format_json,int);//是否格式硬盘 0否1是
		if(is_format == MSG_SERVER_TRUE)
		{
			p_debug("Format_formatdisk\n");
			format_ret = Format_formatall(NTFS_TYPE);
			if(format_ret < 0)
			{
				header->i_code = ERROR_FORMAT_DISK_FAIL;
			}
		}
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/**********
获取限速设备信息
**********/
int dm_get_limit_dev_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint32_t i =0;
	JObj *ip_info[MAX_GROUP_USR_COUNT];
	devbackupinfo mdevbackupinfo;
	stObjSample *mstobjSample = NULL;
	int dev_ret = -1;
   	int max_uploadspeed = -1;
   	int max_downloadspeed = -1;
	char ip[IPADDR_STR_LEN] = {0};
	mstobjSample = IM_GetObjSample();
	
	if(mstobjSample != NULL)
	{
		for(i = 0;i < mstobjSample->nCount;i++)
		{
			  if(check_valid_mac(mstobjSample->stObjCot[i].szMacStr) >= 0&&mstobjSample->stObjCot[i].szName != NULL)
			  {
				p_debug("mstobjSample->stObjCot[%d].szMacStr = %s", i,mstobjSample->stObjCot[i].szMacStr);
				ip_info[i] = JSON_NEW_EMPTY_OBJECT();
				memset(&mdevbackupinfo,0,sizeof(devbackupinfo));
				dev_ret = getDevBackUpInfo(mstobjSample->stObjCot[i].szMacStr,&mdevbackupinfo);
				if(dev_ret >= 0)
				{
					max_uploadspeed = mdevbackupinfo.MaxUpSpeed;
					max_downloadspeed = mdevbackupinfo.MaxDownSpeed;
				}else{
					header->i_code = ERROR_GET_DEV_INFO;
				}
				memset(ip,0,IPADDR_STR_LEN);
				JSON_ADD_OBJECT(ip_info[i], "mac", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szMacStr,string));
				JSON_ADD_OBJECT(ip_info[i], "dev_name", JSON_NEW_OBJECT(mstobjSample->stObjCot[i].szName,string)); 
				JSON_ADD_OBJECT(ip_info[i], "ip", JSON_NEW_OBJECT(mdevbackupinfo.ip,string));
				JSON_ADD_OBJECT(ip_info[i], "uploadspeedpec", JSON_NEW_OBJECT(max_uploadspeed,int));
				JSON_ADD_OBJECT(ip_info[i], "downloadspeedpec", JSON_NEW_OBJECT(max_downloadspeed,int));
				JSON_ARRAY_ADD_OBJECT(response_para_array,ip_info[i]);
			  }else{
				p_debug("ERROR_MAC_PARA_INVALIDE");//header->code = ERROR_PARA_INVALIDE;
			  }
		}
		free(mstobjSample);
	}
	JSON_ADD_OBJECT(response_para_json, "is_limitspeed", JSON_NEW_OBJECT(MSG_SERVER_TRUE,boolean));
	JSON_ADD_OBJECT(response_para_json, "limitspeed_devlist", response_para_array);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*********
设置限速
**********/
int dm_set_limit_speed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	JObj *downloadspeedpec_json = JSON_GET_OBJECT(para_json,"downloadspeedpec");
	JObj *uploadspeedpec_json = JSON_GET_OBJECT(para_json,"uploadspeedpec");
	int limit_ret = -1;
	const char *mac = NULL;
	int downloadspeedpec = 0;
	int uploadspeedpec = 0;
	char speed_limit[64] = {0};
	uint64_t max_speed_bit = 0;
	char *prio = "6";
	if(mac_json != NULL&&downloadspeedpec_json != NULL&&uploadspeedpec_json != NULL)
	{
		mac = JSON_GET_OBJECT_VALUE(mac_json,string);//是否格式硬盘 0否1是
		downloadspeedpec = JSON_GET_OBJECT_VALUE(downloadspeedpec_json,int);
		uploadspeedpec = JSON_GET_OBJECT_VALUE(uploadspeedpec_json,int);
		if(check_valid_mac(mac) >= 0)
		{
			if(uploadspeedpec >= 0)
			{
				max_speed_bit = downloadspeedpec*NETWORK_NET_FLOW_LEVEL;
				sprintf(speed_limit, "%lld", max_speed_bit);
				start_speed_limit();
				set_up_speed_limit(mac,speed_limit,prio);
				stop_speed_limit();
			}else{
				start_speed_limit();
				del_up_speed_limit(mac);
				stop_speed_limit();
			}
			
			if(downloadspeedpec >= 0)
			{
				max_speed_bit = downloadspeedpec*NETWORK_NET_FLOW_LEVEL;
				sprintf(speed_limit, "%lld", max_speed_bit);
				start_speed_limit();
				set_down_speed_limit(mac,speed_limit,prio);
				stop_speed_limit();
			}
			else
			{
				start_speed_limit();
				del_down_speed_limit(mac);
				stop_speed_limit();
			}

			backupdevmaxupspeed(mac,uploadspeedpec);
			backupdevmaxdownspeed(mac,downloadspeedpec);
		}
		else
		{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/*******
设置UPNP
*******/
int dm_set_upnp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj * header_json = NULL;
	JObj * response_json=JSON_NEW_EMPTY_OBJECT();
	JObj * data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj * para_bool_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj * is_upnp_obj = JSON_GET_OBJECT(para_bool_json,"is_upnp");
	char * is_upnp = json_object_to_json_string(is_upnp_obj);

	set_upnp_enable(is_upnp);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	
	return 0;
}

/*********
获取UPNP信息
*********/
int dm_get_upnp(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj * header_json = NULL;
	JObj * response_json =JSON_NEW_EMPTY_OBJECT();
	JObj * response_isupnp_obj =JSON_NEW_EMPTY_OBJECT();
	JObj * response_data_array = JSON_NEW_ARRAY();
	JObj * response_para_array = JSON_NEW_ARRAY();
	JObj * response_para_json=JSON_NEW_EMPTY_OBJECT();
	MINIUPNPD_ST miniupnp;
	int i = 0;
	char value[8] = {0};
	bool is_upnp = false;
		
	memset(&miniupnp,0,sizeof(miniupnp));
	get_upnpinfo_from_lease_file(&miniupnp);
	
	for (i=0 ;i<miniupnp.count ;i++)
	{
		JSON_ADD_OBJECT(response_para_json, "app_name", JSON_NEW_OBJECT(miniupnp.upnpdObjArr[i].app_name,string));
		JSON_ADD_OBJECT(response_para_json, "iport", JSON_NEW_OBJECT(miniupnp.upnpdObjArr[i].iport,int));
		JSON_ADD_OBJECT(response_para_json, "protocol_type", JSON_NEW_OBJECT(miniupnp.upnpdObjArr[i].protocol_type,string));
		JSON_ADD_OBJECT(response_para_json, "oport", JSON_NEW_OBJECT(miniupnp.upnpdObjArr[i].oport,int));
		JSON_ADD_OBJECT(response_para_json, "ip", JSON_NEW_OBJECT(miniupnp.upnpdObjArr[i].ip,string));

		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);	
		
	}

	get_uci_option_value("upnpd","config","enable_upnp",value,sizeof(value));
	p_debug("enable_upnp = %s\n",value);
	if(!strcmp(value,"1"))
		is_upnp = true;
	else
		is_upnp = false;
	
	JSON_ADD_OBJECT(response_isupnp_obj, "is_upnp", JSON_NEW_OBJECT(is_upnp,boolean));
	JSON_ARRAY_ADD_OBJECT(response_para_array,response_isupnp_obj);
	JSON_ARRAY_ADD_OBJECT(response_para_array,response_data_array);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_para_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	p_debug("json:%s\n",JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/****
获取端口转发的信息
***/
int dm_get_port_forward_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	int port_ret = -1;
	uint8_t i = 0;
	port_info_group_t st_port_info_group;
	memset(&st_port_info_group,0,sizeof(port_info_group_t));
	port_ret = get_port_convert_list_t(&st_port_info_group);
	p_debug("st_port_info_group.cout = %d",st_port_info_group.cout);
	p_debug("port_ret = %d",port_ret);
	if(port_ret >= 0)
	{
		JObj *port_forward_info[MAX_GROUP_USR_COUNT];
		for(i = 0;i < st_port_info_group.cout;i++)
		{
			port_forward_info[i] = JSON_NEW_EMPTY_OBJECT();

			JSON_ADD_OBJECT(port_forward_info[i], "app_name", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].app_name,string));
			JSON_ADD_OBJECT(port_forward_info[i], "iport", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].iport,int));
			JSON_ADD_OBJECT(port_forward_info[i], "protocol_type", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].protocol_type,int));
			JSON_ADD_OBJECT(port_forward_info[i], "oport", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].oport,int));
			JSON_ADD_OBJECT(port_forward_info[i], "ip", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].ip,string));
			JSON_ADD_OBJECT(port_forward_info[i], "isvalid", JSON_NEW_OBJECT(st_port_info_group.st_port_info[i].isvalid,int));
			JSON_ARRAY_ADD_OBJECT(response_data_array,port_forward_info[i]);
		}
	}else{
		header->i_code = ERROR_GET_IP_BINDING_INFO;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/******
获取DMZ相关信息
******/
int dm_get_dmz_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
    	char ip[32] = {0};
	int is_dmz = MSG_SERVER_FALSE;
	
	is_dmz = get_DMZ_status(ip);
	if(is_dmz >= 0)
	{
		JSON_ADD_OBJECT(response_para_json, "ip", JSON_NEW_OBJECT(ip,string));
		JSON_ADD_OBJECT(response_para_json, "is_dmz", JSON_NEW_OBJECT(is_dmz,boolean));
	}else{
		header->i_code = ERROR_GET_DMZ_STATUS;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/********
设置DMZ
*******/
int dm_set_dmz_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *is_dmz_json = JSON_GET_OBJECT(para_json,"is_dmz");
	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	uint8_t is_dmz = 0;
	int dmz_ret = -1;
	const char *ip = NULL;
	char *switch_on = "on";
	char *switch_off = "off";
	
	if(is_dmz_json != NULL&&ip_json != NULL)
	{
		is_dmz = JSON_GET_OBJECT_VALUE(is_dmz_json,boolean);
		ip = JSON_GET_OBJECT_VALUE(ip_json,string);
		if(is_dmz == MSG_SERVER_TRUE)
		{
			p_debug("is_dmz1 = %d,ip = %s",is_dmz,ip);
			dmz_ret = switch_DMZ(switch_on,ip);
			p_debug("is_dmz2 = %d,ip = %s",is_dmz,ip);
			if(dmz_ret < 0)
			{
				header->i_code = ERROR_SET_DMZ_INFO;
			}
		}else{
			dmz_ret = switch_DMZ(switch_off,ip);
			if(dmz_ret < 0)
			{
				header->i_code = ERROR_SET_DMZ_INFO;
			}
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*********
获取硬件版本信息
*********/
int dm_get_fw_version(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json =NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
    	char version[MSG_SERVER_VERSION_LEN] = {0};
	char newversion[MSG_SERVER_VERSION_LEN] = {0};
    	Reset_getversion(version);
	//im_get_new_version(newversion);//获取服务器版本接口
	p_debug("the longsys fw newest version : %s",version);
    	JSON_ADD_OBJECT(response_para_json, "hardware_ver", JSON_NEW_OBJECT(version,string));
	JSON_ADD_OBJECT(response_para_json, "hardware_newver", JSON_NEW_OBJECT(newversion,string));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*******
硬件升级
*******/
int dm_web_fw_upgrade(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	Reset_fwupgrade(UPGRADE_FW_PATH);
	return 0;
}
/****
系统备份
****/
int dm_system_backups(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int system_ret = -1;
	char back_url[64] = {0};
	system_ret = setting_backup(back_url);
	if(system_ret >= 0)
	{
		strcpy(back_url,"backup");
		JSON_ADD_OBJECT(response_para_json, "back_url", JSON_NEW_OBJECT(back_url,string));
		JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	}else{
		header->i_code = ERROR_SYSTEM_BACKUPS;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/******
恢复系统备份
******/
int dm_recover_backup_system(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *back_filename_json = JSON_GET_OBJECT(para_json,"back_filename");
	const char *back_filename = NULL;
	int recover_ret = -1;
	if(back_filename_json != NULL)
	{
		back_filename = JSON_GET_OBJECT_VALUE(back_filename_json,string);
		recover_ret = setting_restore(back_filename);
		if(recover_ret < 0)
		{
			header->i_code = ERROR_RECOVERY_SYSTEM;
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/******
获取WAN口状态
******/
int dm_get_wan_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	char wan_mode[WAN_MODE_TYPE] = {0};
	char r_status[4] = {0};
	char ip[32] = {0};
	char dns_list[64] = {0};
    	char netmask[32] = {0};
    	char gateway[32] = {0};
	char dns1_ip[32] = {0};
    	char dns2_ip[32] = {0};
	int con_type = 0;
	int wan_ret = 0;
	
	int32_t switch_ret = get_repeater_switch(r_status);

	if(switch_ret == REPEATER_MODE)
	{
		con_type = REPEATER_TYPE;
	}
	else
	{
		get_wan_mode(wan_mode);
		p_debug("wan_mode = %s",wan_mode);
		if(!strcmp(wan_mode,"pppoe"))
		{
			con_type = PPPOE_TYPE;
		}
		else if(!strcmp(wan_mode,"dhcp"))
		{
			con_type = DHCP_TYPE;
			wan_ret = is_wan_online_t(ip, netmask);
			if(wan_ret >= 0)
			{
				get_gateway(gateway);
				get_dns_list(dns1_ip,dns2_ip);
			}else{
				header->i_code = ERROR_GET_WAN_INFO;
			}
		}
		else if(!strcmp(wan_mode,"static"))
		{
			con_type = STATIC_TYPE;
			char *tmp = NULL;
			int32_t static_ret = -1;
			uint8_t ret = get_vwan_static_status (ip,netmask,gateway,dns_list);
			tmp = strstr(dns_list," ");
			if(tmp!=NULL)
			{
		      		memcpy(dns1_ip,dns_list,tmp-dns_list);
			  	strcpy(dns2_ip,tmp+1); 
			}
			else
			{
		      		strcpy(dns1_ip,dns_list);  
			}
		}
	}
	
    	JSON_ADD_OBJECT(response_para_json, "con_type", JSON_NEW_OBJECT(con_type,int));
	JSON_ADD_OBJECT(response_para_json, "ip",JSON_NEW_OBJECT(ip,string));
	JSON_ADD_OBJECT(response_para_json, "dns1_ip",JSON_NEW_OBJECT(dns1_ip,string));
	JSON_ADD_OBJECT(response_para_json, "dns2_ip",JSON_NEW_OBJECT(dns2_ip,string));
	JSON_ADD_OBJECT(response_para_json, "netmask",JSON_NEW_OBJECT(netmask,string));
	JSON_ADD_OBJECT(response_para_json, "gateway",JSON_NEW_OBJECT(gateway,string));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/*********
获取LAN口状态
********/
int dm_get_lan_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	char mac[32] = {0};
	char ip[32] = {0};
	char netmask[32] = {0};
	int len_ret = -1;
	len_ret = get_len_status(mac,ip,netmask);
	if(len_ret < 0)
	{
		header->i_code = ERROR_GET_LAN_STATUS;
	}
	
    	JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(mac,string));
	JSON_ADD_OBJECT(response_para_json, "ip",JSON_NEW_OBJECT(ip,string));
	JSON_ADD_OBJECT(response_para_json, "netmask",JSON_NEW_OBJECT(netmask,string));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/*******
获取管理PC的MAC地址
*******/
int dm_get_managepc_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	const char *ip_addr = NULL;
	int manage_ret = -1;
	char pc_mac[MAC_LEN] = {0};

//	p_debug("dm_get_managerpc_mac json:%s\n", JSON_TO_STRING(rpc_json));
	
	if(ip_json != NULL)
	{
		ip_addr = JSON_GET_OBJECT_VALUE(ip_json,string);
		manage_ret = get_manage_mac(ip_addr,pc_mac);
		if(manage_ret < 0)
		{
			header->i_code = ERROR_GET_MANAGE_MAC;
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}
	
    	JSON_ADD_OBJECT(response_para_json, "mac", JSON_NEW_OBJECT(pc_mac,string));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/******
获取是否已经连接上internet
******/
int dm_get_access_internet_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
  	uint8_t is_internet = MSG_SERVER_FALSE;
	char ip[32] = {0};
	char netmask[32] = {0};
	
	is_internet = is_wan_online_t(ip, netmask);
    	JSON_ADD_OBJECT(response_para_json, "is_internet", JSON_NEW_OBJECT(is_internet, boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*****
设置自动连接
*****/
int dm_set_dhcp_connect(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
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
		header->i_code = ERROR_SET_VWAN_MODE_DHCP;
	}
	restart_network();

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
   	JSON_ADD_OBJECT(response_json, "header", header_json);
   	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
   	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/*******
获取硬盘设置
*******/
int dm_get_hdisk_settings(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *drive_info[20];
	all_disk_t mAll_disk_t;
	uint8_t drive_count = 0;
	int i=0;
    	char dev_node[32] = {0};
	int32_t isformat = MSG_SERVER_FALSE;
	memset(&mAll_disk_t,0,sizeof(all_disk_t));
	int32_t storage_ret = Format_getstorage (&mAll_disk_t);
	if(storage_ret == 0)
	{
		for(i=0;i < mAll_disk_t.count;i++)
	    {
			if(strstr(mAll_disk_t.disk[i].name,HD_DISK))
			{
				drive_info[i] = JSON_NEW_EMPTY_OBJECT();
				JSON_ADD_OBJECT(drive_info[i], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
				JSON_ADD_OBJECT(drive_info[i], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
				JSON_ADD_OBJECT(drive_info[i], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
				JSON_ARRAY_ADD_OBJECT (response_data_array,drive_info[i]);
			}
		}	
	}else{
		header->i_code = ERROR_CODE_NO_DRIVE;
	}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

void *thread_for_upgrade(void *arg)
{
	S_IM_MSG_FIRMWARE *fw_info = (S_IM_MSG_FIRMWARE *)arg;

	im_upgrade_firmware(fw_info, dm_fw_upgrade);
}

/***********
启动升级
***********/
int dm_start_upgrade(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	static int is_upgrade = 0;
	pthread_t pth_id;
	pthread_attr_t attr;
	int ret = 0;
	JObj* header_json = NULL;
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	
	if (is_upgrade && (g_firmware_info.state != 3))
	{
		goto runing;
	}

	ret = pthread_attr_init(&attr);
	if (ret != 0)
	{
		p_debug("errno:%d msg:%s\b", errno, strerror(errno));
		goto runing;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0)
	{
		p_debug("errno:%d pthread setdetachestate failed\n", errno);
		goto runing;
	}

	/*********  get bin files  information for download, e.m: url, md5***********/
	ret = im_fw_info(NULL, &g_firmware_info);
	if (ret < 0)
	{
		p_debug("get bin file information failed\n");
		goto runing;
	}
	
	/*************  create pthread to handle upgrade ***********/
	ret = pthread_create(&pth_id, &attr, &thread_for_upgrade, &g_firmware_info);
	if (ret != 0)
	{
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
	}
	
	is_upgrade = 1;
	
runing:	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*****
恢复出厂MAC
*****/
int dm_resume_mac(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	int resume_mac_ret = -1;
	resume_mac_ret = del_ghost_mac();
	if(resume_mac_ret < 0)
	{
		header->i_code = ERROR_RESUME_MAC;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}


/*******
添加端口转发信息
*******/
int dm_add_port_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *app_name_json = JSON_GET_OBJECT(para_json,"app_name");
	JObj *oport_json = JSON_GET_OBJECT(para_json,"oport");
	JObj *protocol_type_json = JSON_GET_OBJECT(para_json,"protocol_type");
	JObj *iport_json = JSON_GET_OBJECT(para_json,"iport");
	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	JObj *isvalid_json = JSON_GET_OBJECT(para_json,"isvalid");
	int port_ret = -1;
	uint8_t i = 0;
	uint8_t same_name_flag = MSG_SERVER_FALSE;
	port_info_group_t st_port_info_group;
	if(app_name_json != NULL&&oport_json != NULL&&protocol_type_json != NULL
		&&iport_json != NULL&&isvalid_json != NULL)
		{
			const char *app_name = JSON_GET_OBJECT_VALUE(app_name_json,string);
			memset(&st_port_info_group,0,sizeof(port_info_group_t));
			port_ret = get_port_convert_list_t(&st_port_info_group);
			p_debug("port_ret = %d",port_ret);
			if(port_ret >= 0)
			{
				for(i = 0;i < st_port_info_group.cout;i++)
				{
					if(!strcmp(st_port_info_group.st_port_info[i].app_name,app_name))
					{
						same_name_flag = MSG_SERVER_TRUE;
					}
				}
			}
			if(same_name_flag == MSG_SERVER_FALSE)
			{
				int oport = JSON_GET_OBJECT_VALUE(oport_json,int);
				int protocol_type = JSON_GET_OBJECT_VALUE(protocol_type_json,int);
				int iport = JSON_GET_OBJECT_VALUE(iport_json,int);
				const char *ip = JSON_GET_OBJECT_VALUE(ip_json,string);
				int isvalid = JSON_GET_OBJECT_VALUE(isvalid_json,boolean);
				int port_ret = -1;
				port_redirects st_port_redirects;
				memset(&st_port_redirects,0,sizeof(port_redirects));
				if(protocol_type == 1)
				{
					strcpy(st_port_redirects.potocol, "tcp");
				}else{
					strcpy(st_port_redirects.potocol, "udp");
				}
				p_debug("st_port_redirects.potocol = %s",st_port_redirects.potocol);
				sprintf(st_port_redirects.exter_port,"%d",oport);
				sprintf(st_port_redirects.in_port,"%d",iport);
				p_debug("st_port_redirects.in_port = %s",st_port_redirects.in_port);
				strcpy(st_port_redirects.name, app_name);
				strcpy(st_port_redirects.ip_address, ip);
				port_ret = add_port_convert(&st_port_redirects);
				if(port_ret < 0)
				{
					header->i_code = ERROR_ADD_PORT_FORWORD;
				}
			}else{
				header->i_code = ERROR_PORT_FORWARD_SAME_NAME;
			}
		}else{
			header->i_code = ERROR_PARA_INVALIDE;
		}
	
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/*******
修改端口转发信息
*******/
int dm_port_amend_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *app_name_json = JSON_GET_OBJECT(para_json,"app_name");
	JObj *oport_json = JSON_GET_OBJECT(para_json,"oport");
	JObj *protocol_type_json = JSON_GET_OBJECT(para_json,"protocol_type");
	JObj *iport_json = JSON_GET_OBJECT(para_json,"iport");
	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	JObj *isvalid_json = JSON_GET_OBJECT(para_json,"isvalid");
	
	int port_ret = -1;
	uint8_t i = 0;
	uint8_t same_name_flag = MSG_SERVER_FALSE;
	const char *app_name = NULL;
	
	port_info_group_t st_port_info_group;
	if(app_name_json != NULL&&oport_json != NULL&&protocol_type_json != NULL
		&&iport_json != NULL&&isvalid_json != NULL)
		{
			app_name = JSON_GET_OBJECT_VALUE(app_name_json,string);
			memset(&st_port_info_group,0,sizeof(port_info_group_t));
			port_ret = get_port_convert_list_t(&st_port_info_group);
			p_debug("port_ret = %d",port_ret);
			
			if(port_ret >= 0)
			{
				for(i = 0;i < st_port_info_group.cout;i++)
				{
					if(!strcmp(st_port_info_group.st_port_info[i].app_name,app_name))
					{
						same_name_flag = MSG_SERVER_TRUE;
					}
				}
			}
			
			if(same_name_flag == MSG_SERVER_TRUE)
			{
				int oport = JSON_GET_OBJECT_VALUE(oport_json,int);
				int protocol_type = JSON_GET_OBJECT_VALUE(protocol_type_json,int);
				int iport = JSON_GET_OBJECT_VALUE(iport_json,int);
				const char *ip = JSON_GET_OBJECT_VALUE(ip_json,string);
				int isvalid = JSON_GET_OBJECT_VALUE(isvalid_json,boolean);
				int port_ret = -1;
				port_redirects st_port_redirects;
				memset(&st_port_redirects,0,sizeof(port_redirects));
				if(protocol_type == 1)
				{
					strcpy(st_port_redirects.potocol, "tcp");
				}else{
					strcpy(st_port_redirects.potocol, "udp");
				}
				p_debug("st_port_redirects.potocol = %s",st_port_redirects.potocol);
				sprintf(st_port_redirects.exter_port,"%d",oport);
				sprintf(st_port_redirects.in_port,"%d",iport);
				p_debug("st_port_redirects.in_port = %s",st_port_redirects.in_port);
				strcpy(st_port_redirects.name, app_name);
				strcpy(st_port_redirects.ip_address, ip);
				port_ret = add_port_convert(&st_port_redirects);
				if(port_ret < 0)
				{
					header->i_code = ERROR_ADD_PORT_FORWORD;
				}
			}
			else
			{
				header->i_code = ERROR_PORT_FORWARD_EXIST;
			}
		}
		else
		{
			header->i_code = ERROR_PARA_INVALIDE;
		}
		
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

/******
删除端口转发信息
******/
int dm_del_port_forwarding(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *app_name_json = JSON_GET_OBJECT(para_json,"app_name");
	int port_ret = -1;
	
	if(app_name_json != NULL)
	{
		const char *app_name = JSON_GET_OBJECT_VALUE(app_name_json,string);
		port_ret = 	delete_port_convert(app_name);
		if(port_ret < 0)
		{
			header->i_code = ERROR_DEL_PORT_FORWORD;
		}
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/**************************** get samba info ************************************/
static SINT32 IM_SetOpt(SINT8 *pOpt)
{
    struct uci_ptr stUciPtr;
    SINT32 iRet = 0;
    struct uci_context *pstCtx = NULL;

    pstCtx = uci_alloc_context();
    if (NULL == pstCtx)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Out of memory!");
        return -1;
    }
    
    if (UCI_OK != uci_set_confdir(pstCtx, IM_PER_AUTH_CONF_PATH))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_set_confdir failed, config:%s!", IM_PER_AUTH_CONF_PATH);
        iRet = -1;
        goto Out;
    }

    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "option:%s!", pOpt);
    if (UCI_OK != uci_lookup_ptr(pstCtx, &stUciPtr, pOpt, true))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_lookup_ptr failed, option:%s!", pOpt);
        iRet = -1;
        goto Out;
    }
    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "option:%s!", pOpt);
    
    if (UCI_OK != uci_set(pstCtx, &stUciPtr))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_set failed, option:%s!", pOpt);
        iRet = -1;
        goto Out;
    }
    
    if (UCI_OK != uci_commit(pstCtx, &stUciPtr.p, false))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_commit failed!");
        iRet = -1;
        goto Out;
    }
    
Out:
    if (stUciPtr.p)
	{
		uci_unload(pstCtx, stUciPtr.p);
	}
    uci_free_context(pstCtx);
    
    return iRet;
}

static SINT32 IM_GetOptionValue(SINT8 *pOptKey, SINT8 *pValue, UINT32 nSize)
{
    struct uci_ptr stUciPtr;
    struct uci_package *pstUciPkg = NULL;
    SINT32 iRet = 0;
    struct uci_context *pstCtx = NULL;

    pstCtx = uci_alloc_context();
    if (NULL == pstCtx)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Out of memory!");
        return -1;
    }

    if (UCI_OK != uci_set_confdir(pstCtx, IM_PER_AUTH_CONF_PATH))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_set_confdir failed, config:%s!", IM_PER_AUTH_CONF_PATH);
        iRet = -1;
        goto Out;
    }

    if (UCI_OK != uci_lookup_ptr(pstCtx, &stUciPtr, pOptKey, true))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_lookup_ptr failed, cmd:%s!", pOptKey);
        iRet = -1;
        goto Out;
    }
    
    if (NULL == stUciPtr.o)
    {
        iRet = -2;
        goto Out;
    }
    
    memcpy(pValue, stUciPtr.o->v.string, nSize);

    if (stUciPtr.p)
	{
		uci_unload(pstCtx, stUciPtr.p);
	}

Out:
    uci_free_context(pstCtx);
    return iRet;
}

INT ComputeChecksum(UINT PIN)
{
        INT digit_s;
    	 UINT accum = 0;

        PIN *= 10;
        accum += 3 * ((PIN / 10000000) % 10);
        accum += 1 * ((PIN / 1000000) % 10);
        accum += 3 * ((PIN / 100000) % 10);
        accum += 1 * ((PIN / 10000) % 10);
        accum += 3 * ((PIN / 1000) % 10);
        accum += 1 * ((PIN / 100) % 10);
        accum += 3 * ((PIN / 10) % 10);

        digit_s = (accum % 10);
        return ((10 - digit_s) % 10);
}

/*****
生成随机数---8位
params:
	none
return:
	rand num	 
****/
UINT imove_generate_rand_num(void)
{
	UINT pwd = 0;
	UINT n[3] = {0};
	UINT checksum = 0;
	int i = 0;
	
	srand((unsigned)time(NULL));

	for (i = 0; i < 3; i++)
	{
            n[i] = rand() % 100 + i;
    	}

	pwd = n[2] * 256 * 256 + n[1] * 256 + n[2];
	pwd = pwd % 10000000;
	checksum = ComputeChecksum(pwd);
	pwd = pwd * 10 + checksum;
	
	return pwd;
}

/********
获取SAMBA信息
*******/
int dm_get_samba_info(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
#define SAMBA_CONF	"samba"
#define SAMBA_PATH	"admin_path"
#define SAMBA_PWD	"admin_pwd"
#define SAMBA_USER	"admin_user"
#define NETWORK_LAN	"lan"
#define LAN_IP_ADDR		"ipaddr"

	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	
	char visit_path[128] = {0};
	char usr_name[64] = {0};
	char cmd_line[128] = {0};
	int ret = 0;
	
	const UINT rand_pwd = imove_generate_rand_num();
	
	snprintf(cmd_line, sizeof(cmd_line), "%s.%s.%s", "network", NETWORK_LAN, LAN_IP_ADDR);
	ret = IM_GetOptionValue(cmd_line, visit_path, sizeof(visit_path));
	if (ret != 0)
	{
		p_debug("get path failed, %s\n", cmd_line);
		goto err_ret;
	}

	memset(cmd_line, 0, sizeof(cmd_line));
	snprintf(cmd_line, sizeof(cmd_line), "%s.@%s[0].%s", SAMBA_CONF, SAMBA_CONF, SAMBA_USER);
	ret = IM_GetOptionValue(cmd_line, visit_path, sizeof(visit_path));
	if (ret != 0)
	{
		p_debug("get path user, %s\n", cmd_line);
		goto err_ret;
	}

	/***** set current password to samba config ******/
	memset(cmd_line, 0, sizeof(cmd_line));
	snprintf(cmd_line, sizeof(cmd_line), "%s.@%s[0].%s=%d", SAMBA_CONF, SAMBA_CONF, SAMBA_PWD, rand_pwd);
	ret = IM_SetOpt(cmd_line);
	if (ret != 0)
	{
		p_debug("set pwd failed, %s\n", cmd_line);
		goto err_ret;
	}

	/********* add password to samba password database *******/
	memset(cmd_line, 0, sizeof(cmd_line));
	snprintf(cmd_line, sizeof(cmd_line),"(echo %d;echo %d) | smbpasswd -a %s", rand_pwd, rand_pwd, usr_name);
	system(cmd_line);
	
    	JSON_ADD_OBJECT(response_para_json, "visit_path", JSON_NEW_OBJECT(visit_path,string));
	JSON_ADD_OBJECT(response_para_json,"usr_name",JSON_NEW_OBJECT(usr_name,string));
	JSON_ADD_OBJECT(response_para_json,"password",JSON_NEW_OBJECT(rand_pwd,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

err_ret:
	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/******
添加DDNS
******/
int dm_add_ddns(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *isp_name_json = JSON_GET_OBJECT(para_json,"isp_name");
	JObj *usr_name_json = JSON_GET_OBJECT(para_json,"usr_name");
	JObj *password_json = JSON_GET_OBJECT(para_json,"password");
	JObj *domain_name_json = JSON_GET_OBJECT(para_json,"domain_name");
	const char *isp_name = NULL;
	const char *usr_name = NULL;
	const char *password = NULL;
	const char *domain_name = NULL;
	char *check_time = NULL;
	char *update_time = NULL;
	char service[32] = {0};
	int ddns_ret = -1;
	if(isp_name_json != NULL&&usr_name_json != NULL&&password_json&&domain_name_json)
	{
		isp_name = JSON_GET_OBJECT_VALUE(isp_name_json,string);
		usr_name = JSON_GET_OBJECT_VALUE(usr_name_json,string);
		password = JSON_GET_OBJECT_VALUE(password_json,string);
		domain_name = JSON_GET_OBJECT_VALUE(domain_name_json,string);
		ddns_ret = add_DDNS(isp_name,usr_name,password,domain_name);
		if(ddns_ret < 0)
		{
			header->i_code = ERROR_ADD_DDNS;
		}else{
			switch_DDNS(RESTART);
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

/********
删除DDNS
*******/
int dm_del_ddns(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *isp_name_json = JSON_GET_OBJECT(para_json,"isp_name");
	JObj *domain_name_json = JSON_GET_OBJECT(para_json,"domain_name");
	const char *isp_name = NULL;
	const char *domain_name = NULL;
	int ddns_ret = -1;
	if(isp_name_json != NULL&&domain_name_json != NULL)
	{
		isp_name = JSON_GET_OBJECT_VALUE(isp_name_json,string);
		domain_name = JSON_GET_OBJECT_VALUE(domain_name_json,string);
		ddns_ret = del_DDNS(isp_name);
		if(ddns_ret < 0)
		{
			header->i_code = ERROR_DEL_DDNS;
		}else{
			switch_DDNS(RESTART);
		}
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_DDNS_service_list_t(ddns_list_t *ddns_list)
{
	int i = 0;
	ddns_list->count = 4;
	int ddns_ret = -1;
	char ddns_status_t[8] = {0};
	strcpy(ddns_list->ddns_t[0].isp_name,"oray.com");
	strcpy(ddns_list->ddns_t[1].isp_name,"3322.org");
	strcpy(ddns_list->ddns_t[2].isp_name,"no-ip.com");
	strcpy(ddns_list->ddns_t[3].isp_name,"dyndns.org");
	
	for(i = 0;i < ddns_list->count;i++)
	{
		memset(ddns_status_t,0,8);
		get_DDNS(ddns_list->ddns_t[i].isp_name,ddns_status_t,ddns_list->ddns_t[i].domain_name);
		if(!strcmp(ddns_status_t,"on"))
		{
			ddns_list->ddns_t[i].ddns_status = 1;
		}else{
			ddns_list->ddns_t[i].ddns_status = 0;
		}
	}
	
	return 0;
}

/********
获取DDNS列表
*******/
int dm_get_ddns_list(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	
	ddns_list_t ddns_list;
	int i =0;
	memset(&ddns_list,0,sizeof(ddns_list_t));
	int ddns_list_ret = get_DDNS_service_list_t(&ddns_list);
	if(ddns_list_ret >= 0)
	{
		JObj *ddns_info[ddns_list.count];
		for(i = 0;i < ddns_list.count;i++)
		{
			ddns_info[i] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(ddns_info[i], "isp_name", JSON_NEW_OBJECT(ddns_list.ddns_t[i].isp_name,string));
			JSON_ADD_OBJECT(ddns_info[i],"domain_name",JSON_NEW_OBJECT(ddns_list.ddns_t[i].domain_name,string));
			JSON_ADD_OBJECT(ddns_info[i],"ddns_status",JSON_NEW_OBJECT(ddns_list.ddns_t[i].ddns_status,int));
			JSON_ARRAY_ADD_OBJECT(response_data_array,ddns_info[i]);
		}
	}else{
		header->i_code = ERROR_GET_DDNS_LIST;
	}

	header_json = imove_create_json_msg_header(header);
	if (header_json == NULL)
	{
		p_debug("malloc failed \n");
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		return -1;
	}
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}	

int get_usr_dev_permission(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	uint8_t internet_access_flag = 0;
	uint8_t router_ctrl_flag = 0;
	uint8_t routedisc_access_flag = 0;
	uint8_t routedisc_ctrl_flag = 0;
	uint8_t pridisk_access_flag = 0;
	uint8_t pridisk_ctrl_flag = 0;

	stPermsInfo  *mStPermsInfo = NULL;
	mStPermsInfo = IM_GetObjPermBySess(header->s_session);
	if(mStPermsInfo != NULL)
	{
		internet_access_flag = mStPermsInfo->ucInternetAccEnable;
		router_ctrl_flag = mStPermsInfo->ucRouterCtrlEnable;
		routedisc_access_flag = mStPermsInfo->ucRouterDiscAccEnable;
		routedisc_ctrl_flag = mStPermsInfo->ucRouterDiscCtrlEnable;
		pridisk_access_flag = mStPermsInfo->ucPrivateDiscAccEnable;
		pridisk_ctrl_flag = mStPermsInfo->ucPrivateDiscCtrlEnable;
		p_debug("internet_access_flag = %d", internet_access_flag);
		p_debug("router_ctrl_flag = %d", router_ctrl_flag);
		p_debug("routedisc_access_flag = %d", routedisc_access_flag);
		p_debug("routedisc_ctrl_flag = %d", routedisc_ctrl_flag);
		p_debug("pridisk_ctrl_flag = %d", pridisk_ctrl_flag);
	}else{
		header->i_code = ERROR_GET_USR_DEV_PERMISSION;
		p_debug("mStPermsInfo != NULL");
	}

	JSON_ADD_OBJECT(response_para_json, "internet_access", JSON_NEW_OBJECT(internet_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "router_ctrl", JSON_NEW_OBJECT(router_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_access", JSON_NEW_OBJECT(routedisc_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "routedisc_ctrl", JSON_NEW_OBJECT(routedisc_ctrl_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_access", JSON_NEW_OBJECT(pridisk_access_flag,boolean));
	JSON_ADD_OBJECT(response_para_json, "pridisk_ctrl", JSON_NEW_OBJECT(pridisk_ctrl_flag,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
   	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _get_vwan_dhcp_status(char *hostname,char *dns_list,char *macaddr)
{
   return 0;
}

int _set_vwan_mode_pppoe(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *name_json = JSON_GET_OBJECT(para_json,"adsl_name");
	const char *username = JSON_GET_OBJECT_VALUE(name_json,string);
	JObj *password_json = JSON_GET_OBJECT(para_json,"adsl_password");
	const char *password = JSON_GET_OBJECT_VALUE(password_json,string);
	char *dns_list=NULL;
	char r_status[4] = {0};
	int statue = -1;
	
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		set_to_bridge();	
	}
    set_vwan_mode_pppoe(username ,password,dns_list);

	/* 获取路由初始化状态 */
	get_wizard_init_status(&statue);
	if(statue != WIZARD_OK)
	{
		set_wizard_init_status(WIZARD_WIFI);
	}	
		

	restart_network();
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	header_json = imove_create_json_msg_header(header);
   JSON_ADD_OBJECT(response_json, "header", header_json);
//   strcpy(retstr,JSON_TO_STRING(response_json));
   snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
   JSON_PUT_OBJECT(response_json);
  return 0;
}

int _Wlan_getPPPoEstatus(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	 JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	 JObj *response_data_array = JSON_NEW_ARRAY();
	 JObj* header_json = NULL;
	 JObj* pppoe_info = JSON_NEW_EMPTY_OBJECT();
	 
	char adsl_name[64] = {0};
	char adsl_password[64] = {0};
	char dns_list[64] = {0};
	int32_t pppoe_status = -1;

	get_vwan_pppoe_status(adsl_name,adsl_password,dns_list);
	if(!*adsl_name)
	{
//		p_debug("adsl_name1 = %s,adsl_password = %s,dns_list = %s",adsl_name,adsl_password,dns_list);
		pppoe_status = get_cfg_pppoe_status(adsl_name,adsl_password);
//		p_debug("adsl_name2 = %s,adsl_password = %s,dns_list = %s",adsl_name,adsl_password,dns_list);
		if(pppoe_status < 0)
		{
			header->i_code = ERROR_GET_PPPOE_STATUS;
		}
	}

	JSON_ADD_OBJECT(pppoe_info, "adsl_name",JSON_NEW_OBJECT(adsl_name,string));
	JSON_ADD_OBJECT(pppoe_info, "adsl_password",JSON_NEW_OBJECT(adsl_password,string));
	JSON_ARRAY_ADD_OBJECT (response_data_array,pppoe_info);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	 snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	 JSON_PUT_OBJECT(header_json);
	 JSON_PUT_OBJECT(response_data_array);
	 JSON_PUT_OBJECT(response_json);
	return 0;
}

int _set_vwan_mode_static(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   	JObj *ip_json = JSON_GET_OBJECT(para_json,"ip");
	const char *ipaddr = JSON_GET_OBJECT_VALUE(ip_json,string);
	JObj *dns1_json = JSON_GET_OBJECT(para_json,"dns1_ip");
	JObj *dns2_json = JSON_GET_OBJECT(para_json,"dns2_ip");

   	const char *dns_list1 = JSON_GET_OBJECT_VALUE(dns1_json,string);
   	const char *dns_list2 = JSON_GET_OBJECT_VALUE(dns2_json,string);

   	JObj *netmask_json = JSON_GET_OBJECT(para_json,"netmask");
   	const char *netmask = JSON_GET_OBJECT_VALUE(netmask_json,string);
   	JObj *gateway_json = JSON_GET_OBJECT(para_json,"gateway");
   	const char *gateway = JSON_GET_OBJECT_VALUE(gateway_json,string);
   	char dns_list[64] = {0};
	int statue = -1;
	
   
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
//	p_debug("dns_list = %s",dns_list);
	char r_status[4] = {0};
	int32_t switch_ret = get_repeater_switch(r_status);
	if(switch_ret == REPEATER_MODE)
	{
		set_to_bridge();	
	}
    set_vwan_mode_static(ipaddr,netmask,gateway ,dns_list);


	/* 获取路由初始化状态 */
	get_wizard_init_status(&statue);
	if(statue != WIZARD_OK)
	{
		set_wizard_init_status(WIZARD_WIFI);
	}	
	
	restart_network();
	
	header_json = imove_create_json_msg_header(header);
   	JSON_ADD_OBJECT(response_json, "header", header_json);
   	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

  	JSON_PUT_OBJECT(header_json);
   	JSON_PUT_OBJECT(response_json);
	
	return 0;
}

int _get_vwan_mode_static(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json = NULL;
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
//	p_debug("ipaddr = %s,netmask=%s,gateway=%s,dns_list=%s", ipaddr,netmask,gateway,dns_list);
	tmp = strstr(dns_list," ");
	if(tmp!=NULL)
	{
      memcpy(dns1_ip,dns_list,tmp-dns_list);
	  strcpy(dns2_ip,tmp+1); 
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
			header->i_code = ERROR_GET_STATIC_STATUS;
		}else{
			tmp = strstr(dns_list," ");
//			p_debug("dns_list = %s",dns_list);
			if(tmp!=NULL)
			{
				if(strstr(dns_list,"'"))
				{
					memcpy(dns1_ip,dns_list+1,tmp-dns_list-1);
					memcpy(dns2_ip,tmp+1,strlen(tmp)-2); 
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

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _client_connect_to_ap(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
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
	const char *local_ssid = JSON_GET_OBJECT_VALUE(local_ssid_json,string);
	const char *local_password = JSON_GET_OBJECT_VALUE(local_password_json,string);
	const char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	const char *ap_ssid = JSON_GET_OBJECT_VALUE(ssid_json,string);
	uint8_t channel = JSON_GET_OBJECT_VALUE(channel_json,int);
	const char *encrypt = JSON_GET_OBJECT_VALUE(encrypt_json,string);
	const char *password = JSON_GET_OBJECT_VALUE(password_json,string);
	int32_t repeater_ret = 0;
	Repeater_Param rep_param;
	memset(&rep_param,0,sizeof(Repeater_Param));
	char is_uselocal_str[2] = {0};
	sprintf(rep_param.is_uselocal,"%d",is_uselocal);
	sprintf(rep_param.channel,"%d",channel);
	sprintf(rep_param.is_connect,"%d",0);

	if(local_ssid&&*local_ssid)
	{
		strcpy(rep_param.local_ssid,local_ssid);
	}
	
	if(local_password&&*local_password)
	{
		strcpy(rep_param.local_password,local_password);
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
//	p_debug("rep_param.local_ssid=%s,rep_param.local_password=%s", rep_param.local_ssid,rep_param.local_password);
	repeater_ret = set_to_repeart(&rep_param);
	if(repeater_ret < 0)
	{
		header->i_code = ERROR_SET_REPEATER_FAIL;
	}

	uint8_t repeater_flag = 0;
	uint8_t wifi_flag = 0;
	repeater_flag = (get_init_status()&2) >> 1;
	wifi_flag = get_init_status()&1;
	if(repeater_flag == 0 && wifi_flag == 0)
	{
       set_init_status(2);
	}
	restart_network();

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _get_repeater_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	#define SSID_LENGTH 32
	#define PASSOWRD_LENGTH 32
	#define ENCRYPY_LEN 16

	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=NULL;
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
	memset(&rep_param,0,sizeof(Repeater_Param));
    	repeater_ret = get_repeart_status(&rep_param);	// LIB API

	if(repeater_ret >= 0 )
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
//		p_debug("_get_repeater_status:ssid = %s\n",ssid);
	}
	else{
		header->i_code = ERROR_GET_REPEATER_STATUS;
	}

	JSON_ADD_OBJECT(rep_bri_info, "is_uselocal",JSON_NEW_OBJECT(is_uselocal,boolean));
	JSON_ADD_OBJECT(rep_bri_info, "local_ssid",JSON_NEW_OBJECT(local_ssid,string));
	JSON_ADD_OBJECT(rep_bri_info, "local_password",JSON_NEW_OBJECT(local_password,string));
	JSON_ADD_OBJECT(rep_bri_info, "mac",JSON_NEW_OBJECT(mac,string));
	JSON_ADD_OBJECT(rep_bri_info, "ssid",JSON_NEW_OBJECT(ssid,string));
	JSON_ADD_OBJECT(rep_bri_info, "password",JSON_NEW_OBJECT(password,string));
	JSON_ADD_OBJECT(rep_bri_info, "channel",JSON_NEW_OBJECT(channel,int));
	JSON_ADD_OBJECT(rep_bri_info, "encrypt",JSON_NEW_OBJECT(encrypt,string));
	JSON_ADD_OBJECT(rep_bri_info, "is_connect",JSON_NEW_OBJECT(is_connect,boolean));
	JSON_ARRAY_ADD_OBJECT (response_data_array,rep_bri_info);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}


int imove_set_password(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
   	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	JObj *obj_passpwd_json = JSON_GET_OBJECT(para_json,"router_password");
   	const char *cpassword = JSON_GET_OBJECT_VALUE(obj_passpwd_json,string);

    IM_RootPwdSet(cpassword);

	header_json = imove_create_json_msg_header(header);
    JSON_ADD_OBJECT(response_json, "header", header_json);	
    snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(header_json);	
    JSON_PUT_OBJECT(response_json);
	
	return 0;
}


int imove_password_modification(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
   	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

    JObj *old_pass_json = JSON_GET_OBJECT(para_json,"router_password");
    const char *old_password = JSON_GET_OBJECT_VALUE(old_pass_json,string);
	JObj *new_pass_json = JSON_GET_OBJECT(para_json,"router_newpassword");
    const char *new_password = JSON_GET_OBJECT_VALUE(new_pass_json,string);
	uint8_t pass_ret =  IM_RootPwdAuth(old_password);

	if(pass_ret != 0)
	{
       header->i_code = PLEASE_REINPUT_PASSWORD;
	}
	else
	{
       IM_RootPwdSet(new_password);
	}

	header_json = imove_create_json_msg_header(header);
    JSON_ADD_OBJECT(response_json, "header", header_json);	
    snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(header_json);	
    JSON_PUT_OBJECT(response_json);
	
	return 0;
}

int imove_close_route_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	
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
	  wifi_switch_hot(str_fre_24G,str_hot,switch_off);	// LIB API
	  wifi_switch_hot(str_fre_5G,str_hot,switch_off);
	  restart_wifi();
	}else if(close_type ==2 ){
	   wifi_switch_hot(str_fre_24G,str_hot,switch_on);
	   wifi_switch_hot(str_fre_5G,str_hot,switch_on);
	   restart_wifi();
	}else if(close_type ==3 ){
//		p_debug("Reset_Sleep threadStatus->sleep_flag = %d",threadStatus->sleep_flag);
	   	Reset_Sleep();			// LIB API
	}else if(close_type ==4 ){
	   	Reset_wakeup();			// LIB API
	}else if(close_type ==5 ){
		Reset_system();			// LIB API
	}else if(close_type ==6 ){
		Reset_Halt();
	}

	header_json = imove_create_json_msg_header(header);
    	JSON_ADD_OBJECT(response_json, "header", header_json);
		
    	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);	
    	JSON_PUT_OBJECT(response_json);
		
	return 0;
}

int _Reset_factory(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
  Reset_factory();
  return 0;
}

int imove_reset_getversion(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
#define MSG_SERVER_VERSION_LEN 	32
#define MSG_SERVER_FALSE 			0

	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=NULL;
    	char version[MSG_SERVER_VERSION_LEN] = {0};
	char newversion[MSG_SERVER_VERSION_LEN] = {0};
	uint8_t is_update = MSG_SERVER_FALSE;
    	Reset_getversion(version);			// LIB API
	//ms_get_new_version(newversion);//获取服务器版本接口
	if(!strcmp(version,newversion))
	{
		is_update = MSG_SERVER_FALSE;
	}else{
 		is_update = MSG_SERVER_TRUE;
	}
//	p_debug("the longsys fw newest version : %s",version);
    	JSON_ADD_OBJECT(response_para_json, "kernel_ver", JSON_NEW_OBJECT(version,string));
	JSON_ADD_OBJECT(response_para_json, "kernel_newver", JSON_NEW_OBJECT(newversion,string));
	JSON_ADD_OBJECT(response_para_json, "is_update", JSON_NEW_OBJECT(is_update,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);

	return 0;
}

int imove_get_fw_upgrade_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	uint32_t fw_file_size = 0;
	uint32_t fw_down_size = 0;
	uint8_t update_state = 0;
#if 0	
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
#endif

	fw_file_size = g_firmware_info.tlen;
	fw_down_size = g_firmware_info.dlen;
	update_state = g_firmware_info.state;

    	JSON_ADD_OBJECT(response_para_json, "file_size", JSON_NEW_OBJECT(fw_file_size,int));
	JSON_ADD_OBJECT(response_para_json, "download_size", JSON_NEW_OBJECT(fw_down_size,int));
	JSON_ADD_OBJECT(response_para_json, "update_state", JSON_NEW_OBJECT(update_state,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);

	if (g_firmware_info.state == 3)		// 3 :success download fw
	{
		g_firmware_info.up_flag = 1;
	}
	
	return 0;
}

int dm_fw_upgrade()
{
	p_debug("is going to Reset_fwupgrade\n");
    Reset_fwupgrade(UPGRADE_FW_PATH);
	return 0;
}

int dm_upgrade_firmware(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
#if 0
	char *fw_url = "http://172.16.2.79/test/openwrt-rtkmips-rtl8198c-AP-fw_shengming.bin";
	char *fw_md5 = "A5A14815CAC5FA9D725E2A6BA436BF3D";
	S_IM_MSG_FIRMWARE firmware ;

	memset(&firmware,0,sizeof(S_IM_MSG_FIRMWARE));

	if(fw_url!=NULL&&fw_md5!=NULL&&*fw_url&&*fw_md5)
	{
		memcpy(firmware.im_url,fw_url,MAX_URL_LEN);
		memcpy(firmware.im_md5,fw_md5,MAX_STRING);
		firmware.dlen = (int32_t *)&(threadStatus->complete_fw_len);
		firmware.tlen = (int32_t *)&(threadStatus->total_fw_len);
		threadStatus->upgrade_ret = im_upgrade_firmware(&firmware, dm_fw_upgrade);
	}else{
		header->code = ERROR_PARA_LENGTH_LONG;
	}
#endif
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_wlan_getaccesspointlist(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json= NULL;
    	char *fre = "24G";
    	uint8_t i = 0;
	int list_ret = 0;
	ap_list_info_t ap_list_info;
	memset(&ap_list_info,0,sizeof(ap_list_info_t));
	list_ret = get_scan_result_t(fre,&ap_list_info);
	if(list_ret >= 0)
	{
		if(ap_list_info.count > 100)
		{
			ap_list_info.count = 100;
		}
		JObj *ap_info[ap_list_info.count];
		for(i = 0;i < ap_list_info.count;i++)
		{
			ap_info[i] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(ap_info[i], "ssid",JSON_NEW_OBJECT(ap_list_info.ap_info[i].ssid,string));
			JSON_ADD_OBJECT(ap_info[i], "channel",JSON_NEW_OBJECT(ap_list_info.ap_info[i].channel,int));
			JSON_ADD_OBJECT(ap_info[i], "Is_encrypt",JSON_NEW_OBJECT(ap_list_info.ap_info[i].Is_encrypt,boolean));
			JSON_ADD_OBJECT(ap_info[i], "encrypt",JSON_NEW_OBJECT(ap_list_info.ap_info[i].encrypt,string));
			JSON_ADD_OBJECT(ap_info[i], "tkip_aes",JSON_NEW_OBJECT(ap_list_info.ap_info[i].tkip_aes,string));
			JSON_ADD_OBJECT(ap_info[i], "wifi_signal",JSON_NEW_OBJECT(ap_list_info.ap_info[i].wifi_signal,int));;
			JSON_ARRAY_ADD_OBJECT (response_data_array,ap_info[i]);
		}
	}else{
		header->i_code = ERROR_GET_AP_LSIT;
	}
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	
	return 0;
}

int Wlan_get_cur_speed(char *total_down_speed)
{
	char speed_list[SPEED_LIST_LEN] = {0};
	int ret_speed = -1;
	char *start = NULL;
	char *end = NULL;
	char total_down[32] = {0};
	char total_up[32] = {0};
	char total_count[32] = {0};
	char total_up_speed[32] = {0};
	ret_speed = get_speed_info(speed_list,SPEED_LIST_LEN);
	if(ret_speed < 0)
	{
		return -1;
	}
	if(speed_list!=NULL&&*speed_list)
	{
		start = speed_list;
		 end = strstr(start,",");
		  memcpy(total_down,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_up,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_count,start,end-start);
		 end ++;
		 start = end;
		 end = strstr(end,",");
		 memcpy(total_down_speed,start,end-start);//total_downloadsize
		 end ++;
		 start = end;
		 end = strstr(end,"}");
		 memcpy(total_up_speed,start,end-start);//上传速度
	}else
	{
		return -1;
	}
	return 0;
}

int _Wlan_get_cur_speed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json=NULL;
	char route_speed[SPEED_LIST_LEN] ={0};
	int ret_speed = -1;
	uint32_t route_speed_size = 0;
	ret_speed = Wlan_get_cur_speed(route_speed);
	if(ret_speed <0)
	{
		header->i_code == ERROR_GET_CUR_SPEED_ERROR;
	}
	route_speed_size = atoi(route_speed);

	route_speed_size = route_speed_size/1000;
    	JSON_ADD_OBJECT(response_para_json, "net_speed", JSON_NEW_OBJECT(route_speed_size,int));
	
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	header_json = imove_create_json_msg_header(header);
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
   	JSON_PUT_OBJECT(response_json);
	return 0;
}

int backupdevmaxupspeed(char *mac,int maxupspeed)
{
	JObj* dev_info_json = NULL;
	JObj* single_dev_json = JSON_NEW_EMPTY_OBJECT();
	dev_info_json = json_object_from_file(RATE_LIMIT_UP_CONFIG);
	 if(dev_info_json != NULL)
   	{
   		JObj *mac_json = JSON_GET_OBJECT(dev_info_json,mac);
		JObj *connect_time_json = JSON_GET_OBJECT(mac_json,"connect_time");
		int dev_contime_size = JSON_GET_OBJECT_VALUE(connect_time_json,int);
		
		JObj *down_speed_json = JSON_GET_OBJECT(mac_json,"download_maxspeed");
		uint32_t download_maxspeed = JSON_GET_OBJECT_VALUE(down_speed_json,int);

		JObj *total_down_json = JSON_GET_OBJECT(mac_json,"total_down");
		uint32_t total_down = JSON_GET_OBJECT_VALUE(total_down_json,int);

		JObj *ip_json = JSON_GET_OBJECT(mac_json,"ip");
		const char *ip = JSON_GET_OBJECT_VALUE(ip_json,string);
		
		p_debug("upload_maxspeed = %d",maxupspeed);
		JSON_ADD_OBJECT(single_dev_json, "upload_maxspeed", JSON_NEW_OBJECT(maxupspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "download_maxspeed", JSON_NEW_OBJECT(download_maxspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "connect_time", JSON_NEW_OBJECT(dev_contime_size,int));
		JSON_ADD_OBJECT(single_dev_json, "ip", JSON_NEW_OBJECT(ip,string));
		JSON_ADD_OBJECT(single_dev_json, "total_down", JSON_NEW_OBJECT(total_down,int));
		JSON_ADD_OBJECT(dev_info_json, mac, single_dev_json);
		json_object_to_file(RATE_LIMIT_UP_CONFIG, dev_info_json);
	}else{
		dev_info_json = JSON_NEW_EMPTY_OBJECT();
		JSON_ADD_OBJECT(single_dev_json, "upload_maxspeed", JSON_NEW_OBJECT(maxupspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "download_maxspeed", JSON_NEW_OBJECT(-1,int));
		JSON_ADD_OBJECT(single_dev_json, "connect_time", JSON_NEW_OBJECT(0,int));
		JSON_ADD_OBJECT(single_dev_json, "total_down", JSON_NEW_OBJECT(0,int));
		JSON_ADD_OBJECT(single_dev_json, "ip", JSON_NEW_OBJECT("",string));
		JSON_ADD_OBJECT(dev_info_json, mac, single_dev_json);
		json_object_to_file(RATE_LIMIT_UP_CONFIG, dev_info_json);
	}
	JSON_PUT_OBJECT(dev_info_json);
	return 0;
}

int imove_set_dev_upload_maxspeed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	const char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	JObj *max_speed_json = JSON_GET_OBJECT(para_json,"max_uploadspeed");
	int32_t max_speed = JSON_GET_OBJECT_VALUE(max_speed_json,int);//KB/S
	uint64_t max_speed_bit = 0;
	char speed_limit[64] = {0};
	char *prio = "6";

	if(check_valid_mac(mac) >= 0)
	{
		if(max_speed >= 0)
		{
			max_speed_bit = max_speed*1000;
			sprintf(speed_limit, "%lld", max_speed_bit);
			start_speed_limit();
			set_up_speed_limit(mac,speed_limit,prio);
			stop_speed_limit();
		}else{
			start_speed_limit();
			del_up_speed_limit(mac);
			stop_speed_limit();
		}
		backupdevmaxupspeed(mac,max_speed);
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}


int backupdevmaxdownspeed(char *mac,int maxdownspeed)
{
	JObj* dev_info_json = NULL;
	JObj* single_dev_json = JSON_NEW_EMPTY_OBJECT();
	dev_info_json = json_object_from_file(RATE_LIMIT_UP_CONFIG);
	 if(dev_info_json != NULL)
   	{
   		JObj *mac_json = JSON_GET_OBJECT(dev_info_json,mac);
		JObj *connect_time_json = JSON_GET_OBJECT(mac_json,"connect_time");
		int dev_contime_size = JSON_GET_OBJECT_VALUE(connect_time_json,int);
		
		JObj *up_speed_json = JSON_GET_OBJECT(mac_json,"upload_maxspeed");
		int32_t upload_maxspeed = JSON_GET_OBJECT_VALUE(up_speed_json,int);

		JObj *total_down_json = JSON_GET_OBJECT(mac_json,"total_down");
		uint32_t total_down = JSON_GET_OBJECT_VALUE(total_down_json,int);

		JObj *ip_json = JSON_GET_OBJECT(mac_json,"ip");
		const char *ip = JSON_GET_OBJECT_VALUE(ip_json,string);
		
//		p_debug("download_maxspeed = %d",maxdownspeed);
		JSON_ADD_OBJECT(single_dev_json, "upload_maxspeed", JSON_NEW_OBJECT(upload_maxspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "download_maxspeed", JSON_NEW_OBJECT(maxdownspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "connect_time", JSON_NEW_OBJECT(dev_contime_size,int));
		JSON_ADD_OBJECT(single_dev_json, "ip", JSON_NEW_OBJECT(ip,string));
		JSON_ADD_OBJECT(single_dev_json, "total_down", JSON_NEW_OBJECT(total_down,int));
		JSON_ADD_OBJECT(dev_info_json, mac, single_dev_json);
		json_object_to_file(RATE_LIMIT_UP_CONFIG, dev_info_json);
	}else{
		dev_info_json = JSON_NEW_EMPTY_OBJECT();
		JSON_ADD_OBJECT(single_dev_json, "upload_maxspeed", JSON_NEW_OBJECT(-1,int));
		JSON_ADD_OBJECT(single_dev_json, "download_maxspeed", JSON_NEW_OBJECT(maxdownspeed,int));
		JSON_ADD_OBJECT(single_dev_json, "connect_time", JSON_NEW_OBJECT(0,int));
		JSON_ADD_OBJECT(single_dev_json, "ip", JSON_NEW_OBJECT("",string));
		JSON_ADD_OBJECT(dev_info_json, mac, single_dev_json);
		json_object_to_file(RATE_LIMIT_UP_CONFIG, dev_info_json);
	}
	JSON_PUT_OBJECT(dev_info_json);
}

int imove_set_dev_download_maxspeed(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *mac_json = JSON_GET_OBJECT(para_json,"mac");
	const char *mac = JSON_GET_OBJECT_VALUE(mac_json,string);
	JObj *max_speed_json = JSON_GET_OBJECT(para_json,"max_downloadspeed");
	int32_t max_speed = JSON_GET_OBJECT_VALUE(max_speed_json,int);
	uint64_t max_speed_bit = 0;
	char speed_limit[64] = {0};
	char *prio = "6";
	
	if(check_valid_mac(mac) >= 0)	// check_valid_mac() is LIB API
	{
		if(max_speed >= 0)
		{
			max_speed_bit = max_speed*1000;
			sprintf(speed_limit, "%lld", max_speed_bit);
			start_speed_limit();
			set_down_speed_limit(mac,speed_limit,prio);
			stop_speed_limit();
		}else{
			start_speed_limit();
			del_down_speed_limit(mac);
			stop_speed_limit();
		}
		backupdevmaxdownspeed(mac,max_speed);
	}else{
		header->i_code = ERROR_PARA_INVALIDE;
	}

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_format_disk(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *para_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *disk_json = JSON_GET_OBJECT(para_json,"disk");
	JObj *drivedev_json = JSON_GET_OBJECT(para_json,"dev_node");
	JObj *format_json = JSON_GET_OBJECT(para_json,"is_format");
	const char *drivname = NULL;
	const char *drivedev = NULL;  
	uint8_t format_flag = MSG_SERVER_FALSE;
	int format_ret = -1;
	
	if(disk_json != NULL&&drivedev_json != NULL&&format_json != NULL)
	{
		drivname = JSON_GET_OBJECT_VALUE(disk_json,string);
		drivedev = JSON_GET_OBJECT_VALUE(drivedev_json,string);  
		format_flag = JSON_GET_OBJECT_VALUE(format_json,int); 
		p_debug("drivname = %s,format_flag = %d,drivedev = %s\n",drivname,format_flag,drivedev);
		if(drivname != NULL&&drivedev != NULL&&format_flag == 1)
		{
			if(strlen(drivname) >= 4)
			{
				if(strstr(drivname,"Hdisk"))
				{
					p_debug("Format_formatdisk\n");
					format_ret = Format_formatdisk(drivname, drivedev, NTFS_TYPE);
					if(format_ret!=0)
					{
						header->i_code = ERROR_FORMAT_DISK_FAIL;
					}
				}else{
					header->i_code = ERROR_NO_SUPPORT_FORMAT;
				}
			}else{
				p_debug("Format_formatall\n");
				format_ret = Format_formatall(NTFS_TYPE);
				if(format_ret!=0)
				{
					header->i_code = ERROR_FORMAT_DISK_FAIL;
				}
			}
		}
	}
	else
	{
		header->i_code = ERROR_PARA_INVALIDE;
	}
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_wlan_get_connect_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_pppoe_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_dhcp_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_static_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_repeater_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	
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

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_pppoe_json);
	JSON_PUT_OBJECT(response_dhcp_json);
	JSON_PUT_OBJECT(response_static_json);
	JSON_PUT_OBJECT(response_repeater_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_password_exist(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* sign_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	
	uint8_t is_password = Password_exist();
    	JSON_ADD_OBJECT(response_para_json, "is_password", JSON_NEW_OBJECT(is_password,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_wlan_get_connect_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	uint8_t is_internet =MSG_SERVER_FALSE;
	//is_internet =   Wlan_get_connect_type();
    	JSON_ADD_OBJECT(response_para_json, "is_internet", JSON_NEW_OBJECT(is_internet,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	header_json = imove_create_json_msg_header(header);
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_wlan_get_repeater_type(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;
	uint8_t is_connect =MSG_SERVER_FALSE;
	
	//is_connect =    Wlan_get_repeater_type();
    	JSON_ADD_OBJECT(response_para_json, "is_connect", JSON_NEW_OBJECT(is_connect,boolean));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_para_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
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

int handle_getStorageInfo(JObj* rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	JObj *disk_info_array = JSON_NEW_ARRAY();
	all_disk_t mAll_disk_t;
	uint8_t drive_count = 0;
	int i = 0;
	int j = 6;
	int private_exist = 0;
	uint32_t private_total_size = 0;
	uint32_t private_free_size = 0;
	char private_dev[32] = {0};
	int32_t private_isformat = MSG_SERVER_TRUE;
	uint8_t type = 0;
	memset(&mAll_disk_t,0,sizeof(all_disk_t));
	int32_t storage_ret = Format_getstorage (&mAll_disk_t);
	if(storage_ret != 0)
	{
		header->i_code = ERROR_CODE_NO_DRIVE;
	}
	drive_count = mAll_disk_t.count;
	JObj *drive_info[16];
	for(i = 0;i < 16;i++)
	{
		drive_info[i] = NULL;
	}
	p_debug("drive_count = %d",drive_count);
	for(i  =0;i < drive_count;i++)
    {
    	p_debug("mAll_disk_t.disk[%d].name = %s",i,mAll_disk_t.disk[i].name);
		if(!strcmp(mAll_disk_t.disk[i].name,HD_DISK1))
		{
			drive_info[0] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[0], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[0], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[0], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[0], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[0], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[0], "hd_type",JSON_NEW_OBJECT(1,int));
			JSON_ADD_OBJECT(drive_info[0], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
			if(access(PRIVATE_FULL_PATH,F_OK)!=-1)
			{
				private_exist = 1;
				private_total_size = mAll_disk_t.disk[i].total_size;
				private_free_size = mAll_disk_t.disk[i].free_size;
				strcpy(private_dev,mAll_disk_t.disk[i].dev);
				private_isformat = MSG_SERVER_TRUE;
			}
		}
		else if(!strcmp(mAll_disk_t.disk[i].name,HD_DISK2))
		{
			drive_info[1] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[1], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[1], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[1], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[1], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[1], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[1], "hd_type",JSON_NEW_OBJECT(1,int));
			JSON_ADD_OBJECT(drive_info[1], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
		}else if(!strcmp(mAll_disk_t.disk[i].name,U_DISK1))
		{
			drive_info[3] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[3], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[3], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[3], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[3], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[3], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[3], "hd_type",JSON_NEW_OBJECT(3,int));
			JSON_ADD_OBJECT(drive_info[3], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
		}else if(!strcmp(mAll_disk_t.disk[i].name,U_DISK2))
		{
			drive_info[4] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[4], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[4], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[4], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[4], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[4], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[4], "hd_type",JSON_NEW_OBJECT(3,int));
			JSON_ADD_OBJECT(drive_info[4], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
		}else if(!strcmp(mAll_disk_t.disk[i].name,SD_DISK1))
		{
			drive_info[5] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[5], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[5], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[5], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[5], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[5], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[5], "hd_type",JSON_NEW_OBJECT(2,int));
			JSON_ADD_OBJECT(drive_info[5], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
		}else if(!strcmp(mAll_disk_t.disk[i].name,SD_DISK2))
		{
			drive_info[6] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[6], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[6], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[6], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[6], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[6], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[6], "hd_type",JSON_NEW_OBJECT(2,int));
			JSON_ADD_OBJECT(drive_info[6], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
		}else{
			if(strstr(mAll_disk_t.disk[i].name,HD_DISK))
			{
				type = 1;
			}else if(strstr(mAll_disk_t.disk[i].name,U_DISK)){
				type = 3;
			}else if(strstr(mAll_disk_t.disk[i].name,SD_DISK)){
				type = 2;
			}
			drive_info[j] = JSON_NEW_EMPTY_OBJECT();
			JSON_ADD_OBJECT(drive_info[j], "disk",JSON_NEW_OBJECT(mAll_disk_t.disk[i].name,string));
			JSON_ADD_OBJECT(drive_info[j], "full_path",JSON_NEW_OBJECT(mAll_disk_t.disk[i].path,string));
			JSON_ADD_OBJECT(drive_info[j], "total_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].total_size,int));
			JSON_ADD_OBJECT(drive_info[j], "free_size",JSON_NEW_OBJECT(mAll_disk_t.disk[i].free_size,int));
			JSON_ADD_OBJECT(drive_info[j], "dev_node",JSON_NEW_OBJECT(mAll_disk_t.disk[i].dev,string));
			JSON_ADD_OBJECT(drive_info[j], "hd_type",JSON_NEW_OBJECT(type,int));
			JSON_ADD_OBJECT(drive_info[j], "is_format", JSON_NEW_OBJECT(mAll_disk_t.disk[i].is_format,boolean));
			j++;
		}
	}
	if(private_exist == 1)
	{
		drive_info[2] = JSON_NEW_EMPTY_OBJECT();
		JSON_ADD_OBJECT(drive_info[2], "disk",JSON_NEW_OBJECT(IMOVE_PRIVATE_NAME,string));
		JSON_ADD_OBJECT(drive_info[2], "full_path",JSON_NEW_OBJECT(PRIVATE_FULL_PATH,string));
		JSON_ADD_OBJECT(drive_info[2], "total_size",JSON_NEW_OBJECT(private_total_size,int));
		JSON_ADD_OBJECT(drive_info[2], "free_size",JSON_NEW_OBJECT(private_free_size,int));
		JSON_ADD_OBJECT(drive_info[2], "dev_node",JSON_NEW_OBJECT(private_dev,string));
		JSON_ADD_OBJECT(drive_info[2], "is_format", JSON_NEW_OBJECT(private_isformat,boolean));
		JSON_ADD_OBJECT(drive_info[2], "hd_type",JSON_NEW_OBJECT(1,int));
	}
	for (i = 0;i < j;i++)
	{
		if(drive_info[i] != NULL)
		{
			p_debug("i = %d",i);
			JSON_ARRAY_ADD_OBJECT (disk_info_array,drive_info[i]);
		}
	}
	JSON_ADD_OBJECT(response_para_json, "disk_info", disk_info_array);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);
	
	header_json = imove_create_json_msg_header(header);
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_handle_cp_cancel(JObj *rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
   	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *response_data_array = JSON_NEW_ARRAY();
   	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
   	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
	IM_ST_file_op_rd *node = NULL;
	src_files_t *src_file = NULL;
   	header->i_code = 0;
  // 	 threadStatus->thread_cancel_flag = 0;
	node = imove_find_fileop_by_id(event_id);
  	if (node == NULL)
  	{
		p_debug("find event_id:%d failed\n", event_id);
		JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(0,int));
	}
	else
	{
		src_file = (src_files_t *)node->addr_file;
		if (src_file == NULL)
		{
			JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(0,int));
		}
		else
		{
			src_file->th_info.thread_cancel_flag = 0;
			JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
		}
	}	
	
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_file_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_des_driv_surplus_size(char *des_path)
{
	uint32_t des_driv_size;
	all_disk_t mAll_disk_t;
	int32_t storage_ret = 0;
	int i = 0;
	memset(&mAll_disk_t,0,sizeof(all_disk_t));
	storage_ret = Format_getstorage (&mAll_disk_t);
	if(storage_ret != 0)
	{
		return 0;
	}
	if(access(des_path,F_OK)!=-1)
	{
		for(i = 0;i < mAll_disk_t.count;i++)
		{
			if(strstr(des_path,mAll_disk_t.disk[i].name))
			{
				des_driv_size = mAll_disk_t.disk[i].free_size;
			}
		}
	}else{
		return 0;
	}
	return des_driv_size;
}

void *thread_handle_cp(void *arg)
{
	int i = 0;
	IM_ST_file_op_rd *file_op = (IM_ST_file_op_rd *)arg;
	src_files_t *src_files = (src_files_t *)(file_op->addr_file);
	char cp_retstr[FILE_HANDLE_RET_STR_LEN] = {0};
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};

	for (i = 0; i < src_files->count; i++)
	{
		snprintf(des_full_path, FULL_FILE_PATH_LENGTH, "%s", 
				dm_concat_path_file(src_files->dst_dir, bb_get_last_path_component_strip(src_files->file_t[i].file_name)));
		p_debug("des_full_path = %s",des_full_path);
		if(access(des_full_path,F_OK)!=-1)  
		{
			rename_process(des_full_path);
		}
		char *file_argv[]={"cp", "-r", src_files->file_t[i].file_name, src_files->dst_dir};
		handle_cp(CP_MOUNT,file_argv,cp_retstr, &(src_files->th_info));
	}

	file_op->status = 0;
}

int imove_handle_cp(JObj *rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	uint8_t count = 0;
	uint8_t i =0;
	const char *des_path = NULL;
	const char *src_path = NULL;
	JObj *header_json = NULL;
	JObj *response_data_array = NULL;
	JObj *response_file_json = NULL;
	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
	JObj *des_json = JSON_GET_OBJECT(file_json,"target_dir");
	des_path=JSON_GET_OBJECT_VALUE(des_json,string);
	count = JSON_GET_ARRAY_LEN(src_json);
	src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
	des_json = JSON_GET_OBJECT(file_json,"target_dir");
	des_path = JSON_GET_OBJECT_VALUE(des_json,string);
	count = JSON_GET_ARRAY_LEN(src_json);
	char cp_retstr[FILE_HANDLE_RET_STR_LEN];
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char des_path_tmp[FULL_FILE_PATH_LENGTH] = {0};
	static src_files_t src_files = {.file_t = {{0}, 0}, .count = 0, .total_size = 0, .i_radom = 0};
	struct stat statbuf;
	uint32_t cp_ret = 0;
	IM_ST_file_op_rd *tmp_rd = NULL;
	int ret = 0;
	
	strcpy(des_path_tmp,des_path);
	snprintf(src_files.dst_dir, sizeof(src_files.dst_dir), "%s", des_path);
	
	cp_ret = get_des_driv_surplus_size(des_path_tmp);
	if(cp_ret <= 0)
	{
		header->i_code = ERROR_CODE_DES_NOT_EXIST;
		goto OUT;
	}
	
	src_files.count = count;
	if(count > 1024)
	{
		src_files.count = 1024;
	}
	
	for(i = 0;i < src_files.count;i++)
	{
		src_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(src_json,i),"fileordir_name"),string);
		if(access(src_path,F_OK)!=-1)
		{
			strcpy(src_files.file_t[i].file_name,src_path);
			if (lstat(src_files.file_t[i].file_name, &statbuf)) 
			{
				p_debug(src_files.file_t[i].file_name);
				header->i_code = ERROR_CODE_SRC_NOT_EXIST;
				goto OUT;
			}
			else
			{
				p_debug("src_files.file_t[%d].file_name = %s",i,src_files.file_t[i].file_name);
				p_debug("statbuf.st_size = %u",statbuf.st_size);
				src_files.total_size += statbuf.st_size;
				src_files.total_size = src_files.total_size/1024;
				p_debug("src_files.total_size = %u",src_files.total_size);
			}
		}
		else
		{
			header->i_code = ERROR_CODE_SRC_NOT_EXIST;
			goto OUT;
		}
	}
	
	p_debug("src_files.total_size = %u,mv_ret = %u",src_files.total_size,cp_ret);
	if(src_files.total_size > cp_ret)
	{
		p_debug("access large");
		header->i_code = ERROR_SRC_FILE_LARGE;
		goto OUT;
	}

	tmp_rd = create_new_node();
	if (tmp_rd == NULL)
		goto OUT;

	tmp_rd->i_radom = imove_generate_radom();
	tmp_rd->status = 2;
	tmp_rd->addr_file = NULL;
	src_files.i_radom = tmp_rd->i_radom;
	src_files.th_info.thread_cancel_flag = 1;
	tmp_rd->addr_file = (char *)&src_files;
	add_new2queue(&g_file_op_rd, tmp_rd);
	
	response_data_array = JSON_NEW_ARRAY();
	response_file_json=JSON_NEW_EMPTY_OBJECT();
	JSON_ADD_OBJECT(response_file_json, "event_id", JSON_NEW_OBJECT(tmp_rd->i_radom,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);

	ret = imove_create_thread_gen(&thread_handle_cp, tmp_rd, 1);
	if (ret)
	{
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		JSON_PUT_OBJECT(response_data_array);
	}
	
OUT:
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	if (header->i_code == 0)
	{
		JSON_ADD_OBJECT(response_json, "data", response_data_array);
	}
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_rm_cancel(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
	header->i_code = 0;
//	threadStatus->thread_cancel_flag = 0;

	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_file_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	
	return 0;
}

int imove_handle_rm(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
#define RM_MOUNT 					3 
#define FILE_HANDLE_RET_STR_LEN 	256
	uint8_t count = 0;
   	uint8_t i =0;
   	const char *des_path = NULL;
   	char rm_retstr[FILE_HANDLE_RET_STR_LEN];
   	JObj* header_json = NULL;
   	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_file_json = NULL;
	JObj *response_data_array = NULL;
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data"); 
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   	JObj *des_json = JSON_GET_OBJECT(file_json,"fileordir_list");
   	count = JSON_GET_ARRAY_LEN(des_json);
	char cmd_line[256] = {0};
	IM_ST_file_op_rd *tmp_rd = NULL;
	int null_flag = 0;
	
	header->i_code = 0;	
	
   	for(i=0;i<count;i++)
   	{ 
   	    	des_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(des_json,i),"fileordir_name"),string);
       	if(access(des_path,F_OK)!=-1)
	   	{
          		p_debug("des_path = %s\n",des_path);
	      		snprintf(cmd_line, sizeof(cmd_line), "rm -rf %s", des_path);
			system(cmd_line);
	   	}else{
	      		header->i_code = ERROR_CODE_DES_NOT_EXIST;
	   	}
   	}

	if (header->i_code != ERROR_CODE_DES_NOT_EXIST)
	{
		tmp_rd = create_new_node();
		if (tmp_rd == NULL)
		{
			null_flag = 1;
			goto null_h;
		}
		tmp_rd->i_radom = imove_generate_radom();
		tmp_rd->status = 0;
		g_file_op_rd = tmp_rd;
		add_new2queue(&g_file_op_rd, tmp_rd);
	}

	response_file_json=JSON_NEW_EMPTY_OBJECT();
	response_data_array = JSON_NEW_ARRAY();
	JSON_ADD_OBJECT(response_file_json, "event_id", JSON_NEW_OBJECT(tmp_rd->i_radom,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	
null_h:	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	
	if (0 == null_flag)
	{
		JSON_ADD_OBJECT(response_json, "data", response_data_array);
	}
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_rmdir(JObj * rpc_json,  IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json = JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *src_json = NULL;
	unsigned int count = 0;
	int i= 0;
	const char *src_path = NULL; 
	char cmd_line[128] = {0};
	unsigned int err_flag = 0;
		
	if (header->i_cmd == FN_FILE_RM_DIR)
	{
		 src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
		 count = JSON_GET_ARRAY_LEN(src_json);

		 for(i = 0; i < count; i++)
		 {
			src_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(src_json,i),"fileordir_name"),string);
			if (src_path == NULL)
			{
				err_flag = 1;
				goto err_hd;
			}

			p_debug("delete src_path:%s\n", src_path);
			if (access(src_path, F_OK) != 0)
			{
				err_flag = 1;
				goto err_hd;	
			}

			snprintf(cmd_line, sizeof(cmd_line), "rm -rf %s", src_path);
			system(cmd_line);
		 }
	}	
	else
	{
		header->i_code = ERROR_CODE_SRC_NOT_EXIST;
	}
err_hd:	
	if (err_flag)
	{
		header->i_code = ERROR_CODE_UNKNOW;
	}
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_handle_mv_cancel(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json = JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
	header->i_code = 0;
	IM_ST_file_op_rd *node = NULL;
	src_files_t *src_file = NULL;
//	threadStatus->thread_cancel_flag = 0;

	node = imove_find_fileop_by_id(event_id);
  	if (node == NULL)
  	{
		p_debug("find event_id:%d failed\n", event_id);
		JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(0,int));
	}
	else
	{
		src_file = (src_files_t *)node->addr_file;
		if (src_file == NULL)
		{
			JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(0,int));
		}
		else
		{
			src_file->th_info.thread_cancel_flag = 0;
			JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(1,int));
		}
	}
	
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_file_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

char*  last_char_is(const char *s, int c)
{
	if (s && *s) {
		size_t sz = strlen(s) - 1;
		s += sz;
		if ( (unsigned char)*s == c)
			return (char*)s;
	}
	return NULL;
}

char* dm_xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	if (r < 0)
		p_debug("xasprintf fail");
	return string_ptr;
}

char* dm_concat_path_file(const char *path, const char *filename)
{
	char *lc;

	if (!path)
		path = "";
	lc = last_char_is(path, '/');
	while (*filename == '/')
		filename++;
	return dm_xasprintf("%s%s%s", path, (lc==NULL ? "/" : ""), filename);
}

/*
 * "/"        -> "/"
 * "abc"      -> "abc"
 * "abc/def"  -> "def"
 * "abc/def/" -> ""
 */
char* bb_get_last_path_component_nostrip(const char *path)
{
	char *slash = strrchr(path, '/');

	if (!slash || (slash == path && !slash[1]))
		return (char*)path;

	return slash + 1;
}

/*
 * "/"        -> "/"
 * "abc"      -> "abc"
 * "abc/def"  -> "def"
 * "abc/def/" -> "def" !!
 */
char* bb_get_last_path_component_strip(char *path)
{
	char *slash = last_char_is(path, '/');

	if (slash)
		while (*slash == '/' && slash != path)
			*slash-- = '\0';

	return bb_get_last_path_component_nostrip(path);
}

void *thread_handle_mv(void *arg)
{
	int i = 0;
	IM_ST_file_op_rd *file_op = (IM_ST_file_op_rd *)arg;
	src_files_t *src_files = (src_files_t *)(file_op->addr_file);
	char mv_retstr[FILE_HANDLE_RET_STR_LEN] = {0};
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};

	assert(src_files);

	for (i = 0; i < src_files->count; i++)
	{
		snprintf(des_full_path, FULL_FILE_PATH_LENGTH, "%s", 
				dm_concat_path_file(src_files->dst_dir, bb_get_last_path_component_strip(src_files->file_t[i].file_name)));
		p_debug("des_full_path = %s src_file:%s\n",des_full_path, src_files->file_t[i].file_name);
		if(access(des_full_path,F_OK)!=-1)  
		{
			rename_process(des_full_path);
		}
		char *file_argv[]={"mv", "-f", src_files->file_t[i].file_name, des_full_path};
		handle_mv(MV_COUNT,file_argv,mv_retstr, &(src_files->th_info));
	}

	file_op->status = 0;
}

int _handle_mv(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
   	uint8_t count = 0;
   	uint8_t i =0;
   	char mv_retstr[FILE_HANDLE_RET_STR_LEN];
   	JObj* header_json=NULL;
   	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj* response_file_json = NULL;
   	JObj *response_data_array = NULL;
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);

	 JObj *src_json = NULL;
   	JObj *des_json = NULL;
   	const char *des_path = NULL;
   	const char *src_path = NULL; 
   	char src_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char des_path_tmp[FULL_FILE_PATH_LENGTH] = {0};
	static src_files_t src_files;
	struct stat statbuf;
	uint32_t mv_ret = 0;
 
	IM_ST_file_op_rd *tmp_rd = NULL;
   	int ret = 0;
	
	memset(&src_files,0,sizeof(src_files_t));

	src_json = JSON_GET_OBJECT(file_json,"fileordir_list");
   	des_json = JSON_GET_OBJECT(file_json,"target_dir");
   	des_path = JSON_GET_OBJECT_VALUE(des_json,string);
	
   	count = JSON_GET_ARRAY_LEN(src_json);
   	strcpy(des_path_tmp,des_path);
	snprintf(src_files.dst_dir, sizeof(src_files.dst_dir), "%s", des_path);
	
   	mv_ret = get_des_driv_surplus_size(des_path_tmp);
   	if(mv_ret <= 0)
   	{
			header->i_code = ERROR_CODE_DES_NOT_EXIST;
			goto rsp_h;
   	}
   	
   	
	src_files.count = count;
	if(count > 1024)
	{
		src_files.count = 1024;
	}
	
	for(i = 0; i < src_files.count; i++)
	{
		src_path=JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(JSON_GET_ARRAY_MEMBER_BY_ID(src_json,i),"fileordir_name"),string);
		 if(access(src_path,F_OK) != -1)
		 {
			strcpy(src_files.file_t[i].file_name,src_path);
			if (lstat(src_files.file_t[i].file_name, &statbuf)) 
			{
				p_debug(src_files.file_t[i].file_name);
				header->i_code = ERROR_CODE_SRC_NOT_EXIST;
				goto rsp_h;
			}
			else
			{
				p_debug("src_files.file_t[%d].file_name = %s\n",i,src_files.file_t[i].file_name);
				p_debug("statbuf.st_size = %u\n",statbuf.st_size);
				src_files.total_size += statbuf.st_size;
				src_files.total_size = src_files.total_size/1024;
				p_debug("src_files.total_size = %u\n",src_files.total_size);
			}
		 }
		 else
		 {
			 header->i_code = ERROR_CODE_SRC_NOT_EXIST;
			 goto rsp_h;
		 }
	}

	p_debug("src_files.total_size = %u,mv_ret = %u\n",src_files.total_size,mv_ret);
	if(src_files.total_size > mv_ret)
	{
		p_debug("access large");
		header->i_code = ERROR_SRC_FILE_LARGE;
		goto rsp_h;
	}
   
	tmp_rd = create_new_node();
	if (tmp_rd == NULL)
	{
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		goto rsp_h;
	}
	tmp_rd->i_radom = imove_generate_radom();
	tmp_rd->status = 2;
	tmp_rd->addr_file = NULL;
	src_files.i_radom = tmp_rd->i_radom;
	src_files.th_info.thread_cancel_flag = 1;
	tmp_rd->addr_file = (char *)&src_files;
	add_new2queue(&g_file_op_rd, tmp_rd);
	
	response_file_json = JSON_NEW_EMPTY_OBJECT();
	response_data_array = JSON_NEW_ARRAY();
   	JSON_ADD_OBJECT(response_file_json, "event_id", JSON_NEW_OBJECT(tmp_rd->i_radom,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);

	ret = imove_create_thread_gen(&thread_handle_mv, tmp_rd, 1);
	if (ret)
	{
		header->i_code = ERROR_SYN_RESOURCE_LIMIT;
		JSON_PUT_OBJECT(response_data_array);
	}
	
rsp_h:	
   	header_json = imove_create_json_msg_header(header);
	
	JSON_ADD_OBJECT(response_json, "header", header_json);
	if (0 == header->i_code)
	{
		JSON_ADD_OBJECT(response_json, "data", response_data_array);
	}
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int imove_handle_rn(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	uint8_t count = 0;
   	uint8_t i =0;
   	JObj* header_json= NULL;
   	JObj *response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   	JObj *src_json = NULL;
   	JObj *des_json = NULL;
   
   	const char *des_path = NULL;
   	const char *src_path = NULL; 
   	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	src_json = JSON_GET_OBJECT(file_json,"fileordir_name");
	des_json = JSON_GET_OBJECT(file_json,"fileordir_newname");
	src_path = JSON_GET_OBJECT_VALUE(src_json,string);
	des_path = JSON_GET_OBJECT_VALUE(des_json,string);
	header->i_code = 0;
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
	     header->i_code = ERROR_CODE_SRC_NOT_EXIST;
	  }
	}else{
	  header->i_code = ERROR_CODE_SRC_NOT_EXIST;
	}

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_ls(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
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
	const char *des_path = JSON_GET_OBJECT_VALUE(dir_json,string);
	uint8_t page_no = JSON_GET_OBJECT_VALUE(pageno_json,int);
	uint8_t page_num = JSON_GET_OBJECT_VALUE(pagenum_json,int);
	uint8_t i =0;
	uint8_t file_mode = JSON_GET_OBJECT_VALUE(mode_json,int);
	stFileBrief mStFileBrief;
	memset(&mStFileBrief,0,sizeof(stFileBrief));

	if(page_no >0&&page_num>0)
	{
		if(access(des_path,F_OK) !=-1)	
		{ 
			mStFileBrief.page_no = page_no;
			mStFileBrief.page_num = page_num;
			char *file_argv[]={"ls","-t",des_path};//sort by change time
			p_debug("des_path1 = %s page_no:%d page_num:%d\n",des_path, page_no, page_num);
			handle_ls(LS_MOUNT,file_argv,&mStFileBrief); 
			fprintf(stderr, "%s", "handle_ls out\n");
			JObj *file_info[mStFileBrief.cur_num];
			for(i = 0;i < mStFileBrief.cur_num;i++)
			{
				file_info[i] = JSON_NEW_EMPTY_OBJECT();
				if( file_mode == 0)
				{
					if(strcmp(mStFileBrief.stFileCot[i].fileordir_name,"iMove_Private"))
					{
						JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].fileordir_name,string));
						JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_type,int));
						JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].create_time,int));
						JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_size,int));
						JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
					}else{
						JSON_PUT_OBJECT(file_info[i]);
					}
				}
				else if(file_mode == 1 && mStFileBrief.stFileCot[i].file_type==0)
				{
					if(strcmp(mStFileBrief.stFileCot[i].fileordir_name,"iMove_Private"))
					{
						JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].fileordir_name,string));
						JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_type,int));
						JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].create_time,int));
						JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_size,int));
						JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
					}
					else
					{
						JSON_PUT_OBJECT(file_info[i]);
					}
				}
			
			}
		}
		else	
		{
			header->i_code = ERROR_CODE_DES_NOT_EXIST;
		}  
	}
	else
	{
		header->i_code = ERROR_CODE_PARA_INVALID;
	}

	JSON_ADD_OBJECT(response_file_json, "page_total", json_object_new_int(mStFileBrief.total_page));
   	JSON_ADD_OBJECT(response_file_json, "page_no", json_object_new_int(page_no));
   	JSON_ADD_OBJECT(response_file_json, "page_num", json_object_new_int(page_num));
   	JSON_ADD_OBJECT(response_file_json, "fileordir_info", fileordir_info_array);
   	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);

	header_json = imove_create_json_msg_header(header);
   	JSON_ADD_OBJECT(response_json, "header", header_json);
   	JSON_ADD_OBJECT(response_json, "data", response_data_array);
   	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

   	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_file_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);

	return 0;
}

int _handle_ls_r(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
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
	uint8_t i =0;
	uint8_t file_mode = JSON_GET_OBJECT_VALUE(mode_json,int);
	stFileBrief mStFileBrief;
	memset(&mStFileBrief,0,sizeof(stFileBrief));
	
   	if(page_no > 0&&page_num > 0)	
   	{
   		int file_start = (mStFileBrief.page_no-1)*(mStFileBrief.page_num);
	    	int file_end = 0;
		if(access(des_path,F_OK)!=-1)
		{
			mStFileBrief.page_no = page_no;
			mStFileBrief.page_num = page_num;
			char *file_argv[]={"ls","-R",des_path};//sort by change time
			p_debug("des_path1 = %s",des_path);
			handle_ls_r(LS_MOUNT,file_argv,&mStFileBrief); 

			if(mStFileBrief.cur_num%(mStFileBrief.page_num) == 0 )
			{
		       	mStFileBrief.total_page = mStFileBrief.cur_num/(mStFileBrief.page_num);
			}
			else
			{
		       	mStFileBrief.total_page = mStFileBrief.cur_num/(mStFileBrief.page_num) + 1;
			}
			
			JObj *file_info[mStFileBrief.page_num];
			if(mStFileBrief.page_no <=  mStFileBrief.total_page)
			{
				if(mStFileBrief.page_no ==  mStFileBrief.total_page)
				{
					file_end = mStFileBrief.cur_num;
				}
				else
				{
					file_end = file_start + mStFileBrief.page_num;
				}
				p_debug("file_start = %d\n",file_start);
				p_debug("file_end = %d\n",file_end);
				for(i=file_start;i<file_end;i++)
				{
					file_info[i] = JSON_NEW_EMPTY_OBJECT();
					p_debug("fileordir_name[%d] = %s",i,mStFileBrief.stFileCot[i].file_fullname);
					if(file_mode == 0)
					{
						JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_fullname,string));
						JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_type,int));
						JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].create_time,int));
						JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_size,int));
						JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
					}else if(file_mode == 1 && mStFileBrief.stFileCot[i].file_type==0)
					{
						JSON_ADD_OBJECT(file_info[i], "fileordir_name",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_fullname,string));
						JSON_ADD_OBJECT(file_info[i], "file_type",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_type,int));
						JSON_ADD_OBJECT(file_info[i], "create_time",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].create_time,int));
						JSON_ADD_OBJECT(file_info[i], "file_size",JSON_NEW_OBJECT(mStFileBrief.stFileCot[i].file_size,int));
						JSON_ARRAY_ADD_OBJECT (fileordir_info_array,file_info[i]);
					}
				}
			}
			else
			{
				 header->i_code = ERROR_CODE_PARA_INVALID;
				 goto E_OUT;
			}
			
		}
		else
		{
		   header->i_code = ERROR_CODE_DES_NOT_EXIST;
		    goto E_OUT;
		}
   	}
	else	
   	{ 
       	header->i_code = ERROR_CODE_PARA_INVALID;
		 goto E_OUT;
   	}

	header->i_code = 0;
	JSON_ADD_OBJECT(response_file_json, "page_total", JSON_NEW_OBJECT(mStFileBrief.total_page,int));
	JSON_ADD_OBJECT(response_file_json, "page_no", JSON_NEW_OBJECT(page_no,int));
	JSON_ADD_OBJECT(response_file_json, "page_num", JSON_NEW_OBJECT(page_num,int));
	JSON_ADD_OBJECT(response_file_json, "fileordir_info", fileordir_info_array);
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);
	
E_OUT:
	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);

	if (0 == header->i_code)
		JSON_ADD_OBJECT(response_json, "data", response_data_array);
	
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));
	
	JSON_PUT_OBJECT(response_json);
  	return 0;
}

int _handle_pwd(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
  	return 0;
}

int _handle_mkdir(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
	JObj *dir_json = JSON_GET_OBJECT(file_json,"dir_name");
	const char *des_path = JSON_GET_OBJECT_VALUE(dir_json,string);
	char des_full_path[FULL_FILE_PATH_LENGTH] = {0};
	char mkdir_retstr[FILE_HANDLE_RET_STR_LEN] = {0};
	strcpy(des_full_path,des_path);
	header->i_code = 0;
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
		header->i_code = ERROR_CREATE_FILE;
	}

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
   	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
   	JSON_PUT_OBJECT(response_json);
	return 0;
}

int _handle_touch(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
  	return 0;
}

int _handle_query_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* header_json = NULL;
   	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *response_data_array = JSON_NEW_ARRAY();
   	JObj* response_file_json=JSON_NEW_EMPTY_OBJECT();
   	JObj *data_json = JSON_GET_OBJECT(rpc_json,"data");
   	JObj *file_json = JSON_GET_ARRAY_MEMBER_BY_ID(data_json,0);
   	JObj *event_json = JSON_GET_OBJECT(file_json,"event_id");
   	uint32_t event_id = JSON_GET_OBJECT_VALUE(event_json,int);
   	uint8_t event_result = 0;
	IM_ST_file_op_rd *tmp = NULL;
   	p_debug("DM event_id =  0x%x",(unsigned int)event_id);
   	header->i_code = 0;
    /*uint8_t total_file = threadStatus->total_file_number;
      uint8_t finished_file = threadStatus->complete_file_number;
      JSON_ADD_OBJECT(response_file_json, "file_total", JSON_NEW_OBJECT(total_file,int));
	JSON_ADD_OBJECT(response_file_json, "file_finished", JSON_NEW_OBJECT(finished_file,int));*/

#if 0
	if(threadStatus->thread_cancel_flag == 1)
	{
		event_result = 2;
	}else if(threadStatus->thread_cancel_flag == 0)
	{
		event_result = 0;
	}
#endif

	tmp = g_file_op_rd;
	while (tmp)
	{
		if (tmp->i_radom == event_id)
		{
			event_result = 0;
			del_node_from_queue(&g_file_op_rd, tmp);
			add_new2queue(&g_file_op_freelist, tmp);
			break;
		}
		tmp = tmp->next;
	}
	
	if (tmp == NULL)
	{
		event_result = 2;
	}
	
	JSON_ADD_OBJECT(response_file_json, "event_result", JSON_NEW_OBJECT(event_result,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_file_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_file_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_ssid_and_route_id(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
//	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json = JSON_NEW_EMPTY_OBJECT();;
	JObj* route_id_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* header_json=NULL;
    char router_id[64] = {0};
	int id = -1;
	id = get_cfg_sn_status(router_id);
	if(id < 0)
	{
		header->i_code = ERROR_GET_SN_FAIL;
	}
	JSON_ADD_OBJECT(route_id_json, "router_id",JSON_NEW_OBJECT(atoi(router_id),int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,route_id_json);
#if 0	
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(header->sign,string));
#endif
	header_json = imove_create_json_msg_header(header);

	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
//	strcpy(retstr,JSON_TO_STRING(response_json));
	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

int get_router_init_status(JObj * rpc_json, IM_ST_msg_header *header, IM_ST_request *request)
{
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj* header_json = NULL;

	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj *response_para_json=JSON_NEW_EMPTY_OBJECT();
	int router_initstatus = -1;

	/* 获取路由器初始化状态 */	
	get_wizard_init_status(&router_initstatus);
	if(router_initstatus == WIZARD_UNINIT)
	{
		router_initstatus = WIZARD_PPPOE;  /* 默认PPPOE拔号 */ 
	}

	JSON_ADD_OBJECT(response_para_json, "router_initstatus", JSON_NEW_OBJECT(router_initstatus,int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_para_json);

	header_json = imove_create_json_msg_header(header);
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);

	snprintf(request->buffer, sizeof(request->buffer), "%s", JSON_TO_STRING(response_json));

	JSON_PUT_OBJECT(header_json);
	JSON_PUT_OBJECT(response_data_array);
	JSON_PUT_OBJECT(response_json);
	return 0;
}

IM_ST_handle_func *imove_find_fun_by_cmd(int cmd)
{
	IM_ST_handle_func *func = NULL;
	int i = 0; 
	int num = 0;
	unsigned short func_cmd = 0;
	unsigned int g_cmd = 0;
	if (cmd <= 0)
	{
		WARN("cmd error!!!");
		return NULL;
	}

	func_cmd = (unsigned short)cmd;
	g_cmd = (cmd & 0xff00) >> 8;

	p_debug("func_cmd:%x g_cmd:%x\n", func_cmd, g_cmd);	
	switch(g_cmd)
	{
		case SYS_CMD:
		{


			num = sizeof(system_cmd_func) / sizeof(system_cmd_func[0]);
			for (i = 0; i < num; i++)
			{
				if (system_cmd_func[i].cmd == func_cmd)
				{
					func = &(system_cmd_func[i]);
					goto find_ret;
				}
			}
			break;
		}
		case STORAGE_CMD:
		{
			num = sizeof(storage_manage_cmd_func) / sizeof(IM_ST_handle_func);
			for (i = 0; i < num; i++)
			{
				if (storage_manage_cmd_func[i].cmd == func_cmd)
				{
					func = &(storage_manage_cmd_func[i]);
					goto find_ret;
				}
			}
			break;
		}
		case SPEED_CHECK_CMD:
		{
			num = sizeof(speed_check_cmd_func) / sizeof(IM_ST_handle_func);
			for (i = 0; i < num; i++)
			{
				if (speed_check_cmd_func[i].cmd == func_cmd)
				{
					func = &(speed_check_cmd_func[i]);
					goto find_ret;
				}
			}
			break;
		}
		case GET_UPLOAD_CMD:
		{
			num = sizeof(ge_upload_speed_cmd_func) / sizeof(IM_ST_handle_func);
			for (i = 0; i < num; i++)
			{
				if (ge_upload_speed_cmd_func[i].cmd == func_cmd)
				{
					func = &(ge_upload_speed_cmd_func[i]);
					goto find_ret;
				}
			}
			break;
		}
		default:
			num = sizeof(unknow_cmd_funcs) / sizeof(IM_ST_handle_func);
			for (i = 0; i < num; i++)
			{
				if (unknow_cmd_funcs[i].cmd == func_cmd)
				{
					func = &(unknow_cmd_funcs[i]);
					goto find_ret;
				}
			}
			break;
	}
find_ret:
	return func;
}
