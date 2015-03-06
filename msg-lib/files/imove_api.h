#ifndef __IMOVE_API_HEAD
#define __IMOVE_API_HEAD


typedef struct file_cotent{    
	char fileordir_name[256]; 
	char file_fullname[1024];
	int file_type;
	unsigned long long create_time;
	unsigned long long file_size;
}stFileCotent, *pstFileCotent;
typedef struct file_brief{    
	int page_no; 
	int page_num;
	int cur_num;
	int total_page;
	stFileCotent stFileCot[512];
}stFileBrief, *pstFileBrief; 
#define MAX_FILES_STAT 1024

//firmware version

#ifndef FW_VERSION
#define FW_VERSION		"1.1.14.150204_beta"
#endif

#define WPS_TYPE_PBC	"PBC"
#define WPS_TYPE_PIN	"PIN"


struct wirelessInfo
{
	char name[64];
	int encrypt;// 加密方式0 none 1 wpa/wpa2
	char password[64]; //密码
	int wifi_type;// 0 5G host  1 5G gust 2 2.4G client 3 2.4 host 4 2.4 guset
	int wifi_ap;// 1 host 2 guest
	int wifi_switch; // 0 关1 开
	int wifi_hide; // 0 隐藏1 不隐藏
	int channel;
	int wifi_sign;
	int is_wps;
	char wps_type[6];
	int is_autochannel;
};

typedef struct _scan_AP{
	int has_encrypt;
	int encrypt;
	int rssidbm;
	char mac_addr[18];
	char ssid[64];
	int channel;
} scan_ap_struct;
#if 1
typedef struct _repeater_parm{
	char is_uselocal[2]; // 1 is local enable 0 disable
	char local_ssid[32];
	char local_password[32];
	char ssid[32];
	char password[32];
	char channel[4];
	char encrypt[16];
	char is_connect[2]; // 1 is repeater mode connect
	char mac[20];
}Repeater_Param;
#endif
typedef struct _port_info{
	int app_idx; 
	char app_name[32];
	int oport;
	int protocol_type;
	int iport;
	char ip[32];
	int isvalid;
}port_info_t;
typedef struct port_info_group{    
	int cout;
	port_info_t st_port_info[20];
}port_info_group_t; 
typedef struct ip_binding{
	char ip[32]; 
	char mac[32];
	int isvalid;
}ip_binding_t;

typedef struct ip_binding_group{    
	int count;
	ip_binding_t ip_binding_info[100];
}ip_binding_group_t;

typedef struct _port_redirects{
	char name[32];
    char potocol[32];
	char exter_port[32];
    char ip_address[20];
    char in_port[5];
}port_redirects;
typedef struct ap_info{
	char mac[32];
	char ssid[32];
	int channel;
	int Is_encrypt;
	char encrypt[16];
	char tkip_aes[16];
	int wifi_signal;
}ap_info_t;

typedef struct ap_list_info{    
	int count;
	ap_info_t ap_info[100];
}ap_list_info_t;


#define ORAY_SEVICE			"oraysev"
#define CLUD_SEVICE			"cludsev"
#define NOIP_SEVICE			"onipsev"
#define DYNDNS_SEVICE		"dyndnssev"

#define ORAY_SEVICE_URL		"oray.com"
#define CLUD_SEVICE_URL		"3322.org"
#define NOIP_SEVICE_URL		"no-ip.com"
#define DYNDNS_SEVICE_URL	"dyndns.org"
#define START_FLAG		"start"
#define STOP_FLAG		"stop"
#define RESTART			"restart"

#define rtl_encryp_control "/proc/gpio_imove/rtl_encryp_control"
#define rtl_led_control "/proc/led_imove/led_control"

#define sleep_status_get  12		//sleep 6 wakeup 9

#define CLOSE_CPU_POWER	13
#define GET_SUNSHINE_STATUS	14	//fan close 6 open 9

#define SET_PCIE_RESET	16
#define SET_BT_RESET	17
#define SET_HUB_PWR		18
#define R_315_CTR		19
#define G3_PWR_CTR		20
#define SD_PWR_CTR		21
#define G3_RESET		22
#define LED_CTR			23
#define	SATA_CTR		24

#define M315_PWR		25
#define PWM_OUT			26
#define LED_LEVEL		27
#define LED_RED			28
#define LED_YELLO		29
#define LED_BLUE		30
#define BLUE_WAKEUP		31
#define RATE_LIMIT_UP_CONFIG "/etc/config/rate_limit_up_config"
#define FLOW_TOTAL_DOWN "/etc/config/flow_total_down"

/*******************************************************************************
 * Function:
 *    int backupdevinfo(char *mac, unsigned int contime,char *ipaddr,int con_type)
 * Description:
 *    backup the dev infomation include mac,ip,connect time.
 * Parameters:
 *    mac	[IN] 
 *	contime	[IN] connect time.
 * 	ipaddr [IN]
 * Returns:
 *    0  success
 *	-1 error

 *******************************************************************************/

int backupdevinfo(char *mac, unsigned int contime,char *ipaddr,int con_type);
int ctr_imov_gpio(int ctr_index, int *ctr_para);
int ctl_3g_led(int cmd,int start);

//-------------------------------------------------------------------------------------
//app manage
int load_opk (char *app_name);
//加载ipk应用
//输入参数:app_name ipk文件名及路径
int unload_opk(char *app_name);
//卸载ipk应用
//输入参数:app_name ipk文件名及路径
int start_app(char *app_name,char *u_g_name,char * flag);
//启动应用
//输入参数:app_name 应用文件名
//输入参数:u_g_name UID
//输入参数:flag
int stop_app(char *app_name);
//停止应用
//输入参数:app_name应用文件名
//-------------------------------------------------------------------------------------
int Reset_system(void);
//重启系统
int Reset_Halt(void);
//关闭系统
int Reset_factory (void);
//恢复工厂设定
int Reset_getversion(char *version);
//得到版本?
//输入参数:version 存放版本号
int Reset_fwupgrade(char *update_file);
//更新固件
//输入参数:update_file,固件文件名及路径
int set_root_password(char *password);
//改变超级用户密码
//输入参数:password,密码，不做校验

int Reset_Sleep(void);
int Reset_wakeup(void);



//-------------------------------------------------------------------------------------
//funtion get the setting through uci command
//input parameter
//uci_option_str --> uci command
//uci_str_value --> return uci setting
//output parameter
//return 0 success
int shell_uci_get_value(char *uci_option_str,char *uci_str_value); 
//-------------------------------------------------------------------------------------
//funtion search the option from macth_patten and get setting when match through uci command  
//input parameter
//macth_patten --> uci command
//uci_str_value --> return uci setting
//output parameter
//return 0 success
int shell_uci_find_value(char *macth_patten,char *uci_str);
//-------------------------------------------------------------------------------------
//funtion set the value through uci command
//input parameter
//uci_str --> uci command include option value
//output parameter
//return 0 success
int shell_uci_set_value(char *uci_str);
//-------------------------------------------------------------------------------------
//无线相关
//输入参数:str_fre 24G表示2.4G,5G表示5G信号
//输入参数:str_hot HOSTAP 主或 GUESTAP 来宾AP 或CLIENTTAP 客户端节点 ALLAP所有节点 
//输入参数:str_on_off on 表示开或 off 关  

int WiFi_set_country(char *str_fre,char *str_country);
//设定无线国别
//输入参数:str_fre 24G或者5G
//输入参数:str_country 国别{CN,}
int WiFi_set_power(char *str_fre,char *str_power);
//设定无线发射功率
//输入参数:str_fre 24G或者5G
//输入参数:str_power 功率值
int WiFi_hidewireless (char *str_fre,char *str_hot,char *str_on_off);
//设定无线是否隐藏
//输入参数:str_fre 24G或者5G
//输入参数:str_hot  HOSTAP or GUESTAP or CLIENTTAP ALLAP 
//输入参数:str_on_off on 或者off
int wifi_switch_hot(char *str_fre,char *str_hot,char *str_on_off);
//设定无线节点是否关闭
//输入参数:str_fre 24G或者5G
//输入参数:str_hot  HOSTAP or GUESTAP or CLIENTTAP ALLAP 
//输入参数:str_on_off on 或者off
int wifi_set_ssid(char *str_fre,char *str_hot,char *str_ssid);
//设定无线ssid名称
//输入参数:str_fre 24G或者5G
//输入参数:str_hot  HOSTAP or GUESTAP or CLIENTTAP ALLAP 
//输入参数:str_ssid ssid名称
int WiFi_setwireless(char *str_fre,char *str_hot, char *ssid,char *encrypt,char *password);
//设定无线ssid名称
//输入参数:str_fre 24G或者5G
//输入参数:str_hot  HOSTAP or GUESTAP or CLIENTTAP ALLAP 
//输入参数:ssid ssid名称
//输入参数:encrypt 加密方式none表示无(固定为psk2+ccmp)
//输入参数:password 密码如果有加密方式
int set_wireless(struct wirelessInfo *info);
int WiFi_getwirelessstatus(char *str_fre,char *str_hot,struct wirelessInfo *info);
//设定无线是否关闭
//输入参数:str_fre 24G或者5G
//输入参数:str_on_off on 或者off
int WiFi_switch_wireless(char *str_fre,char *str_on_off);
//设定无线信道
//输入参数:str_fre 24G或者5G
//输入参数:str_chanel 信道值
int WiFi_switch_channel(char *str_fre,char *str_chanel);
//设定无线频段带宽
//输入参数:str_fre 24G或者5G
//输入参数:str_bandwith 带宽 VHT80 VHT- VHT+ VHT20 none
int WiFi_set_bandwith(char *str_fre,char *str_bandwith);

//-------------------------------------------------------------------------------------
int cgi_scan(char *ifname, char *outstr);
int cgi_get_channel(char *ifname, char *chstr);
//int get_scan_ssid(char *dev_name,char *ap_ssid);
int get_scan_result(char *fre,char *scan_result);
int get_scan_result_t(char *fre,ap_list_info_t *ap_list_info);
//得到扫描外部AP列表
//输入参数:fre 24G 表示扫2.4G,5G表示扫5G
//输出参数:scan_result,扫描结果每行的格式{mac地址,ssid,信道,是否加密,加密方式,功率}
int client_connect_to_ap(char *ap_ssid,int channel,char *encrypt,char *secret);
//连接到外部AP
//输入参数:ap_ssid外部ssid
//输入参数:channel外部ssid所指的信道
//输入参数:encrypt加密方式(none表示不用加密)
//输入参数:secret 连接密码
int get_encrypt_mode_int(int encrypt,char *encry_mode);
int get_online_iplist(char *ip_list);

//-------------------------------------------------------------------------------------
//dhcp参数设定
int get_dhcp_leasetime(char *time_c);
//得到租约时间
//输出参数:time_c存放租约时间，单位分钟
int get_dhcp_start_ip(char *start_ip);
//得到dhcp IP池起始IP
//输出参数:start_ip存放起始IP
int get_dhcp_end_ip(char *end_ip);
//得到dhcp IP池结束IP
//输出参数:end_ip存放结束IP
int set_dhcp_leasetime(char *g_mimute);
//设定租约时间
//输入参数:time_c租约时间，单位分钟
int set_dhcp_start_ip(char *start_ip);
//设定dhcp IP池起初IP
//输入参数:start_ip 起始IP值，大小2-253
int set_dhcp_end_ip(char *end_ip);
//设定dhcp IP池结束IP
//输入参数:end_ip 结束IP值，大小2-253
int switch_dhcp(char *str_on_off);
//开关dhcp功能
//输入参数:str_on_off  on 表示打开off表示关内
//-------------------------------------------------------------------------------------
//外网接入方式
int set_vwan_mode_pppoe(char *username ,char *password,char *dns_list);
int get_vwan_pppoe_status(char *username ,char *password,char *dns_list);
//设置pppoe上网
//输入参数:username 用户名
//输入参数:password 密码
//输入参数:dns_list dns IP地址
int set_vwan_mode_l2tp(char *username ,char *password,char *server);
int get_vwan_l2tp_status(char *username ,char *password,char *server);
//设置l2tp上网
//输入参数:username 用户名
//输入参数:password 密码
//输入参数:server  l2tp服务器IP地址
int set_vwan_mode_pptp(char *username ,char *password,char *server);
int get_vwan_pptp_status(char *username ,char *password,char *server);
//设置pptp上网
//输入参数:username 用户名
//输入参数:password 密码
//输入参数:server pptp服务器IP地址
int set_vwan_mode_dhcp(char *hostname,char *dns_list,char *macaddr);
int get_vwan_dhcp_status(char *hostname,char *dns_list,char *macaddr);
//设置dhcp上网
//输入参数:hostname 主机名
//输入参数:dns_list dns IP地址
//输入参数macaddr 绑定MAC地址
int set_vwan_mode_static(char *ipaddr,char *netmask,char *gateway ,char *dns_list);
int get_vwan_static_status(char *ipaddr,char *netmask,char *gateway ,char *dns_list);
//设置static上网
//输入参数:ipaddr 上网连接的IP地址
//输入参数:netmask 子网掩码
//输入参数gateway 网关
//输入参数:dns_list dns IP地址
int get_wan_mode(char *wan_mode);
//得外网上网方式pppoe dhcp static pptp l2tp
//输出参数:wan_mode 上网方式pppoe dhcp static pptp l2tp
int restart_network(void);
//重启网络
int restart_wifi(void);
//重启WIFI
int Password_exist(void);
int restart_host_dhcp(void);
//判断是否设了密码
int get_vwan_dhcp_status(char *hostname,char *dns_list,char *macaddr);
int get_online_iplist(char *ip_list);

int password_check(char *username,char *passwrd);
int find_ipmac_last_index(char *uci_sec_cmd);

//-------------------------------------------------------------------------------------------
//高级设定
int upnpd_switch_on_off(char *on_off);
//开关upnpd
//输入参数:on_off on 或者off
int upnpd_get_device_list(char *list_buffer);
//列出连接上的upnpd设备
//输出参数list_buffer {应用名,协议名,外部端口,内部端口,IP地址}
int switch_firewall(char *on_off);
//开关防火墙
//输入参数:on_off on 或者off
int switch_DMZ(char *on_off,char *service_ip_address);
//开关DMZ
//输入参数:on_off on 或者off
//输入参数:service_ip_address DMZ服务器
int get_DMZ_status(char *dst_ip); 
//get DMZ status
//return 1 DMZ on 0 is off
//dst_ip dst ip address
int add_port_convert(port_redirects *red_port); //char *name,char *potocol,char *exter_port,char *ip_address,char *in_port
//增加端口转发
//输入参数:name 名称
//输入参数:potocol协议名
//输入参数:exter_port外部端口号
//输入参数:ip_address 源IP地址
//输入参数:in_port 内部端口号
int delete_port_convert(char *name);
//删除一个端口转发
//输入参数:name 名称
int get_firewall_policy(char *policy_list);
//得到防火墙策略
//输出参数:policy_list策略列，注意分大点空间
int get_port_convert_list(char *port_convert_list);

int get_port_convert_list_t(port_info_group_t *st_port_info_group);

int find_match_name(char *dst,char *macth);
//from server get ispname
//macth server 
//dst ispname
//----------------------------------------------------------
//得到目前端口转换列表
//输出参数:port_convert_list 转换列表
int get_DDNS(char *service,char *on_off,char *hostname);
//通过主机名得该这机主机名的状态
//输入参数:hostname 主机名
///输出参数:on_off on开,off 关
int get_DDNS_service_list(char *service_list);
//得到DDNS服务器名
//输出参数:service_list仅有oray.com 3322.org no-ip.com dyndns.org四种
int set_DDNS(char *service,char *on_off);
//通过主机名设定这机主机名的状态
//输入参数:hostname 主机名
///输出参数:on_off on开,off 关
int add_DDNS(char *service,char *hostname,char *username,char *password);
//增加更改DDNS服务
//输入参数:service 服务器名仅有oray.com 3322.org no-ip.com dyndns.org四种
//输入参数:username用户名
//输入参数:password密码
int del_DDNS(char *service);//char *hostname
int switch_DDNS(char *ddns_act);
//-------------------------------------------------------------------------------------------
int send_arp_and_rev(char *dev_name,char *g_ip);
int arp_get(char *ip);
//-------------------------------------------------------------------------------------------
int start_speed_limit(void);
int stop_speed_limit(void);
int set_up_speed_limit(char *ip_a,char *speed_limit,char *prio);
int set_down_speed_limit(char *ip_a,char *speed_limit,char *prio);
int del_up_speed_limit(char *ip_a);
int del_down_speed_limit(char *ip_a);
int get_ip_mac_dev(char *ip_list);
int get_dev_info(char *ip_list,int dev_info_len);
//list format mac ,IP wifi_type,hostname
//-------------------------------------------------------------------------------------------
int set_to_repeart(Repeater_Param *rep_param);
int get_repeater_switch(char *r_status);
int set_to_bridge(void);
int get_repeart_status(Repeater_Param *rep_param);
/*******************************************************************************
 * Function:
 *    static void get_wan_ip(char *wan_ip)
 * Description:
 *    get wan ip in dhcp mode
 * Parameters:
 *    wan_ip   [OUT]
 * Returns:
 *    0:success,other : fail  
 *******************************************************************************/
int get_wan_ip(char *wan_ip);

//-------------------------------------------------------------------------------------------
//get wan mac
//wan_ip return mac
int get_wan_mac(char *wan_ip);
//set ghost mac address
//c_ip from cleint mac
int set_ghost_mac(char *c_ip);
//del wan mac
int del_ghost_mac(void);
//get lan status mac ip and mask
//mac -->lan_mac ip -->lan_ip mask -->lan_netmask
int get_len_status(char *lan_mac,char *lan_ip,char *lan_netmask);
//-------------------------------------------------------------------------------------------
//add bind ip mac dhcp address
int add_dhcp_ip_mac(char *d_ip,char *d_mac);
//del bind by mac
int del_dhcp_ip_mac(char *d_mac);
int get_dhcp_bind_t(ip_binding_group_t *ip_binding_group);

//get bind ip mac list 
//mac is first
int get_dhcp_ip_mac(char *ip_mac_list);
//add backlist
int add_dhcp_backlist(char *d_mac);
//del backlist
int del_dhcp_backlist(char *d_mac);
//get backlist
int get_dhcp_backlist(char *ip_mac_list);
int get_cfg_wifictrl_status();
int set_cfg_wifictrl_status(int ctrl_count);
int dhcp_restart();
//-------------------------------------------------------------------------------------------
/*******************************************************************************
 * Function:
 *   int get_samba_info(char *path,char *usr_name,char *password)
 * Description:
 *    get samba info
 * Parameters:
 *    path share path
 * usr_name user name
 *password user password
 *******************************************************************************/

int get_samba_info(char *path,char *usr_name,char *password);



int is_wan_online_t(char *ip,char *netmask);
int get_gateway(char *gateway);
int get_dns_list(char *dns1_ip,char *dns2_ip);
//return 1 is online 0 is off

int is_wan_online(void);


//device detail
#define MAX_WLAN_DEVICE 4
#define WLAN0_DEVICE_FILE "/proc/wlan0/sta_keyinfo"
#define WLAN0_1_DEVICE_FILE "/proc/wlan0-1/sta_keyinfo"
#define WLAN1_DEVICE_FILE "/proc/wlan1/sta_keyinfo"
#define WLAN1_1_DEVICE_FILE "/proc/wlan1-1/sta_keyinfo"

#define DHCP_LEASES "/tmp/dhcp.leases"
typedef struct dev_detail{
	char mac[32];
    char ip[32];
    unsigned int time;
    int online; 
}dev_detail_t;
typedef struct all_detail{
	dev_detail_t dev[128];
	int count;
}all_detail_t;

/*******************************************************************************
 * Function:
 *    int get_device_type(char *mac)
 * Description:
 *    get device type
 * Parameters:
 *    mac [IN] mac address xx:xx:xx:xx:xx:xx
 * Returns:
 *    1 , wifi
 *    0 , eth
 *    -1, error
 *******************************************************************************/
int get_device_type(char *mac);
/*******************************************************************************
 * Function:
 *    int is_dev_online(char *mac)
 * Description:
 *    is device online
 * Parameters:
 *    mac [IN] mac address xx:xx:xx:xx:xx:xx
 * Returns:
 *    1 , online
 *    0  , offline
 *******************************************************************************/
int is_dev_online(char *mac);
/*******************************************************************************
 * Function:
 *    int get_dev_detail(all_detail_t *dev)
 * Description:
 *    get device defail info
 * Parameters:
 *    no
 * Returns:
 *    -1 , get fail
 *    0  , get success
 *******************************************************************************/
int get_dev_detail(all_detail_t *dev);
/*******************************************************************************
 * Function:
 *    int check_valid_mac(char *mac_addr)
 * Description:
 *    check mac is valid
 * Parameters:
 *    mac_addr	[IN] mac string, example xx:xx:xx:xx:xx:xx
 * Returns:
 *    valid mac return 0;
 *	  error mac return -1.  
 *******************************************************************************/
int check_valid_mac(char *mac_addr);

// hd device function
//disk_info struct
typedef struct disk_info {
	char name[32];
	char path[256];
	char dev[32];
	unsigned long total_size; //1KB
	unsigned long free_size;  //1KB
	int is_format;
	int type; //1--HD; 2--Sdcard; 3--UDisk; -1--unknown
}disk_info_t;

typedef struct all_disk{
	disk_info_t disk[16];
	int count;
}all_disk_t;

/*******************************************************************************
 * Function:
 *    int check_mac(char *mac_addr, char *new_mac)
 * Description:
 *    check mac is valid
 * Parameters:
 *    mac_addr	[IN] old mac string, example xx:xx:xx:xx:xx:xx
 *	  new_mac	[IN] new mac string, example xxxxxxxxxxxx
 * Returns:
 *    valid mac return 0;
 *	  error mac return -1.  
 *******************************************************************************/
int check_mac(char *mac_addr, char *new_mac);

/*******************************************************************************
* Function:
*    char *get_name_from_dev(char *dev)
* Description:
*    get dev name,
* Parameters:
*    dev   [IN] device, sample: sda1
* Returns:
*    NULL, not found match
*    device name string
*******************************************************************************/
char *get_name_from_dev(char *dev);
/*******************************************************************************
 * Function:
 *    char *get_hd_dev(char *driver)
 * Description:
 *    get hdisk device num ;sample /dev/sda1
 * Parameters:
 *    driver   [IN] hd path name, sample:hdisk1
 * Returns:
 *    NULL,   no found device
 *    string, success
 *    
*******************************************************************************/
char *get_hd_dev(char *driver);
/*******************************************************************************
* Function:
*    Format_getstorage (all_disk_t *alldisk)
* Description:
*    get storage info list,
* Parameters:
*    alldisk   [IN/OUT] disk info struct,
* Returns:
*    0, success
*    other, failed.
*******************************************************************************/
int Format_getstorage (all_disk_t *alldisk);

/*******************************************************************************
* Function:
*    int dev_is_hd(char *dev)
* Description:
*    dev is hd?
* Parameters:
*    dev   [IN] device name, sample: sda1
* Returns:
*    0, is hd device
*    other, no hd
*******************************************************************************/
int dev_is_hd(char *dev);

/*******************************************************************************
* Function:
*    int Format_formatdisk(char *drivname, char *drivdev,int type)
* Description:
*    format hd
* Parameters:
*    drivname   [IN] hd path, sample: hdisk1
*    drivdev    [IN] hd dev name, sample: sda1
*    type       [IN] format type, ntfs - 1, ext4 - 2
* Returns:
*    0   success
*    -1  no hd device
*    -2  device isn't hd
*    -3  other error
*******************************************************************************/
int Format_formatdisk(char *drivname, char *drivdev, int type);

/*******************************************************************************
* Function:
*    int Format_formatall(int type)
* Description:
*    format all disk zone
* Parameters:
*    type       [IN] format type, ntfs - 1, ext4 - 2
* Returns:
*    0   success
*    -1  no hd device
*    -2  device isn't hd
*    -3  other error
*******************************************************************************/
int Format_formatall(int type);
int get_init_status();
int set_init_status(int init_status);
int get_cfg_pppoe_status(char *pppoe_name,char *pppoe_password);
int get_cfg_static_status(char *static_ip,char *static_mask,char *static_gateway,char *static_dns);
/* Parameters:
*    dev   [IN] device name, sample: sda1
* Returns:
*    0, is hd device
*    other, no hd
*******************************************************************************/
int dev_is_hd(char *dev);

int check_valid_storage();


typedef struct {
	char name[64]; //router name
	unsigned int runtime;//totoal time, S
	unsigned int devnum;//device count
	char mac[32]; //route mac
	char ver[32]; //route version
}router_info_t;

#define UPTIME_FILE "/proc/uptime"
/*******************************************************************************
 * Function:
 *    int get_dev_detail(char *mac, dev_detail_t *dev)
 * Description:
 *    get device defail info
 * Parameters:
 *    no
 * Returns:
 *    -1 , get fail
 *    0  , get success
 *******************************************************************************/
int getrouterinfo(router_info_t *info);

/*******************************************************************************
 * Function:
 *    int hd_sleep(int minute, char *sdev)
 * Description:
 *    set hd sleep
 * Parameters:
 *    minute   [IN]delay minutes, default:-1(default sleep mode), 1, 5, 10, 20 minutes;
 *    sdev     [IN] device file, sample:/dev/sda1
 * Returns:
 *    0   success
 *    -1  error, minute invalid
 *******************************************************************************/
int hd_sleep(int minute, char *sdev);


/*******************************************************************************
 * Function:
 *    int check_valid_storage()
 * Description:
 *    set hd sleep
 * Parameters:
 *   no
 * Returns:
 *    0   success
 *    -1  failed
 *******************************************************************************/
int check_valid_storage();

/*******************************************************************************
 * Function:
 *    int setting_backup(char *fullname)
 * Description:
 *    backup setting
 * Parameters:
 *    fullname   [OUT] backup file fullpath
 * Returns:
 *    0     success
 *    -1    open file failed.
 *******************************************************************************/

int setting_backup(char *fullname);

/*******************************************************************************
 * Function:
 *    int setting_restore(char *fullname)
 * Description:
 *    restore backup setting
 * Parameters:
 *    fullname   [IN] backup file name. sample:/tmp/backup_20150113
 * Returns:
 *    0     success
 *    -1    open file failed
 *    -2    md5 check failed
 *******************************************************************************/
int setting_restore(char *fullname);
/*******************************************************************************
 * Function:
 *    int get_manage_mac(char *ip,char *pc_mac)
 * Description:
 *    get manage MAC accord to ip
 * Parameters:
 *    ip : [IN]manage ip;
 *	mac:[OUT] manage mac;
 * Returns:
 *    0     success
 *    -1   error
 *******************************************************************************/
int get_manage_mac(char *ip,char *pc_mac);
/*******************************************************************************
 * Function:
 *    int is_dnsmasq_exist()
 * Description:
 *    get dnsmasq status
 * Parameters:
 * Returns:
 *    0   dns is exist
 *    -1   dns is not exist
 *******************************************************************************/
int is_dnsmasq_exist();
#endif

