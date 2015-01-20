/*##############################################################################
** 文 件 名: basic-common.c
** Copyright (c), 2013-2016, T&W ELECTRONICS(SHENTHEN) Co., Ltd.
** 日    期: 2013-11-16
** 描    述:
** 版    本:
** 修改历史:
** 2013-11-16   创建本文件；
##############################################################################*/

/*############################## Includes ####################################*/
#include "basic-common.h"

/*############################## Global Variable #############################*/
int g_bc_unix_socket = -1;  //接收和发送回复消息的socket
unsigned long g_tx_bytes[2] = {0}; // 0 index txbytes, 1 index the time seconds when retrieve it
unsigned long g_rx_bytes[2] = {0}; // 0 index rxbytes, 1 index the time seconds when retrieve it
static char g_reply_msg_buff[1024*8] = {0}; //用户回复消息的buf

/* wifi消息处理表 */
static wifi_msg_prcs_func_ptr g_wifi_msg_prcs_tab[] = 
{
    (wifi_msg_prcs_func_ptr)NULL,   //开始
    (wifi_msg_prcs_func_ptr)bc_prcs_wifi_set,   //set
    (wifi_msg_prcs_func_ptr)bc_prcs_wifi_get,   //get
    (wifi_msg_prcs_func_ptr)NULL,   //add
    (wifi_msg_prcs_func_ptr)NULL,   //del
    (wifi_msg_prcs_func_ptr)NULL    //结束
};

/* 客户端消息处理表 */
static clilist_msg_prcs_func_ptr g_clilist_msg_prcs_tab[] = 
{
    (clilist_msg_prcs_func_ptr)NULL,    //开始
    (clilist_msg_prcs_func_ptr)NULL,    //set
    (clilist_msg_prcs_func_ptr)bc_prcs_clilist_get, //get
    (clilist_msg_prcs_func_ptr)bc_prcs_clilist_add, //add
    (clilist_msg_prcs_func_ptr)bc_prcs_clilist_del, //del
    (clilist_msg_prcs_func_ptr)NULL     //结束
};

/* 黑名单消息处理表 */
static blacklist_msg_prcs_func_ptr g_blacklist_msg_prcs_tab[] = 
{
    (blacklist_msg_prcs_func_ptr)NULL,  //开始
    (blacklist_msg_prcs_func_ptr)NULL,  //set
    (blacklist_msg_prcs_func_ptr)bc_prcs_blacklist_get, //get
    (blacklist_msg_prcs_func_ptr)NULL,  //add
    (blacklist_msg_prcs_func_ptr)NULL,  //del
    (blacklist_msg_prcs_func_ptr)NULL   //结束
};

/* 系统信息消息处理表 */
static sysinfo_msg_prcs_func_ptr g_sysinfo_msg_prcs_tab[] = 
{
    (sysinfo_msg_prcs_func_ptr)NULL,    //开始
    (sysinfo_msg_prcs_func_ptr)NULL,    //set
    (sysinfo_msg_prcs_func_ptr)bc_prcs_sysinfo_get, //get
    (sysinfo_msg_prcs_func_ptr)NULL,    //add
    (sysinfo_msg_prcs_func_ptr)NULL,    //del
    (sysinfo_msg_prcs_func_ptr)NULL     //结束
};

/* 软件升级信息消息处理表 */
static imgupdate_msg_prcs_func_ptr g_imgupdate_msg_prcs_tab[] = 
{
    (imgupdate_msg_prcs_func_ptr)NULL,    //开始
    (imgupdate_msg_prcs_func_ptr)bc_prcs_imgupdate_set,    //set
    (imgupdate_msg_prcs_func_ptr)NULL,    //get
    (imgupdate_msg_prcs_func_ptr)NULL,    //add
    (imgupdate_msg_prcs_func_ptr)NULL,    //del
    (imgupdate_msg_prcs_func_ptr)NULL     //结束
};

/* 系统重启信息消息处理表 */
static sysreboot_msg_prcs_func_ptr g_reboot_msg_prcs_tab[] = 
{
    (sysreboot_msg_prcs_func_ptr)NULL,    //开始
    (sysreboot_msg_prcs_func_ptr)bc_prcs_sysreboot_set,    //set
    (sysreboot_msg_prcs_func_ptr)NULL,    //get
    (sysreboot_msg_prcs_func_ptr)NULL,    //add
    (sysreboot_msg_prcs_func_ptr)NULL,    //del
    (sysreboot_msg_prcs_func_ptr)NULL     //结束
};

static synaccount_msg_prcs_func_ptr g_synaccount_msg_prcs_tab[] = 
{
    (synaccount_msg_prcs_func_ptr)NULL,    //开始
    (synaccount_msg_prcs_func_ptr)bc_prcs_sysaccount_set,    //set
    (synaccount_msg_prcs_func_ptr)NULL,    //get
    (synaccount_msg_prcs_func_ptr)NULL,    //add
    (synaccount_msg_prcs_func_ptr)NULL,    //del
    (synaccount_msg_prcs_func_ptr)NULL     //结束
};
/*############################## Functions ###################################*/
int bc_prcs_wifi_set(MsgHeader *msg, int wifi_idx, int fd)
{
    unsigned int msg_len = 0;
    char *p_curr = NULL;
    char value_buf[2048] = {0};
    json_object *my_string, *my_obj;
    char *ssid = NULL;
    char *encryption = NULL;
    char *key = NULL;
    int disabled = 0;
    char module_name[64] = {0}; 
    char cmd[128] = {0};
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int ret = RESULT_CODE_SUCCESS;
    char desc[64] = {0};
    
    if (wifi_idx !=1 && wifi_idx != 2)
    {
        printf("wrong wifi index(%d), not 2.4g or 5g!\n", wifi_idx);
        bc_log("Wifi set:wrong wifi index(%d), not 2.4g or 5g.", wifi_idx);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }

    msg_len = request_msg_head->dataLength;
    if (0 == msg_len)
    {
        printf("length of received wifi set msg is zero!\n");
        bc_log("Wifi set:length of received wifi set msg is zero.");
        ret = RESULT_CODE_MSG_SHORT;
        goto reply;
    }

    p_curr = (char *)(request_msg_head + 1);
    memset(value_buf, 0, sizeof(value_buf));
    if (msg_len > sizeof(value_buf))
    {
        printf("length of received wifi set msg is too big!\n");
        bc_log("Wifi set:length(%d) of received wifi set msg is too big.", msg_len);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    memcpy(value_buf, p_curr, msg_len);

    my_string = json_tokener_parse(value_buf);
    if (is_error(my_string)) 
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

    if (wifi_idx == 1)
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", DEVICE_NAME_OF_2G);
        snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_2G_SET_REPLY);
    }
    else
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", DEVICE_NAME_OF_5G);
        snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_5G_SET_REPLY);
    }

    my_obj = json_object_object_get(my_string, "disabled");
    if (my_obj != NULL)
    {
        disabled = json_object_get_int(my_obj);
        {
            if ((disabled != 0) && (disabled != 1))
            {
                ret = RESULT_CODE_WRONG_PARAMETER;
                bc_log("Wifi set:disabled value %d of radio %d is wrong.", disabled, wifi_idx);
                goto reply;
            }
        }
        sprintf(cmd, "uci set %s.disabled=%d", module_name, disabled);
        ret = bc_system(cmd, 1);
        if (ret != RESULT_CODE_SUCCESS)
            goto reply;
        bc_log("Wifi set:disabled of radio %d set %d.", wifi_idx, disabled);
    }
    json_object_put(my_obj);

    if (wifi_idx == 1)
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", IF_NAME_OF_2G);
    }
    else
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", IF_NAME_OF_5G);
    }

    my_obj = json_object_object_get(my_string, "ssid");
    if (my_obj != NULL)
    {
        ssid = json_object_get_string(my_obj);
        if (strlen(ssid) >= 128)
        {
            ret = RESULT_CODE_WRONG_PARAMETER;
            bc_log("Wifi set:ssid of radio %d set %s, but is too long(len:%d).", wifi_idx, ssid, strlen(ssid));
            goto reply;
        }
        converter_string_with_special_character(ssid);
        sprintf(cmd, "uci set %s.ssid=%s", module_name, ssid);
        ret = bc_system(cmd, 1);
        if (ret != RESULT_CODE_SUCCESS)
            goto reply;
        bc_log("Wifi set:ssid of radio %d set %s.", wifi_idx, ssid);
    }
    json_object_put(my_obj);

    my_obj = json_object_object_get(my_string, "encryption");
    if (my_obj != NULL)
    {
        encryption = json_object_get_string(my_obj);
        if (strcmp(encryption, "mixed") && strcmp(encryption, "none"))
        {
            ret = RESULT_CODE_WRONG_PARAMETER;
            bc_log("Wifi set:encryption of radio %d set %s, but is wrong(only support:mixed or none).", wifi_idx, encryption);
            goto reply;
        }
        sprintf(cmd, "uci set %s.encryption=%s", module_name, encryption);
        ret = bc_system(cmd, 1);
        if (ret != RESULT_CODE_SUCCESS)
            goto reply;
        bc_log("Wifi set:encryption of radio %d set %s.", wifi_idx, encryption);
    }
    json_object_put(my_obj);

    my_obj = json_object_object_get(my_string, "key");
    if (my_obj != NULL)
    {
        key = json_object_get_string(my_obj);
        sprintf(cmd, "uci set %s.key=%s", module_name, key);
        ret = bc_system(cmd, 1);
        if (ret != RESULT_CODE_SUCCESS)
            goto reply;
        bc_log("Wifi set:key of radio %d set %s.", wifi_idx, key);
    }

    sprintf(cmd, "%s", APPLY_COMMIT);
    ret = bc_system(cmd, 1);
    if (ret != RESULT_CODE_SUCCESS)
        goto reply;
    else
        goto reply_apply;

reply:
    bc_set_reply(ret, desc, request_msg_head, fd);
    
    json_object_put(my_string);	
    json_object_put(my_obj);
    
    return ret;
    
reply_apply:    //无线生效时间较长,生效前先回复
    bc_set_reply(ret, desc, request_msg_head, fd);
    
    json_object_put(my_string);	
    json_object_put(my_obj);
    
    sprintf(cmd, "%s", APPLY_WIFI);
    ret = bc_system(cmd, 1);
    if (ret != RESULT_CODE_SUCCESS)
    {
        printf("wifi set failed!\n");
        bc_log("Wifi set:failed.");
    }

    return ret;
}

int bc_prcs_wifi_get(MsgHeader *msg, int wifi_idx, int fd)
{
    int disabled = 0;
    char ssid[128] = {0};
    char encryption[32] = {0};
    char key[32] = {0};
    char value_str[128] = {0};
    char module_name[64] = {0};
    int ret = 0;
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    json_object *my_object;
    char *my_string = NULL;
    char desc[64] = {0};
    int len = 0;
    
    if (wifi_idx !=1 && wifi_idx != 2)
    {
        printf("wrong wifi index, not 2.4g or 5g!\n");
        bc_log("Wifi get:wrong wifi index(%d), not 2.4g or 5g.", wifi_idx);
        return -1;
    }

    if (wifi_idx == 1)
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", DEVICE_NAME_OF_2G);
        snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_2G_INFO);
        bc_log("Wifi get:wifi index(%d), is 2.4g.", wifi_idx);
    }
    else
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", DEVICE_NAME_OF_5G);
        snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_5G_INFO);
        bc_log("Wifi get:wifi index(%d), is 5g.", wifi_idx);
    }
    
    if(get_uci_option_value(module_name, "disabled", value_str) != 0)
    {
        return -1;
    }
    disabled = atoi(value_str);
    bc_log("Wifi get:disabled(uci:%s):%d.", value_str, disabled);

    if (wifi_idx == 1)
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", IF_NAME_OF_2G);
    }
    else
    {
        snprintf(module_name, sizeof(module_name) - 1, "wireless.%s", IF_NAME_OF_5G);
    }
    
    if(get_uci_option_value(module_name, "ssid", value_str) != 0)
    {
        return -1;
    }
    snprintf(ssid, sizeof(ssid) - 1, "%s", value_str);
    bc_log("Wifi get:ssid(uci:%s):%s.", value_str, ssid);

    if(get_uci_option_value(module_name, "encryption", value_str) != 0)
    {
        return -1;
    }
    snprintf(encryption, sizeof(encryption) - 1, "%s", value_str);
    bc_log("Wifi get:encryption(uci:%s):%s.", value_str, encryption);

    if (strcmp(encryption, "none")) //加密
    {
        if(get_uci_option_value(module_name, "key", value_str) != 0)
        {
            return -1;
        }
        snprintf(key, sizeof(key) - 1, "%s", value_str);
        bc_log("Wifi get:key(uci:%s):%s.", value_str, key);
    }
    else    //未加密
    {
        snprintf(key, sizeof(key) - 1, "%s", "none");
        bc_log("Wifi get:key:%s.", key);
    }
    
    my_object = json_object_new_object();
    json_object_object_add(my_object, OBJECT_WIFI_DISABLED, json_object_new_int(disabled));
    json_object_object_add(my_object, OBJECT_WIFI_SSID, json_object_new_string(ssid));
    json_object_object_add(my_object, OBJECT_WIFI_ENCRYPT, json_object_new_string(encryption));
    json_object_object_add(my_object, OBJECT_WIFI_KEY, json_object_new_string(key));

    my_string = json_object_to_json_string(my_object);
    len = strlen(my_string);
    bc_create_reply_msg(request_msg_head, my_string, len);
    json_object_put(my_object);

    msg_printf((void *)g_reply_msg_buff, desc, len + sizeof(MsgHeader), 2);
    ret = msg_send(fd, (MsgHeader *)g_reply_msg_buff);

    return ret;
}

int bc_prcs_clilist_add(MsgHeader *msg, int fd)
{
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    unsigned int msg_len = 0;
    char *p_curr = NULL;
    char value_buf[2048] = {0};
    json_object *my_string, *my_obj;
    int ret = RESULT_CODE_SUCCESS;
    char *mac_str = NULL;
    char cmd[128 + MAX_STAS_LEN] = {0};
    char option_black_mac[16] = OPTION_BLACK_STA;
    char value_string[MAX_STAS_LEN] = {0};
    char tmp[32] = {0};
    char desc[64] = {0};
    
    msg_len = request_msg_head->dataLength;
    if (0 == msg_len)
    {
        printf("length of received black table set msg is zero!\n");
        bc_log("Black list set:length of received black table set msg is zero.");
        ret = RESULT_CODE_MSG_SHORT;
        goto reply;
    }

    p_curr = (char *)(request_msg_head + 1);
    memset(value_buf, 0, sizeof(value_buf));
    if (msg_len > sizeof(value_buf))
    {
        printf("length of received black table set msg is too big!\n");
        bc_log("Black list set:length(%d) of received black table set msg is too big.", msg_len);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    memcpy(value_buf, p_curr, msg_len);

    my_string = json_tokener_parse(value_buf);
    if (is_error(my_string))
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

    my_obj = json_object_object_get(my_string, "mac");
    if (my_obj != NULL)
    {
        mac_str = json_object_get_string(my_obj);
        if (strlen(mac_str) != 17)
        {
            printf("wrong mac(len:%d) of set black table!\n", strlen(mac_str));
            ret = RESULT_CODE_WRONG_PARAMETER;
            goto reply;
        }
        
        if (get_uci_option_value(MODULE_NAME_OF_THIS, option_black_mac, value_string) == 0)
        {
            if (!strstr(value_string, mac_str)) //黑名单中已经存在的用户不重复添加
            {
                snprintf(cmd, sizeof(cmd) - 1, "iptables -I FORWARD -m mac --mac-source %s -j DROP", mac_str);
                ret = bc_system(cmd, 1);
                if (ret != RESULT_CODE_SUCCESS)
                    goto reply;
                bc_log("Black list set:mac %s add to blacklist.", mac_str);

                if (!strcmp(value_string, "none"))  //配置为空，没有用户mac
                {
                    snprintf(cmd, sizeof(cmd) - 1, "uci set %s.@%s[0].%s=%s", MODULE_NAME_OF_THIS, MODULE_NAME_OF_THIS, OPTION_BLACK_STA, mac_str);
                    ret = bc_system(cmd, 1);
                    if (ret != RESULT_CODE_SUCCESS)
                        goto reply;
                }
                else
                {
                    snprintf(tmp, sizeof(tmp) - 1, "-%s", mac_str);
                    strcat(value_string, tmp);
                    
                    snprintf(cmd, sizeof(cmd) - 1, "uci set %s.@%s[0].%s=%s", MODULE_NAME_OF_THIS, MODULE_NAME_OF_THIS, OPTION_BLACK_STA, value_string);
                    ret = bc_system(cmd, 1);
                    if (ret != RESULT_CODE_SUCCESS)
                        goto reply;
                }

                snprintf(cmd, sizeof(cmd) - 1, "%s", APPLY_COMMIT);
                ret = bc_system(cmd, 1);
                if (ret != RESULT_CODE_SUCCESS)
                    goto reply;
            }
        }
    }
    else
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

reply: 
    bc_set_reply(ret, desc, request_msg_head, fd);
    
    json_object_put(my_string);	
    json_object_put(my_obj);

    return ret;
}

int bc_prcs_clilist_del(MsgHeader *msg, int fd)
{
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    unsigned int msg_len = 0;
    char *p_curr = NULL;
    char value_buf[2048] = {0};
    json_object *my_string, *my_obj;
    int ret = RESULT_CODE_SUCCESS;
    char *mac_str = NULL;
    char cmd[128 + MAX_STAS_LEN] = {0};
    char option_black_mac[16] = OPTION_BLACK_STA;
    char value_string[MAX_STAS_LEN] = {0};
    char tmp[32] = {0};
    char desc[64] = {0};
    
    msg_len = request_msg_head->dataLength;
    if (0 == msg_len)
    {
        printf("length of received black table set msg is zero!\n");
        bc_log("Black list set:length of received black table set msg is zero.");
        ret = RESULT_CODE_MSG_SHORT;
        goto reply;
    }

    p_curr = (char *)(request_msg_head + 1);
    memset(value_buf, 0, sizeof(value_buf));
    if (msg_len > sizeof(value_buf))
    {
        printf("length of received black table set msg is too big!\n");
        bc_log("Black list set:length(%d) of received black table set msg is too big.", msg_len);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    memcpy(value_buf, p_curr, msg_len);

    my_string = json_tokener_parse(value_buf);
    if (is_error(my_string))
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

    my_obj = json_object_object_get(my_string, "mac");
    if (my_obj != NULL)
    {
        mac_str = json_object_get_string(my_obj);
        if (strlen(mac_str) != 17)
        {
            printf("wrong mac(len:%d) of set black table!\n", strlen(mac_str));
            ret = RESULT_CODE_WRONG_PARAMETER;
            goto reply;
        }
        
        if (get_uci_option_value(MODULE_NAME_OF_THIS, option_black_mac, value_string) == 0)
        {
            snprintf(tmp, sizeof(tmp) - 1, "-%s", mac_str);
            if (strstr(value_string, tmp))  //mac串在配置中间或结尾
            {
                snprintf(cmd, sizeof(cmd) - 1, "iptables -D FORWARD -m mac --mac-source %s -j DROP", mac_str);
                ret = bc_system(cmd, 1);
                if (ret != RESULT_CODE_SUCCESS)
                    goto reply;
                bc_log("Black list set:mac %s del from blacklist.", mac_str);

                del_substr(value_string, tmp);
                snprintf(cmd, sizeof(cmd) - 1, "uci set %s.@%s[0].%s=%s", MODULE_NAME_OF_THIS, MODULE_NAME_OF_THIS, OPTION_BLACK_STA, value_string);
                ret = bc_system(cmd, 1);
                if (ret != RESULT_CODE_SUCCESS)
                    goto reply;
            }
            else
            {
                snprintf(tmp, sizeof(tmp) - 1, "%s", mac_str);  //mac串在配置的开头
                if (strstr(value_string, tmp))
                {
                    snprintf(cmd, sizeof(cmd) - 1, "iptables -D FORWARD -m mac --mac-source %s -j DROP", mac_str);
                    ret = bc_system(cmd, 1);
                    if (ret != RESULT_CODE_SUCCESS)
                        goto reply;
                    bc_log("Black list set:mac %s del from blacklist.", mac_str);
                        
                    del_substr(value_string, tmp);
                    snprintf(cmd, sizeof(cmd) - 1, "uci set %s.@%s[0].%s=%s", MODULE_NAME_OF_THIS, MODULE_NAME_OF_THIS, OPTION_BLACK_STA, value_string);
                    ret = bc_system(cmd, 1);
                    if (ret != RESULT_CODE_SUCCESS)
                        goto reply;
                }
            }

            snprintf(cmd, sizeof(cmd) - 1, "%s", APPLY_COMMIT);
            ret = bc_system(cmd, 1);
            if (ret != RESULT_CODE_SUCCESS)
                goto reply;
        }
    }
    else
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

reply: 
    bc_set_reply(ret, desc, request_msg_head, fd);
    
    json_object_put(my_string);	
    json_object_put(my_obj);

    return ret;
}

int bc_prcs_clilist_get(MsgHeader *msg, int fd)
{
    online_sta_table sta_table;
    brctl_mac_table mac_table;
    int rst = -1;
    int i = 0;
    json_object *my_array, *my_string, *body_object;
    char *body_string = NULL;
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int len = 0;
    char desc[64] = {0};
    char none_value[32] = {0};
    
    sta_table_init(&sta_table);
    mac_table_init(&mac_table);

    rst = online_sta_table_set_entry(&sta_table, &mac_table);
    if (sta_table.sta_num > 0)  //有在线用户
    {
        my_array = json_object_new_array();
        for (i = 0; i < sta_table.sta_num; i++)
        {
            my_string = json_object_new_object();
            json_object_object_add(my_string, OBJECT_CLILIST_MAC, json_object_new_string(sta_table.online_sta_info[i].macstr));
            json_object_object_add(my_string, OBJECT_CLILIST_IP, json_object_new_string(sta_table.online_sta_info[i].ipaddr));
            json_object_object_add(my_string, OBJECT_CLILIST_HOST_NAME, json_object_new_string(sta_table.online_sta_info[i].hostname));
            json_object_object_add(my_string, OBJECT_CLILIST_LINK_TYPE, json_object_new_int(sta_table.online_sta_info[i].link_type));
            json_object_object_add(my_string, OBJECT_CLILIST_LINK_STATUS, json_object_new_int(sta_table.online_sta_info[i].line_status));
            json_object_array_add(my_array, my_string);
        }
        
        body_object = json_object_new_object();
        json_object_object_add(body_object, OBJECT_CLILIST_TITLE, my_array);
        body_string = json_object_to_json_string(body_object);
        len = strlen(body_string);
        bc_create_reply_msg(request_msg_head, body_string, len);

        json_object_put(my_string); 
        json_object_put(my_array); 
        json_object_put(body_object);
    }
    else    //没有在线用户
    {
        body_object = json_object_new_object();
        snprintf(none_value, sizeof(none_value) - 1, "%s", "none");
        json_object_object_add(body_object, OBJECT_CLILIST_TITLE, json_object_new_string(none_value));
        body_string = json_object_to_json_string(body_object);
        len = strlen(body_string);
        bc_create_reply_msg(request_msg_head, body_string, len);
        json_object_put(body_object);
    }

    snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_CLI_LIST);
    msg_printf((void *)g_reply_msg_buff, desc, len + sizeof(MsgHeader), 2);
    rst = msg_send(fd, (MsgHeader *)g_reply_msg_buff);

    return rst;
}

int bc_prcs_blacklist_get(MsgHeader *msg, int fd)
{
    online_sta_table sta_table;
    brctl_mac_table mac_table;
    int rst = -1;
    char option_black_mac[16] = OPTION_BLACK_STA;
    char value_string[MAX_STAS_LEN] = {0};
    int online_status = 0;
    json_object *my_array, *my_string, *body_object;
    char *body_string = NULL;
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int len = 0;
    char desc[64] = {0};
    char none_value[32] = {0};
    
    sta_table_init(&sta_table);
    mac_table_init(&mac_table);

    rst = online_sta_table_set_entry(&sta_table, &mac_table);

    if (get_uci_option_value(MODULE_NAME_OF_THIS, option_black_mac, value_string) == 0)
    {
        if (strlen(value_string) >= 17)
        {
            char *mac_str = NULL;
            char delims[] = "-";
            char cmd[128] = {0};

            my_array = json_object_new_array();
            mac_str = strtok(value_string, delims);
            while(mac_str != NULL)
            {
                if(sta_mac_table_search(&sta_table, mac_str) != -1)
                {
                    online_status = 1;  //在线用户列表中找到该mac，表明该用户在线
                }
                else
                {
                    online_status = 0;
                }

                my_string = json_object_new_object();
                json_object_object_add(my_string, OBJECT_CLILIST_MAC, json_object_new_string(mac_str));
                json_object_object_add(my_string, OBJECT_CLILIST_ONLINE_STATUS, json_object_new_int(online_status));
                json_object_array_add(my_array, my_string);
                
                mac_str = strtok(NULL, delims);
            }
            
            body_object = json_object_new_object();
            json_object_object_add(body_object, OBJECT_BLACKLIST_TITLE, my_array);
            body_string = json_object_to_json_string(body_object);
            len = strlen(body_string);
            bc_create_reply_msg(request_msg_head, body_string, len);

            json_object_put(my_string); 
            json_object_put(my_array); 
            json_object_put(body_object);
        }
        else
        {
            body_object = json_object_new_object();
            snprintf(none_value, sizeof(none_value) - 1, "%s", "none");
            json_object_object_add(body_object, OBJECT_BLACKLIST_TITLE, json_object_new_string(none_value));
            body_string = json_object_to_json_string(body_object);
            len = strlen(body_string);
            bc_create_reply_msg(request_msg_head, body_string, len);
            json_object_put(body_object);
        }
        
        snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_BLACK_LIST);
        msg_printf((void *)g_reply_msg_buff, desc, len + sizeof(MsgHeader), 2);
        rst = msg_send(fd, (MsgHeader *)g_reply_msg_buff);
    }

    return rst;
}

int bc_prcs_sysinfo_get(MsgHeader *msg, int fd)
{
    int cpu_percent;
    float mem_total, mem_used;
    float up_rate, down_rate;
    int ret = 0;
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    json_object *my_object;
    char *my_string = NULL;
    char value_str[8] = {0};
    int len = 0;
    
    get_cpu_info(&cpu_percent);
    get_mem_info(&mem_total, &mem_used);
    get_wan_info(&up_rate, &down_rate);

    my_object = json_object_new_object();
    json_object_object_add(my_object, OBJECT_SYSTEM_CPU, json_object_new_int(cpu_percent));

    sprintf(value_str, "%.2f", mem_used);
    json_object_object_add(my_object, OBJECT_SYSTEM_MEM_USED, json_object_new_string(value_str));

    sprintf(value_str, "%.2f", mem_total);
    json_object_object_add(my_object, OBJECT_SYSTEM_MEM_TOTAL, json_object_new_string(value_str));

    sprintf(value_str, "%.2f", up_rate);
    json_object_object_add(my_object, OBJECT_SYSTEM_UP_RATE, json_object_new_string(value_str));

    sprintf(value_str, "%.2f", down_rate);
    json_object_object_add(my_object, OBJECT_SYSTEM_DOWN_RATE, json_object_new_string(value_str));

    my_string = json_object_to_json_string(my_object);
    len = strlen(my_string);
    bc_create_reply_msg(request_msg_head, my_string, len);
    
    json_object_put(my_object);

    msg_printf((void *)g_reply_msg_buff, MSG_DESC_SYSINFO, len + sizeof(MsgHeader), 2);
    ret = msg_send(fd, (MsgHeader *)g_reply_msg_buff);

    return ret;
}

int bc_prcs_imgupdate_set(MsgHeader *msg, int fd)
{
    unsigned int msg_len = 0;
    char *p_curr = NULL;
    char value_buf[2048] = {0};
    json_object *my_string, *soft_version_obj, *url_obj, *md5_obj;
    char *sw_ver = NULL;
    char *url = NULL;
    char *md5 = NULL;
    char cmd[DOWNLOAD_PATH_LEN] = {0};
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int ret = RESULT_CODE_SUCCESS;
    char desc[64] = {0};
    char md5_str[64] = {0};
    http_response_msg *http_response = NULL;
    json_object *body_object;
    char titlestring[31] = {0};
    char descstring[31] = {0};
    char msgstring[31] = {0};
    char *body_string = NULL;
    char send_buf[1024] = {0};
    int len = 0;
    char *pcur = NULL;
    char img_url[128] = MODULE_URL;

    msg_len = request_msg_head->dataLength;
    if (0 == msg_len)
    {
        printf("length of received img update msg is zero!\n");
        bc_log("Img update:length of received img update msg is zero.");
        ret = RESULT_CODE_MSG_SHORT;
        goto reply;
    }

    p_curr = (char *)(request_msg_head + 1);
    memset(value_buf, 0, sizeof(value_buf));
    if (msg_len > sizeof(value_buf))
    {
        printf("length of received img update msg is too big!\n");
        bc_log("Img update:length(%d) of received img update msg is too big.", msg_len);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    memcpy(value_buf, p_curr, msg_len);

    my_string = json_tokener_parse(value_buf);
    if (is_error(my_string)) 
    {
        printf("json_tokener_parse failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

    /* 解析获取软件版本sw_ver */
    soft_version_obj = json_object_object_get(my_string, "sw_ver");
    if (soft_version_obj == NULL)
    {
        printf("json_object_object_get sw_ver failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }
    
    sw_ver = json_object_get_string(soft_version_obj);
    if (sw_ver == NULL)
    {
        printf("json_object_get_string sw_ver is NULL!\n");
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    bc_log("Img update:software version is %s.", sw_ver);

    /* 解析获取url */
    url_obj = json_object_object_get(my_string, "url");
    if (url_obj == NULL)
    {
        printf("json_object_object_get url failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }
    
    url = json_object_get_string(url_obj);
    if (url == NULL)
    {
        printf("json_object_get_string url is NULL!\n");
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    bc_log("Img update:software url is %s.", url);

    /* 解析获取md5 */
    md5_obj = json_object_object_get(my_string, "md5");
    if (md5_obj == NULL)
    {
        printf("json_object_object_get url failed!\n");
        ret = RESULT_CODE_INTERNAL_ERR;
        goto reply;
    }

    md5 = json_object_get_string(md5_obj);
    if (md5 == NULL)
    {
        printf("json_object_get_string md5 is NULL!\n");
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    bc_log("Img update:software md5 is %s.", md5);

    /* 下载升级之前先回复 */
    ret = RESULT_CODE_SUCCESS;
    snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_SYS_UPD_REPLY);
    bc_set_reply(ret, desc, request_msg_head, fd);
    
    /* 根据url下载升级文件 */
    snprintf(cmd, DOWNLOAD_PATH_LEN-1, "rm -f %s%s.bin", FIRMWARE_DOWNLOAD_PATH, sw_ver);
    ret = bc_system(cmd, 1);
    snprintf(cmd, DOWNLOAD_PATH_LEN-1,
            "/usr/bin/wget %s -O %s%s.bin",
            url, FIRMWARE_DOWNLOAD_PATH, sw_ver);
    ret = download_file(cmd, DOWNLOAD_TIME_OUT);
    if (ret != RESULT_CODE_SUCCESS)
    {
        printf("system %s download file failed!\n", cmd);
        bc_log("Img update:system %s download file failed.", cmd);
        goto reply;
    }
    bc_log("Img update:wget download file %s success.", url);

    /* 计算下载的升级文件md5值 */
    snprintf(cmd, DOWNLOAD_PATH_LEN-1, "md5sum "FIRMWARE_DOWNLOAD_PATH"%s.bin | cut -d ' ' -f 1", sw_ver);
    ret = get_cmd_value(cmd, md5_str);
    if (ret != RESULT_CODE_SUCCESS)
    {
        printf("get_cmd_value(%s) failed!\n", cmd);
        bc_log("Img update:get_cmd_value(%s) failed.", cmd);
        goto reply;
    }

    /* 用md5值对升级文件进行校验,如果校验不过,删除下载的文件 */
    if (strcmp(md5, md5_str) != 0)
    {
        printf("md5s are not equal, local is %s, while msg's is %s!\n", md5_str, md5);
        bc_log("Img update:md5s are not equal, local is %s, while msg's is %s.\n", md5_str, md5);
        snprintf(cmd, DOWNLOAD_PATH_LEN-1, "rm -f %s%s.bin", FIRMWARE_DOWNLOAD_PATH, sw_ver);
        bc_system(cmd, 1);
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto reply;
    }
    else
    {
        /* 先回复再升级，应为升级会重启系统 */
        goto reply_and_apply;
    }


reply:
    json_object_put(my_string);
    json_object_put(soft_version_obj);
    json_object_put(url_obj);
    json_object_put(md5_obj);

    return ret;
    
reply_and_apply:
    body_object = json_object_new_object();
    sprintf(titlestring, "%s", MSG_TITLE);
    json_object_object_add(body_object, OBJECT_TITLE, json_object_new_string(titlestring));
    sprintf(descstring, "%s", MSG_DESC);
    json_object_object_add(body_object, OBJECT_DESC, json_object_new_string(descstring));
    sprintf(msgstring, "%s", MSG_RST);
    json_object_object_add(body_object, OBJECT_MSG, json_object_new_string(msgstring));
    body_string = json_object_to_json_string(body_object);

    memset(send_buf, 0, sizeof(send_buf));//每次组装前先清零
    pcur = (char *)((char *)send_buf);
    len = strlen(body_string);
    memcpy(pcur, body_string, len);
    
    msg_printf((void *)send_buf, MSG_DESC_IMG_UPDATE, len, 2);  //打印发送给http库消息
    http_response = http_client(M_POST, img_url, (char *)send_buf, len, TYPE_APP_JSON);
    FREE_BUF_AND_NULL_PTR(http_response);
    json_object_put(body_object);
    
    /* 软件升级，保存配置 */
    bc_log("Img update:system is going to update and reboot.\n");
    snprintf(cmd, DOWNLOAD_PATH_LEN-1, "sysupgrade "FIRMWARE_DOWNLOAD_PATH"%s.bin", sw_ver);
    //snprintf(cmd, DOWNLOAD_PATH_LEN-1, "mtd -r write "FIRMWARE_DOWNLOAD_PATH"%s.bin firmware", sw_ver);
    system(cmd);

    json_object_put(my_string); 
    json_object_put(soft_version_obj);
    json_object_put(url_obj);
    json_object_put(md5_obj);
    
    return ret;
}

int bc_prcs_sysreboot_set(MsgHeader *msg, int fd)
{
    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int ret = RESULT_CODE_SUCCESS;
    char desc[64] = {0};
    
    snprintf(desc, sizeof(desc) - 1, "%s", MSG_DESC_SYS_REB_REPLY);
reply: 
    bc_set_reply(ret, desc, request_msg_head, fd);
    sleep(2);
    bc_log("Reboot set:receive reboot command and system will reboot soon.");
    bc_system("reboot", 1);
    
    return ret;
}

void cmdline_to_argcv(char *cmd, int *argc, char *argv[])
{
    int     count = 0;
    char    *head;
    char    *end;

    head = cmd;
    do
    {
        if (count >= *argc)
        {
            break;
        }

        /* 去除首部多余的空格与制表符 */
        for (; (*head == ' ' || *head == '\t'); head++)
        {
        }

        if (*head == '\0')
        {
            break;
        }

        if (   (NULL != (end = strchr(head, ' ')))
            || (NULL != (end = strchr(head, '\t')))
           )
        {
            *end = '\0';
            argv[count++] = head;
            head = end + 1;
        }
        else
        {
            argv[count++] = head;
            break;
        }
    } while (1);

    argv[count] = NULL;
    *argc = count;
}

void bc_execvp(const char *fmt, ...)
{
    va_list     args;
    char        cmd[512] = {0};
    char        *argv[128] = {0};
    int         argc = sizeof(argv)/sizeof(argv[0]);

	va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd) - 1, fmt, args);
	va_end(args);

    cmdline_to_argcv(cmd, &argc, argv);

    execvp(argv[0], argv);
}

int download_file(char *cmd, int time_out)
{
    pid_t       pid;
    int         status;
    unsigned long msec = (unsigned long)time_out * 1000;
    struct sigaction    nsa;
    struct sigaction    osa;
    struct itimerval    nitv;
    struct itimerval    oitv;

    void sig_handler(int sig)
    {
        int bakup = errno;

        switch (sig)
        {
            case SIGALRM:
            case SIGTERM:
                kill(pid, SIGTERM);
                break;
            default:
                break;
        }

        errno = bakup;
    }

    if (NULL == cmd)
    {
        printf("Bad argument\n");
        return RESULT_CODE_WRONG_PARAMETER;
    }

    pid = vfork();

    if (-1 == pid) /* 异常情况 */
    {
        return RESULT_CODE_INTERNAL_ERR;
    }

    if (pid == 0) /* 子进程 */
    {
        bc_execvp(cmd);
    }

    if (0 != msec)
    {
    	nsa.sa_handler = sig_handler;
    	sigemptyset(&nsa.sa_mask);
    	nsa.sa_flags = 0;
    	sigaction(SIGALRM, &nsa, &osa);

    	nitv.it_value.tv_sec = msec / 1000;
    	nitv.it_value.tv_usec = (msec % 1000) * 1000;
    	nitv.it_interval.tv_sec = 0;
        nitv.it_interval.tv_usec = 0;
    	setitimer(ITIMER_REAL, &nitv, &oitv);
    }

    /* 父进程等待子进程返回 */
    do
    {
        if (waitpid(pid, &status, 0) == -1)
        {
            if (EINTR != errno)
            {
                status = -1;
                break;
            }
        }
        else
        {
            break;
        }
    } while (1);

    /*-------- 根据子进程退出状态进行相应处理 --------*/
    if (0 != msec)
    {
        /* 恢复旧的SIGALRM的处理 */
    	sigaction(SIGALRM, &osa, NULL);
        setitimer(ITIMER_REAL, &oitv, NULL);
    }

    if (status != 0)
    {
       return RESULT_CODE_INTERNAL_ERR;
    }

    return RESULT_CODE_SUCCESS;
}

/***
function:   将字符串进行MD5加密
params:
    enc_pwd:    [in|out] 值结果参数，用来保存加密后的密码
    len:        length of enc_pwd buff
    pwd:_str:   原始密码，明文
return:
    -1: failed
    0:  success
***/
static int md5_encryption(char *enc_pwd, int len, char *pwd_str)
{
    assert(enc_pwd && (len > 0) && pwd_str);
    
	char tmp[3]={'\0'};
	char buf[128] = {0};
	unsigned char md[16] = {0};
	int i = 0;
    int ret_len = 0;
    
#define ENC_KEY_CLOUD    "{opencloud}"    

	ret_len = snprintf(buf,sizeof(buf),"%s",pwd_str);
    if (ret_len <= 0)
    {
        return -1;
    }
    
    if (ret_len + strlen(ENC_KEY_CLOUD) >= sizeof(buf))
    {
        return -1;
    }
	strcat(buf,ENC_KEY_CLOUD);
	MD5(buf,strlen(buf),md);
	
	memset(buf,0,sizeof(buf));
	for (i = 0; i < 16; i++){
		snprintf(tmp,sizeof(tmp),"%2.2x",md[i]);
		strcat(buf,tmp);
	}
	
	snprintf(enc_pwd,len,"%s",buf);
	
	return 0;
	
}


/***
function:   通过命令行的方式将数据写入到flash
params:
    cmd_line:   对应的执行命令
    val:        命令行的参数
    flag:       提示下发参数时是否要将上单引号
return
    -1: failed
    0:  success
***/
static int write_value2flash(char *cmd, char *val, int flag)
{
    assert(cmd && val);

    char cmd_line[128] = {0};

    if (flag)
    {
        snprintf(cmd_line, sizeof(cmd_line), "%s \'%s\'", cmd, val);
    }
    else
    {
        snprintf(cmd_line, sizeof(cmd_line), "%s %s", cmd, val);
    }
    
    system(cmd_line);

    return 0;
}

/***
function:   更新shadow文件，更新用户名和密码
params:
    user_name:  被更新的用户名
    cry_pwd:    更新后的cry加密的密码
return:
    <0: failed
    0:  success
***/
static int updata_shadow_file(char *user_name, char *cry_pwd)
{
    assert(user_name && cry_pwd);

    FILE *fp = NULL;
    system("cp /etc/shadow.bak /etc/shadow");
    
    fp = fopen("/etc/shadow","ab+");
    if (fp == NULL)
    {
        return -1;
    }

    fprintf(fp,"%s:%s:0:0:99999:7:::\n",user_name, cry_pwd);

    fclose(fp);
    fp = NULL;
    return 0;
}

/***
function:   更新samba的云账户
params:
    user_name:  云帐号
    pwd:        云密码
return:
    none
***/
static void update_smaba_pwdfile(char *user_name, char *pwd)
{
    assert(user_name && pwd);
    char cmd_line[128] = {0};
    snprintf(cmd_line, sizeof(cmd_line), 
                "(echo %s;echo %s) | smbpasswd -a -s %s;", pwd, pwd, user_name);
    bc_log("cmd_line:%s\n", cmd_line);
    system(cmd_line);
    return;
}

/***
function:   处理密码更新消息
params:
    msg:    数据包内容
    fd:     unix 文件描述符
return:
    <0: failed
    0:  success
***/
int bc_prcs_sysaccount_set(MsgHeader *msg, int fd)
{
    if (msg == NULL || fd < 0)
    {
        bc_log("sysaccount input params have some error.\n");
        return -1;
    }
    
#define MAX_PWD_LENGTH      64

    MsgHeader *request_msg_head = (MsgHeader *)msg;
    int ret = RESULT_CODE_SUCCESS;
    char desc[64] = {0};
    char md5_pwd[MAX_PWD_LENGTH] = {0};
    unsigned int msg_len = 0;
    char *p_curr = NULL;
    json_object *body_obj = NULL;
    json_object *pwd_obj = NULL;
    char *pwd_str = NULL;
    char value_buff[128] = {0};
    char *cry_pwd = NULL;
    static char user_name[MAX_STAS_LEN];
    
    msg_len = request_msg_head->dataLength;
    if (msg_len <= 0)
    {
        ret = RESULT_CODE_MSG_SHORT;
        goto set_failed;
    }

    p_curr = (char *)(request_msg_head + 1);

    if (msg_len >= sizeof(value_buff))
    {
        ret = RESULT_CODE_WRONG_PARAMETER;
        bc_log("body msg too long ,msg_len:%d\n", msg_len);
        goto set_failed;
    }

    memcpy(value_buff, p_curr, msg_len);

    body_obj = json_tokener_parse(value_buff);
    if (body_obj == NULL)
    {
        ret = RESULT_CODE_WRONG_PARAMETER;
        bc_log("json tokener parse failed value_buff:%s\n", value_buff);
        goto set_failed;
    }

    pwd_obj = json_object_object_get(body_obj, PWD_KEY);
    if (pwd_obj == NULL)
    {
        ret = RESULT_CODE_WRONG_PARAMETER;
        bc_log("get %s object failed\n", PWD_KEY);
        goto set_failed;
    }

    pwd_str = json_object_get_string(pwd_obj);
    if (pwd_str == NULL)
    {
        ret = RESULT_CODE_WRONG_PARAMETER;
        goto set_failed;
    }

    if (strlen(user_name) == 0)
    {
        if (get_cmd_value("protest --cloud_name -r", user_name) < 0)
        {
            ret = RESULT_CODE_INTERNAL_ERR;
            bc_log("protest get username failed\n");
            goto set_failed;
        }
    }
    update_smaba_pwdfile(user_name, pwd_str);        // 更新samba的用户名和密码

    write_value2flash(SET_PWD2FLASH, pwd_str, 1);   // 将原始明文密码写入flash
    
    if (md5_encryption(md5_pwd, MAX_PWD_LENGTH, pwd_str) < 0)   // 明文密码进行MD5加密
    {
        ret = RESULT_CODE_INTERNAL_ERR;
        bc_log("md5 encry failed\n");
        goto set_failed;
    }
    
    write_value2flash(SET_MD5PWD2FLASH, md5_pwd, 1);    // 将MD5加密后的密码写入flash

    cry_pwd = crypt(pwd_str,CRYPT_KEY_STRING);
    if (cry_pwd == NULL)
    {
        ret = RESULT_CODE_INTERNAL_ERR;
        bc_log("crypt failed, pwd:%s\n", pwd_str);
        goto set_failed;
    }

    write_value2flash(SET_CRYPWD2FLASH, cry_pwd, 1);
    
    if (updata_shadow_file(user_name, cry_pwd) < 0)  // 更新shadow文件
    {
        ret = RESULT_CODE_INTERNAL_ERR;
        bc_log("updata shadow file failed\n");
        goto set_failed;
    }

set_failed:
    bc_set_reply(ret, CHANGE_PWD, request_msg_head, fd);	
    json_object_put(pwd_obj);
    json_object_put(body_obj);
    return ret;
}

static void bc_create_reply_msg(MsgHeader *request_msg_head, char *my_string, int len)
{
    MsgHeader *reply_msg_head = (MsgHeader *)g_reply_msg_buff;
    char *p_cur = (char *)(reply_msg_head + 1);
    memcpy(reply_msg_head->src, request_msg_head->dst, sizeof(reply_msg_head->dst));
    memcpy(reply_msg_head->dst, request_msg_head->src, sizeof(reply_msg_head->src));
    memcpy(reply_msg_head->messageId, request_msg_head->messageId, sizeof(reply_msg_head->messageId));
    reply_msg_head->flags.bits.response = 1;
    reply_msg_head->sequenceNumber = request_msg_head->sequenceNumber;
    reply_msg_head->actionType = request_msg_head->actionType;
    reply_msg_head->dataLength = len;
    memcpy(p_cur, my_string, len);
}

static void bc_create_rst_msg(char *rst_msg, int ret)
{
    switch (ret)
    {
        case RESULT_CODE_SUCCESS:
        {
            sprintf(rst_msg, "%s", RESULT_SUCCESS);
            break;
        }
        case RESULT_CODE_WRONG_PARAMETER:
        {
            sprintf(rst_msg, "%s", RESULT_WRONG_PARAMETER);
            break;
        }
        case RESULT_CODE_MSG_SHORT:
        {
            sprintf(rst_msg, "%s", RESULT_MSG_SHORT);
            break;
        }
        case RESULT_CODE_INTERNAL_ERR:
        {
            sprintf(rst_msg, "%s", RESULT_INTERNAL_ERR);
            break;
        }
        case RESULT_CODE_SYSTEM_CMD_ERR:
        {
            sprintf(rst_msg, "%s", RESULT_SYSTEM_CMD_ERR);
            break;
        }
        case RESULT_CODE_SYSTEM_CMD_TIMEOUT:
        {
            sprintf(rst_msg, "%s", RESULT_MSG_SYSTEM_CMD_TIMEOUT);
            break;
        }
        case RESULT_CODE_DOWNLOADING_IMG:
        {
            sprintf(rst_msg, "%s", RESULT_UPDATING);
            break;
        }
        default:
        {
            sprintf(rst_msg, "%s", RESULT_UNKOWN);
            break;
        }
    }
}

void bc_set_reply(int ret, char *desc, MsgHeader *request_msg_head, int fd)
{
    json_object *reply_object;
    char rst_msg[128] = {0};
    char *value_str = NULL;
    int len = 0;
    
    reply_object = json_object_new_object();
    json_object_object_add(reply_object, OBJECT_ERROR_CODE, json_object_new_int(ret));

    bc_create_rst_msg(rst_msg, ret);
    json_object_object_add(reply_object, OBJECT_ERROR_MSG, json_object_new_string(rst_msg));

    value_str = json_object_to_json_string(reply_object);
    
    len = strlen(value_str);
    bc_create_reply_msg(request_msg_head, value_str, len);

    json_object_put(reply_object);

    msg_printf((void *)g_reply_msg_buff, desc, len + sizeof(MsgHeader), 2);
    ret = msg_send(fd, (MsgHeader *)g_reply_msg_buff);
}

void bc_log(const char *fmt, ...)
{
    va_list         args;
    char            timedscrptn[32];
    char            buffer[256];
    int             lftlen = sizeof(buffer) - 1;
    int             tmplen;
    char           *pos = buffer;
    char            bakfilename[32] = {0};
    static  char   *filename = NULL;
    static  FILE   *file = NULL;
    static  u_long  count = 0;
    struct stat     m_fileStat ;
    
    /* fill to buffer */
    time_to_string(time(NULL), timedscrptn, sizeof(timedscrptn));
    tmplen  = snprintf(pos, lftlen, "[%s] ", timedscrptn);
    pos    += tmplen;
    lftlen -= tmplen;

	va_start(args, fmt);
    tmplen  = vsnprintf(pos, lftlen, fmt, args);
	va_end(args);
    pos    += tmplen;
    lftlen -= tmplen;

    tmplen  = snprintf(pos, lftlen, "\n");
    pos    += tmplen;
    lftlen -= tmplen;

	memset(&m_fileStat,0x0,sizeof(m_fileStat));
	if ( 0 == stat(BC_LOG_FILE_NAME, &m_fileStat))
	{
		count = m_fileStat.st_size;
	}

    /* 如果已经将文件写的太大，
       rename 会失败，直接删除。
    */
    if (count >= 100 * 1024)   //100K Byte
    {
        if(file) fclose(file);
        file = NULL;
        count = 0;

        unlink(filename);
    }
    else if (count >= BC_LOG_MAX_SIZE * 15)   //60K Byte
    {
        /* rename this file to re-create */
        if(file) fclose(file);
        file = NULL;
        count = 0;

        snprintf(bakfilename, sizeof(bakfilename) - 1, "%s.old", filename);
        rename(filename, bakfilename);
    }

    if (NULL == file) /* the first time */
    {
        file = fopen(BC_LOG_FILE_NAME, "a");
        if (NULL == file)
        {
            goto write_end;
        }
    }
    
    fprintf(file, buffer);
    fflush(file);

write_end:

    return;
}

static int bc_find_str_in_file(const char *fileName, const char *str)
{
    FILE *fd = NULL;
    char buf[512] = {0};
    int ret = -1;

    fd = fopen(fileName, "r");
    if(NULL == fd)
    {
    	printf("Open %s file failed!", fileName);
    	return ret;
    }

    while(1)
    {
        if(fgets(buf, sizeof(buf), fd) == NULL)
        {
            break;
        }
        if(strstr(buf, str) != NULL)
        {
            ret = 0;
            break;
        }
    }

    fclose(fd);

    return ret;
}

static void get_cpu_info(int *cpu_percent)
{
    int cpu = 0;
    char cmd[64] = {0};
    char value_string[8] = {0};

    snprintf(cmd, sizeof(cmd) - 1, "%s", PATH_CPU_RATE_SH);
    get_cmd_value(cmd, value_string);
    cpu = atoi(value_string);
    *cpu_percent = cpu;
}

#if 0
void get_cpuoccupy (cpu_occupy *cpust) //对无类型get函数含有一个形参结构体类弄的指针O
{   
    FILE *fd;         
    int n;            
    char buff[256]; 
    cpu_occupy *cpu_occupy;
    cpu_occupy = cpust;
                                                                                                               
    fd = fopen ("/proc/stat", "r"); 
    fgets (buff, sizeof(buff), fd);
    
    sscanf (buff, "%s %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice,&cpu_occupy->system, &cpu_occupy->idle);
    
    fclose(fd);     
}

int cal_cpuoccupy (cpu_occupy *o, cpu_occupy *n) 
{   
    unsigned long od, nd;    
    unsigned long id, sd;
    int cpu_use = 0;   
    
    od = (unsigned long) (o->user + o->nice + o->system +o->idle);//第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (unsigned long) (n->user + n->nice + n->system +n->idle);//第二次(用户+优先级+系统+空闲)的时间再赋给od
      
    id = (unsigned long) (n->user - o->user);    //用户第一次和第二次的时间之差再赋给id
    sd = (unsigned long) (n->system - o->system);//系统第一次和第二次的时间之差再赋给sd
    if((nd-od) != 0)
        cpu_use = (int)((sd+id)*10000)/(nd-od); //((用户+系统)乖100)除(第一次和第二次的时间差)再赋给g_cpu_used
    else 
        cpu_use = 0;
    
    return cpu_use;
}
#endif

static void get_mem_info(float *mem_total, float *mem_used)
{
    char buffer[1024+1];
    int fd, len;
    char *p;
    int i;
    unsigned long memory_stats[MEM_STATS_NUM];

    fd = open("/proc/meminfo", O_RDONLY);
	len = read(fd, buffer, sizeof(buffer)-1);
	close(fd);
	buffer[len] = '\0';

    p = buffer;
    for (i = 0; i < MEM_STATS_NUM; i++)
    {
        p = skip_token(p);			
        memory_stats[i] = strtoul(p, &p, 10);
        p = strchr(p, '\n');
        p++;
    }

    if (memory_stats[0] > 0)
    {
        *mem_total = (float)memory_stats[0] / 1024.0;
    }
    if ((memory_stats[0] - memory_stats[1] - memory_stats[2] - memory_stats[3]) > 0)
    {
        *mem_used = (float)(memory_stats[0] - memory_stats[1] - memory_stats[2] - memory_stats[3]) / 1024.0;
    }
    
    return;
}

void converter_string_with_special_character(char *str)
{
    int  len, i;
    char buffer[256];
    char *pOut;

    memset(buffer,0,256);
    len = strlen(str);
    pOut = &buffer[0];

    for (i = 0; i < len; i++)
    {
        /* check special character */
        switch (str[i])
        {
            case '"':
                strcpy (pOut, "\\\"");
                pOut += 2;
                break;
            case '&':
                strcpy (pOut, "\\\&");
                pOut += 2;
                break;
            case '(':
                strcpy (pOut, "\\\(");
                pOut += 2;
                break;
            case ')':
                strcpy (pOut, "\\\)");
                pOut += 2;
                break;
            case '|':
                strcpy (pOut, "\\\|");
                pOut += 2;
                break;
            case '\\':
                strcpy (pOut, "\\\\");
                pOut += 2;
                break;
            case '\'':
                strcpy (pOut, "\\\'");
                pOut += 2;
                break;
            case '<':
                strcpy (pOut, "\\\<");
                pOut += 2;
                break;
            case '>':
                strcpy (pOut, "\\\>");
                pOut += 2;
                break;
            case ';':
                strcpy (pOut, "\\\;");
                pOut += 2;
                break;
            case ' ':
                strcpy (pOut, "\\\ ");
                pOut += 2;
                break;
            default:  
                *pOut = str[i];
                pOut++;
                break;
        }
    }

    *pOut = '\0';
    strcpy(str, buffer);

    return;
}   

int del_substr(char *str, char *substr)
{
    int i = 0;
    char *temp_str = str;
    char const *temp_substr = substr;
    int sub_len = strlen(substr);
    
    while(1)
    {
        if(*temp_str == *temp_substr)
        {
            temp_substr++;
            if(*temp_substr == '\0')
            {
                break;
            }
        }
        else
        {
            temp_substr = substr;
        }
        
        if(*temp_str == '\0')
        {
            return 0;
        }
        temp_str++;
    }
    char *preDel = temp_str - (sub_len - 1);
    while(*(preDel + (i+sub_len)) != '\0')
    {
        *(preDel + i) = *(preDel + (i+sub_len));
        i++;
    }
    *(preDel + i) = '\0';
    
    return 1;
}

char *skip_white(char *ptr)
{
    if (ptr == NULL)
        return (NULL);
    while (*ptr != 0 && isspace(*ptr))
        ptr++;
    if (*ptr == 0 || *ptr == '#')
        return (NULL);
    return (ptr);
}

char *skip_not_white(char *ptr)
{
    if (ptr == NULL)
        return (NULL);
    while (*ptr != 0 && !isspace(*ptr))
        ptr++;
    if (*ptr == 0 || *ptr == '#')
        return (NULL);
    return (ptr);
}

char *skip_token(char *ptr)
{
    ptr = skip_white(ptr);
    ptr = skip_not_white(ptr);
    ptr = skip_white(ptr);
    return (ptr);
}

static void get_wan_info(float *up_rate, float *down_rate)
{
    unsigned long ul_temp = 0;
    static float  up_kbps = 0.00;
    static float  down_kbps = 0.00;
    unsigned long time=times(NULL);
    char wan_name[16] = "eth2";
    char cmd[16] = "ifconfig";
    char value_str[64] = {0};

    if (time - g_tx_bytes[1] > 100)//增加时间限制，避免频繁获取
    {
        if(cmd_read(cmd, wan_name, NULL, "TX bytes", ":", value_str, sizeof(value_str)))
        {
            return ;
        }

        ul_temp = strtoul(value_str,NULL,0);
        up_kbps = (float)((ul_temp - g_tx_bytes[0])*100) / (float)((time - g_tx_bytes[1]));
        up_kbps /= 1024.00;
        g_tx_bytes[0] = ul_temp;
        g_tx_bytes[1] = time;
    }
    *up_rate = up_kbps;

    if (time - g_rx_bytes[1] > 100)
    {
        if(cmd_read(cmd, wan_name, NULL, "RX bytes", ":", value_str, sizeof(value_str)))
        {
            return ;
        }

        ul_temp = strtoul(value_str,NULL,0);
        down_kbps = (float)((ul_temp - g_rx_bytes[0])*100) / (float)((time - g_rx_bytes[1]));
        down_kbps /= 1024.00;
        g_rx_bytes[0] = ul_temp;
        g_rx_bytes[1] = time;
    }
    *down_rate = down_kbps;
}

int cmd_read(const char* command, const char* ifname, const char *pszPrefix, const char* itemname, const char* seperator, char* value, size_t size)
{
	int ret = 0;
	FILE* fp = NULL;
	char cmd[64];
	char valuetemp[64]={0};
	char buff[256];
	char* pos = NULL;

	snprintf(cmd, sizeof(cmd) - 1, "%s %s 2>/dev/null", command, ifname);
	fp = popen(cmd, "r");
	if (!fp) 
	{
		printf("err: open pipe of '%s' for read failed!\n", cmd);
		return -1;
	}
	
	ret = -1;		/* default not found */
	while (!feof(fp)) 
	{
		if (!fgets(buff, sizeof(buff), fp)) 
		{
			break;
		}
		
        if(pszPrefix) 
        {/*to continue the followint strstr() marked 2, it must meet the condition in this embrace*/
            char *tp = strstr(buff, pszPrefix);
            if(!tp) continue;
        }
        
		pos = strstr(buff, itemname);   // 2 
		if (!pos) 
		{
			continue;
		}
		
		ret = 0;
		if (value && size) 
		{
			pos += strlen(itemname);
			pos = strtok(pos, seperator);
			if (strlen(pos)<size) 
			{	

                for(;;)//去掉字符串开始的空格
                {
                    if(*pos==' ')
                        pos++;
                    else	
                        break;
                }
				if(*pos=='\0')
				{
					break;//字符串为空,直接返回  
				}	
				strcpy(valuetemp,pos);//dest 和src不能重叠
				strcpy(value,valuetemp);
				pos=value;
				while(*pos!=' '&&*pos!='\0')//去掉字符串后面的部分,加上结束符
				{
					pos++;
				}
				*pos='\0';
				break;
			} 
			else 
			{
			
				printf("err: buffer size too small!\n");
				ret = -1;
				break;
			}
		}
		break;
	}
	
	while (!feof(fp)) 
	{
		if (!fgets(buff, sizeof(buff), fp)) 
		{
			break;
		}
	}
	pclose(fp);
	
	return ret;
}

static int bc_system(char *command, int printFlag)
{
	int pid = 0, status = 0;
    time_t start, current;    
  	pid_t  pid_ret=0;
    char szCmd[128] = {0};

    if(!command)
    {
        printf("detectsta_system: Null Command, Error!");
        return RESULT_CODE_SYSTEM_CMD_ERR;
    }

	pid = fork();
  	if (pid == -1)
  	{
		return RESULT_CODE_SYSTEM_CMD_ERR;
	}

  	if (pid == 0)
  	{
        char *argv[4];
    	argv[0] = "sh";
    	argv[1] = "-c";
    	argv[2] = command;
    	argv[3] = 0;
    	if (printFlag)
    	{
	        printf("[system]: %s\r\n", command);
        }
    	execv("/bin/sh", argv);
    	exit(127);
	}

  	start = time(NULL);
  	/* wait for child process return */
  	do
  	{
        pid_ret = waitpid(pid, &status, WNOHANG);
        if (pid_ret < 0)
        {
            if (errno != EINTR)
            {
                printf("ERROR! exce  %s  error, pid_ret %d, status %d pid %d(father pid %d)\n", command, pid_ret, status, pid, getpid());
                return RESULT_CODE_SYSTEM_CMD_ERR;
            }
        }
        else if(pid_ret == 0)
        {
            // do nothing!
        }
        else
        {
            return RESULT_CODE_SUCCESS;
        }

        current = time(NULL);
        if (SYSTEM_TIME_OUT <=  ((unsigned long)current - (unsigned long)start))
        {
            printf("[system]:ERROR! exce %s  timeout[%lu more than %d], pid_ret %d, status %d pid %d(father pid %d). \r\n", command, ((unsigned long )current - (unsigned long )start), SYSTEM_TIME_OUT, pid_ret, status, pid, getpid());
            bc_log("Basic-common:system exce %s timeout.", command);
            break;
        }
	} while (1);

	return RESULT_CODE_SYSTEM_CMD_TIMEOUT;
}

static void sta_table_init(online_sta_table *tab) 
{
	int i;
	
	tab->sta_num = 0;
	for (i = 0; i < MAX_LEN_OF_ONLINE_STA_TABLE; i++) 
	{
		memset(&tab->online_sta_info[i], 0, sizeof(online_sta_entry));
	}
}

static void mac_table_init(brctl_mac_table *tab) 
{
	int i;
	
	tab->mac_num = 0;
	for (i = 0; i < MAX_LEN_OF_ONLINE_STA_TABLE; i++) 
	{
		memset(&tab->brctl_mac_info[i], 0, sizeof(brctl_mac_entry));
	}
}

static void online_sta_set_entry(online_sta_entry *p_entry, char *name, char *ipstr, char *macstr, int type, int status)
{
    memcpy(p_entry->hostname, name, MAX_NAME_LEN);
    memcpy(p_entry->ipaddr, ipstr, IP_ADDR_LEN);
    memcpy(p_entry->macstr, macstr, MAC_STR_LEN);
    p_entry->link_type = type;
    p_entry->line_status = status;
}

static void brctl_mac_set_entry(brctl_mac_entry *p_entry, int port, char *macstr, char *localstr)
{
    p_entry->port_no = port;
    memcpy(p_entry->local_status, localstr, STATUS_LEN);
    memcpy(p_entry->macstr, macstr, MAC_STR_LEN);
}

static int brctl_mac_table_search(brctl_mac_table *tab, char *macstr) 
{
	int i;
	
	for (i = 0; i < tab->mac_num; i++) 
	{
		if (!memcmp(tab->brctl_mac_info[i].macstr, macstr, MAC_STR_LEN - 1)) 
		{ 
			return tab->brctl_mac_info[i].port_no;
		}
	}
	
	return 0;
}

static int sta_mac_table_search(online_sta_table *tab, char *macstr) 
{
	int i;
	
	for (i = 0; i < tab->sta_num; i++) 
	{
		if (!memcmp(tab->online_sta_info[i].macstr, macstr, MAC_STR_LEN - 1)) 
		{ 
			return i;
		}
	}
	
	return -1;
}

static int online_sta_table_set_entry(online_sta_table *sta_tab, brctl_mac_table *mac_tab)
{
    int idx = 0;
    char name[MAX_NAME_LEN] = {0};
    char ipstr[IP_ADDR_LEN] = {0}; 
    char macstr[MAC_STR_LEN] = {0};
    char localstr[STATUS_LEN] = {0};
    unsigned long expire;
    FILE *fp = NULL;
    char buf[BUFF_LEN] = {0};
    int num = 0;
    char cmd[BUFF_LEN] = {0};
    int port = 0;
    int mac_port = 0;
    int link_type = 0;
    char option_black_mac[16] = OPTION_BLACK_STA;
    char value_string[MAX_STAS_LEN] = {0};
    int link_status = 0;

    snprintf(cmd, sizeof(cmd) - 1, "%s", CMD_BRCTL_SHOW_MACS);
    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        printf("%s failed!\n", CMD_BRCTL_SHOW_MACS);
        return -1;
    }

    fgets(buf, sizeof(buf) - 1, fp);//第一行为头，跳过
    while (NULL != fgets(buf, sizeof(buf) - 1, fp))
    {
        if (mac_tab->mac_num >= MAX_LEN_OF_ONLINE_STA_TABLE)
        {
            printf("mac num is too big!\n");
            break;
        }
        
        num = sscanf(buf, "%d   %s  %s", &port, macstr, localstr);
        if (num < 3)
        {
            printf("parse pipe of cmd(%s) fail!\n", CMD_BRCTL_SHOW_MACS);
            break;
        }
        
        idx = mac_tab->mac_num;
        brctl_mac_set_entry(&mac_tab->brctl_mac_info[idx], port, macstr, localstr);
        mac_tab->mac_num++;
    }
    pclose(fp);
    
    if (0 != access(DHCP_LEASE_FILE, R_OK))
    {
        printf("file %s does not exist!\n", DHCP_LEASE_FILE);
        return -1;
    }
    
    fp = fopen(DHCP_LEASE_FILE, "r");
    if (fp == NULL)
    {
        printf("dhcp lease file:%s is NULL!\n", DHCP_LEASE_FILE);
        return -1;
    }
    
    while (NULL != fgets(buf, sizeof(buf) - 1, fp))
    {
        if (sta_tab->sta_num >= MAX_LEN_OF_ONLINE_STA_TABLE)
        {
            printf("online sta num is too big!\n");
            return -1;
        }
        
        num = sscanf(buf, "%lu %s %s %s", &expire, macstr, ipstr, name);
        if (num < 3)
        {
            printf("parse line of file(%s) fail!\n", DHCP_LEASE_FILE);
            break;
        }

        mac_port = brctl_mac_table_search(mac_tab, macstr);
        if (mac_port == 1)//有线 eth2.1
        {
            link_type = 0;
        }
        else if (mac_port == 2)//5g rai0
        {
            link_type = 2;
        }
        else if (mac_port == 3)//2.4g ra0
        {
            link_type = 1;
        }
        else//该用户不在线
        {
            continue;
        }

        if (get_uci_option_value(MODULE_NAME_OF_THIS, option_black_mac, value_string) == 0)
        {
            if (strstr(value_string, macstr))
            {
                link_status = 0;
            }
            else
            {
                link_status = 1;
            }

        }
        
        idx = sta_tab->sta_num;
        online_sta_set_entry(&sta_tab->online_sta_info[idx], name, ipstr, macstr, link_type, link_status);
        sta_tab->sta_num++;
    }
    fclose(fp);

    return 0;  
}

int get_uci_option_value(char *name, char *option, char *value)
{
    char cmd[128] = {0};
    FILE* fp = NULL;
    
    snprintf(cmd, sizeof(cmd) - 1, "uci show %s |grep %s |cut -d '=' -f 2", name, option);
    fp = popen(cmd, "r");
    if (!fp)
    {
    	return -1;
    }

	fgets(value, MAX_STAS_LEN - 1, fp);
	if (value[strlen(value)-1] == 0x0a)
		value[strlen(value)-1] = '\0';
    pclose(fp);
    
    return 0;
}

int get_cmd_value(char *name, char *value)
{
    char cmd[256] = {0};
    FILE* fp = NULL;
    
    snprintf(cmd, sizeof(cmd) - 1, "%s", name);
    fp = popen(cmd, "r");
    if (!fp)
    {
    	return -1;
    }

	fgets(value, MAX_STAS_LEN - 1, fp);
	if (value[strlen(value)-1] == 0x0a)
		value[strlen(value)-1] = '\0';
    pclose(fp);
    
    return 0;
}

int main(int argc, char *argv[])
{
    MsgRet ret = MSGRET_SUCCESS;
    MsgHeader *p_msg = NULL;
    char option_black_mac[16] = OPTION_BLACK_STA;
    char value_string[MAX_STAS_LEN] = {0};
    unsigned int time_out = TIME_OUT;
    int acc_fd = -1;
    char mac_str[32] = {0};

    if (get_uci_option_value(MODULE_NAME_OF_THIS, option_black_mac, value_string) == 0)
    {
        if (strcmp(value_string, "none") != 0)  //none为空配置，表示没有黑名单用户
        {
            char *mac_str = NULL;
            char delims[] = "-";
            char cmd[128] = {0};
            
            mac_str = strtok(value_string, delims);
            while(mac_str != NULL)
            {
                snprintf(cmd, sizeof(cmd) - 1, "iptables -I FORWARD -m mac --mac-source %s -j DROP", mac_str);
                bc_system(cmd, 1);
                mac_str = strtok(NULL, delims);
            }
        }
    }
    
    g_bc_unix_socket = unix_domain_server_socket_init(MODULE_NAME_OF_THIS);
    while (1)
    {
        acc_fd = server_accept_before_msg_send_and_receive(g_bc_unix_socket);
        ret = msg_receive(acc_fd, &p_msg, &time_out);
        
        if (ret != MSGRET_SUCCESS)
        {
            printf("msg receive failed acc_fd = %d!\n", acc_fd);
            bc_log("Baisc-common:msg receive failed acc_fd = %d.", acc_fd);
            goto bad_msg;
        }
        
        msg_printf((void *)p_msg, MSG_DESC_CONFIG, p_msg->dataLength + sizeof(MsgHeader), 1);
        if (p_msg->dataLength <= 0)
        {
            printf("Bad msg:length(%d) too short!\n", p_msg->dataLength);
            bc_log("Baisc-common:length(%d) of msg receive is too short.", p_msg->dataLength);
            goto bad_msg;
        }
        
        if (p_msg->dst == NULL)
        {
            printf("Bad msg:mode name is empty!\n");
            bc_log("Baisc-common:dest mode name is empty.");
            goto bad_msg;
        }
        
        switch (p_msg->actionType)
        {
            case ACTION_SET:
            case ACTION_GET:
            case ACTION_ADD:
            case ACTION_DEL:
            {
                switch (strcmp(p_msg->dst, MODULE_NAME_OF_WIFI1) == 0 ? 1:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_WIFI2) == 0 ? 2:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_SYSTEM) == 0 ? 3:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_CLILIST) == 0 ? 4:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_BLACKLIST) == 0 ? 5:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_REBOOT) == 0 ? 6:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_IMGUPDATE) == 0 ? 7:( \
                    strcmp(p_msg->dst, MODULE_NAME_OF_SYNACCOUNT) == 0 ? 8:DEFAULT_VALUE))))))))
                {
                    case 1:
                    {
                        if ((p_msg->actionType != 1) && (p_msg->actionType != 2))
                        {
                            printf("wifi process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Wifi set:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_wifi_msg_prcs_tab[p_msg->actionType](p_msg, 1, acc_fd);
                        break;
                    }
                    case 2:
                    {
                        if ((p_msg->actionType != 1) && (p_msg->actionType != 2))
                        {
                            printf("wifi process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Wifi set:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_wifi_msg_prcs_tab[p_msg->actionType](p_msg, 2, acc_fd);
                        break;
                    }
                    case 3:
                    {
                        if (p_msg->actionType != 2)
                        {
                            printf("sysinfo process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Sysinfo set:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_sysinfo_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    case 4:
                    {
                        if ((p_msg->actionType != 2) && (p_msg->actionType != 3) && (p_msg->actionType != 4))
                        {
                            printf("client list process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Client list set:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_clilist_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    case 5:
                    {
                        if (p_msg->actionType != 2)
                        {
                            printf("black list process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Black list set:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_blacklist_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    case 6:
                    {
                        if (p_msg->actionType != 1)
                        {
                            printf("system reboot process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("System reboot:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_reboot_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    case 7:
                    {
                        if (p_msg->actionType != 1)
                        {
                            printf("img update process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("Img update:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_imgupdate_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    case 8:
                    {
                        if (p_msg->actionType != 1)
                        {
                            printf("pwd syn process does not support p_msg->actionType %d\n", p_msg->actionType);
                            bc_log("pwd syn:receive not support action type %d.", p_msg->actionType);
                            break;
                        }
                        g_synaccount_msg_prcs_tab[p_msg->actionType](p_msg, acc_fd);
                        break;
                    }
                    default:
                    {
                        printf("unkown destination object(%s)!\n", p_msg->dst);
                        bc_log("Basic-common:receive not support destination object %s.", p_msg->dst);
                        break;
                    }
                }
                break;
            }
            default:
            {
                printf("unkown action(%d)!\n", p_msg->actionType);
                bc_log("Basic-common:receive not support action %d.", p_msg->actionType);
                break;
            }
        }

 bad_msg:
    FREE_BUF_AND_NULL_PTR(p_msg);
    unix_domain_client_socket_deinit(acc_fd);
    continue; 
    }

quit:
    unix_domain_client_socket_deinit(g_bc_unix_socket);
    bc_log("Basic-common:basic common module quit");
    printf("basic common module quit!\n");
    
    return 0; 
}
