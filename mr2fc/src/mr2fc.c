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
#
*************************************************************************/
#ifdef __cplusplus
#if __cplusplus
        extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

/******************************************************************************
 *                               INCLUDES                                     *
 ******************************************************************************/
#include "mr2fc.h"

static int tcp_prcs_http_request(char *msg_body, unsigned int msg_len, unsigned int seq);
static int tcp_prcs_login_ret(char *msg_body, unsigned int msg_len, unsigned int seq);
static int tcp_prcs_logout_ret(char *msg_body, unsigned int msg_len, unsigned int seq);
static int tcp_prcs_heartbeat_ret(char *msg_body, unsigned int msg_len, unsigned int seq);
static int get_system_info(char *cmd, char *value, unsigned int size);
static int tcp_send_msg_via_ssl(socket_manage_info *socket_info, void *msg_buf, int msg_len);
static int tcp_send_msg(socket_manage_info *socket_info, void *msg_buf, int msg_len);
static int tcp_creat_normal_resp_frame(msg_type type, unsigned int seq, void *head_data, unsigned int head_len, void *resp_data, unsigned int len);
static JsonHeadInfo *json_msg_head_parse(char *msg, int len);
static usr_login_info *json_msg_login_data_parse(char *pMsg, unsigned long iLen);
static void *json_msg_bind_data_parse(char *pMsg, unsigned long iLen, int type);
static int find_app_in_shm(int app_id);
static char *tcp_send_msg_to_other(const char *module_name, char *msg_body, int msg_len, int *recv_len);
static void http_set_ret_msg(char *ret_msg, int ret);
static int tcp_recv_msg(socket_manage_info *socket_info, void **msg_buf, int *msg_len);
static int tcp_send_msg(socket_manage_info *socket_info, void *msg_buf, int msg_len);

static char *http_content_types[] = 
{
    "Content-Type:application/json;charset=UTF-8", 
    "Content-Type:text/html;charset=UTF-8", 
	"Content-Type:application/xml; charset=UTF-8", 
	"Content-Type:application/octet-stream;charset=UTF-8"
};

socket_manage_info g_TcpSocketInfo;
mr2fc_config_info g_Mr2fcConfigInfo;
run_stage_type g_RunStage;
static char g_tcp_send_buff[TCP_REPLY_BUF_LEN] = {0};
unsigned long long g_curr_tcp_session = 0;
unsigned int g_heart_beat_count = 0;
static AppProcInfo g_app_proc_info[PROC_INFO_SHM_NUM];
unsigned int g_seq_no = 0;
unsigned char g_client_online_flags[MAX_ONLINE_CLIENT_CNT] = {0};
http_client g_http_clients[MAX_ONLINE_CLIENT_CNT];
static int g_StateBind = 0;
unsigned char g_BindProc = 0;
pthread_mutex_t bind_execute_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bind_nozero = PTHREAD_COND_INITIALIZER;
pthread_mutex_t bind_proc_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bind_proc_nozero = PTHREAD_COND_INITIALIZER;
pthread_mutex_t perauth_proc_mutex = PTHREAD_MUTEX_INITIALIZER;
char g_curr_tcp_cli_session[MAX_SESSION_STR_LEN] = {0};

struct 
{
    const char *key;
    const char *format;
    char *value;
} g_Mr2fcConfigSt[] = 
{
    {"ServerName",          FORMAT_STRING, (char *)g_Mr2fcConfigInfo.server_name},
    {"PortNo",              FORMAT_UNINT,  (char *)&g_Mr2fcConfigInfo.server_port},
    {"HBInterval",          FORMAT_UNINT,  (char *)&g_Mr2fcConfigInfo.heart_beat_interval},
    {"HttpPort",            FORMAT_UNINT,  (char *)&g_Mr2fcConfigInfo.http_port},
};

static tcp_msg_prcs_tbl_item g_tcp_msg_prcs_table[] = 
{
    {SSID_SEND,             "MSG_FORM_APP_HTTP_REQUEST", tcp_prcs_http_request},
    {ROUTER_LOGIN_RET,      "DEV_LOGIN_RESULT",          tcp_prcs_login_ret},
    {ROUTER_LOGINOUT_RET,   "DEV_LOGOUT_RESULT",         tcp_prcs_logout_ret},
    {ROUTER_HEARBEAT_RET,   "HEART_BEAT_FROM_CLOUD",     tcp_prcs_heartbeat_ret},

};

/******************************************************************************
 *                         PRIVATE FUNCTIONS                                  *
 ******************************************************************************/
static void http_dump_request(struct evhttp_request *req, enum evhttp_cmd_type req_type, void *arg);
static int http_fix_reply_head(struct evkeyvalq *header);
static int http_post_process(struct evhttp_request *req, char *post_data, unsigned long data_len);
static void http_req_get_prc(struct evhttp_request *req, void *arg);
static void http_req_post_prc(struct evhttp_request *req, void *arg);
static void http_genc_prc_cb(struct evhttp_request *req, void *arg);

/******************************************************************************
 *                               FUNCTIONS                                    *
 ******************************************************************************/

static int get_system_info(char *cmd, char *value, unsigned int size)
{
    char cmd_buf[512] = {0};
    FILE *fp = NULL;
    
    snprintf(cmd_buf, sizeof(cmd_buf) - 1, "%s", cmd);
    fp = popen(cmd_buf, "r");
    if (!fp)
    {
    	return -1;
    }

	fgets(value, size, fp);
	if (value[strlen(value)-1] == 0x0a)
		value[strlen(value)-1] = '\0';
    pclose(fp);
    
    return 0;
}

static unsigned long long net_to_host_dw(char *p)
{
    unsigned int tmp;
    unsigned long long value = 0;

    tmp = (unsigned int)(*p << 24 | *(p + 1) << 16 | *(p + 2) << 8 | *(p + 3));
    value = tmp;
    p += 4;
    tmp = (unsigned int)(*p << 24 | *(p + 1) << 16 | *(p + 2) << 8 | *(p + 3));
    value = (unsigned long long)(value << 32 | tmp);

    return value;
}

static void http_dump_request(struct evhttp_request *req, enum evhttp_cmd_type req_type, void *arg)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;

	switch (req_type) 
	{
    	case EVHTTP_REQ_GET: 
    	    cmdtype = "GET"; 
    	    break;
    	case EVHTTP_REQ_POST: 
    	    cmdtype = "POST"; 
    	    break;
    	case EVHTTP_REQ_HEAD: 
    	    cmdtype = "HEAD"; 
    	    break;
    	case EVHTTP_REQ_PUT: 
    	    cmdtype = "PUT"; 
	        break;
    	case EVHTTP_REQ_DELETE: 
    	    cmdtype = "DELETE"; 
    	    break;
    	case EVHTTP_REQ_OPTIONS: 
    	    cmdtype = "OPTIONS"; 
    	    break;
    	case EVHTTP_REQ_TRACE: 
    	    cmdtype = "TRACE"; 
    	    break;
    	case EVHTTP_REQ_CONNECT: 
    	    cmdtype = "CONNECT"; 
    	    break;
    	case EVHTTP_REQ_PATCH: 
    	    cmdtype = "PATCH"; 
    	    break;
    	default: 
    	    cmdtype = "unknown"; 
    	    break;
	}

    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "request type:%s", cmdtype);
	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header; header = header->next.tqe_next) 
    {
		IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "  %s: %s", header->key, header->value);
	}
}

static int http_fix_reply_head(struct evkeyvalq *header)
{
    int ret;
    
    if(0 != (ret = evhttp_add_header(header, "Server", "imove http v1.1.0")))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error, reason:%d", ret);
        return -1;
    }

    if(0 != (ret = evhttp_add_header(header, "Content-Type", "text/plain; charset=UTF-8")))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error, reason:%d", ret);
        return -1;
    }

    if(0 != (ret = evhttp_add_header(header, "Connection", "keep-alive")))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error, reason:%d", ret);
        return -1;
    }

    if(0 != (ret = evhttp_add_header(header, "Cache_Control", "no-cache")))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error, reason:%d", ret);
        return -1;
    }

    return 0;
}

static int http_reg_client(struct evhttp_request *req, int index, unsigned int time)
{
    char cmd[128] = {0};
    int i = 0;
    char mac_str[MAC_STR_LEN + 1] = {0};


    /* client mac */
    if (0 == access(ARP_FILE, F_OK))
    {
        snprintf(cmd, sizeof(cmd) - 1, "cat %s | grep %s | cut -d ' ' -f %d", 
            ARP_FILE, req->remote_host, 36 - strlen(req->remote_host));
        if (0 != get_system_info(cmd, mac_str, MAC_STR_LEN + 1))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "get client mac failed, cmd:%s!", cmd);
            return -1;
        }
    }

    /* treat mac as the identity of client */
    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        if (1 == g_client_online_flags[i])
        {
            if (0 == strcmp(mac_str, g_http_clients[i].mac))
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "same client existing, mac:%s", g_http_clients[i].mac);
                return i;
            }
        }
    }
    
    /* client ip, port, last communicate time, session id */
    snprintf(g_http_clients[index].ip, MAX_IP_LEN + 1, "%s", req->remote_host);
    g_http_clients[index].port = req->remote_port;
    g_http_clients[index].last_time = time;
    snprintf(g_http_clients[index].session, MAX_SESSION_STR_LEN + 1, "%d", time);

    /* client mac */
    sprintf(g_http_clients[index].mac, "%s", mac_str);

    /* client host name */
    if (0 == access(DHCP_RELEASE_FILE, F_OK))
    {
        snprintf(cmd, sizeof(cmd) - 1, "cat %s | grep %s | cut -d ' ' -f 4", 
            DHCP_RELEASE_FILE, g_http_clients[index].ip);
        if (0 != get_system_info(cmd, g_http_clients[index].name, MAX_HOST_NAME_LEN + 1))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "get client hostname failed, cmd:%s!", cmd);
            return -1;
        }
    }
    g_client_online_flags[index] = 1;

    return 9999;
}

static void http_unreg_client(int index)
{
    memset(&g_http_clients[index], 0, sizeof(http_client));
    g_client_online_flags[index] = 0;
}

static int tcp_creat_bind_msg(usr_bind_info *bind_info)
{
    tcp_msg_head *send_msg_head = (tcp_msg_head *)g_tcp_send_buff;
    int msg_len = 0;
    char cmd[256] = {0};
    char value[128] = {0};
    usr_bind_dev_info *dev_bind_info = (usr_bind_dev_info *)(g_tcp_send_buff + sizeof(tcp_msg_head));
    char *p_curr = (char *)(dev_bind_info + 1);

    memcpy(send_msg_head->sync, DEFAULT_SYNC, SYNC_LEN);
    send_msg_head->cmd = ROUTER_USER_BIND;
    send_msg_head->seq_no = g_seq_no;

    /* 8 bytes session + 1 byte usr name len + usr name + 1 byte dev name len + dev name + 64 bytes dev id */
    dev_bind_info->session_id = g_curr_tcp_session;
    /* usr name */
    dev_bind_info->usr_name_len = strlen(bind_info->usr_name);
    if (dev_bind_info->usr_name_len > 0 && NULL != bind_info->usr_name)
    {
        memcpy(p_curr, bind_info->usr_name, dev_bind_info->usr_name_len);
        p_curr += dev_bind_info->usr_name_len;
    }

    /* router name */
    snprintf(cmd, sizeof(cmd), "uci show wireless | grep 3].ssid | cut -d = -f 2");
    get_system_info(cmd, value, sizeof(value));
    *(unsigned char *)p_curr = strlen(value);
    p_curr += sizeof(unsigned char);
    if (strlen(value) > 0 && NULL != value)
    {
        memcpy(p_curr, value, strlen(value));
        p_curr += strlen(value);
    }

    /* dev id */
    memcpy(p_curr, g_Mr2fcConfigInfo.mac_str, DEV_ID_LEN);
    p_curr[DEV_ID_LEN] = '\0';

    /* 8 bytes session + 1 byte usr name len + usr name + 1 byte dev name len + dev name + 64 bytes dev id */
    send_msg_head->msg_len = sizeof(unsigned long long) + sizeof(unsigned char) + \
        strlen(bind_info->usr_name) + sizeof(unsigned char) + strlen(value) + DEV_ID_LEN;
        
    msg_len = sizeof(tcp_msg_head) + send_msg_head->msg_len;

    return msg_len;
}

static int tcp_creat_bind_state_msg(bind_state_info *bind_state)
{
    tcp_msg_head *send_msg_head = (tcp_msg_head *)g_tcp_send_buff;
    int msg_len = 0;
    usr_bind_dev_info *dev_bind_info = (usr_bind_dev_info *)(g_tcp_send_buff + sizeof(tcp_msg_head));
    char *p_curr = (char *)(dev_bind_info + 1);

    memcpy(send_msg_head->sync, DEFAULT_SYNC, SYNC_LEN);
    send_msg_head->cmd = ROUTER_USER_BIND_STATE;
    send_msg_head->seq_no = g_seq_no;

    /* 8 bytes session + 1 byte usr name len + usr name + 64 bytes dev id */
    dev_bind_info->session_id = g_curr_tcp_session;
    /* usr name */
    dev_bind_info->usr_name_len = strlen(bind_state->usr_name);
    if (dev_bind_info->usr_name_len > 0 && NULL != bind_state->usr_name)
    {
        memcpy(p_curr, bind_state->usr_name, dev_bind_info->usr_name_len);
        p_curr += dev_bind_info->usr_name_len;
    }

    /* dev id */
    memcpy(p_curr, g_Mr2fcConfigInfo.mac_str, DEV_ID_LEN);
    p_curr[DEV_ID_LEN] = '\0';

    /* 8 bytes session + 1 byte usr name len + usr name + 64 bytes dev id */
    send_msg_head->msg_len = sizeof(unsigned long long) + sizeof(unsigned char) + \
        strlen(bind_state->usr_name) + DEV_ID_LEN;
        
    msg_len = sizeof(tcp_msg_head) + send_msg_head->msg_len;

    return msg_len;
}

static void http_bind_reply(JsonHeadInfo *json_head, struct evhttp_request *req, struct evbuffer *reply_buf, void *bind_ret, int ret, int type)
{
    json_object *head_obj = NULL;
    json_object *data_obj = NULL;
    json_object *data_array_obj = NULL;
    json_object *resp_obj = NULL;
    char *resp_str = NULL;
    int len = 0;
    char ret_msg[128] = {0};
    char cmd[256] = {0};
    char value[128] = {0};

    resp_obj = json_object_new_object();
    /* create response json header */
    head_obj = json_object_new_object();
    json_object_object_add(head_obj, K_CMD_ID, json_object_new_int(json_head->iCmd));
    json_object_object_add(head_obj, K_VERSION_NUM, json_object_new_int(json_head->iVer));
    json_object_object_add(head_obj, K_SEQ_NUM, json_object_new_int(json_head->iSeq));
    json_object_object_add(head_obj, K_DEV_TYPE, json_object_new_int(json_head->iDevice));
    json_object_object_add(head_obj, K_APP_ID, json_object_new_int(json_head->iAppId));
    if (NULL == bind_ret)
    {
        json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(ret));
    }
    else
    {
        if (ROUTER_USER_BIND_RET == type)
        {
            json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(((usr_bind_ret *)bind_ret)->state));//bind result
        }
        else
        {
            json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(0));
        }
    }
    json_object_object_add(head_obj, K_SESSION_ID, json_object_new_string(json_head->szSession));
    json_object_object_add(head_obj, K_SIGN, json_object_new_string(json_head->szSign));
    json_object_object_add(resp_obj, K_HEAD, head_obj);

    /* create response json data */
    data_obj = json_object_new_object();
    /* bind result */
    if (NULL == bind_ret)
    {
        json_object_object_add(data_obj, K_RET_CODE, json_object_new_int(ret));
        http_set_ret_msg(ret_msg, ret);
        json_object_object_add(data_obj, K_RET_MSG, json_object_new_string(ret_msg));
    }
    /* succ */
    else
    {
        if (ROUTER_USER_BIND_RET == type)
        {
            usr_bind_ret *bind_act_ret = (usr_bind_ret *)bind_ret;
            snprintf(cmd, sizeof(cmd), "uci show wireless | grep 3].ssid | cut -d = -f 2");
            get_system_info(cmd, value, sizeof(value));
            json_object_object_add(data_obj, K_DEV_NAME, json_object_new_string(value));
            json_object_object_add(data_obj, K_ROUTER_ID, json_object_new_int(NTOHL(bind_act_ret->router_idx)));
            json_object_object_add(data_obj, K_ROUTER_STAT, json_object_new_int(1));//0,offline,1,online
        }
        else
        {
            usr_bind_state_ret *bind_state_ret = (usr_bind_state_ret *)bind_ret;
            json_object_object_add(data_obj, K_BIND_STATE, json_object_new_int(bind_state_ret->state));
        }
    }
    data_array_obj = json_object_new_array();
    json_object_array_add(data_array_obj, data_obj);
    json_object_object_add(resp_obj, K_DATA, data_array_obj);

    /* create reponse json string and send to client */
    resp_str = (char *)json_object_to_json_string(resp_obj);
    len = strlen(resp_str);
    evbuffer_add_printf(reply_buf, "%s", resp_str);
    //IM_MsgPrintf(resp_str, "reply msg to app", len, 2);
    evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);

out:
    /* free source */
    IM_FREE_JSON_OBJ(head_obj);
    IM_FREE_JSON_OBJ(data_obj);
    IM_FREE_JSON_OBJ(data_array_obj);
    IM_FREE_JSON_OBJ(resp_obj);
}


static int tcp_handle_bind_msg(JsonHeadInfo *json_head, struct evhttp_request *req, struct evbuffer *reply_buf, void *msg_buf, int msg_len)
{
    int ret = 0;
    unsigned short cmd_id = 0;
    unsigned int data_len = 0;
    unsigned int seq = 0;
    char sync[SYNC_LEN + 1] = {0};
    char *bind_ret = (char *)(msg_buf + sizeof(tcp_msg_head));

    if (NULL == msg_buf || msg_len <= 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }

    memcpy(sync, msg_buf, SYNC_LEN);
    sync[SYNC_LEN] = '\0';
    if (strcmp(sync, DEFAULT_SYNC))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong sync:%s!", sync);
        return -1;
    }

    data_len = NTOHL(((tcp_msg_head *)msg_buf)->msg_len);
    cmd_id = NTOHS(((tcp_msg_head *)msg_buf)->cmd);
    seq = NTOHL(((tcp_msg_head *)msg_buf)->seq_no);
    if ((ROUTER_USER_BIND_RET != cmd_id && ROUTER_USER_BIND_STATE_RET != cmd_id) || data_len <= 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong msg:cmd_id:%d, len:%d!", cmd_id, data_len);
        return -1;
    }

    http_bind_reply(json_head, req, reply_buf, bind_ret, 0, cmd_id);

    return ret;
}

static int http_usr_bind_proc(JsonHeadInfo *json_head, struct evhttp_request *req, struct evbuffer *reply_buf, char *post_data, unsigned long data_len, int type)
{
    int ret = 0;
    usr_bind_info *bind_info = NULL;
    bind_state_info *bind_state = NULL;
    char tmp[128] = {0};
    int msg_len = 0;
    char *recv_buf = NULL;

    if (CMD_USR_BIND == type)
    {
        bind_info = (usr_bind_info *)json_msg_bind_data_parse(post_data, data_len, type);
        if (NULL == bind_info)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
            ret = INTERNAL_ERR;
            goto err;
        }

        if (0 != IM_RootPwdGet(tmp))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_RootPwdGet failed!");
            ret = INTERNAL_ERR;
            goto err;
        }

        if (strcmp(bind_info->dev_pwd, tmp))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong pwd:%s!", bind_info->dev_pwd);
            ret = PWD_ERR;
            goto err;
        }

        msg_len = tcp_creat_bind_msg(bind_info);
        if (msg_len <= 0)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_bind_msg failed!");
            ret = INTERNAL_ERR;
            goto err;
        }
    }
    else
    {
        bind_state = (bind_state_info *)json_msg_bind_data_parse(post_data, data_len, type);
        if (NULL == bind_state)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_bind_data_parse failed!");
            ret = INTERNAL_ERR;
            goto err;
        }

        msg_len = tcp_creat_bind_state_msg(bind_state);
        if (msg_len <= 0)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_bind_state_msg failed!");
            ret = INTERNAL_ERR;
            goto err;
        }
    }

    if (0 == tcp_send_msg(&g_TcpSocketInfo, g_tcp_send_buff, msg_len))
    {
        g_seq_no++;
        if (0 == tcp_recv_msg(&g_TcpSocketInfo, &recv_buf, &msg_len))
        {
            ret = tcp_handle_bind_msg(json_head, req, reply_buf, recv_buf, msg_len);
            goto out;
        }
        else
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_recv_msg failed!");
            ret = INTERNAL_ERR;
            goto err;
        }
    }
    else
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_send_msg failed!");
        ret = INTERNAL_ERR;
        goto err;
    }
    goto out;
    
err:
    http_bind_reply(json_head, req, reply_buf, NULL, ret, type);
out:
    IM_FREE(recv_buf);
    IM_FREE(bind_info);
    IM_FREE(bind_state);
    return ret;
}

static int htt_server_timeout_check(unsigned int time_now)
{
    stObjBrief *obj_info = NULL;
    int i = 0;

    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        if (1 == g_client_online_flags[i])
        {
            if ((time_now - g_http_clients[i].last_time) > HTTP_CMM_TIME_OUT)
            {
                /* delete obj from root group when time out */
                obj_info = IM_GetObjBrief(g_http_clients[i].mac);
                if (NULL == obj_info)
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_GetObjBrief failed, mac:%s!", g_http_clients[i].mac);
                    return -1;
                }

                if (USR_TYPE_ROOT == obj_info->nGrpId)
                {
                    IM_DelObjFromGrp(g_http_clients[i].mac);
                }
                IM_FREE(obj_info);

                http_unreg_client(i);
            }
        }
    }

    return 0;
}

static int http_client_check(char *cli_mac, unsigned int time_now, struct evhttp_request *req, usr_login_type type)
{
    int ret = DEFAULTE_CODE;
    int i = 0;
    stObjBrief *obj_info = NULL;

    if (type != LOGIN_ANONYMOUS && type != LOGIN_PWD)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong type:%d!", type);
        ret = INTERNAL_ERR;
        goto out;
    }

    if (MAC_STR_LEN != strlen(cli_mac))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong mac!");
        ret = INTERNAL_ERR;
        goto out;
    }

    if (NULL == req)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong req!");
        ret = INTERNAL_ERR;
        goto out;
    }
    
    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        if (1 == g_client_online_flags[i])
        {
            if (0 == strcmp(cli_mac, g_http_clients[i].mac))
            {
                g_http_clients[i].last_time = time_now;
                snprintf(g_http_clients[i].ip, MAX_IP_LEN + 1, "%s", req->remote_host);

                if (type == LOGIN_ANONYMOUS)
                {
                    /* change obj to visitor when in root group */
                    obj_info = IM_GetObjBrief(g_http_clients[i].mac);
                    if (NULL == obj_info)
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_GetObjBrief failed, mac:%s!", g_http_clients[i].mac);
                        ret = INTERNAL_ERR;
                        goto out;
                    }

                    if (USR_TYPE_ROOT == obj_info->nGrpId)
                    {
                        IM_DelObjFromGrp(g_http_clients[i].mac);
                        /* add object to visitor group */
                        ret = IM_AddObj2Grp(USR_TYPE_VISITOR, g_http_clients[i].name, g_http_clients[i].mac);
                        if (0 != ret && -2 != ret)
                        {
                            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_AddObj2Grp failed!");
                            ret = INTERNAL_ERR;
                            goto out;
                        }

                        /* bind session to object */
                        IM_AllSessUnbindMac(g_http_clients[i].mac);
                        if (0 != IM_SessBindMac(g_http_clients[i].session, g_http_clients[i].mac))
                        {
                            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_SessBindMac failed!");
                            ret = INTERNAL_ERR;
                            goto out;
                        }
                    }
                }
                else
                {
                    IM_DelObjFromGrp(g_http_clients[i].mac);
                    /* add object to root group */
                    ret = IM_AddObj2Grp(USR_TYPE_ROOT, g_http_clients[i].name, g_http_clients[i].mac);
                    if (0 != ret && -2 != ret)
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_AddObj2Grp failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }

                    /* bind session to object */
                    IM_AllSessUnbindMac(g_http_clients[i].mac);
                    if (0 != IM_SessBindMac(g_http_clients[i].session, g_http_clients[i].mac))
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_SessBindMac failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }
                }
                
                IM_FREE(obj_info);
                ret = i;
                goto out;
            }
        }
    }

out:
    IM_FREE(obj_info);
    return ret;
}

static int http_regedit_client(unsigned int time_now, struct evhttp_request *req, usr_login_type type)
{
    int ret = DEFAULTE_CODE;
    int i = 0;

    if (type != LOGIN_ANONYMOUS && type != LOGIN_PWD)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong type:%d!", type);
        ret = INTERNAL_ERR;
        goto out;
    }

    if (NULL == req)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong req!");
        ret = INTERNAL_ERR;
        goto out;
    }
    
    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        if (0 == g_client_online_flags[i])
        {
            ret = http_reg_client(req, i, time_now);
            /* reg failed */
            if (ret < 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_reg_client failed!");
                ret = INTERNAL_ERR;
                goto out;
            }
            /* reg succ or already exist */
            else
            {
                if (type == LOGIN_ANONYMOUS)
                {
                    /* add object to visitor group */
                    ret = IM_AddObj2Grp(USR_TYPE_VISITOR, g_http_clients[i].name, g_http_clients[i].mac);
                    if (0 != ret && -2 != ret)
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_AddObj2Grp failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }

                    /* bind session to object */
                    IM_AllSessUnbindMac(g_http_clients[i].mac);
                    if (0 != IM_SessBindMac(g_http_clients[i].session, g_http_clients[i].mac))
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_SessBindMac failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }
                }
                else
                {
                    IM_DelObjFromGrp(g_http_clients[i].mac);
                    /* add object to root group */
                    ret = IM_AddObj2Grp(USR_TYPE_ROOT, g_http_clients[i].name, g_http_clients[i].mac);
                    if (0 != ret && -2 != ret)
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_AddObj2Grp failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }

                    /* bind session to object */
                    IM_AllSessUnbindMac(g_http_clients[i].mac);
                    if (0 != IM_SessBindMac(g_http_clients[i].session, g_http_clients[i].mac))
                    {
                        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_SessBindMac failed!");
                        ret = INTERNAL_ERR;
                        goto out;
                    }
                }
                
                ret = i;
            }
            goto out;
        }
    }

out:
    return ret;
}

static int http_client_logout(char *session)
{
    int i = 0;
    stObjBrief *obj_info = NULL;
    int ret = DEFAULTE_CODE;

    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        if (1 == g_client_online_flags[i])
        {
            if (0 == strcmp(session, g_http_clients[i].session))
            {
                http_unreg_client(i);

                /* delete obj from root group when log out */
                obj_info = IM_GetObjBrief(g_http_clients[i].mac);
                if (NULL == obj_info)
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_GetObjBrief failed, mac:%s!", g_http_clients[i].mac);
                    ret = INTERNAL_ERR;
                    goto out;
                }

                if (USR_TYPE_ROOT == obj_info->nGrpId)
                {
                    IM_DelObjFromGrp(g_http_clients[i].mac);
                }
                IM_FREE(obj_info);
                
                ret = 0;
                break;
            }
        }
    }

out:
    return ret;
}

static int http_app_usr_auth(struct evhttp_request *req, struct evbuffer *reply_buf, char *post_data, unsigned long data_len)
{
    int ret = DEFAULTE_CODE;
    JsonHeadInfo *json_head = NULL;
    usr_login_info *login_ifo = NULL;
    char tmp[128] = {0};
    unsigned int time_now = 0;
    int i = 0;
    int auth_pass = 0;
    char cli_mac[MAC_STR_LEN + 1] = {0};
    char cmd[128] = {0};
    
    /* parse json head */
    json_head = json_msg_head_parse(post_data, data_len);
    if (NULL == json_head)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
        ret = INTERNAL_ERR;
        goto out;
    }

    /* get client mac */
    if (0 == access(ARP_FILE, F_OK))
    {
        snprintf(cmd, sizeof(cmd) - 1, "cat %s | grep %s | cut -d ' ' -f %d", 
            ARP_FILE, req->remote_host, 36 - strlen(req->remote_host));
        if (0 != get_system_info(cmd, cli_mac, MAC_STR_LEN + 1))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "get client mac failed, cmd:%s!", cmd);
            ret = INTERNAL_ERR;
            goto out;
        }
    }

    if (MAC_STR_LEN != strlen(cli_mac))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong client!");
        ret = INTERNAL_ERR;
        goto out;
    }
    
    /* client communicate time out process */
    time_now = time(NULL);
    if (0 != htt_server_timeout_check(time_now))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "htt_server_timeout_check failed!");
        ret = INTERNAL_ERR;
        goto out;
    }
        
    /* process user/dev log in */
    if (json_head->iCmd == CMD_USR_LOGIN)
    {
        login_ifo = json_msg_login_data_parse(post_data, data_len);
        if (NULL == login_ifo)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
            ret = INTERNAL_ERR;
            goto out;
        }

        switch (login_ifo->login_type)
        {
            case LOGIN_ANONYMOUS:
                /* already login, update comunicate time, change group when necessary */
                ret = http_client_check(cli_mac, time_now, req, LOGIN_ANONYMOUS);
                if (DEFAULTE_CODE != ret)
                {
                    goto out;
                }
                
                /* regedit new client */
                ret = http_regedit_client(time_now, req, LOGIN_ANONYMOUS);
                if (DEFAULTE_CODE != ret)
                {
                    goto out;
                }
                
                /* exceed max client count, can not regedit anymore */
                ret = EXCEED_MAX_CLI;
                goto out;

                break;
            case LOGIN_PWD:
                if (0 != IM_RootPwdGet(tmp))
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_RootPwdGet failed!");
                    ret = INTERNAL_ERR;
                    goto out;
                }
                if (0 == strcmp(login_ifo->pwd, tmp))
                {
                    /* already login, update comunicate time, add to root group */
                    ret = http_client_check(cli_mac, time_now, req, LOGIN_PWD);
                    if (DEFAULTE_CODE != ret)
                    {
                        goto out;
                    }
                    
                    /* regedit new client */
                    ret = http_regedit_client(time_now, req, LOGIN_PWD);
                    if (DEFAULTE_CODE != ret)
                    {
                        goto out;
                    }
                    
                    /* exceed max client count, can not regedit anymore */
                    ret = EXCEED_MAX_CLI;
                    goto out;
                }
                else
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong password!");
                    ret = PWD_ERR;
                    goto out;
                }
                break;
            default:
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong login type:%d!", login_ifo->login_type);
                ret = LOGIN_TYPE_ERR;
                goto out;
        }
    }
    /* log out process */
    else if (json_head->iCmd == CMD_USR_LOGOUT)
    {
        ret = http_client_logout(json_head->szSession);
        if (DEFAULTE_CODE == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev logout err, no such dev/user, ip:%s!", req->remote_host);
            ret = LOGOUT_ERR;
            goto out;
        }
        else
        {
            if (0 != ret)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev logout err!");
                ret = INTERNAL_ERR;
            }
            else
            {
                ret = LOGOUT_SUCC;
            }
            goto out;
        }
    }
    else if (json_head->iCmd == CMD_USR_BIND || json_head->iCmd == CMD_GET_BIND_STATE)
    {
        pthread_mutex_lock(&bind_proc_mutex);
        g_BindProc = 1;
        pthread_mutex_unlock(&bind_proc_mutex);
 
        pthread_mutex_lock(&bind_execute_mutex);
        if (g_StateBind == 0)
        {
            pthread_cond_wait(&bind_nozero, &bind_execute_mutex);
        }
        if (0 == http_usr_bind_proc(json_head, req, reply_buf, post_data, data_len, json_head->iCmd))
        {
            ret = BIND_SUCC;
        }
        else
        {
            ret = BIND_FAIL;
        }
        g_StateBind = 0;
        pthread_mutex_unlock(&bind_execute_mutex);
       
        pthread_mutex_lock(&bind_proc_mutex);
        g_BindProc = 0;
        pthread_cond_signal(&bind_proc_nozero);
        pthread_mutex_unlock(&bind_proc_mutex);

        goto out;
    }
    /* auth session id */
    else
    {
        for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
        {
            if (0 == strcmp(json_head->szSession, g_http_clients[i].session))
            {
                /* already login, update comunicate time */
                for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
                {
                    if (0 == strcmp(req->remote_host, g_http_clients[i].ip))
                    {
                        g_http_clients[i].last_time = time_now;
                        break;
                    }
                }
                auth_pass = 1;
                break;
            }
        }

        if (1 != auth_pass)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev do not login, session:%s!", json_head->szSession);
            ret = SESSION_ERR;
            goto out;
        }
        else
        {
            ret = AUTH_SUCC;
            goto out;
        }
    }

out:
    IM_FREE(json_head);
    IM_FREE(login_ifo);
    
    return ret;
}

static void http_set_ret_msg(char *ret_msg, int ret)
{
    switch (ret)
    {
        case AUTH_SUCC:
            sprintf(ret_msg, "%s", RET_MSG_AUTH_SUCC);
            break;
        case LOGOUT_SUCC:
            sprintf(ret_msg, "%s", RET_MSG_LOGOUT_SUCC);
            break;
        case INTERNAL_ERR:
            sprintf(ret_msg, "%s", RET_MSG_INTERNAL_ERR);
            break;
        case LOGIN_TYPE_ERR:
            sprintf(ret_msg, "%s", RET_MSG_LOGINTYPE_ERR);
            break;
        case PWD_ERR:
            sprintf(ret_msg, "%s", RET_MSG_PWD_ERR);
            break;
        case SESSION_ERR:
            sprintf(ret_msg, "%s", RET_MSG_SESSION_ERR);
            break;
        case LOGOUT_ERR:
            sprintf(ret_msg, "%s", RET_MSG_LOGOUT_ERR);
            break;
        case EXCEED_MAX_CLI:
            sprintf(ret_msg, "%s", RET_MSG_EXCEED_MAX_CLI);
            break;
        default:
            sprintf(ret_msg, "%s", RET_MSG_UNKOWN);
            break;
    }
}

static void http_app_auth_ret_proc(struct evhttp_request *req, struct evbuffer *reply_buf, char *post_data, unsigned long data_len, int ret)
{
    JsonHeadInfo *json_head = NULL;
    json_object *head_obj = NULL;
    json_object *data_obj = NULL;
    json_object *data_array_obj = NULL;
    json_object *resp_obj = NULL;
    char *resp_str = NULL;
    int len = 0;
    char ret_msg[128] = {0};

    /* parse json head */
    json_head = json_msg_head_parse(post_data, data_len);
    if (NULL == json_head)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
        goto out;
    }

    resp_obj = json_object_new_object();
    /* create response json header */
    head_obj = json_object_new_object();
    json_object_object_add(head_obj, K_CMD_ID, json_object_new_int(json_head->iCmd));
    json_object_object_add(head_obj, K_VERSION_NUM, json_object_new_int(json_head->iVer));
    json_object_object_add(head_obj, K_SEQ_NUM, json_object_new_int(json_head->iSeq));
    json_object_object_add(head_obj, K_DEV_TYPE, json_object_new_int(json_head->iDevice));
    json_object_object_add(head_obj, K_APP_ID, json_object_new_int(json_head->iAppId));
    if (ret < LOGOUT_SUCC)
    {
        switch (ret)
        {
            case SESSION_ERR:
                json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(CODE_NO_PERM));
                break;
            default:
                json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(ret));
                break;
        }
    }
    else
    {
        json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(0));
    }
    json_object_object_add(head_obj, K_SESSION_ID, json_object_new_string(json_head->szSession));
    json_object_object_add(head_obj, K_SIGN, json_object_new_string(json_head->szSign));
    json_object_object_add(resp_obj, K_HEAD, head_obj);

    /* create response json data */
    data_obj = json_object_new_object();
    /* auth result */
    if (ret < 0)
    {
        json_object_object_add(data_obj, K_RET_CODE, json_object_new_int(ret));
        http_set_ret_msg(ret_msg, ret);
        json_object_object_add(data_obj, K_RET_MSG, json_object_new_string(ret_msg));
    }
    /* login */
    else
    {
        json_object_object_add(data_obj, K_SESS_KEY, json_object_new_string(g_http_clients[ret].session));
    }
    data_array_obj = json_object_new_array();
    json_object_array_add(data_array_obj, data_obj);
    json_object_object_add(resp_obj, K_DATA, data_array_obj);

    /* create reponse json string and send to client */
    resp_str = (char *)json_object_to_json_string(resp_obj);
    len = strlen(resp_str);
    evbuffer_add_printf(reply_buf, "%s", resp_str);
    //IM_MsgPrintf(resp_str, "reply msg to app", len, 2);
    evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);

out:
    /* free source */
    IM_FREE(json_head);
    IM_FREE_JSON_OBJ(head_obj);
    IM_FREE_JSON_OBJ(data_obj);
    IM_FREE_JSON_OBJ(data_array_obj);
    IM_FREE_JSON_OBJ(resp_obj);
}

static int http_post_process(struct evhttp_request *req, char *post_data, unsigned long data_len)
{
    int client_fd = MSG_INVALID_FD;
    int ret = 0;
    char *http_send_buf = NULL;
    char *p_msg = NULL;
    unsigned int time_out = RECV_TIMEOUT;
    struct evbuffer *reply_buf = NULL;
    JsonHeadInfo *json_head = NULL;
    int app_shm_idx = -1;
    int retry = 0;

    /* Create buf for reply */
    reply_buf = evbuffer_new();
    if (NULL == reply_buf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "evbuffer_new error!");
        ret = -1;
        goto out;
    }

    pthread_mutex_lock(&perauth_proc_mutex);
    ret = http_app_usr_auth(req, reply_buf, post_data, data_len);
    pthread_mutex_unlock(&perauth_proc_mutex);
    if (AUTH_SUCC == ret)
    {
        ret = 0;
        goto auth_succ;
    }

    if (BIND_SUCC == ret || BIND_FAIL == ret)
    {
        ret = 0;
        goto out;
    }
    
    /* new client or logout */
    if (ret >= 0)
    {
        http_app_auth_ret_proc(req, reply_buf, post_data, data_len, ret);
        ret = 0;
        goto out;
    }
    /* auth failed, or log out success */
    else
    {
        /* logout */
        if (LOGOUT_SUCC == ret)
        {
            http_app_auth_ret_proc(req, reply_buf, post_data, data_len, ret);
            ret = 0;
            goto out;
        }
        else
        {
            http_app_auth_ret_proc(req, reply_buf, post_data, data_len, ret);
            goto out;
        }
    }

auth_succ:
    /* parse json head */
    json_head = json_msg_head_parse(post_data, data_len);
    if (NULL == json_head)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
        ret = -1;
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        goto err_2;
    }

    /* read app info in share memory and find the app with app id */
    app_shm_idx = find_app_in_shm(json_head->iAppId);
    if (app_shm_idx < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "find_app_in_shm(%d) failed!", json_head->iAppId);
        ret = -1;
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        goto err_2;
    }
    
    /* check app is inmem or not */
    if (0 == g_app_proc_info[app_shm_idx].cInMemFlag)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "dest module is not in mem!");
        ret = -1;
        evbuffer_add_printf(reply_buf, "%s", "module dead");
        goto err_1;
    }

    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "RX http post:cmd:%x,sess:%s,appid:%d", 
        json_head->iCmd, json_head->szSession, json_head->iAppId);

    /* Connect and send post data to module */
    client_fd = IM_DomainClientInit(g_app_proc_info[app_shm_idx].szAppName);
    if (MSG_INVALID_FD == client_fd)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "connect to server error!");
        ret = -1;
        evbuffer_add_printf(reply_buf, "%s", "module dead");
        goto err_1;
    }
    
    ret = IM_MsgSend(client_fd, post_data, data_len);
    if (0 != ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "send error!");
        ret = -1;
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        goto err_2;
    }
    IM_MsgPrintf((void *)post_data, "message to server module", data_len, 2);

    /* Recieve reply from module */
    while (1)
    {
        ret = IM_MsgReceive(client_fd, &p_msg, &time_out);
        if (ret > 0)
        {
            //IM_MsgPrintf((void *)p_msg, "reply message from server module", ret, 1);
            break;
        }
        else if (MSGRET_TIMED_OUT == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recieve reply message from server module timeout!");
            break;
        }
        else if (MSGRET_DISCONNECTED == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "server disconnect!");
            break;
        }
        else if (MSGRET_INVALID_ARGUMENTS == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "invalid arguments!");
            break;
        }
        else if (0 == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recv length 0 msg!");
            continue;
        }
        else
        {
            if (MAX_RECV_RETRY_TIMES > retry)
            {
                retry++;
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recv retry %d!", retry);
                continue;
            }
            else
            {
                retry = 0;
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "internal err");
                break;
            }
        }
    }

    /* Fix reply http header */
    if (0 != http_fix_reply_head(req->output_headers))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error!");
        ret = -1;
        goto out;
    }

    /* Set reply http body */
    if (ret > 0 && p_msg)
    {
        http_send_buf = (char *)malloc(ret + 1);    // +1 for '\0'
        if (!http_send_buf)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
            ret = -1;
            evbuffer_add_printf(reply_buf, "%s", "internal err");
            goto err_2;
        }
        memset(http_send_buf, 0, ret + 1);
        
        memcpy(http_send_buf, p_msg, ret);
        http_send_buf[ret] = '\0';
        evbuffer_add_printf(reply_buf, "%s", http_send_buf);
        //IM_MsgPrintf(http_send_buf, "msg for response HTTP POST request", ret, 2);
        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
    }
    else if (MSGRET_TIMED_OUT == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "process timeout");
        evhttp_send_reply(req, HTTP_INTERNAL, "TIMEOUT", reply_buf);
    }
    else if (MSGRET_DISCONNECTED == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "server disconnect");
        evhttp_send_reply(req, HTTP_INTERNAL, "DISCONNECT", reply_buf);
    }
    else if (MSGRET_INVALID_ARGUMENTS == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "invalid arguments");
        evhttp_send_reply(req, HTTP_INTERNAL, "INVALID ARGS", reply_buf);
    }
    else
    {
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
    }
    ret = 0;
    goto out;

err_1:
    evhttp_send_reply(req, HTTP_INTERNAL, "MODULE DEAD", reply_buf);
    goto out;

err_2:
    evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);

out:
    IM_FREE(p_msg);
    IM_DomainClientDeinit(client_fd);
    IM_FREE(http_send_buf);
    IM_FREE(post_data);
    if (reply_buf)
    {
		evbuffer_free(reply_buf);
	}

    return ret;
}

static http_query_var_tbl *http_pare_query_var(const char *uri, int uri_len)
{
    int len = 0;
    int cnt = 0;
    char *q, *name, *value;
    char *query_uri = NULL;
    char *query = NULL;
    http_query_var_tbl *query_tbl = NULL;
    int idx = 0;
    
    if (NULL == uri || uri_len <= 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong uri!");
        return NULL;
    }
    
    query_tbl = (http_query_var_tbl *)malloc(sizeof(http_query_var_tbl));
    if (NULL == query_tbl)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(query_tbl, 0, sizeof(http_query_var_tbl));

    /* uri */
    query_uri = (char *)malloc(uri_len);
    if (NULL == query_uri)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        IM_FREE(query_tbl);
        return NULL;
    }
    memset(query_uri, 0, uri_len);
    memcpy(query_uri, uri, uri_len);
    query_uri[uri_len] = '\0';

    /* query */
    query = query_uri;
    if (NULL == strsep(&query, "?"))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong uri!");
        IM_FREE(query_tbl);
        IM_FREE(query_uri);
        return NULL;
    }
    
    len = strlen(query);
    if (len <= 0 || NULL == query)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong uri!");
        IM_FREE(query_tbl);
        IM_FREE(query_uri);
        return NULL;
    }

    /* paras delim & */
    q = query;
    while (strsep(&q, "&"))
    {
        cnt++;
    }

    /* get paras */
    query_tbl->count = cnt;
    for (idx = 0, q = query; q < (query + len) && idx < HTTP_MAX_QUERY_VARS;)
    {
        name = value = q;
        for (q += strlen(q); q < (query + len) && !*q; q++)
            ;
        name = strsep(&value, "=");
        strncpy(query_tbl->query_vars[idx].name, name, HTTP_VAR_NAME_LEN);
        strncpy(query_tbl->query_vars[idx].value, value, HTTP_VAR_VALUE_LEN);
        idx++;
    }

    IM_FREE(query_uri);
    return query_tbl;
}

static void delete_subchar(char *str, char c)
{
    int i = 0;
    int j = 0;

    for (i = 0, j = 0; str[i] != '\0'; i++)
    {
        if (str[i] != c)
        {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
}

static void delete_substr(char *str, char *substr)
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
            return;
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
}

static query_vars *http_parse_query_tbl(http_query_var_tbl *query_tbl)
{
    query_vars *http_vars = NULL;
    int i = 0;
    int head_itm = 0;
    int data_itm = 0;

    if (NULL == query_tbl)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong query_tbl!");
        return NULL;
    }

    http_vars = (query_vars *)malloc(sizeof(query_vars));
    if (NULL == http_vars)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(http_vars, 0, sizeof(query_vars));

    for (i = 0; i < query_tbl->count; i++)
    {
        /* get header */
        if (strstr(query_tbl->query_vars[i].name, K_HEAD))
        {
            if (head_itm < MAX_HEAD_ITEMS)
            {
                /* name */
                strncpy(http_vars->head_vars[head_itm].name, query_tbl->query_vars[i].name, HTTP_VAR_NAME_LEN);
                delete_substr(http_vars->head_vars[head_itm].name, K_HEAD);
                delete_subchar(http_vars->head_vars[head_itm].name, '[');
                delete_subchar(http_vars->head_vars[head_itm].name, ']');
                /* type and value */
                if (query_tbl->query_vars[i].value[0] == '"')
                {
                    strncpy(http_vars->head_vars[head_itm].value, query_tbl->query_vars[i].value, HTTP_VAR_VALUE_LEN);
                    delete_subchar(http_vars->head_vars[head_itm].value, '"');
                    http_vars->head_vars[head_itm].type = TYPE_STR;
                }
                else
                {
                    http_vars->head_vars[head_itm].type = TYPE_INT;
                    strncpy(http_vars->head_vars[head_itm].value, query_tbl->query_vars[i].value, HTTP_VAR_VALUE_LEN);
                }

                head_itm++;
            }
        }
        /* get data */
        else if (strstr(query_tbl->query_vars[i].name, K_DATA))
        {
            if (data_itm < MAX_DATA_ITEMS)
            {
                /* name */
                strncpy(http_vars->data_vars[data_itm].name, query_tbl->query_vars[i].name, HTTP_VAR_NAME_LEN);
                delete_substr(http_vars->data_vars[data_itm].name, K_DATA);
                delete_substr(http_vars->data_vars[data_itm].name, "[0]");
                delete_subchar(http_vars->data_vars[data_itm].name, '[');
                delete_subchar(http_vars->data_vars[data_itm].name, ']');
                /* type and value */
                if (query_tbl->query_vars[i].value[0] == '"')
                {
                    strncpy(http_vars->data_vars[data_itm].value, query_tbl->query_vars[i].value, HTTP_VAR_VALUE_LEN);
                    delete_subchar(http_vars->data_vars[data_itm].value, '"');
                    http_vars->data_vars[data_itm].type = TYPE_STR;
                }
                else
                {
                    http_vars->data_vars[data_itm].type = TYPE_INT;
                    strncpy(http_vars->data_vars[data_itm].value, query_tbl->query_vars[i].value, HTTP_VAR_VALUE_LEN);
                }

                data_itm++;
            }
        }
        /* get callback */
        else if (0 == strcmp(query_tbl->query_vars[i].name, K_CALLBACK))
        {
            strncpy(http_vars->call_back, query_tbl->query_vars[i].value, HTPP_CLB_LEN);
        }

        http_vars->head_itm_cnt = head_itm;
        http_vars->data_itm_cnt = data_itm;
    }

    return http_vars;
}

static int http_get_construct_and_send(query_vars *query_vars, int fd)
{
    char *request_str = NULL;
    json_object *head_obj = NULL;
    json_object *data_obj = NULL;
    json_object *data_array_obj = NULL;
    json_object *req_obj = NULL;
    int i = 0;
    int len = 0;
    int ret = 0;

    req_obj = json_object_new_object();
    /* construct header */
    head_obj = json_object_new_object();
    for (i = 0; i < query_vars->head_itm_cnt; i++)
    {
        if (query_vars->head_vars[i].type == TYPE_INT)
        {
            json_object_object_add(head_obj, query_vars->head_vars[i].name, json_object_new_int(atoi(query_vars->head_vars[i].value)));
        }
        else
        {
            json_object_object_add(head_obj, query_vars->head_vars[i].name, json_object_new_string(query_vars->head_vars[i].value));
        }
    }
    json_object_object_add(req_obj, K_HEAD, head_obj);

    /* construct data */
    data_obj = json_object_new_object();
    for (i = 0; i < query_vars->data_itm_cnt; i++)
    {
        if (query_vars->data_vars[i].type == TYPE_INT)
        {
            json_object_object_add(data_obj, query_vars->data_vars[i].name, json_object_new_int(atoi(query_vars->head_vars[i].value)));
        }
        else
        {
            json_object_object_add(data_obj, query_vars->data_vars[i].name, json_object_new_string(query_vars->data_vars[i].value));
        }
    }
    data_array_obj = json_object_new_array();
    json_object_array_add(data_array_obj, data_obj);
    json_object_object_add(req_obj, K_DATA, data_array_obj);

    /* send request to module */
    request_str = (char *)json_object_to_json_string(req_obj);
    len = strlen(request_str);
    IM_MsgPrintf(request_str, "request msg to msg server", len, 2);
    ret = IM_MsgSend(fd, request_str, len);

    /* free source */
    IM_FREE_JSON_OBJ(head_obj);
    IM_FREE_JSON_OBJ(data_obj);
    IM_FREE_JSON_OBJ(data_array_obj);
    IM_FREE_JSON_OBJ(req_obj);

    return ret;
}

static usr_login_info *http_web_login_data_parse(query_vars *query_vars)
{
    usr_login_info *login_info = NULL;
    int i = 0, flag1 = 0, flag2 = 0, flag3 = 0;
    
    login_info = (usr_login_info *)malloc(sizeof(usr_login_info));
    if (NULL == login_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        goto out;
    }
    memset(login_info, 0, sizeof(usr_login_info));

    for (i = 0; i < query_vars->data_itm_cnt; i++)
    {
        if (0 == strcmp(query_vars->data_vars[i].name, K_USR_NAME))
        {
            strncpy(login_info->name, query_vars->data_vars[i].value, HTTP_VAR_VALUE_LEN);
            flag1 = 1;
        }
        else if (0 == strcmp(query_vars->data_vars[i].name, K_PWD))
        {
            strncpy(login_info->pwd, query_vars->data_vars[i].value, HTTP_VAR_VALUE_LEN);
            flag2 = 1;
        }
        else if (0 == strcmp(query_vars->data_vars[i].name, K_LOGIN_TYPE))
        {
            login_info->login_type = atoi(query_vars->data_vars[i].value);
            flag3 = 1;
        }
    }

    if (0 == flag1 || 0 == flag2 || 0 == flag3)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong login paras(name,%d;pwd,%d;type,%d)!",
            flag1, flag2, flag3);
        goto out;
    }

out:
    return login_info;
}

static int http_web_usr_auth(struct evhttp_request *req, query_vars *query_vars, struct evbuffer *reply_buf)
{
    int ret = DEFAULTE_CODE;
    unsigned int time_now = 0;
    int i = 0, j = 0;
    unsigned char flag = 0;
    int cmd = 0;
    usr_login_info *login_ifo = NULL;
    char tmp[128] = {0};
    int auth_pass = 0;
    char session[HTTP_VAR_VALUE_LEN] = {0};
    char cli_mac[MAC_STR_LEN + 1] = {0};
    char cmd_str[128] = {0};

    /* paras check */
    if (NULL == req || NULL == query_vars || NULL == reply_buf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong para!");
        ret = INTERNAL_ERR;
        goto out;
    }

    /* get client mac */
    if (0 == access(ARP_FILE, F_OK))
    {
        snprintf(cmd_str, sizeof(cmd_str) - 1, "cat %s | grep %s | cut -d ' ' -f %d", 
            ARP_FILE, req->remote_host, 36 - strlen(req->remote_host));
        if (0 != get_system_info(cmd_str, cli_mac, MAC_STR_LEN + 1))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "get client mac failed, cmd:%s!", cmd_str);
            ret = INTERNAL_ERR;
            goto out;
        }
    }

    if (MAC_STR_LEN != strlen(cli_mac))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong client!");
        ret = INTERNAL_ERR;
        goto out;
    }

    /* client communicate time out process */
    time_now = time(NULL);
    if (0 != htt_server_timeout_check(time_now))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "htt_server_timeout_check failed!");
        ret = INTERNAL_ERR;
        goto out;
    }

    /* get cmd */
    for (i = 0; i < query_vars->head_itm_cnt; i++)
    {
        if (0 == strcmp(query_vars->head_vars[i].name, K_CMD_ID))
        {
            flag = 1;
            break;
        }
    }

    if (0 == flag)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras, no cmd in request!");
        ret = INTERNAL_ERR;
        goto out;
    }
    flag = 0;

    /* get session id */
    for (j = 0; j < query_vars->head_itm_cnt; j++)
    {
        if (0 == strcmp(query_vars->head_vars[j].name, K_SESSION_ID))
        {
            flag = 1;
            break;
        }
    }
    
    if (0 == flag)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras, no session id in request!");
        ret = INTERNAL_ERR;
        goto out;
    }
    strncpy(session, query_vars->head_vars[j].value, HTTP_VAR_VALUE_LEN);

    /* process login, logout, or auth session */
    cmd = atoi(query_vars->head_vars[i].value);
    /* login */
    if (CMD_USR_LOGIN == cmd)
    {
        login_ifo = http_web_login_data_parse(query_vars);
        if (NULL == login_ifo)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_web_login_data_parse failed!");
            ret = INTERNAL_ERR;
            goto out;
        }

        switch (login_ifo->login_type)
        {
            case LOGIN_ANONYMOUS:
                /* already login, update comunicate time, change group when necessary */
                ret = http_client_check(cli_mac, time_now, req, LOGIN_ANONYMOUS);
                if (DEFAULTE_CODE != ret)
                {
                    goto out;
                }
                
                /* regedit new client */
                ret = http_regedit_client(time_now, req, LOGIN_ANONYMOUS);
                if (DEFAULTE_CODE != ret)
                {
                    goto out;
                }
                
                /* exceed max client count, can not regedit anymore */
                ret = EXCEED_MAX_CLI;
                goto out;

                break;
            case LOGIN_PWD:
                if (0 != IM_RootPwdGet(tmp))
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_RootPwdGet failed!");
                    ret = INTERNAL_ERR;
                    goto out;
                }
                if (0 == strcmp(login_ifo->pwd, tmp))
                {
                    /* already login, update comunicate time, add to root group */
                    ret = http_client_check(cli_mac, time_now, req, LOGIN_PWD);
                    if (DEFAULTE_CODE != ret)
                    {
                        goto out;
                    }
                    
                    /* regedit new client */
                    ret = http_regedit_client(time_now, req, LOGIN_PWD);
                    if (DEFAULTE_CODE != ret)
                    {
                        goto out;
                    }
                    
                    /* exceed max client count, can not regedit anymore */
                    ret = EXCEED_MAX_CLI;
                    goto out;
                }
                else
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong password!");
                    ret = PWD_ERR;
                    goto out;
                }
                break;
            default:
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong login type:%d!", login_ifo->login_type);
                ret = LOGIN_TYPE_ERR;
                goto out;
        }
    }
    /* logout */
    else if (CMD_USR_LOGOUT == cmd)
    {
        ret = http_client_logout(session);
        if (DEFAULTE_CODE == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev logout err, no such dev/user, ip:%s!", req->remote_host);
            ret = LOGOUT_ERR;
            goto out;
        }
        else
        {
            if (0 != ret)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev logout err!");
                ret = INTERNAL_ERR;
            }
            else
            {
                ret = LOGOUT_SUCC;
            }
            goto out;
        }
    }
    /* auth session id */
    else
    {
        for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
        {
            if (0 == strcmp(session, g_http_clients[i].session))
            {
                /* already login, update comunicate time */
                for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
                {
                    if (0 == strcmp(req->remote_host, g_http_clients[i].ip))
                    {
                        g_http_clients[i].last_time = time_now;
                        break;
                    }
                }
                auth_pass = 1;
                break;
            }
        }

        if (1 != auth_pass)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "user/dev do not login, session:%s!", session);
            ret = SESSION_ERR;
            goto out;
        }
        else
        {
            ret = AUTH_SUCC;
            goto out;
        }
    }

out:
    IM_FREE(login_ifo);
    return ret;
}

static void http_web_auth_ret_proc(struct evhttp_request *req, struct evbuffer *reply_buf, query_vars *query_vars, int ret)
{
    json_object *head_obj = NULL;
    json_object *data_obj = NULL;
    json_object *data_array_obj = NULL;
    json_object *resp_obj = NULL;
    char *resp_str = NULL;
    int len = 0;
    char ret_msg[128] = {0};
    int i = 0;
    char *http_send_buf = NULL;

    resp_obj = json_object_new_object();
    /* create response json header */
    head_obj = json_object_new_object();
    for (i = 0; i < query_vars->head_itm_cnt; i++)
    {
        if (strcmp(query_vars->head_vars[i].name, K_RST_CODE))
        {
            if (TYPE_INT == query_vars->head_vars[i].type)
            {
                json_object_object_add(head_obj, query_vars->head_vars[i].name, json_object_new_int(atoi(query_vars->head_vars[i].value)));
            }
            else
            {
                json_object_object_add(head_obj, query_vars->head_vars[i].name, json_object_new_string(query_vars->head_vars[i].value));
            }
        }
        else
        {
            if (ret < LOGOUT_SUCC)
            {
                json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(ret));
            }
            else
            {
                json_object_object_add(head_obj, K_RST_CODE, json_object_new_int(0));
            }
        }
    }
    json_object_object_add(resp_obj, K_HEAD, head_obj);

    /* create response json data */
    data_obj = json_object_new_object();
    /* auth result */
    if (ret < 0)
    {
        json_object_object_add(data_obj, K_RET_CODE, json_object_new_int(ret));
        http_set_ret_msg(ret_msg, ret);
        json_object_object_add(data_obj, K_RET_MSG, json_object_new_string(ret_msg));
    }
    /* login */
    else
    {
        json_object_object_add(data_obj, K_SESS_KEY, json_object_new_string(g_http_clients[ret].session));
    }
    data_array_obj = json_object_new_array();
    json_object_array_add(data_array_obj, data_obj);
    json_object_object_add(resp_obj, K_DATA, data_array_obj);

    /* create reponse json string and send to client */
    resp_str = (char *)json_object_to_json_string(resp_obj);
    len = strlen(resp_str);

    http_send_buf = (char *)malloc(strlen(query_vars->call_back) + 2 + len + 1);    // +1 for '\0'
    if (!http_send_buf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
    }
    /* reply body:callbakfunc(reponse json data)*/
    memset(http_send_buf, 0, strlen(query_vars->call_back) + 2 + len + 1);
    memcpy(http_send_buf, query_vars->call_back, strlen(query_vars->call_back));
    http_send_buf[strlen(query_vars->call_back)] = '(';
    memcpy(http_send_buf + strlen(query_vars->call_back) + 1, resp_str, len);
    http_send_buf[strlen(query_vars->call_back) + 1 + len] = ')';
    http_send_buf[strlen(query_vars->call_back) + 2 + len + 1] = '\0';
    evbuffer_add_printf(reply_buf, "%s", http_send_buf);
    //IM_MsgPrintf(http_send_buf, "msg for response HTTP GET request", strlen(query_vars->call_back) + 2 + len, 2);
    evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);

out:
    /* free source */
    IM_FREE(http_send_buf);
    IM_FREE_JSON_OBJ(head_obj);
    IM_FREE_JSON_OBJ(data_obj);
    IM_FREE_JSON_OBJ(data_array_obj);
    IM_FREE_JSON_OBJ(resp_obj);    
}

static char* string_replace_with_malloc(const char *src, const char *old_str, const char *new_str)
{
    char *ret_buf = NULL;
    char *buf = NULL;
    char *tmp = NULL;
    char *start = NULL;
    char *end = NULL;
    int count = 0;
    int old_str_len = 0;
    int ret_len = 0;

    if(NULL == src || NULL == old_str || NULL == new_str)
        return NULL;

    tmp = buf = strdup(src);
    /*if equal, return without replace*/
    if(0 == strcmp(old_str, new_str))
        return buf;

    old_str_len = strlen(old_str);
    while(NULL != (tmp = strstr(tmp, old_str)))
    {
        count++;
        tmp += old_str_len;
    }

    /*calculate memory size add modify it*/
    ret_len = strlen(src) + (strlen(new_str) - strlen(old_str)) * count + 1;
    ret_buf = malloc(ret_len);
    if(NULL == ret_buf)
    {
        free(buf);
        return NULL;
    }
    memset(ret_buf, 0, ret_len);

    start = buf;
    tmp = ret_buf;
    
    /*replace content in pcTmp to pcRetBuf*/
    while(NULL != (end = strstr(start, old_str)))
    {
        strncpy(tmp, start, end-start);
        strcat(tmp, new_str);
        tmp += strlen(tmp);
        start = end + old_str_len;
    }
    strcat(tmp, start);

    free(buf);
    return ret_buf;
}

static void http_req_get_prc(struct evhttp_request *req, void *arg)
{
    int ret = 0;
    const char *uri;
    char *decoded_uri;
    struct evkeyval *header;
    struct evbuffer *reply_buf;
    char send_buf[1024] = {0};
    http_query_var_tbl *query_tbl = NULL;
    query_vars *query_vars = NULL;
    int i = 0;
    int client_fd = -1;
    char *p_msg = NULL;
    unsigned int time_out = RECV_TIMEOUT;
    char *http_send_buf = NULL;
    int flag = 0;
    int app_shm_idx = -1;
    int retry = 0;
    
    /* Get request uri*/
    uri = evhttp_request_get_uri(req);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "Got a GET request for uri<%s,len:%d>",  uri, strlen(uri));

    /* Decode uri */
    decoded_uri = evhttp_decode_uri(uri);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "Got a GET request for decoded_uri<%s>", decoded_uri);

    /* parse uri and get vars */
    query_tbl = http_pare_query_var(decoded_uri, strlen(decoded_uri));
    if (NULL == query_tbl)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_pare_query_var error!");
        goto out;
    }

    /* Create buf for reply */
    reply_buf = evbuffer_new();
    if (NULL == reply_buf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "evbuffer_new error!");
        goto out;
    }

    /* Fix reply http header */
    if (0 != http_fix_reply_head(req->output_headers))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "add header error!");
        goto out;
    }
    
#if 0
    for (i = 0; i < query_tbl->count; i++)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "idx:%d,name:%s,value:%s",
            i, query_tbl->query_vars[i].name, query_tbl->query_vars[i].value);
    }
#endif
    /* parse vars and get key-value */
    query_vars = http_parse_query_tbl(query_tbl);
    if (NULL == query_tbl)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_parse_query_tbl error!");
        goto out;
    }

    
#if 1
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "callback:%s",
            query_vars->call_back);
    for (i = 0; i < query_vars->head_itm_cnt; i++)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "headers:idx:%d,name:%s,value:%s,type:%d",
            i, query_vars->head_vars[i].name, query_vars->head_vars[i].value, query_vars->head_vars[i].type);
    }
    for (i = 0; i < query_vars->data_itm_cnt; i++)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "datas:idx:%d,name:%s,value:%s,type:%d",
            i, query_vars->data_vars[i].name, query_vars->data_vars[i].value, query_vars->data_vars[i].type);
    }
#endif

    pthread_mutex_lock(&perauth_proc_mutex);
    ret = http_web_usr_auth(req, query_vars, reply_buf);
    pthread_mutex_unlock(&perauth_proc_mutex);
    if (AUTH_SUCC == ret)
    {
        ret = 0;
        goto auth_succ;
    }
    
    /* new client or logout */
    if (ret >= 0)
    {
        http_web_auth_ret_proc(req, reply_buf, query_vars, ret);
        ret = 0;
        goto out;
    }
    /* auth failed, or log out success */
    else
    {
        /* logout */
        if (LOGOUT_SUCC == ret)
        {
            http_web_auth_ret_proc(req, reply_buf, query_vars, ret);
            ret = 0;
            goto out;
        }
        else
        {
            http_web_auth_ret_proc(req, reply_buf, query_vars, ret);
            goto out;
        }
    }
    
auth_succ:

    /* get appid */
    for (i = 0; i < query_vars->head_itm_cnt; i++)
    {
        if (0 == strcmp(query_vars->head_vars[i].name, K_APP_ID))
        {
            flag = 1;
            break;
        }
    }
    
    if (0 == flag)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras, no cmd in request!");
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
        goto out;
    }

    /* read app info in share memory and find the app with app id */
    app_shm_idx = find_app_in_shm(atoi(query_vars->head_vars[i].value));
    if (app_shm_idx < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "find_app_in_shm(%d) failed!", atoi(query_vars->head_vars[i].value));
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
        goto out;
    }

    /* check app is inmem or not */
    if (0 == g_app_proc_info[app_shm_idx].cInMemFlag)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "dest module is not in mem!");
        evbuffer_add_printf(reply_buf, "%s", "module dead");
        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
        goto out;
    }

    /* Connect and send post data to module */
    client_fd = IM_DomainClientInit(g_app_proc_info[app_shm_idx].szAppName);
    if (MSG_INVALID_FD == client_fd)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "connect to server error!");
        evbuffer_add_printf(reply_buf, "%s", "module dead");
        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
        goto out;
    }

    /* construct json request and send to module */
    ret = http_get_construct_and_send(query_vars, client_fd);
    if (0 != ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_get_construct error!");
        evbuffer_add_printf(reply_buf, "%s", "send failed");
        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
        goto out;
    }
    
    while (1)
    {
        /* recieve reply */
        ret = IM_MsgReceive(client_fd, &p_msg, &time_out);
        if (ret > 0)
        {
            //IM_MsgPrintf((void *)p_msg, "reply message from server module", ret, 1);
            break;
        }
        else if (MSGRET_TIMED_OUT == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recieve reply message from server module timeout!");
            break;
        }
        else if (MSGRET_DISCONNECTED == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "server disconnect!");
            break;
        }
        else if (MSGRET_INVALID_ARGUMENTS == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "invalid arguments!");
            break;
        }
        else if (0 == ret)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recv length 0 msg!");
            continue;
        }
        else
        {
            if (MAX_RECV_RETRY_TIMES > retry)
            {
                retry++;
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recv retry %d!", retry);
                continue;
            }
            else
            {
                retry = 0;
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "internal err");
                break;
            }
        }
    }

    /* Set reply http body */
    if (ret > 0 && p_msg)
    {
        http_send_buf = (char *)malloc(strlen(query_vars->call_back) + 2 + ret + 1);    // +2 for (),+1 for \0
        if (!http_send_buf)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
            evbuffer_add_printf(reply_buf, "%s", "internal err");
            evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
        }
        memset(http_send_buf, 0, strlen(query_vars->call_back) + 2 + ret + 1); // +2 for (),+1 for \0
        
        /* reply body:callbakfunc(reponse json data) */
        memcpy(http_send_buf, query_vars->call_back, strlen(query_vars->call_back));
        http_send_buf[strlen(query_vars->call_back)] = '(';
        memcpy(http_send_buf + strlen(query_vars->call_back) + 1, p_msg, ret);
        http_send_buf[strlen(query_vars->call_back) + 1 + ret] = ')';
        http_send_buf[strlen(query_vars->call_back) + 2 + ret + 1] = '\0';
        evbuffer_add_printf(reply_buf, "%s", http_send_buf);
        //IM_MsgPrintf(http_send_buf, "msg for response HTTP GET request", strlen(query_vars->call_back) + 2 + ret, 2);
        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
    }
    else if (MSGRET_TIMED_OUT == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "process timeout");
        evhttp_send_reply(req, HTTP_INTERNAL, "TIMEOUT", reply_buf);
    }
    else if (MSGRET_DISCONNECTED == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "server disconnect");
        evhttp_send_reply(req, HTTP_INTERNAL, "DISCONNECT", reply_buf);
    }
    else if (MSGRET_INVALID_ARGUMENTS == ret)
    {
        evbuffer_add_printf(reply_buf, "%s", "invalid arguments");
        evhttp_send_reply(req, HTTP_INTERNAL, "INVALID ARGS", reply_buf);
    }
    else
    {
        evbuffer_add_printf(reply_buf, "%s", "internal err");
        evhttp_send_reply(req, HTTP_INTERNAL, "INTERNAL ERR", reply_buf);
    }

out:
    IM_FREE(p_msg);
    IM_DomainClientDeinit(client_fd);
    IM_FREE(http_send_buf);
    IM_FREE(decoded_uri);
    IM_FREE(query_tbl);
    IM_FREE(query_vars);
    if (reply_buf)
        evbuffer_free(reply_buf);
}

static void http_req_post_prc(struct evhttp_request *req, void *arg)
{
    char *post_data = NULL;
    struct evkeyvalq *header_paras = NULL;
    const char *content_len_str = NULL;
    const char *imove_type_str = NULL;
    unsigned long data_len = 0;
    unsigned int post_len = 0;
    char *tmp_buf = NULL;
    int ret = 0;

    /* Get request headers */
    header_paras = evhttp_request_get_input_headers(req);
    
    /* Get Content-Length in headers and check */
    content_len_str = evhttp_find_header(header_paras, K_CONTENT_LEN);
    if (!content_len_str)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "Wrong post request, not have Content-Length!");
        return;
    }
#if 0
    /* Check imove type in http header */
    imove_type_str = evhttp_find_header(header_paras, K_IMOVE_TYPE);
    if (NULL == imove_type_str || !strlen(imove_type_str))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "unsurpport http msg type!");
        return;
    }
#endif    
    data_len = strtoul(content_len_str, NULL, 10);
    if (0 == data_len)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "Wrong post request, Content-Length is 0!");
        return;
    }

    /* Get post data */
    post_data = (char *)EVBUFFER_DATA(req->input_buffer);
    post_len = EVBUFFER_LENGTH(req->input_buffer);
    tmp_buf = (char *)malloc(post_len);
    if (NULL == tmp_buf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return;
    }
    memset(tmp_buf, 0, post_len);
    memcpy(tmp_buf, post_data, post_len);

    /* Printf post data */
    //IM_MsgPrintf(tmp_buf, "msg from HTTP POST request", data_len, 1);

    /* Process data and reply */
    ret = http_post_process(req, tmp_buf, data_len);
    if (0 != ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "post request process error!");
    }
}

static void http_genc_prc_cb(struct evhttp_request *req, void *arg)
{
    enum evhttp_cmd_type req_type;

    /* Get request type and dump request header */
    req_type = evhttp_request_get_command(req);
    //http_dump_request(req, req_type, arg);

    /* Process http get or post request only */
    switch (req_type)
    {
        /* web */
        case EVHTTP_REQ_GET:
            http_req_get_prc(req, arg);
            break;
        /* app */
        case EVHTTP_REQ_POST:
            http_req_post_prc(req, arg);
            break;
        /* should never happen */
        default:
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "Got a wrong request type:<%d>", req_type);
            return;
    }
}

static void http_server_run(void)
{
    struct event_base *base;
	struct evhttp *http;
	struct evhttp_bound_socket *handle;
	int time_out = HTTP_REQ_TIMEOUT;

    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "http server start port <%d>", g_Mr2fcConfigInfo.http_port);

    /* Create and return a new event_base to use with the rest of Libevent. */
    base = event_base_new();
	if (!base) 
	{
		IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "Couldn't create an event_base: exiting.");
		return;
	}

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) 
	{
		IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "couldn't create evhttp. Exiting.");
		return;
	}

    /* Set the timeout for an HTTP request. */
	evhttp_set_timeout(http, time_out);

	/* We want to accept arbitrary requests, so we need to set a "generic"
	 * cb.  We can also add callbacks for specific paths. */
	evhttp_set_gencb(http, http_genc_prc_cb, NULL);

	/* Now we tell the evhttp what port to listen on. */
	handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", g_Mr2fcConfigInfo.http_port);
	if (!handle) 
	{
		IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "couldn't bind to port %d. Existing.",
		    g_Mr2fcConfigInfo.http_port);
		return;
	}

    /* Main loop */
	event_base_dispatch(base);

    /* Exit */
	evhttp_free(http);
}

int httpserver_bindsocket(int port, int backlog) 
{
    int r;
    int one = 1;
    int nfd;
    struct sockaddr_in addr;
    int flags;
    nfd = socket(AF_INET, SOCK_STREAM, 0);

    if (nfd < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "socket creat failed.");
        return -1;
    }

    r = setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof(int));
    r = setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(int));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if ((flags = fcntl(nfd, F_GETFL, 0)) < 0
        || fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "fcntl failed.");
        return -1;
    }

    r = bind(nfd, (struct sockaddr*)&addr, sizeof(addr));
    if (r < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "bind failed.");
        return -1;
    }

    r = listen(nfd, backlog);
    if (r < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "listen failed.");
        return -1;
    }

    return nfd;
}

void* httpserver_Dispatch(void *arg) 
{
    event_base_dispatch((struct event_base *)arg);
    return NULL;
}

static int http_server_start(int port, int nthreads, int backlog)
{
    int r, i;
    pthread_t ths[nthreads];
    int nfd = httpserver_bindsocket(port, backlog);
    
    if (nfd < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "httpserver_bindsocket failed.");
        return -1;
    }
    
    for (i = 0; i < nthreads; i++) 
    {
        struct event_base *base = event_init();
        if (NULL == base) 
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "event_init failed.");
            return -1;
        }
        
        struct evhttp *httpd = evhttp_new(base);
        if (NULL == httpd) 
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "evhttp_new failed.");
            return -1;
        }
        
        r = evhttp_accept_socket(httpd, nfd);
        if (0 != r)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "evhttp_accept_socket failed.");
            evhttp_free(httpd);
            return -1;
        }
        
        evhttp_set_gencb(httpd, http_genc_prc_cb, NULL);
        r = pthread_create(&ths[i], NULL, httpserver_Dispatch, base);
        if (0 != r) 
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "pthread_create failed.");
            evhttp_free(httpd);
            return -1;
        }
    }
    
    for (i = 0; i < nthreads; i++) 
    {
        pthread_join(ths[i], NULL);
    }

    return 0;
}

static void tcp_free_connect(socket_manage_info *socket_info)
{
    if (socket_info->ssl)
    {
        SSL_shutdown(socket_info->ssl);
        SSL_free(socket_info->ssl);
        socket_info->ssl = NULL;
    }

    if (socket_info->socket_fd >= 0)
    {
        close(socket_info->socket_fd);
        socket_info->socket_fd = INVALID_SOCKET;
    }

    if (socket_info->ssl_ctx)
    {
        SSL_CTX_free(socket_info->ssl_ctx);
        socket_info->ssl_ctx = NULL;
    }

    socket_info->fail_count = 0;
}

static int tcp_ssl_connect(const char *server_name, unsigned int port_num, socket_manage_info *socket_info)
{
    int ret = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl_conn = NULL;
    int sock_fd = -1;
    struct addrinfo *answer, hint;
    int sev_ip = 0;
    struct sockaddr_in sev_addr;
    int flags = 0;
    int yes = 1;
    int i = 0;
    int seed_int[100];
    
    if (NULL == server_name || port_num < 0 || NULL == socket_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }
    
    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(server_name, NULL, &hint, &answer);
    if (ret != 0)
    {
        //IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "getaddrinfo:%s!", gai_strerror(ret));
        ret = -1;
        goto exit;
    }
    memcpy(&sev_ip, &((struct sockaddr_in *)(answer->ai_addr))->sin_addr, sizeof(int));
    freeaddrinfo(answer);
    
    bzero(&sev_addr, sizeof(sev_addr));
    sev_addr.sin_family = AF_INET;
    sev_addr.sin_port = htons(port_num);
    sev_addr.sin_addr.s_addr = sev_ip;
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd < 0)
    {
        if (errno == EACCES)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "permission denied!");
        }
        else
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "creat err!");
        }
        ret = -1;
        goto exit;
    }

    if (0 != setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "setsockopt failed!");
        ret = -1;
        goto exit;
    }
    
    if (0 != setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "setsockopt failed!");
        ret = -1;
        goto exit;
    }
    
    if (0 != connect(sock_fd, (struct sockaddr *) &sev_addr, sizeof(sev_addr)))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "connect failed:%s!", strerror(errno));
        ret = -1;
        goto exit;
    }

#ifdef SSL_SURPPORT    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    //ctx = SSL_CTX_new(SSLv23_client_method());
    ctx = SSL_CTX_new(TLSv1_client_method());
    if (NULL == ctx)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_CTX_new failed!");
        ret = -1;
        goto out;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, TSL_CACERT, NULL);
    if (0 == SSL_CTX_use_certificate_file(ctx, TSL_MYCERTF, SSL_FILETYPE_PEM))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_CTX_use_certificate_file failed!");
        ret = -1;
        goto out;
    }

    if (0 == SSL_CTX_use_PrivateKey_file(ctx, TSL_MYKEY, SSL_FILETYPE_PEM))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_CTX_use_PrivateKey_file failed!");
        ret = -1;
        goto out;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_CTX_check_private_key failed!");
        ret = -1;
        goto out;
    }

    srand((unsigned)time(NULL));
    for (i = 0; i < 100; i++)
    {
        seed_int[i] = rand();
    }

    RAND_seed(seed_int, sizeof(seed_int));
    SSL_CTX_set_cipher_list(ctx, SSL_CIPHER_RC4_MD5);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    
    ssl_conn = SSL_new(ctx);
    SSL_set_fd(ssl_conn, sock_fd);
    if (-1 == SSL_connect(ssl_conn))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_connect failed!");
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto out;
    }
    else
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "Connected with %s encryption", SSL_get_cipher(ssl_conn));
    }
#endif

    flags = fcntl(sock_fd, F_GETFL);
    if (flags == -1)
        goto out;

    flags |= O_NONBLOCK;
    flags = fcntl(sock_fd, F_SETFL, flags);

    memset(socket_info, 0, sizeof(socket_manage_info));
    socket_info->ssl = ssl_conn;
    socket_info->socket_fd = sock_fd;
    socket_info->ssl_ctx = ctx;

    return 0;

out:
    if (ssl_conn)
    {
        SSL_shutdown(ssl_conn);
        SSL_free(ssl_conn);
        ssl_conn = NULL;
    }

    if (ctx)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
exit:
    if (sock_fd > 0)
    {
        close(sock_fd);
        sock_fd = -1;
    }

    return ret;
}

static void alarm_handle(int sig_no)
{
    if (sig_no != SIGALRM)
    {
        return;
    }

    if (g_RunStage == STAGE_NORMAL)
    {
        g_RunStage = STAGE_HEART_BEAT;
    }
    alarm(g_Mr2fcConfigInfo.heart_beat_interval);
    g_heart_beat_count++;
}

static void signal_init(void)
{
    struct sigaction sa;

    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigaddset(&sa.sa_mask, SIGPIPE);
    sigaddset(&sa.sa_mask, SIGALRM);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = alarm_handle;
    sigaction(SIGALRM, &sa, NULL);
}

static int tcp_prcs_login_ret(char *msg_body, unsigned int msg_len, unsigned int seq)
{
    dev_login_ret *login_ret = (dev_login_ret *)msg_body;
    char session[LEN_OF_SESSIONID] = {0};

    if (g_curr_tcp_session != login_ret->session_id)
    {
        IM_AllSessUnbindMac(DEFAULTE_ROOT_MAC);
        g_curr_tcp_session = login_ret->session_id;
        /* bind new session to root mac */
        snprintf(session, sizeof(session), "%llu", g_curr_tcp_session);
        IM_SessBindMac(session, DEFAULTE_ROOT_MAC);
    }
    alarm(g_Mr2fcConfigInfo.heart_beat_interval);
    return 0;
}

static int tcp_prcs_logout_ret(char *msg_body, unsigned int msg_len, unsigned int seq)
{
    dev_logout_ret *logout_ret = (dev_logout_ret *)msg_body;
    char session[LEN_OF_SESSIONID] = {0};

    if (g_curr_tcp_session != logout_ret->session_id)
    {
        IM_AllSessUnbindMac(DEFAULTE_ROOT_MAC);
        g_curr_tcp_session = logout_ret->session_id;
        /* bind new session to root mac */
        snprintf(session, sizeof(session), "%llu", g_curr_tcp_session);
        IM_SessBindMac(session, DEFAULTE_ROOT_MAC);
    }
    
    return 0;
}

static int tcp_prcs_heartbeat_ret(char *msg_body, unsigned int msg_len, unsigned int seq)
{
    heart_beat_info *hb_info = (heart_beat_info *)msg_body;
    char session[LEN_OF_SESSIONID] = {0};

    if (g_curr_tcp_session != hb_info->session_id)
    {
        IM_AllSessUnbindMac(DEFAULTE_ROOT_MAC);
        g_curr_tcp_session = hb_info->session_id;
        snprintf(session, sizeof(session), "%llu", g_curr_tcp_session);
        /* bind new session to root mac */
        IM_SessBindMac(session, DEFAULTE_ROOT_MAC);
    }
    g_heart_beat_count = 0;
    
    return 0;
}

#if 0
static size_t http_resp_process(char *buf, size_t size, size_t nmemb, void *stream)
{
    size_t len = size * nmemb;
    http_resp_msg *respons_msg = (http_resp_msg *)stream;
    
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
        size, nmemb, len, respons_msg->content_len);
    if (len > 0)
    {
        respons_msg = realloc(respons_msg, (sizeof(http_resp_msg) + len + 1));
        if (NULL == respons_msg)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "realoc failed!");
            return 0;
        }
    }
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
        size, nmemb, len, respons_msg->content_len);
    memcpy(respons_msg->data + respons_msg->content_len, buf, len);
    respons_msg->content_len += len;
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
        size, nmemb, len, respons_msg->content_len);

    return len;
}
#else
static size_t http_resp_process(char *buf, size_t size, size_t nmemb, void *stream)
{
    size_t len = size * nmemb;
    http_resp_msg *respons_msg = (http_resp_msg *)stream;
    
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
        size, nmemb, len, respons_msg->content_len);
    if (len > 0 && (respons_msg->content_len + len) < MAX_HTTP_RESP_DATA_LEN)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
            size, nmemb, len, respons_msg->content_len);
        memcpy(respons_msg->data + respons_msg->content_len, buf, len);
        respons_msg->content_len += len;
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "****size:%d nmemb:%d len:%d respons_msg->content_len:%d!", 
            size, nmemb, len, respons_msg->content_len);
    }

    return len;
}
#endif

static http_resp_msg *http_request(http_req_method method, const char *req_url, char *msg_content, unsigned int msg_len, http_content_type type)
{
    http_resp_msg *http_resp = NULL;
    CURL *easy_handle = NULL;
    struct curl_slist *headers = NULL;
    char *http_get_url = NULL;
    char http_get_paras[MAX_HTTP_GET_PARAS_LEN] = {0};
    CURLcode ret = 0;
    long response_code = 0;
    size_t len = 0;

    /* paras check */
    if (HTTP_GET != method && HTTP_POST != method)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "unsurpport http request method %d!", method);
        return NULL;
    }

    if (NULL == req_url)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http url is null!");
        return NULL;
    }

    if ((NULL == msg_content && msg_len > 0) || msg_len < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "content conflict with content len(%d)!", msg_len);
        return NULL;
    }

    if (type < TYPE_JSON || type > TYPE_OCT_STREAM)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "unsurpport http content type %d!", type);
        return NULL;
    }

    /* init libcurl */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get easy handle */
    easy_handle = curl_easy_init();
    if (NULL == easy_handle)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "curl_easy_init failed!");
        goto out;
    }

    /* fix headers */
    headers = curl_slist_append(headers,  "User-Agent:I_MOVE");
	headers = curl_slist_append(headers,  "Accept: text/html,application/xml,application/json");
	headers = curl_slist_append(headers,  "Connection: keep-alive");

	http_resp = (http_resp_msg *)malloc(sizeof(http_resp_msg) + MAX_HTTP_RESP_DATA_LEN);
	if (NULL == http_resp)
	{
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        goto out;
	}
	memset(http_resp, 0, sizeof(http_resp_msg) + MAX_HTTP_RESP_DATA_LEN);

    switch (method)
    {
        case HTTP_GET:
            http_get_url = (char *)malloc(strlen(req_url) + msg_len + 2);
            if (NULL == http_get_url)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
                goto out;
            }
            if (msg_len > MAX_HTTP_GET_PARAS_LEN)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http get paras too long(%d)!", msg_len);
                goto out;
            }
            memcpy(http_get_paras, msg_content, msg_len);
            snprintf(http_get_url, strlen(req_url) + msg_len + 2, "%s?%s", req_url, http_get_paras);
            curl_easy_setopt(easy_handle, CURLOPT_URL, http_get_url);
            break;
        case HTTP_POST:
            curl_easy_setopt(easy_handle, CURLOPT_URL, req_url);
            if (0 != msg_len)
			{
			    headers = curl_slist_append(headers,  http_content_types[type]);    //content type
				curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, msg_content);     //content data
				curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, msg_len);      //content len
			}
            else
            {
                headers = curl_slist_append(headers,  http_content_types[TYPE_TXT_HTML]);
                curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, NULL);
                curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, 0L);
            }
            break;
        default:
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "unsurpport http request method %d!", method);
            goto out;
    }

    /* set easy handle */
    curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT, HTTP_REQ_PRC_TIMEOUT);
    curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, http_resp_process);
	curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, http_resp);

    /* perform easy handle */
	ret = curl_easy_perform(easy_handle);
	if (CURLE_OK != ret)
	{
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "curl_easy_perform failed reason:%s!", curl_easy_strerror(ret));
        goto out;
	}

	ret = curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
	//ret = curl_easy_getinfo(easy_handle, CURLINFO_SIZE_DOWNLOAD, &len);
	http_resp->status = response_code;

out:
    IM_FREE(http_get_url);
    curl_slist_free_all(headers);
	curl_easy_cleanup(easy_handle);
	curl_global_cleanup();
	
	return http_resp;
}

static int tcp_creat_normal_resp_frame(msg_type type, unsigned int seq, void *head_data, unsigned int head_len, void *resp_data, unsigned int len)
{
    tcp_normal_whole_msg_head *send_msg_head = (tcp_normal_whole_msg_head *)g_tcp_send_buff;
    char *p_curr = (char *)(send_msg_head + 1);

    if (NULL == resp_data || len <= 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras(iLen:%d)!", len);
        return -1;
    }

    memcpy(send_msg_head->sync, DEFAULT_SYNC, SYNC_LEN);
    send_msg_head->cmd = SSID_RECIEVE;
    send_msg_head->seq_no = seq;
    /* 8 bytes session id + 1 byte type + 4 bytes head len + head len + 4 bytes data len + data len */
    send_msg_head->msg_len = sizeof(unsigned long long) + sizeof(char) + \
        sizeof(unsigned int) + head_len + sizeof(unsigned int) + len;   
    send_msg_head->session_id = g_curr_tcp_session;
    send_msg_head->msg_type = type;
    send_msg_head->head_len = head_len;
    if (head_len > 0 && NULL != head_data)
    {
        memcpy(p_curr, head_data, head_len);
        p_curr += head_len;
    }
    *(unsigned int *)p_curr = len;
    p_curr += sizeof(unsigned int);
    memcpy(p_curr, resp_data, len);
    p_curr[len] = '\0';

    return sizeof(tcp_normal_whole_msg_head) + head_len + sizeof(unsigned int) +len;
}

static JsonHeadInfo *json_msg_head_parse(char *msg, int len)
{
    char *pMsgBuf = NULL;
    json_object *pMyObject = NULL;
    json_object *pHeadObject = NULL;
    json_object *pTmpObject = NULL;
    JsonHeadInfo *pstJsonHead = NULL;
    char *pSession = NULL;
    char *pSign = NULL;
    
    if (NULL == msg || len <= 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras(iLen:%d)!", len);
        return NULL;
    }

    pMsgBuf = (char *)malloc(len);
    if (NULL == pMsgBuf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pMsgBuf, 0, len);

    pstJsonHead = (JsonHeadInfo *)malloc(sizeof(JsonHeadInfo));
    if (NULL == pstJsonHead)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstJsonHead, 0, sizeof(JsonHeadInfo));

    /* parse json */
    memcpy(pMsgBuf, msg, len);
    pMyObject = json_tokener_parse(pMsgBuf);
    if (is_error(pMyObject))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_tokener_parse body failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }

    /* get header object */
    pHeadObject = json_object_object_get(pMyObject, K_HEAD);
    if (NULL == pHeadObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    IM_FREE_JSON_OBJ(pTmpObject);
    
    /* get cmd */
    pTmpObject = json_object_object_get(pHeadObject, K_CMD_ID);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iCmd = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get version */
    pTmpObject = json_object_object_get(pHeadObject, K_VERSION_NUM);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iVer = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get seq */
    pTmpObject = json_object_object_get(pHeadObject, K_SEQ_NUM);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iSeq = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_DEV_TYPE);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iDevice = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_APP_ID);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iAppId = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_RST_CODE);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iCode = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get session id in header */
    pTmpObject = json_object_object_get(pHeadObject, K_SESSION_ID);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pSession = (char *)json_object_get_string(pTmpObject);
    snprintf(pstJsonHead->szSession, JSON_SESSION_LEN, "%s", pSession);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get sign in header */
    pTmpObject = json_object_object_get(pHeadObject, K_SIGN);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pSign = (char *)json_object_get_string(pTmpObject);
    snprintf(pstJsonHead->szSign, JSON_SIGN_LEN, "%s", pSign);

Out:
    IM_FREE_JSON_OBJ(pTmpObject);
    IM_FREE_JSON_OBJ(pHeadObject);
    IM_FREE_JSON_OBJ(pMyObject);
    IM_FREE(pMsgBuf);
    
    return pstJsonHead;
}

static usr_login_info *json_msg_login_data_parse(char *pMsg, unsigned long iLen)
{
    int iRet = 0;
    char *pMsgBuf = NULL;
    json_object *pMyObject = NULL;
    json_object *pArrayObject = NULL;
    json_object *pDataOject = NULL;
    json_object *pTmpObject = NULL;
    usr_login_info *login_info = NULL;
    char *usr_name = NULL;
    char *pwd = NULL;
    int login_type = 0;

    pMsgBuf = (char *)malloc(iLen);
    if (NULL == pMsgBuf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pMsgBuf, 0, iLen);

    login_info = (usr_login_info *)malloc(sizeof(usr_login_info));
    if (NULL == login_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        goto Out;
    }
    memset(login_info, 0, sizeof(usr_login_info));

    memcpy(pMsgBuf, pMsg, iLen);
    pMyObject = json_tokener_parse(pMsgBuf);
    if (is_error(pMyObject))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_tokener_parse body failed!");
        IM_FREE(login_info);
        goto Out;
    }
    /* Get data */
    pDataOject = json_object_object_get(pMyObject, K_DATA);
    if (NULL == pDataOject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(login_info);
        goto Out;
    }

    /* Get first array in data */
    pArrayObject = json_object_array_get_idx(pDataOject, 0);
    if (NULL == pArrayObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_array_get_idx failed!");
        IM_FREE(login_info);
        goto Out;
    }

    /* Get usr name */
    pTmpObject = json_object_object_get(pArrayObject, K_USR_NAME);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(login_info);
        goto Out;
    }
    usr_name = (char *)json_object_get_string(pTmpObject);
    snprintf(login_info->name, MAX_USR_NAME_LEN, "%s", usr_name);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get pwd */
    pTmpObject = json_object_object_get(pArrayObject, K_PWD);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(login_info);
        goto Out;
    }
    pwd = (char *)json_object_get_string(pTmpObject);
    snprintf(login_info->pwd, MAX_PWD_LEN, "%s", pwd);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get login type */
    pTmpObject = json_object_object_get(pArrayObject, K_LOGIN_TYPE);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(login_info);
        goto Out;
    }
    login_type = json_object_get_int(pTmpObject);
    login_info->login_type = login_type;

Out:
    IM_FREE_JSON_OBJ(pTmpObject);
    IM_FREE_JSON_OBJ(pArrayObject);
    IM_FREE_JSON_OBJ(pDataOject);
    IM_FREE_JSON_OBJ(pMyObject);
    IM_FREE(pMsgBuf);
    
    return login_info;
}

static void *json_msg_bind_data_parse(char *pMsg, unsigned long iLen, int type)
{
    int iRet = 0;
    char *pMsgBuf = NULL;
    json_object *pMyObject = NULL;
    json_object *pArrayObject = NULL;
    json_object *pDataOject = NULL;
    json_object *pTmpObject = NULL;
    usr_bind_info *bind_info = NULL;
    bind_state_info *bind_state = NULL;
    char *usr_name = NULL;
    char *pwd = NULL;
    char *dev_name = NULL;
    char *dev_id = NULL;

    pMsgBuf = (char *)malloc(iLen);
    if (NULL == pMsgBuf)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pMsgBuf, 0, iLen);

    bind_info = (usr_bind_info *)malloc(sizeof(usr_bind_info));
    if (NULL == bind_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        goto Out;
    }
    memset(bind_info, 0, sizeof(usr_bind_info));

    bind_state = (bind_state_info *)malloc(sizeof(bind_state_info));
    if (NULL == bind_state)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        goto Out;
    }
    memset(bind_state, 0, sizeof(bind_state_info));

    memcpy(pMsgBuf, pMsg, iLen);
    pMyObject = json_tokener_parse(pMsgBuf);
    if (is_error(pMyObject))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_tokener_parse body failed!");
        IM_FREE(bind_info);
        goto Out;
    }
    /* Get data */
    pDataOject = json_object_object_get(pMyObject, K_DATA);
    if (NULL == pDataOject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(bind_info);
        goto Out;
    }

    /* Get first array in data */
    pArrayObject = json_object_array_get_idx(pDataOject, 0);
    if (NULL == pArrayObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_array_get_idx failed!");
        IM_FREE(bind_info);
        goto Out;
    }

    /* Get usr name */
    pTmpObject = json_object_object_get(pArrayObject, K_USR_NAME);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(bind_info);
        goto Out;
    }
    usr_name = (char *)json_object_get_string(pTmpObject);
    snprintf(bind_info->usr_name, MAX_USR_NAME_LEN, "%s", usr_name);
    snprintf(bind_state->usr_name, MAX_USR_NAME_LEN, "%s", usr_name);
    IM_FREE_JSON_OBJ(pTmpObject);

    if (CMD_USR_BIND == type)
    {
        /* Get pwd */
        pTmpObject = json_object_object_get(pArrayObject, K_PWD);
        if (NULL == pTmpObject)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
            IM_FREE(bind_info);
            goto Out;
        }
        pwd = (char *)json_object_get_string(pTmpObject);
        snprintf(bind_info->dev_pwd, MAX_PWD_LEN, "%s", pwd);
        IM_FREE_JSON_OBJ(pTmpObject);

        /* Get router name */
        pTmpObject = json_object_object_get(pArrayObject, K_DEV_NAME);
        if (NULL == pTmpObject)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
            IM_FREE(bind_info);
            goto Out;
        }
        dev_name = (char *)json_object_get_string(pTmpObject);
        snprintf(bind_info->dev_name, MAX_PWD_LEN, "%s", dev_name);
        IM_FREE_JSON_OBJ(pTmpObject);
    }

    /* Get device id */
    pTmpObject = json_object_object_get(pArrayObject, K_DEV_ID);
    if (NULL == pTmpObject)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(bind_info);
        goto Out;
    }
    dev_id = (char *)json_object_get_string(pTmpObject);
    snprintf(bind_info->dev_id, MAX_PWD_LEN, "%s", dev_id);
    snprintf(bind_state->dev_id, MAX_PWD_LEN, "%s", dev_id);

Out:
    IM_FREE_JSON_OBJ(pTmpObject);
    IM_FREE_JSON_OBJ(pArrayObject);
    IM_FREE_JSON_OBJ(pDataOject);
    IM_FREE_JSON_OBJ(pMyObject);
    IM_FREE(pMsgBuf);

    if (CMD_USR_BIND == type)
    {
        IM_FREE(bind_state);
        return (void *)bind_info;
    }
    else
    {
        IM_FREE(bind_info);
        return (void *)bind_state;
    }
}


static int find_app_in_shm(int app_id)
{
    int i = 0;
    int ret = 0;

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        memset(&g_app_proc_info[i], 0, sizeof(AppProcInfo));
    }

    ret = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)g_app_proc_info, PROC_INFO_SHM_NUM * sizeof(AppProcInfo), 0);
    if (0 != ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "IM_PosixShmRead failed!");
        return -1;
    }

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (g_app_proc_info[i].nAppId == app_id)
        {
            return i;
        }
    }

    return -1;
}

static char *tcp_send_msg_to_other(const char *module_name, char *msg_body, int msg_len, int *recv_len)
{
    int client_fd = -1;
    int ret = 0;
    unsigned int time_out = RECV_TIMEOUT;
    char *recv_buf = NULL;

    if (NULL == module_name)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong para!");
        return NULL;
    }
    
    /* Connect and send post data to module */
    client_fd = IM_DomainClientInit(module_name);
    if (MSG_INVALID_FD == client_fd)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "connect to server error!");
        goto out;
    }

    ret = IM_MsgSend(client_fd, msg_body, msg_len);
    if (0 != ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "send error!");
        goto out;
    }
    IM_MsgPrintf((void *)msg_body, "message to server module", msg_len, 2);

    /* Recieve reply from module */
    ret = IM_MsgReceive(client_fd, &recv_buf, &time_out);
    if (ret > 0)
    {
        //IM_MsgPrintf((void *)recv_buf, "reply message from server module", ret, 1);
    }
    else if (MSGRET_TIMED_OUT == ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "recieve reply message from server module timeout!");
        goto out;
    }
    else if (MSGRET_DISCONNECTED == ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "server disconnect!");
        goto out;
    }
    else if (MSGRET_INVALID_ARGUMENTS == ret)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "invalid arguments!");
        goto out;
    }
    else
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_WARN, "other err!");
        goto out;
    }
    *recv_len = ret;

out:
    IM_DomainClientDeinit(client_fd);

    return recv_buf;
}

static int tcp_prcs_http_request(char *msg_body, unsigned int msg_len, unsigned int seq)
{
    http_resp_msg *response_msg = NULL;
    int ret = 0;
    int resp_len = 0;
    char tmp_buf[1024] = {0};
    tcp_normal_msg_sub_head *sub_head = (tcp_normal_msg_sub_head *)msg_body;
    unsigned int head_len = 0;
    char *head_content = NULL;
    unsigned int data_len = 0;
    char *p_curr = (char *)(sub_head + 1);
    JsonHeadInfo *json_head = NULL;
    int app_shm_idx = -1;
    char *recv_buf = NULL;
    int recv_len = 0;
    char tmp_cmd[128] = {0};
    char session[128] = {0};

    head_len = NTOHL(sub_head->head_len);
        
    /* IMOVE type msg:0 bytes head content + 4 bytes data len + data content */
    if (sub_head->msg_type == MSG_IMOVE)
    {
        data_len = NTOHL(*(unsigned int *)p_curr);    //data len
        p_curr += sizeof(unsigned int);               //offset data len

        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "tcp_head:%d len_sub:%d len_whole:%d session:%llu type:%d head_len:%x(%x) data_len:%x!", 
            sizeof(tcp_msg_head), sizeof(tcp_normal_msg_sub_head), sizeof(tcp_normal_whole_msg_head), sub_head->session_id, 
            sub_head->msg_type, head_len, sub_head->head_len, data_len);

        /* parse json head */
        json_head = json_msg_head_parse(p_curr, data_len);
        if (NULL == json_head)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "json_msg_head_parse failed!");
            ret = -1;
            goto out;
        }

        /* bind new session to root mac */
        if (strcmp(g_curr_tcp_cli_session, json_head->szSession))
        {
            memset(&g_curr_tcp_cli_session, 0, sizeof(g_curr_tcp_cli_session));
            snprintf(g_curr_tcp_cli_session, sizeof(g_curr_tcp_cli_session), "%s", json_head->szSession);
            pthread_mutex_lock(&perauth_proc_mutex);
            IM_AllSessUnbindMac(DEFAULTE_ROOT_MAC);
            IM_SessBindMac(json_head->szSession, DEFAULTE_ROOT_MAC);
            pthread_mutex_unlock(&perauth_proc_mutex);
        }

        /* read app info in share memory and find the app with app id */
        app_shm_idx = find_app_in_shm(json_head->iAppId);
        if (app_shm_idx < 0)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "find_app_in_shm(%d) failed!", json_head->iAppId);
            ret = -1;
            goto out;
        }

        /* first, send msg to app and recieve response when proc in mem;then,send the response to cloud server */
        if (g_app_proc_info[app_shm_idx].cInMemFlag)
        {
            recv_buf = tcp_send_msg_to_other(g_app_proc_info[app_shm_idx].szAppName, p_curr, data_len, &recv_len);
            if (NULL == recv_buf)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_send_msg_to_other(%s) process failed!", g_app_proc_info[app_shm_idx].szAppName);
                ret = -1;
                goto out;
            }
            
            resp_len = tcp_creat_normal_resp_frame(sub_head->msg_type, seq, NULL, 0, recv_buf, recv_len);
            if (resp_len <= 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_normal_resp_frame failed!");
                ret = -1;
                goto out;
            }
        }
        else
        {
            snprintf(tmp_buf, sizeof(tmp_buf), "app %s is not im mem", g_app_proc_info[app_shm_idx].szAppName);
            resp_len = tcp_creat_normal_resp_frame(sub_head->msg_type, seq, NULL, 0, tmp_buf, strlen(tmp_buf));
            if (resp_len <= 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_normal_resp_frame failed!");
                ret = -1;
                goto out;
            }
        }
        ret = tcp_send_msg(&g_TcpSocketInfo, g_tcp_send_buff, resp_len);
    }
    /* OTHER type msg:head content + 4 bytes data len + data content */
    else
    {
        head_content = (char *)malloc(head_len + 1);
        if (NULL == head_content)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
            ret = -1;
            goto out;
        }
        memset(head_content, 0, head_len + 1);
        
        memcpy(head_content, p_curr, head_len);
        head_content[head_len] = '\0';                  //head content
        p_curr += head_len;                             //offset head content
        data_len = NTOHL(*(unsigned int *)p_curr);      //data len
        p_curr += sizeof(unsigned int);                 //offset data len
        
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "tcp_head:%d len_sub:%d len_whole:%d session:%llu type:%d head_len:%x(%x) data_len:%x!", 
            sizeof(tcp_msg_head), sizeof(tcp_normal_msg_sub_head), sizeof(tcp_normal_whole_msg_head), sub_head->session_id, 
            sub_head->msg_type, head_len, sub_head->head_len, data_len);

        /* http post data to aria2 and get response */
        //IM_MsgPrintf(p_curr, "http request to http server", data_len, 2);
        response_msg = http_request(HTTP_POST, ARIA2_URL, p_curr, data_len, TYPE_JSON);
        if (NULL == response_msg)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "http_request failed!");
            ret = -1;
            goto out;
        }
        //IM_MsgPrintf(response_msg->data, "http response from http server", response_msg->content_len, 1);

        /* create reply with http response and send to cloud server */
        if (response_msg->content_len <= 0)
        {
            sprintf(tmp_buf, "%s", "no response data!");
            resp_len = tcp_creat_normal_resp_frame(sub_head->msg_type, seq, head_content, head_len, tmp_buf, strlen(tmp_buf));
            if (resp_len <= 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_normal_resp_frame failed!");
                ret = -1;
                goto out;
            }
        }
        else
        {
            resp_len = tcp_creat_normal_resp_frame(sub_head->msg_type, seq, head_content, head_len, response_msg->data, response_msg->content_len);
            if (resp_len <= 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp_creat_normal_resp_frame failed!");
                ret = -1;
                goto out;
            }
        }
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "########send to server:seq:%x(%d)!",
            seq, seq);
        ret = tcp_send_msg(&g_TcpSocketInfo, g_tcp_send_buff, resp_len);
    }

out:
    IM_FREE(json_head);
    IM_FREE(recv_buf);
    IM_FREE(head_content);
    IM_FREE(response_msg);
    return ret;
}

static int tcp_creat_request_frame(run_stage_type run_stage)
{
    tcp_msg_head *send_msg_head = (tcp_msg_head *)g_tcp_send_buff;
    int msg_len = 0;

    memcpy(send_msg_head->sync, DEFAULT_SYNC, SYNC_LEN);

    switch (run_stage)
    {
        case STAGE_REPORT_DEV_FOR_AUTH:
        {
            dev_login_info *login_info = (dev_login_info *)(g_tcp_send_buff + sizeof(tcp_msg_head));
            send_msg_head->cmd = ROUTER_LOGIN;
            send_msg_head->seq_no = g_seq_no;
            send_msg_head->msg_len = sizeof(dev_login_info);
            memcpy(login_info->dev_id, g_Mr2fcConfigInfo.mac_str, MAC_STR_LEN);
            msg_len = sizeof(tcp_msg_head) + sizeof(dev_login_info);
            break;
        }
        case STAGE_HEART_BEAT:
        {
            dev_heart_beat_info *heart_beat_info = (dev_heart_beat_info *)(g_tcp_send_buff + sizeof(tcp_msg_head));
            send_msg_head->cmd = ROUTER_HEARBEAT;
            send_msg_head->seq_no = g_seq_no;
            send_msg_head->msg_len = sizeof(dev_heart_beat_info);
            memcpy(heart_beat_info->dev_id, g_Mr2fcConfigInfo.mac_str, MAC_STR_LEN);
            heart_beat_info->session_id = g_curr_tcp_session;
            msg_len = sizeof(tcp_msg_head) + sizeof(dev_heart_beat_info);
            break;
        }
        default:
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong stage %x!", run_stage);
            msg_len = 0;
            break;

    }

    return msg_len;
}

static int tcp_send_msg_via_ssl(socket_manage_info *socket_info, void *msg_buf, int msg_len)
{
    fd_set write_fds;
    struct timeval time_out = {SEND_TIME_OUT, 0};
    int ret = 0;
    
    if (NULL == msg_buf || msg_len <= 0 || NULL == socket_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }

    FD_ZERO(&write_fds);
    FD_SET(socket_info->socket_fd, &write_fds);
    ret = select(socket_info->socket_fd + 1, NULL, &write_fds, NULL, &time_out);
    if (ret < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "select err!");
        return -1;
    }
    else
    {
#ifdef SSL_SURPPORT 
        ret = SSL_write(socket_info->ssl, msg_buf, msg_len);
#else
        ret = write(socket_info->socket_fd, msg_buf, msg_len);
#endif
        if (ret = msg_len)
        {
            //IM_MsgPrintf(msg_buf, "msg to cloud server", msg_len, 2);
        }
        else
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "SSL_write err!");
            return -1;
        }
    }

    return 0;
}

static int tcp_send_msg(socket_manage_info *socket_info, void *msg_buf, int msg_len)
{
    int ret = 0;
    
    if (NULL == msg_buf || msg_len <= 0 || NULL == socket_info || INVALID_SOCKET == socket_info->socket_fd)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }
    
#ifdef SSL_SURPPORT
    if (socket_info->ssl)
#endif
    {
        ret = tcp_send_msg_via_ssl(socket_info, msg_buf, msg_len);
    }

    if (0 != ret)
    {
        socket_info->fail_count++;
    }
    else
    {
        socket_info->fail_count = 0;
    }
    memset(&g_tcp_send_buff, 0, sizeof(g_tcp_send_buff));

    return ret;
}

static int tcp_recv_msg_via_ssl(socket_manage_info *socket_info, void **msg_buf, int *msg_len)
{
    fd_set read_fds;
    struct timeval time_out = {RECV_TIME_OUT, 0};
    int ret = 0;
    tcp_msg_head *msg = NULL;
    int rc = 0;
    int data_len = 0;
    
    if (NULL == msg_buf || NULL == msg_len || NULL == socket_info)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }
    *msg_buf = NULL;

    FD_ZERO(&read_fds);
    FD_SET(socket_info->socket_fd, &read_fds);
    ret = select(socket_info->socket_fd + 1, &read_fds, NULL, NULL, &time_out);
    if (ret < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "select err!");
        return -1;
    }
    
    msg = (tcp_msg_head *)malloc(sizeof(tcp_msg_head));
    if (NULL == msg)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
        return -1;
    }
    memset(msg, 0, sizeof(tcp_msg_head));

    /* first read for getting data len */
#ifdef SSL_SURPPORT
    rc = SSL_read(socket_info->socket_fd, msg, sizeof(tcp_msg_head));
#else
    rc = read(socket_info->socket_fd, msg, sizeof(tcp_msg_head));
#endif
    if (rc < 0 || rc != sizeof(tcp_msg_head))
    {
        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "bad read, rc=%d errno=%d reason:%s", rc, errno, strerror(errno));
        }
        IM_FREE(msg);
        return -1;
    }

    data_len = NTOHL(msg->msg_len);
    if (data_len > 0)
    {
        int readed_size = 0;
        int remain_size = data_len;
        char *read_buf = NULL;

        /* there is additional data in the message */
        msg = (tcp_msg_head *)realloc(msg, sizeof(tcp_msg_head) + data_len);
        if(msg == NULL)
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "malloc failed!");
            IM_FREE(msg);
            return -1;
        }

        read_buf = (char *)(msg + 1);
        while (readed_size < data_len)
        {
            FD_ZERO(&read_fds);
            FD_SET(socket_info->socket_fd, &read_fds);
            ret = select(socket_info->socket_fd + 1, &read_fds, NULL, NULL, &time_out);
            if (ret < 0)
            {
                IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "select err!");
                IM_FREE(msg);
                return -1;
            }

            /* second read for getting data content */
#ifdef SSL_SURPPORT
            rc = SSL_read(socket_info->socket_fd, read_buf, remain_size);
#else
            rc = read(socket_info->socket_fd, read_buf, remain_size);
#endif
            if(rc <= 0)
            {
                if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                {
                    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "bad data read, rc=%d errno=%d readed=%d remaining=%d reason:%s", 
                            rc, errno, readed_size, remain_size, strerror(errno));
                }
                IM_FREE(msg);
                return -1;
            }
            else
            {
                read_buf += rc;
                readed_size += rc;
                remain_size -= rc;
            }
        }
    }

    *msg_buf = msg;
    *msg_len = sizeof(tcp_msg_head) + data_len;

    return 0;
}

static int tcp_recv_msg(socket_manage_info *socket_info, void **msg_buf, int *msg_len)
{
    int ret = -1;
    
    if (NULL == msg_buf || NULL == msg_len || NULL == socket_info || INVALID_SOCKET == socket_info->socket_fd)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong paras!");
        return -1;
    }
#ifdef SSL_SURPPORT
    if (socket_info->ssl)
#endif
    {
        ret = tcp_recv_msg_via_ssl(socket_info, msg_buf, msg_len);
    }

    return ret;
}

static int tcp_handle_recv_msg(void *msg_buf, int msg_len, run_stage_type run_stage)
{
    int ret = 0;
    unsigned short cmd_id = 0;
    int table_size = sizeof(g_tcp_msg_prcs_table) / sizeof(g_tcp_msg_prcs_table[0]);
    int i = 0;
    unsigned int data_len = 0;
    unsigned int seq = 0;
    char sync[SYNC_LEN + 1] = {0};

    memcpy(sync, msg_buf, SYNC_LEN);
    sync[SYNC_LEN] = '\0';
    if (strcmp(sync, DEFAULT_SYNC))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "wrong sync:%s!", sync);
        return -1;
    }

    data_len = NTOHL(((tcp_msg_head *)msg_buf)->msg_len);
    cmd_id = NTOHS(((tcp_msg_head *)msg_buf)->cmd);
    seq = NTOHL(((tcp_msg_head *)msg_buf)->seq_no);
    for (i = 0; i < table_size; i++)
    {
        if (cmd_id == g_tcp_msg_prcs_table[i].msg_type)
        {
            break;
        }
    }
    if (i >= table_size)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "invalid msg type:%x!", cmd_id);
        return -1;
    }
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "########****recieve msg type:%x, len:%d, seq:(%x)%d!", 
        cmd_id, data_len + sizeof(tcp_msg_head), seq, seq);
    
    if (NULL == g_tcp_msg_prcs_table[i].msg_handl)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "no handle for msg:%d!", cmd_id);
        return -1;
    }
    else
    {
        ret = g_tcp_msg_prcs_table[i].msg_handl((char *)(msg_buf + sizeof(tcp_msg_head)), data_len, seq);
    }

    return ret;
}

static int tcp_run_stage_ctrl(run_stage_type run_stage)
{
    int msg_len = 0;
    char *recv_buf = NULL;
    int ret = -1;

    if ((msg_len = tcp_creat_request_frame(run_stage)) > 0)
    {
        if (0 == tcp_send_msg(&g_TcpSocketInfo, g_tcp_send_buff, msg_len))
        {
            g_seq_no++;
            if (STAGE_HEART_BEAT == run_stage)
            {
                return 0;
            }
            
            if (0 == tcp_recv_msg(&g_TcpSocketInfo, &recv_buf, &msg_len))
            {
                ret = tcp_handle_recv_msg(recv_buf, msg_len, run_stage);
            }
        }
    }

    IM_FREE(recv_buf);
    return ret;
}

static void tcp_client_prcs_task(void)
{
    int fail_count = 0;
    char *recv_buf = NULL;
    int ret = -1;
    int msg_len = 0;
    pthread_t thread_id;
    tcp_msg_prc_paras prc_paras;
    tcp_msg_prc_paras_new prc_paras_new;
    
    signal_init();

    while (1)
    {
build_tcp:
        tcp_free_connect(&g_TcpSocketInfo);
        if (0 != tcp_ssl_connect(g_Mr2fcConfigInfo.server_name, g_Mr2fcConfigInfo.server_port, &g_TcpSocketInfo))
        {
            IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "tcp connet err!");
            sleep(3);
            goto build_tcp;
        }
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "tcp connet success(server:%s port:%d)!",
            g_Mr2fcConfigInfo.server_name, g_Mr2fcConfigInfo.server_port);
            
        g_heart_beat_count = 0;
        g_RunStage = STAGE_REPORT_DEV_FOR_AUTH;

        while (1)
        {
            pthread_mutex_lock(&bind_proc_mutex);
            if (1 == g_StateBind && 1 == g_BindProc)
            {
                pthread_cond_wait(&bind_proc_nozero, &bind_proc_mutex);
            }
            pthread_mutex_unlock(&bind_proc_mutex);

            if (g_TcpSocketInfo.fail_count > MAX_TCP_CONN_FALI_CNT)
            {
                goto build_tcp;
            }

            if (g_heart_beat_count > MAX_HB_FAIL_CNT)
            {
                goto build_tcp;
            }

            if (g_RunStage != STAGE_NORMAL)
            {
                pthread_mutex_lock(&bind_execute_mutex);
                if (0 == tcp_run_stage_ctrl(g_RunStage))
                {
                    fail_count = 0;
                    g_RunStage = STAGE_NORMAL;
                    /* for bind process */
                    if (0 == g_StateBind)
                    {
                        pthread_cond_signal(&bind_nozero);
                    }
                    g_StateBind = 1;
                    pthread_mutex_unlock(&bind_execute_mutex);
                }
                else
                {
                    pthread_mutex_unlock(&bind_execute_mutex);
                    if (++fail_count > MAX_TCP_FAIL_CNT)
                    {
                        fail_count = 0;
                        goto build_tcp;
                    }
                    else
                    {
                        sleep(2);
                    }
                }
            }
            else
            {
                pthread_mutex_lock(&bind_execute_mutex);
                if (0 == tcp_recv_msg(&g_TcpSocketInfo, &recv_buf, &msg_len))
                {
                    tcp_handle_recv_msg(recv_buf, msg_len, g_RunStage);
                }
                IM_FREE(recv_buf);
                
                /* for bind process */
                if (0 == g_StateBind)
                {
                    pthread_cond_signal(&bind_nozero);
                }
                g_StateBind = 1;
                pthread_mutex_unlock(&bind_execute_mutex);
            }
        }
    }
}

static int config_get_from_file()
{
    FILE *fd = NULL;
    char buf[256] = {0};
    char tmp_buf[256] = {0};
    int i = 0, j = 0, k = 0, flag = 0;
    char *key = NULL, *value = NULL;

    if (0 != access(MR2FC_CONFIG_FILE, F_OK))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "file %s does not exist!", MR2FC_CONFIG_FILE);
        return 0;
    }
    
    if (NULL == (fd = fopen(MR2FC_CONFIG_FILE, "r")))
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "open %s failed!", MR2FC_CONFIG_FILE);
        return -1;
    }

    while (1)
    {
        if (fgets(buf, sizeof(tmp_buf), fd))
        {
            j = flag = 0;
            for (i = 0; i < strlen(buf); i++)
            {
                if (buf[i] == ' ')
                    continue;
                else if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '#')
                    break;
                else
                {
                    tmp_buf[j] = buf[i];
                    if (buf[i] == '=')
                    {
                        tmp_buf[j] = '\0';
                        flag = j;
                    }
                    j++;
                }
            }
            tmp_buf[j] = '\0';
            if (!flag)
                continue;

            key = &tmp_buf[0];
            value = &tmp_buf[flag + 1];

            for (k = 0; k < sizeof(g_Mr2fcConfigSt)/sizeof(g_Mr2fcConfigSt[0]); k++)
            {
                if (strcmp(key, g_Mr2fcConfigSt[k].key))
                {
                    continue;
                }

                if (!strcmp(g_Mr2fcConfigSt[k].format, FORMAT_STRING))
                {
                    strcpy(g_Mr2fcConfigSt[k].value, value);
                }

                if (!strcmp(g_Mr2fcConfigSt[k].format, FORMAT_UNINT))
                {
                    sscanf(value, FORMAT_UNINT, (unsigned int *)g_Mr2fcConfigSt[k].value);
                }

                if (!strcmp(g_Mr2fcConfigSt[k].format, FORMAT_INT))
                {
                    sscanf(value, FORMAT_INT, (int *)g_Mr2fcConfigSt[k].value);
                }
            }
        }
        else
        {
            break;
        }
    }
    fclose(fd);

    return 0;
}

static void get_dev_mac(void)
{
    int fd = -1;
    struct ifreq ifreq;
    int i = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "creat socket failed!");
        return;
    }

    strncpy(ifreq.ifr_name, DEV_IF_NAME, sizeof(ifreq.ifr_name));
    if (ioctl(fd, SIOCGIFHWADDR, &ifreq) < 0)
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "ioctl failed!");
        close(fd);
        return;
    }

    for (i = 0; i < 6; i++)
    {
        sprintf(g_Mr2fcConfigInfo.mac_str + 3 * i, "%02X:", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
    }
    g_Mr2fcConfigInfo.mac_str[strlen(g_Mr2fcConfigInfo.mac_str) - 1] = '\0';
    
    close(fd);
}

static void config_print(void)
{
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "\n\n****************config used as below****************");
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "=============================================================");
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "server name:%s", g_Mr2fcConfigInfo.server_name);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "server port:%u", g_Mr2fcConfigInfo.server_port);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "dev mac    :%s", g_Mr2fcConfigInfo.mac_str);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "HB interval:%u", g_Mr2fcConfigInfo.heart_beat_interval);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "http port  :%u", g_Mr2fcConfigInfo.http_port);
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "=============================================================\n");
}

static void init_app_info(AppProcInfo *app_proc_info)
{
    memset(app_proc_info, 0, sizeof(AppProcInfo));
}

static int mr2fc_init(void)
{
    int i = 0;
    
    memset(&g_TcpSocketInfo, 0, sizeof(g_TcpSocketInfo));
    g_TcpSocketInfo.socket_fd = INVALID_SOCKET;

    /* config init */
    memset(&g_Mr2fcConfigInfo, 0, sizeof(g_Mr2fcConfigInfo));
    if(0 != config_get_from_file())
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "config_get_from_file failed!");
        return -1;
    }

    get_dev_mac();
    config_print();

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        init_app_info(&g_app_proc_info[i]);
    }

    for (i = 0; i < MAX_ONLINE_CLIENT_CNT; i++)
    {
        memset(&g_http_clients[i], 0, sizeof(http_client));
    }

    /* init per auth lib */
    IM_PerAuthInit();
    
    return 0;
}

int main(int argc, char *argv[])
{
    int rslt = 0;
    pthread_t tid_tcp_msg;

    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_INFO, "mr2fc version %s", MR2FC_VER);
    /* init */
    if (0 != mr2fc_init())
    {
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "mr2fc_init failed!");
        rslt = -1;
        goto quit;
    }

    /* Recieve message from tcp, process and reply */
    if (0 != (rslt = pthread_create(&tid_tcp_msg, NULL, (void *)tcp_client_prcs_task, NULL)))
    { 
        IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "Create tcp msg prcs thread failed!");
        rslt = -1;
        goto quit;
    }
    pthread_detach(tid_tcp_msg);

#if 0   //main process for http server
    http_server_run();
#else   //thread or threads for http server
    http_server_start(g_Mr2fcConfigInfo.http_port, HTTP_SERVER_THREAD_NUM, HTTP_SERVER_BACKLOG);
#endif

quit:
    IM_MR2FC_LOG(IM_MR2FC_LOG_FLAG, IM_MR2FC_LOG_ERR, "mr2fc main task quit!\n");
    return rslt;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */
