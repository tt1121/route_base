#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "imove_msg_server.h"

#define THE_UNIX_PATH	 "msg_server"

fd_set block_read_fdset;
fd_set block_write_fdset;
static struct timeval req_timeout;     /* timeval for select */
static int max_fd = -1;
time_t current_time;
int use_localtime;
int pending_requests = 0;
int devnullfd = 0;

int sigchld_flag = 0;
int verbose_cgi_logs = 0;
int sigterm_flag = 0;

IM_ST_request *request_cache_list = NULL;        // cacha list head, cacha for some reqeust
IM_ST_request *request_free_list = NULL; 		// free list head
IM_ST_request *request_ready_list = NULL;        // ready list head
IM_ST_request *request_block_list = NULL;        // block list head

void inline imove_free_json_object(struct json_object *ptr);

/***
设置文件描述符为非阻塞
params:
	fd:[in] file fd
return:
	0: success 
	-1: failed
***/
int imove_set_noblock_fd(int fd)
{
	assert(fd > 0);
	int flags;

    	flags = fcntl(fd, F_GETFL);
    	if (flags == -1)
    	    return -1;

    	flags |= O_NONBLOCK;
    	flags = fcntl(fd, F_SETFL, flags);
    	return flags;
}

/*** 
创建server套接字
params:
	path:[in] string  the file path ,i.e: /var/run/imove_msg_server
return:
	-1:failed;
	0:	error
	>0: success
***/
int imove_create_unix_socket(char *path)
{
	int fd;
	if (path == NULL)
	{
		goto c_err;
	}

	fd = IM_DomainServerInit(path);
	if (fd < 0)
	{
		goto c_err;
	}

	if (imove_set_noblock_fd(fd) < 0)
	{
		WARN("set noblock failed\n");
	}

	return fd;
c_err:
	return -1;
}

void sigsegv(int dummy)
{
    fprintf(stderr, "caught SIGSEGV, dumping core \n");
    fclose(stderr);
    abort();
}

void sigbus(int dummy)
{
	fprintf(stderr, "caught SIGBUS, dumping core \n");
    	fclose(stderr);
    	abort();
}

void sigchld(int sigo)
{
	sigchld_flag = 1;
}

void sigchld_run(void)
{
    int status;
    pid_t pid;

    sigchld_flag = 0;
	
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        if (verbose_cgi_logs) {
            fprintf(stderr, "reaping child %d: status %d\n", (int) pid, status);
        }
    return;
}

void sigint(int dummy)
{
    fputs("caught SIGINT: shutting down\n", stderr);
    fclose(stderr);
    exit(1);
}

void sigterm(int dummy)
{
    sigterm_flag = 1;
}

void sigterm_stage2_run(void) /* lame duck mode */
{
    fprintf(stderr, "exiting Boa normally \n");
    imove_free_requests();
    exit(0);
}
/***
初始化信号处理函数
***/
void imove_init_signals(void)
{
	 struct sigaction sa;
	 sa.sa_flags = 0;

	 sigemptyset(&sa.sa_mask);
	 sigaddset(&sa.sa_mask, SIGSEGV);
    	 sigaddset(&sa.sa_mask, SIGBUS);
	 sigaddset(&sa.sa_mask, SIGPIPE);
	 sigaddset(&sa.sa_mask, SIGTERM);
    	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGCHLD);
	
	 sa.sa_handler = sigsegv;
    	 sigaction(SIGSEGV, &sa, NULL);

    	sa.sa_handler = sigbus;
    	sigaction(SIGBUS, &sa, NULL);
	 
	sa.sa_handler = SIG_IGN;
    	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sigterm;
    	sigaction(SIGTERM, &sa, NULL);

    	sa.sa_handler = sigint;
    	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = sigchld;
    	sigaction(SIGCHLD, &sa, NULL);
		
}

/***
malloc new request
***/
IM_ST_request *imove_new_request(void)
{
	IM_ST_request *req;
	
	if (request_free_list)
	{
		req = request_free_list;
		imove_dequeue(&request_free_list, request_free_list);
	}
	else
	{
		req = (IM_ST_request *)malloc(sizeof(IM_ST_request));
		if (!req)
		{
			perror("malloc for new request");
			return NULL;
		}
	}
	memset(req, 0, offsetof(IM_ST_request, msg_header));
	return req;
}

/**
根据字符串解析出请求头部
params:
	msg:[in] reqeust msg
	req_header:[in|out] request msg header
return:
	0:success
	-1:failed
**/
static int imove_parse_json_msg2header(char *msg,  IM_ST_msg_header *req_header)
{	
	assert(msg != NULL);
	assert(req_header != NULL);

	json_object *msg_object = NULL;
	json_object *head_object = NULL;
	json_object *tmp_object = NULL;

	p_debug("imove_parse_json_msg2header in \n");
	// construct json object according string msg
	msg_object = json_tokener_parse(msg);
	if (msg_object == NULL)
	{
		goto parse_e;
	}

	// get msg header
	head_object = json_object_object_get(msg_object, KEY_HEADER);
	if (head_object == NULL)
	{
		goto head_e;
	}

	// get cmd
	tmp_object = json_object_object_get(head_object, KEY_CMD);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_cmd = json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get version
	tmp_object = json_object_object_get(head_object, KEY_VER);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_ver= json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get seq
	tmp_object = json_object_object_get(head_object, KEY_SEQ);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_seq= json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get device
	tmp_object = json_object_object_get(head_object, KEY_DEVICE);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_device= json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get appid
	tmp_object = json_object_object_get(head_object, KEY_APPID);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_appid= json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get code
	tmp_object = json_object_object_get(head_object, KEY_CODE);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	req_header->i_code = json_object_get_int(tmp_object);
	imove_free_json_object(tmp_object);

	// get session
	tmp_object = json_object_object_get(head_object, KEY_SESSIONID);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	snprintf(req_header->s_session, sizeof(req_header->s_session), "%s", json_object_get_string(tmp_object));
	imove_free_json_object(tmp_object);

	// get sign
	tmp_object = json_object_object_get(head_object, KEY_SIGN);
	if (tmp_object == NULL)
	{
		goto cmd_e;
	}
	snprintf(req_header->s_sign, sizeof(req_header->s_sign), "%s", json_object_get_string(tmp_object));
	imove_free_json_object(tmp_object);
	
	imove_free_json_object(head_object);
	head_object = NULL;

	imove_free_json_object(msg_object);
	msg_object = NULL;
	
	WARN("imove_parse_json_msg2header OUT \n");
	return 0;
	
cmd_e:
	imove_free_json_object(head_object);
	head_object = NULL;
head_e:
	imove_free_json_object(msg_object);
	msg_object = NULL;
parse_e:
	return -1;
}


/**
释放json object
params:
	ptr:[in] json object
return:
	none
**/
void inline imove_free_json_object(struct json_object *ptr)
{
	int i = 0;
	int ref_cnt = 1;	// because json_pbject_put free last reference ,will return 1

	if (ptr == NULL)
		return;
	
	ref_cnt = json_object_put(ptr);	// while ptr'2 reference > 1, json_object_put return 0
	while (!ref_cnt)
	{
		WARN("json object put \n");
		ref_cnt= json_object_put(ptr);
	}
	ptr = NULL;
}

/*** 
根据IM_ST_msg_header构造return msg header of json format object 
***/
struct json_object* imove_create_json_msg_header(IM_ST_msg_header *str_hd)
{
	json_object *hd = NULL;

	if (str_hd == NULL)
	{
		p_debug("imove_create_json_msg_header input str_hd is null\n");
		return hd;
	}

	hd = json_object_new_object();
	if (hd == NULL)
	{
		return NULL;
	}

	json_object_object_add(hd, KEY_CMD, json_object_new_int(str_hd->i_cmd));
	json_object_object_add(hd, KEY_VER, json_object_new_int(str_hd->i_ver));
	json_object_object_add(hd, KEY_SEQ, json_object_new_int(str_hd->i_seq));
	json_object_object_add(hd, KEY_DEVICE, json_object_new_int(str_hd->i_device));
	json_object_object_add(hd, KEY_APPID, json_object_new_int(str_hd->i_appid));
	json_object_object_add(hd, KEY_CODE, json_object_new_int(str_hd->i_code));
	json_object_object_add(hd, KEY_SESSIONID, json_object_new_string(str_hd->s_session));
	json_object_object_add(hd, KEY_SIGN, json_object_new_string(str_hd->s_sign));

	return hd;
}

/**
根据构造的head json object and data json object generate response string
params:
	rsp_buff:	[in|out]  save string of response msg
	buf_len: [in] length of rsp_buff
	hd:	[in]	json object of msg header
	data:[in] json object of msg data
return:
	0: success
	-1: failed
**/
static int imove_create_response_string(char *rsp_buff ,int buf_len, json_object *hd, json_object *data)
{
	assert(hd && rsp_buff && buf_len > 0);
	json_object *rsp_object = NULL;
	char *rsp_string = NULL;
	
	rsp_object = json_object_new_object();
	if (rsp_object == NULL)
	{
		goto c_err;
	}

	json_object_object_add(rsp_object, KEY_HEADER, hd);
	if (data)
	{
		json_object_object_add(rsp_object, KEY_DATA, data);
	}

	rsp_string = json_object_to_json_string(rsp_object);
	if (rsp_string == NULL)
	{
		goto c_err;
	}

	snprintf(rsp_buff, buf_len, "%s", rsp_string);
	imove_free_json_object(rsp_object);
	return 0;
	
c_err:
	imove_free_json_object(rsp_object);
	return -1;
}

/***
缓存的查找，目前以遍历的方式，待后续修改为用hash表的方式
params:
	cmd:[in] command, 
return:
	NULL:	not found
	!NULL: 	found
***/
static IM_ST_request *imove_find_cache_by_cmd(int cmd)
{
	assert(cmd >0);
	IM_ST_request *current = NULL;

	for (current = request_cache_list; current; current = current->next)
	{
		if (current->cmd == cmd)
		{
			break;
		}
	}

	return current;
}

/****
从缓存中获取response 数据，
PARAMS:
	req:	[in] current request
return:
	0:	success
	-1:	failed
****/
static int imove_get_response_from_cache(IM_ST_request *req)
{
	assert(req);
	int cmd = req->msg_header.i_cmd;
	IM_ST_request *cacha_req = NULL;

	cacha_req = imove_find_cache_by_cmd(cmd);
	if (!cacha_req)
	{
		goto n_found;
	}

	if (req->time_last > cacha_req->time_last)	// time out
	{
		imove_dequeue(request_cache_list, cacha_req);
		imove_enqueue(request_free_list, cacha_req);
		goto n_found;
	}

	snprintf(req->buffer, sizeof(req->buffer), "%s", cacha_req->buffer);
	return 0;
	
n_found:
	return -1;
}

/***
发送消息到客户端
params:
	req: [IN] request block
return:
	0: success
	-1:	block
	1:	interupt by signal
***/
static int imove_send_msg2client(IM_ST_request *req)
{
	int ret = 0;

	assert(req);

	if (req->status != MSG_WRITE)
		return 1;
	
	ret = IM_MsgSend(req->fd, req->buffer, strlen(req->buffer));
	if (ret < 0)
	{
		 if (errno == EWOULDBLOCK || errno == EAGAIN)
	 	{
	 		ret = -1;
			return;
	 	}
    		else if (errno == EINTR)
		{
			ret = 1;
			return;
		}
		ret = 0;
	}

	req->status = DONE;
	ret = 0;
	return ret;
}

/***
处理接收到的消息
params:
	pmsg:[in] string 接收到的消息
return:
	-1:	block
	0:	success
	1:	interrupt by signal or others
	-2:	failed, malloc failed possibly
***/
int imove_handle_receive_msg(IM_ST_request *req)
{
	IM_ST_msg_header msg_hd;
	IM_ST_handle_func *cmd_func= NULL;
	int num = 0;
	int i = 0;
	int auth_ret = HAVE_NO_PERMISSION;
	int ret = 0;
	json_object *rsp_hd = NULL;
	json_object *req_obj = NULL;

	p_debug("imove_handle_receive_msg in\n");
	if (req == NULL)
	{
		WARN("INPUT request req is NULL \n");
		return -2;
	}
	
	/*** parse msg header ***/
	if (req->status < MSG_HANDLE_2)
	{
		if (imove_parse_json_msg2header(req->client_stream, &(req->msg_header)) < 0)
		{
			WARN("parse msg to json header failed\n");
			req->msg_header.i_code = ERROR_CODE_JSON_INVALID;
			goto parse_hd_e;
		}
	}
	
	req->status = MSG_HANDLE_2;
	
	p_debug("IM_CheckPermBySessionCmd IN\n");
	if (req->msg_header.i_cmd == FN_GET_USR_DEV_ACCESS_PER)
	{
		p_debug("quick handle 0x229 cmd\n");
		goto quick_handle;
	}
	
	p_debug("s_session:%s cmd:%x\n", req->msg_header.s_session, req->msg_header.i_cmd);
	
	/*** check whether or not have authority ,except cmd = 0x021F ***/
	if (req->msg_header.i_cmd != FN_GET_ROUTER_INIT_STATUS )
	{
		auth_ret = IM_CheckPermBySessionCmd(req->msg_header.s_session, req->msg_header.i_cmd);
	}
	else
	{
		auth_ret = 1;
	}
	
	if (auth_ret != HAVE_PERMISSION_OPRATION)
	{
		if (auth_ret == HAVE_NO_PERMISSION)
		{
			WARN("have not permisson \n");
			req->msg_header.i_code = ERROR_CODE_AUTH;
			goto parse_hd_e;
		}
		else
		{
			WARN("error core unknow\n");
			req->msg_header.i_code = ERROR_CODE_UNKNOW;
			goto parse_hd_e;
		}
	}
	p_debug("IM_CheckPermBySessionCmd OUT \n");
	
quick_handle:	
	/** find accordig function by cmd **/
	cmd_func = imove_find_fun_by_cmd(req->msg_header.i_cmd);
	if (cmd_func == NULL)
	{
		WARN("find func by cmd failed\n");
		req->msg_header.i_code = ERROR_NO_FUNC_MODULE_DEFINED;
		goto parse_hd_e;	
	}

	/** this moudle set flag warn maybe result have cached  **/
	if (cmd_func->combine)
	{
		if (request_cache_list)
		{
			if (0 == imove_get_response_from_cache(req))
			{
				req->is_cache = 0;
				goto msg_snd;
			}
			
		}
	}

	/**** run  ****/
	p_debug("run cmd :%d func\n", req->msg_header.i_cmd);
	req_obj = json_tokener_parse(req->client_stream);
	if (req_obj == NULL)
	{
		WARN("json_tokener_parsr failed\n");
		goto parse_hd_e;
	}

	cmd_func->func(req_obj, &(req->msg_header), req);
	if (cmd_func->combine)
	{
		req->is_cache = 1;
	}
	
	imove_free_json_object(req_obj);
	p_debug("run func out ,beging to send msg\n");
//	IM_MsgPrintf(req->buffer, "reponse msg:", strlen(req->buffer), 2);
msg_snd:
	req->status = MSG_WRITE;
	ret = imove_send_msg2client(req);
	return ret;
	
parse_hd_e:
	rsp_hd = imove_create_json_msg_header(&(req->msg_header));
	if (rsp_hd == NULL)
	{
		return -2;
	}
	
	if (imove_create_response_string(req->buffer, sizeof(req->buffer), rsp_hd, NULL) == 0)
	{
		goto msg_snd;
	}
	else
	{
		imove_free_json_object(rsp_hd);
		return -2;
	}
}

/***
接收新的请求
***/
void imove_get_request(int server_s)
{
	assert(server_s);
#define RECV_TIMEOUT	5000	// 5S
#define CONN_TIMEOUT	5		// 5S

	int acc_fd = -1;
	struct sockaddr_un client_addr;
    	UINT32 sock_addr_size;
	IM_ST_request *conn = NULL;
	char *pmsg = NULL;
	int time_out = RECV_TIMEOUT;
	int ret = 0;
	
	sock_addr_size = sizeof(client_addr);

	p_debug("ACCEPT begining\n");
	acc_fd = accept(server_s, &client_addr, &sock_addr_size);
	if (acc_fd < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			WARN("accept");
		}
		else
			 pending_requests = 0;
		return;
	}

	if (acc_fd >= FD_SETSIZE) 
	{
        	WARN("Got fd >= FD_SETSIZE.");
        	close(acc_fd);
		return;
    	}

	 /* nonblocking socket */
   	if (imove_set_noblock_fd(acc_fd) == -1)
       	WARN("fcntl: unable to set new socket to non-block");

	/* set close on exec to true */
    	if (fcntl(acc_fd, F_SETFD, 1) == -1)
        	WARN("fctnl: unable to set close-on-exec for new socket");

	p_debug("imove new request\n");
	conn = imove_new_request();
	if (!conn)
	{
		goto e_out;
	}
	
	conn->fd = acc_fd;
	conn->status = MSG_READ;
	conn->time_last = current_time;
	
	if (IM_MsgReceive(acc_fd, &pmsg, &time_out) <= 0)
	{
		if (errno == EAGAIN && errno == EWOULDBLOCK)
			ret = -1;
		else if (errno == EINTR)
			ret = 1;
		else
			ret = 0;
		goto again_ret;
	}

	if (pmsg && (strlen(pmsg) >= SOCKETBUF_SIZE || strlen(pmsg) < sizeof(IM_ST_msg_header)))
	{
		WARN("receive msg,but msg length error\n");
		ret = 0;
		goto again_ret;
	}

	memset(conn->client_stream, 0, sizeof(conn->client_stream));
	snprintf(conn->client_stream, sizeof(conn->client_stream), "%s", pmsg);

	conn->status = MSG_HANDLE;
	ret = imove_handle_receive_msg(conn);
again_ret:
	switch (ret)
	{
		case -1:
			conn->time_last += CONN_TIMEOUT;
			imove_enqueue(&request_block_list, conn);
			break;
		case 0:	// is send response msg success
			IMOVE_CLOSE_FD(conn->fd);
			if (conn->is_cache)
			{
				conn->time_last += conn->interval;
				imove_enqueue(&request_cache_list, conn);
			}
			else
			{
				imove_enqueue(&request_free_list, conn);
			}
			break;
		case 1:
			conn->time_last += CONN_TIMEOUT;
			imove_enqueue(&request_ready_list, conn);
			break;
		default:
			IMOVE_CLOSE_FD(conn->fd);
			imove_enqueue(&request_free_list, conn);
			break;
	}

	FREE_MEM(pmsg);
	return;
	
e_out:
	IMOVE_CLOSE_FD(acc_fd);
	return;
}

/***
处理被阻塞的请求
params:
	conn: current reqeust
return:
	none
***/
static void imove_block_request(IM_ST_request *conn)
{
	assert(conn);
	imove_dequeue(&request_ready_list, conn);
	imove_enqueue(&request_block_list, conn);

	switch(conn->status)
	{
		case MSG_WRITE:
		case DONE:
			 IMOVE_FD_SET(conn->fd, &block_write_fdset);
			 break;
		case PIPE_READ:
			IMOVE_FD_SET(conn->data_fd, &block_read_fdset);
			break;
		default:
			IMOVE_FD_SET(conn->fd, &block_read_fdset);
	}
	return;
}

/***
将唤醒的request移至准备队列，等待处理
params:
	conn:[in] 
return:
	none
***/
static void imove_ready_request(IM_ST_request *conn)
{
	assert(conn);
	imove_dequeue(&request_block_list, conn);
	imove_enqueue(&request_ready_list, conn);

	switch(conn->status)
	{
		case MSG_WRITE:
		case DONE:
			FD_CLR(conn->fd, &block_write_fdset);
			break;
		case PIPE_READ:
			FD_CLR(conn->data_fd, &block_read_fdset);
			break;
		case PIPE_WRITE:
			FD_CLR(conn->data_fd, &block_write_fdset);
			break;
		default:
			FD_CLR(conn->fd, &block_read_fdset);
	}	
}

/****
释放请求
****/
static void imove_free_request(IM_ST_request *conn)
{
	assert(conn);

	IMOVE_CLOSE_FD(conn->fd);

	if (conn->status == DONE && conn->is_cache)
	{
		conn->time_last += conn->interval;
		imove_dequeue(&request_ready_list, conn);
		imove_enqueue(&request_cache_list, conn);
		return;
	}
	
	imove_dequeue(&request_ready_list, conn);
	imove_enqueue(&request_free_list, conn);
}

/****
更新阻塞队列中的请求
params:
	none
return:
	none
****/
static void imove_updata_block_request(void)
{
	IM_ST_request *current ,*next;

	for (current = request_block_list; current; current = next)
	{
		next = current->next;
		switch(current->status)
		{
			case MSG_WRITE:
				if (FD_ISSET(current->fd, &block_write_fdset))
				{
					imove_ready_request(current);
				}
				else
				{
					IMOVE_FD_SET(current->fd, &block_write_fdset);
				}
				break;
			case PIPE_WRITE:
				if (FD_ISSET(current->data_fd, &block_write_fdset))
					imove_ready_request(current);
				else
					IMOVE_FD_SET(current->data_fd, &block_write_fdset);
				break;
			case PIPE_READ:
				if (FD_ISSET(current->data_fd, &block_read_fdset))
					imove_ready_request(current);
				else
					IMOVE_FD_SET(current->data_fd, &block_read_fdset);
				break;
			case MSG_READ:
				if (FD_ISSET(current->fd, &block_read_fdset))
					imove_ready_request(current);
				else
					IMOVE_FD_SET(current->fd, &block_read_fdset);
				break;
			default:
				if (FD_ISSET(current->fd, &block_write_fdset))
					imove_ready_request(current);
				else
					IMOVE_FD_SET(current->fd, &block_write_fdset);
				break;
				
		}
	}
}

/*****
从连接套接字读取数据
params:
	req: [IN] request block
return:
	0: err
	1: success and need handle after
	-1: block
*****/
static int imove_read_msg(IM_ST_request *req)
{
	int ret = 0;
	int bytes_rd = 0;
	
	if (req == NULL)
		goto OUT;

	if (req->fd <=0 )
		goto OUT;

	bytes_rd = read(req->fd, req->client_stream, sizeof(req->client_stream));
	if (bytes_rd == 0)	// read end-of-file, for tcp conn, is closed by peer
	{
		ret = 0;
		goto OUT;
	}
	else if (bytes_rd < 0)
	{
		 if (errno == EWOULDBLOCK || errno == EAGAIN)
 			ret = -1;        /* read blocked */
		else if(errno == EINTR)
			ret = 1;
		else
			ret = 0;
	}
	else
	{
		req->status = MSG_HANDLE;
		ret = 1;
	}
	
OUT:
	return ret;
}

/****
处理连接请求
params:
	server_s:[in]  socket, return by listen();
return:
	none
***/
static void imove_process_request(int server_s)
{
	int retval = 0;
	IM_ST_request *current = NULL, *tailer;
	
	assert(server_s > 0);
	
	if (pending_requests)
	{
		imove_get_request(server_s);
		pending_requests = 0;
	}

	time(&current_time);
	current = request_ready_list;
	while (current)
	{
		
		if (current_time > current->time_last)
		{
			current->status = TIME_OUT;
		}
		switch(current->status)
		{
			case MSG_WRITE:
				retval = imove_send_msg2client(current);
				break;
			case PIPE_WRITE:
				break;
			case MSG_READ:
				retval = imove_read_msg(current);
				break;
			case MSG_HANDLE:
				retval = imove_handle_receive_msg(current);
				break;
			case DONE:
				retval = 0;
				break;
			case TIME_OUT:
				retval = 0;
				break;
		}

		switch(retval)
		{
			case -1:
				tailer = current;
				current = current->next;
				imove_block_request(tailer);
				break;
			case 0:
				current->status = DONE;
				tailer = current;
				current = current->next;
				imove_free_request(tailer);
				break;
			case 1:
				current = current->next;
				break;
			case -2:
				tailer = current;
				current = current->next;
				imove_free_request(tailer);
				break;
			default:
			//	WARN("Unknown retval in proccess_request  status:%d retval:%d\n",
			//			current->status, retval);
				break;
		}
	}
}

/****
管理日志文件,当日志文件的大小超过10K时，保存为备份的日志文件，并创建新的日志文件
params:
	logfile_path:	日志文件路径
	bk_file_path:	备份的日志文件路径
	cur_tm:		当前系统时间
return:
	none
****/
static void imove_manage_logfile(char *logfile_path, char *bk_file_path, time_t cur_tm)
{
#define MAXSIZE_LOGFILE		5*1024		// 5K 
#define CHECK_INTERVAL		1800		// 30 mineus

	struct stat st;
	int ret = 0;
	char copyfile[128] = {0};
	char clearfile[56] = {0};
	static time_t last_tm;

	if (cur_tm - last_tm < CHECK_INTERVAL)
		return;
	
	if (logfile_path == NULL || bk_file_path == NULL)
	{
		p_debug("input logfile_path is NULL\n");
		return;
	}

	ret = lstat(logfile_path, &st);
	if (ret < 0)
	{
		p_debug("logfile:%s errno:%d\n", logfile_path, errno);
	}

	if (st.st_size >= MAXSIZE_LOGFILE)
	{
		snprintf(copyfile, sizeof(copyfile), "cp %s %s", logfile_path, bk_file_path);
		snprintf(clearfile, sizeof(clearfile), "echo \"\" > %s", logfile_path);
		system(copyfile);
		system(clearfile);
	}

	last_tm = cur_tm;
	return;
}


/***
circle handle all request
params:
	server_s:[in] unix socket 
return:
	none
***/
void imove_select_loop(int server_s)
{
#define REQUEST_TIMEOUT 60
	assert(server_s > 0);
	FD_ZERO(&block_read_fdset);
    	FD_ZERO(&block_write_fdset);

	 req_timeout.tv_sec = REQUEST_TIMEOUT;
	 req_timeout.tv_usec = 01;

	 max_fd = -1;

	 while (1)
	 {
	 	if (sigchld_flag)
            		sigchld_run();

		if (sigterm_flag) 
			sigterm_stage2_run();
		
		if (request_block_list)
		{
			imove_updata_block_request();
		}

		imove_process_request(server_s);

		imove_manage_logfile(ERROR_LOG_FILE, ERROR_LOG_FILE_BK, current_time);

		IMOVE_FD_SET(server_s, &block_read_fdset);

		req_timeout.tv_sec = request_ready_list ? 0 : REQUEST_TIMEOUT;

		if (select(max_fd + 1, &block_read_fdset, &block_write_fdset, NULL, 
				(request_ready_list || request_block_list ? &req_timeout : NULL)) < 0)
		{
			if (errno == EINTR)
				continue;
			else if (errno != EBADF)
			{
				DIE("select");
			}
		}
		
		time(&current_time);
		if (FD_ISSET(server_s, &block_read_fdset))
			pending_requests = 1;	
	 }
}

/***
将日志写入/dev/null设备
params:
	none
return:
	none
***/
void imove_open_null_dev(void)
{
	 devnullfd = open("/dev/null", 0);

	 /* make STDIN and STDOUT point to /dev/null */
	 if (devnullfd == -1) 
	{
        	DIE("can't open /dev/null");
    	}

	if (dup2(devnullfd, STDIN_FILENO) == -1) 
	{
        	DIE("can't dup2 /dev/null to STDIN_FILENO");
    	}

    	if (dup2(devnullfd, STDOUT_FILENO) == -1) 
	{
        	DIE("can't dup2 /dev/null to STDOUT_FILENO");
    	}
	 
}

int main(int agrc, char *argv[])
{
	int server_s =0;

	imove_open_null_dev();

	imove_open_logs();
	
	server_s = imove_create_unix_socket(THE_UNIX_PATH);
	if (server_s < 0)
	{
		WARN("imove msg server create server sock failed\n");
		goto out;
	}
	
	imove_init_signals();
	
	imove_select_loop(server_s);
out:
	if (server_s > 0)
	{
		close(server_s);
		server_s = -1;
	}
}
