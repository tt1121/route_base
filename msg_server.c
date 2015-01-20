/************************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-10-23
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


/*############################## Includes ####################################*/
#include "msg_server.h"

/*############################## Global Variable #############################*/
int g_unix_socket = -1; 

/*############################## Functions ###################################*/

void sighand(int signo)
{
    p_debug("Thread %u in signal handler", (unsigned int )pthread_self());  
}

void server_msg_prcs_task(void)
{
    uint8_t ret = 0;
    char *p_msg = NULL;
    int time_out = RECV_TIMEOUT;
    int acc_fd = -1;
    char cmd_buf[1024] = {0};
	JObj *rpc_json = NULL;
	uint16_t cmd = 0;
	uint16_t sessionid = 0;
	Thread_pool *consume_pool = NULL; 
	Thread_pool *unconsume_pool = NULL;
	JObj *header_json;
	consume_pool = pool_init(CONSUME_THREAD_COUNT);
	unconsume_pool = pool_init(UNCONSUME_THREAD_COUNT);
    header_info header;
	thread_info threadStatus;
	memset(&header,0,sizeof(header_info));
	memset(&threadStatus,0,sizeof(thread_info));
	threadStatus.thread_cancel_flag = 0;
	threadStatus.complete_file_number = 0;
	threadStatus.total_file_number =0;
	
    g_unix_socket = IM_DomainServerInit(THIS_MODULE);
	IM_PerAuthInit();
	struct sigaction actions;	
	memset(&actions, 0, sizeof(actions));	 
	sigemptyset(&actions.sa_mask);		 
	actions.sa_flags = 0;   
	actions.sa_handler = sighand;  
	sigaction(SIGALRM, &actions, NULL); 
    while(1)
    {
        acc_fd = IM_ServerAcceptClient(g_unix_socket);
		p_debug("acc_fd = %d",acc_fd);
        ret = IM_MsgReceive(acc_fd, &p_msg, &time_out);
		p_debug("DM receive p_msg = %s",p_msg);
        if (ret < 0)
        {
            p_debug("msg receive failed acc_fd = %d!",acc_fd);
			if(p_msg != NULL)
				IM_FREE(p_msg);
            continue;
        }
	    if(p_msg != NULL)
	    {	
	        memset(cmd_buf,0,1024);
			strcpy(cmd_buf,p_msg);
			IM_FREE(p_msg);
			p_debug("server cmd_buf = %s",cmd_buf);
            #ifdef THREADS_POOL_ENABLE 
		    if(cmd_buf != NULL&&strstr(cmd_buf,"{")&&strstr(cmd_buf,"}"))
		    {
				rpc_json = JSON_PARSE(cmd_buf);
				if(is_error(rpc_json))
				{
				  p_debug("### error:post data is not a json string");
				  continue;
				}
				header_json = JSON_GET_OBJECT(rpc_json,"header");
				header.cmd = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"cmd"),int);
				p_debug("header.cmd = %d",JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"cmd"),int));
				header.ver = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"ver"),int);
				header.seq = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"seq"),int);
				header.device = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"device"),int);
				header.appid = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"appid"),int);
				header.code = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"code"),int);
				header.code =0;
				strcpy(header.sessionid,JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"sessionid"),string));
				strcpy(header.sign,JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"sign"),string));

				if(header.cmd == FN_FILE_COPY_FILE_DIR || header.cmd == FN_FILE_MOVE_FILE_DIR || header.cmd == FN_FILE_RM_FILE_DIR)//access to consume pool
				{
				   p_debug("access to consume_pool");
		           pool_add_worker(consume_process,rpc_json,&acc_fd,&header,consume_pool,&threadStatus);
				}
				else
				{
				   p_debug("access to unconsume_pool");
		           pool_add_worker(unconsume_process,rpc_json,&acc_fd,&header,unconsume_pool,&threadStatus);
				}
			}else{
			   p_debug("input data is invalid");
               continue;
			}
		#else 
		    char retstr[1024*5] = {0};
		    if(cmd_buf != NULL&&strstr(cmd_buf,"{")&&strstr(cmd_buf,"}"))
		    {
		       rpc_json=JSON_PARSE(cmd_buf); 
			   if(is_error(rpc_json))
			   {
				 p_debug("### error:post data is not a json string");
				 strcpy(retstr,"input data is invalid");
			   }else{
					header_json = JSON_GET_OBJECT(rpc_json,"header");
					header.cmd = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"cmd"),int);
					p_debug("header.cmd = %d",JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"cmd"),int));
					header.ver = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"ver"),int);
					header.seq = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"seq"),int);
					header.device = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"device"),int);
					header.appid = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"appid"),int);
					header.code = JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"code"),int);
					header.code = 0;
					strcpy(header.sessionid,JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"sessionid"),string));
					strcpy(header.sign,JSON_GET_OBJECT_VALUE(JSON_GET_OBJECT(header_json,"sign"),string));
                    api_process(rpc_json,retstr,&header);
				    p_debug("server retstr= %s",retstr);
			   }
			}
			else{
			   p_debug("input data is invalid");
               strcpy(retstr,"input data is invalid");
			}
            ret = IM_MsgSend(acc_fd, retstr, strlen(retstr));
            if (ret != 0)
            {
                p_debug("msg send failed with %d!",ret);
            }
			IM_DomainServerDeinit(acc_fd);
		#endif
		}else{
		    char emp_ret_str[256] = {0};
			strcpy(emp_ret_str,MSG_SERVER_EMPTY_RET);
			p_debug("acc_fd3 = %d",acc_fd);
			IM_DomainServerDeinit(acc_fd);
		} 
    }
    pool_destory(consume_pool);
	pool_destory(unconsume_pool);
    IM_DomainServerDeinit(g_unix_socket);
    p_debug("cloud_msg_prcs_task quit!");
    return;
}

FILE *f_serial = NULL;

int main(int argc, char *argv[])
{
    int rslt = 0;
    pthread_t tid_server_msg;
    /* 云通信模块发过来的消息的处理线程 */
    if (0 != (rslt = pthread_create(&tid_server_msg, NULL, (void *)server_msg_prcs_task, NULL)))
    { 
       p_debug("Create server msg prcs thread failed!");
	   fclose(f_serial);
	   system("echo \"failed!\" >> /dev/console");
        rslt = -1;
        goto quit;
    }
    pthread_detach(tid_server_msg);

    /* forever,可做异常退出或其他处理 */
    do
    {
        sleep(3);
    }
    while(1);

quit:
    p_debug("msg server main task quit!");
    return rslt;
}
