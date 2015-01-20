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

void server_msg_prcs_task(void)
{
    int ret = 0;
    char *p_msg = NULL;
    int time_out = RECV_TIMEOUT;
    int acc_fd = -1;
    char *send_buf = NULL;
    
    g_unix_socket = IM_DomainServerInit(THIS_MODULE);
    while(1)
    {
        acc_fd = IM_ServerAcceptClient(g_unix_socket);
        ret = IM_MsgReceive(acc_fd, &p_msg, &time_out);
        
        if (ret < 0)
        {
            printf("[%s]-%d msg receive failed acc_fd = %d!\n", __FUNCTION__, __LINE__, acc_fd);
            goto bad_msg;
        }
        
        IM_MsgPrintf((void *)p_msg, "message from client module", ret, 1);

        //TODO
        /* msg process and reply */
        /* for example: while length of msg recieved is more than 10, send reply to client*/
        //if (ret > 10)
        {
            send_buf = (char *)malloc(ret);
            if (!send_buf)
            {
                printf("[%s]-%d malloc failed!\n", __FUNCTION__, __LINE__);
            }
            memset(send_buf, 0, ret);
            memcpy(send_buf, p_msg, ret);
            IM_MsgPrintf((void *)send_buf, "reply message to client module", ret, 2);
            ret = IM_MsgSend(acc_fd, send_buf, ret);

            if (ret != 0)
            {
                printf("[%s]-%d msg send failed with %d!\n", __FUNCTION__, __LINE__, ret);
            }
        }

bad_msg:
    IM_FREE(p_msg);
    IM_FREE(send_buf);
    IM_DomainServerDeinit(acc_fd);
    continue;
    }
    
    IM_DomainServerDeinit(g_unix_socket);
    printf("[%s]-%d cloud_msg_prcs_task quit!\n", __FUNCTION__, __LINE__);
    
    return;
}

int main(int argc, char *argv[])
{
    int rslt = 0;
    pthread_t tid_server_msg;

    /* 接收消息的处理线程 */
    if (0 != (rslt = pthread_create(&tid_server_msg, NULL, (void *)server_msg_prcs_task, NULL)))
    { 
        printf("Create server msg prcs thread failed!");
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
    printf("msg server main task quit!\n");
    return rslt;
}
