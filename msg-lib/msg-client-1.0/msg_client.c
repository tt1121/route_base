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
#include "msg_client.h"

/*############################## Global Variable #############################*/

/*############################## Functions ###################################*/


int main(int argc, char *argv[])
{
    int ret = 0;
    int client_fd;
    char send_buf[2048] = {0};
    int time_out = RECV_TIMEOUT;
    char *p_msg = NULL;

    while (1)
    {
        printf("Please enter the content you want to send:\n");
        memset(send_buf, 0, sizeof(send_buf));
        fgets(send_buf, sizeof(send_buf), stdin);

        client_fd = IM_DomainClientInit(SERVER_MODULE);
        ret = IM_MsgSend(client_fd, send_buf, strlen(send_buf));
        if (ret == 0)
        {
            IM_MsgPrintf((void *)send_buf, "message to server module", strlen(send_buf), 2);
            while (1)
            {
                ret = IM_MsgReceive(client_fd, &p_msg, &time_out);
                if (MSGRET_TIMED_OUT == ret)
                {
                    printf("server_client:recieve reply from server timeout!\n");
                    break;
                }
                
                if (ret > 0)
                {
                    IM_MsgPrintf((void *)p_msg, "reply message from server module", ret, 1);
                    break;
                }

            }
            
            IM_FREE(p_msg);
            IM_DomainClientDeinit(client_fd);
            client_fd = -1;
        }
    }

    return ret;
}
