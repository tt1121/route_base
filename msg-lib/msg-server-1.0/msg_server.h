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
# Revision Table
#
# Version     | Name             |Date           |Description
# ------------|------------------|---------------|-------------------
#  0.1.0.1    |lishengming       |2014-10-23     |Trial Version
#
*************************************************************************/

#ifndef __MSG_SERVER_H__
#define __MSG_SERVER_H__

#if __cplusplus
extern "C" {
#endif

/*############################## Includes ####################################*/
#include <sys/stat.h>      
#include <unistd.h>      
#include <stdio.h>      
#include <stdlib.h>      
#include <sys/socket.h>      
#include <sys/types.h>      
#include <string.h>      
#include <asm/types.h>      
#include <linux/netlink.h>      
#include <linux/socket.h>      
#include <stddef.h>   
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <msg.h>

/*############################## Macros ######################################*/

#define gettid() syscall(__NR_gettid)
  
#define RECV_TIMEOUT        30
#define THIS_MODULE         "msg_server"

/*############################## Enums ######################################*/

/*############################## Structs #####################################*/

/*############################## Prototypes ##################################*/

#if __cplusplus
}
#endif

#endif /* __MSG_SERVER_H__ */

