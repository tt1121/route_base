/************************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-10-28
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
#  0.1.0.1    |lishengming       |2014-10-28     |Trial Version
#
*************************************************************************/


#ifndef __SHM_H__
#define __SHM_H__

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <stdarg.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h> 
#include <sys/types.h> 
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

/******************************************************************************
 *                                 MACRO                                      *
 ******************************************************************************/

/* SHM lib debug macro. */
#define IM_SHM_LOG_ERR              0x00000001
#define IM_SHM_LOG_WARN             0x00000002
#define IM_SHM_LOG_INFO             0x00000004
#define IM_SHM_LOG_TRACE            0x00000008

/* Default, print the first three levels log */
#define IM_SHM_LOG_FLAG             0x00000007

#define IM_SHM_LOG(IMLogFlag, IMLogLevel, fmt, args...) do { \
    if ((IMLogFlag) & (IMLogLevel)) { \
        FILE *fp = fopen("/dev/console", "w"); \
    	if (fp) { \
            fprintf(fp, "[IM_SHM][%s]-%d ", __FUNCTION__, __LINE__); \
    		fprintf(fp, fmt, ## args); \
    		fprintf(fp, "\n"); \
    		fclose(fp); \
    	} \
    } \
} while (0)

/* Some macros in common use. */
#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define PM_SHM_NAME      "app_proc_info_shm"
#define PM_SHM_SEM_NAME  "app_proc_info_shm_sem"

/******************************************************************************
 *                                 TYPEDEF                                    *
 ******************************************************************************/

/* Integer and bool type definition. */
typedef int 		        SINT32;
typedef unsigned int        UINT32;
typedef short int 	        SINT16;
typedef unsigned short int  UINT16;
typedef char 		        SINT8;
typedef unsigned char       UINT8;
typedef unsigned char       UBOOL8;

/******************************************************************************
 *                               FUNCTION                                     *
 ******************************************************************************/

/*******************************************************************************
 * Function:
 *    SINT32 IM_PosixShmCreat(UINT32 nShmSize, const SINT8 *pShmName)
 * Description:
 *    Creat share memory and init
 * Parameters:
 *    nShmSize (IN) Size of share memory 
 *    pShmName (IN) Name of share memory
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmCreat(UINT32 nShmSize, const SINT8 *pShmName);

/*******************************************************************************
 * Function:
 *    SINT32 IM_PosixShmDestroy(const SINT8 *pShmName, const SINT8 *pShmSemName)
 * Description:
 *    Destroy share memory
 * Parameters:
 *    pShmName    (IN) Name of share memory
 *    pShmSemName (IN) Name of semaphore 
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmDestroy(const SINT8 *pShmName, const SINT8 *pShmSemName);

/*******************************************************************************
 * Function:
 *    SINT32 IM_PosixShmRead(const SINT8 *pShmSemName, const SINT8 *PShmName, 
 *          SINT8 *pRetBuf, UINT32 nReadLen, UINT32 nOffset)
 * Description:
 *    Read content of share memory
 * Parameters:
 *    pShmSemName (IN)  Name of semaphore 
 *    pShmName    (IN)  Name of share memory
 *    pRetBuf     (OUT) Buf of read
 *    nReadLen    (IN)  Length of want to read
 *    nOffset     (IN)  Offset of share memory
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmRead(const SINT8 *pShmSemName, const SINT8 *PShmName, 
    SINT8 *pRetBuf, UINT32 nReadLen, UINT32 nOffset);

/*******************************************************************************
 * Function:
 *    SINT32 IM_PosixShmWrite(const SINT8 *pShmSemName, const SINT8 *pShmName, 
 *          SINT8 *pFromBuf, UINT32 nWriteLen, UINT32 nOffset)
 * Description:
 *    Write content to share memory
 * Parameters:
 *    pShmSemName (IN)  Name of semaphore 
 *    pShmName    (IN)  Name of share memory
 *    pFromBuf    (IN)  Buf of write content
 *    nWriteLen   (IN)  Length of content want to write
 *    nOffset     (IN)  Offset of share memory
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmWrite(const SINT8 *pShmSemName, const SINT8 *pShmName, 
    SINT8 *pFromBuf, UINT32 nWriteLen, UINT32 nOffset);

/*******************************************************************************
 * Function:
 *    SINT32 IM_PosixShmSemCreat(const SINT8 *pShmSemName) 
 * Description:
 *    Creat semaphore
 * Parameters:
 *    pShmSemName (IN)  Name of semaphore 
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmSemCreat(const SINT8 *pShmSemName);

/*******************************************************************************
 * Function:
 *    IM_PosixShmSemDestroy(const SINT8 *pShmSemName) 
 * Description:
 *    Destroy semaphore
 * Parameters:
 *    pShmSemName (IN)  Name of semaphore 
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PosixShmSemDestroy(const SINT8 *pShmSemName);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __SHM_H__ */
