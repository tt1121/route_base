/************************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-11-7
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
# Version   | Name             |Date           |Description
# ----------|------------------|---------------|-------------------
#  1.1.0    |lishengming       |2015-01-10     |Trial Version
#
*************************************************************************/


#ifndef __PRC_MGT_H__
#define __PRC_MGT_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/procfs.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <asm/ioctls.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>

#include <msg.h>
#include <shm.h>
#include <json.h>
#include <per_auth.h>

#ifdef __cplusplus
#if __cplusplus
    extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

#define PRC_MGT_VER                 "1.1.0"
#define PRC_MGT_MODULE              "prc_mgt"

#define PM_PROC_INFO_BASE_FLIR      "/usr/prc_mgt/"
#define PM_PROC_INFO_LIST_FILE      "/usr/prc_mgt/prcs_info_bak"
#define PM_PROC_BOOT_LIST_FILE      "/usr/prc_mgt/prcs_boot_list"
#define PM_APP_IPK_TMP_NAME         "/tmp/app_tmp.ipk"
#define PM_APP_INFO_TMP_NAME        "/tmp/app_tmp.info"
#define PM_APP_WGET_LOG_FILE        "/tmp/wget.log"

/* Keys in app info file */
#define K_APP_INFO_NAME          "name"
#define K_APP_IMOVE_TYPE         "imove_type"
#define K_APP_INFO_DES           "desc"
#define K_APP_INFO_VERSION       "version"
#define K_APP_INFO_ID            "id"
#define K_APP_INFO_CONF_PATH     "conf_path"
#define K_APP_INFO_CONF_CMD      "conf_cmd"
#define K_APP_INFO_INMEM_FLAG    "in_mem"
#define K_APP_INFO_BOOT_FLAG     "boot_flag"
#define K_APP_INFO_PRC_NAME      "prc_name"

/* Key of json msg used in header */
#define K_HEAD              "header"
#define K_CMD_ID            "cmd"
#define K_VERSION_NUM       "ver"
#define K_SEQ_NUM           "seq"
#define K_DEV_TYPE          "device"
#define K_APP_ID            "appid"
#define K_RST_CODE          "code"
#define K_SESSION_ID        "sessionid"
#define K_SIGN              "sign"

/* Key of json msg used in data */
#define K_DATA              "data"
#define K_IM_TYPE           "imove_type"
#define K_OP_TYPE           "type"
#define K_APP_NAME          "name"
#define K_VERSION           "version"
#define K_APP_URL           "app_url"
#define K_APP_MD5           "app_md5"
#define K_INFO_URL          "info_url"
#define K_INFO_MD5          "info_md5"

/* Response data key */
#define K_RET_CODE          "ret_code"
#define K_RET_MSG           "ret_msg"

#define RET_CODE_SUCCESS            0
#define RET_CODE_WRONG_HEAD         -1
#define RET_CODE_WRONG_DATA         -2

#define RET_MSG_SUCC                "correct msg"
#define RET_MSG_WRONG_HEAD          "wrong head msg"
#define RET_MSG_WRONG_DATA          "wrong data msg"
#define RET_MSG_UNKNOWN             "unknown msg"

#define PM_MSG_TIMEOUT             20
#define PM_MSG_REV_TIMEOUT         (10 * 1000)

/* Definitions for some generic length and path. */
#define PROC_INFO_SHM_NUM  100
#define PROC_INFO_SHM_SIZE (PROC_INFO_SHM_NUM * sizeof(AppProcInfo)) 

/* Size definition for APP process information table's member. */
#define PM_APP_NAME_LEN        64
#define PM_CPD_NAME_LEN        64
#define PM_APP_PROCESS_LEN     64
#define PM_CONFIG_PATH_LEN     256
#define PM_CONFIG_CMD_LEN      256
#define PM_MD5_STR_LEN         64
#define PM_DOWNLOAD_URL_LEN    256
#define PM_VERSION_LEN         32
#define PM_PRC_DETECT_INTERVAL 30

#define JSON_SESSION_LEN       64
#define JSON_SIGN_LEN          64

/* macros for timer */
#if 0
#define PM_TIMER_BASE          (20 * 1000)                          //200 ms
#define PM_TIMER_PERIOD_SEC    ((1000 * 1000) / PM_TIMER_BASE)      //one second period
#define PM_TIMER_PERIOD_MIN    ((60 * 1000 * 1000) / PM_TIMER_BASE) //one minute period
#define PM_MAX_TIMERS          16
#else
#define PM_TIMER_BASE          2                          //2s
#define PM_MAX_TIMERS          16

#endif
/* APP_MGT debug macro. */
#define IM_PM_LOG_ERR              0x00000001
#define IM_PM_LOG_WARN             0x00000002
#define IM_PM_LOG_INFO             0x00000004
#define IM_PM_LOG_TRACE            0x00000008

/* Default, print the first three levels log */
#define IM_PM_LOG_FLAG             0x00000007

#define IM_PM_LOG(IMLogFlag, IMLogLevel, fmt, args...) do { \
    if ((IMLogFlag) & (IMLogLevel)) { \
        FILE *fp = fopen("/dev/console", "w"); \
    	if (fp) { \
            fprintf(fp, "[IM_PRCMGT][%s]-%d ", __FUNCTION__, __LINE__); \
    		fprintf(fp, fmt, ## args); \
    		fprintf(fp, "\n"); \
    		fclose(fp); \
    	} \
    } \
} while (0)

/* Close a file fd and set the pointer to null. */
#define IM_FCLOSE(pFd) \
    do { \
        if ((pFd) != NULL) {fclose((pFd)); (pFd) = NULL;}   \
} while (0)

#define IM_PCLOSE(pFd) \
    do { \
        if ((pFd) != NULL) {pclose((pFd)); (pFd) = NULL;}   \
} while (0)

#define IM_FREE_JSON_OBJ(ptr) \
    do { \
        if(ptr) {json_object_put(ptr); ptr = NULL;}   \
} while (0)


#ifndef TRUE
#define TRUE  1
#endif
      
#ifndef FALSE
#define FALSE 0
#endif

/******************************************************************************
 *                                STRUCT                                      *
 ******************************************************************************/

typedef struct 
{
    int iCmd;
    int iVer;
    int iSeq;
    int iDevice;
    int iAppId;
    int iCode;
    char szSession[JSON_SESSION_LEN];
    char szSign[JSON_SIGN_LEN];
}JsonHeadInfo, *pJsonHeadInfo;

/* This is the structure for APP process information table. */
typedef struct app_proc_info
{
    unsigned int    nAppId;                         //APP id
    char            cIMType;
    char            szAppName[PM_APP_NAME_LEN];     //APP name,ikp module name
    char            szDesc[PM_CPD_NAME_LEN];        //Description of app
    char            szConfPath[PM_CONFIG_PATH_LEN];
    char            szConfCmd[PM_CONFIG_CMD_LEN];
    char            szVersion[PM_VERSION_LEN];
    char            cInMemFlag;
    char            cBootFlag;
    char            szProcName[PM_APP_PROCESS_LEN]; //process name
    unsigned int    nProcId;
    unsigned int    nProcPri;
}AppProcInfo, *pAppProcInfo;

/* IPC accept FD structs. */
typedef struct IpcAcceptFdNode
{
	int iFd;
	struct IpcAcceptFdNode *pstNext;
}IpcAcceptFd;

/* IPC FD set structs. */
typedef struct
{
    int iIpcListenFd;
    IpcAcceptFd *pstIpcAcceptFdList;
    int iIpcMr2fFd;
}PmFdSet, *pPmFdSet;

typedef struct 
{
    unsigned long   ulCount;            /* 定时器当前计数 tick */
    unsigned long   ulStart;            /* 周期定时器延时启动 tick */
    unsigned long   ulPeriod;           /* 周期定时器的预定周期 tick */
    void    (*pfnTimerProc)(void *);    /* 定时器到期的处理函数 */
    void            *pArgs;             /* 处理函数的参数 */
    unsigned char   ucTimerType;        /* 定时器类型 0:一次性 1:周期性 */
    unsigned char   ucEnable;           /* 定时器是否启用 0:未启用 1:启用 */
}PmTimer;

/* APP action type definition. */
typedef enum
{
    OPERATE_TYPE_INSTALL    = 1,
    OPERATE_TYPE_UNINSTALL  = 2,
    OPERATE_TYPE_UPGRADE    = 3,
    OPERATE_TYPE_UNKNOWN    = 4,
}E_OpType;

typedef enum
{
    TYPE_IMOVE = 1,
    TYPE_OTHER = 2,
}E_IMType;

/* Download file type definition. */
typedef enum
{
    FILE_TYPE_INSTALL_PACKAGE = 1,
    FILE_TYPE_APP_INFO_FILE   = 2,
}E_DownloadFileType;

/* Timer type. */
typedef enum
{
    ONE_TIME_TIMER  = 0,
    CIRCLE_TIMER    = 1,
}E_TimerType;

/* APP operation key message. */
typedef struct
{
    E_IMType im_type;
    E_OpType action_type;
    char szUrlIpk[PM_DOWNLOAD_URL_LEN];
    char szUrlInfo[PM_DOWNLOAD_URL_LEN];    
    char szVersion[PM_VERSION_LEN];
    char szMd5Ipk[PM_MD5_STR_LEN];
    char szMd5Info[PM_MD5_STR_LEN];
    char szModName[PM_APP_NAME_LEN];        //APP name,ikp module name
    unsigned int nModId;                    //Module id,app id
}AppOpMsg;


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __PRC_MGT_H__ */
