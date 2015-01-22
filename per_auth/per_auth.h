/************************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-11-4
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
#  0.1.0.1    |lishengming       |2014-11-4      |Trial Version
#  0.1.0.2    |lishengming       |2014-12-12     |Add serval functions
#
*************************************************************************/


#ifndef __PER_AUTH_H__
#define __PER_AUTH_H__

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
#include <sys/time.h>
#include <uci.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

/******************************************************************************
 *                                 MACRO                                      *
 ******************************************************************************/
#define IM_SYSTEM_TIME_OUT              20  //unit:second
#define PERAUTH_OBJ_NAME_LEN            64  //length of object name
#define GROUP_MAX_OBJECT_COUNT          16  //max count of object in one group
#define MAC_STR_LEN                     17  //length of mac
#define PERAUTH_GRP_NAME_LEN            64  //length of group name
#define MAX_GROUP_COUNT                 8   //max count of group
#define MAX_SESSION_COUNT_OF_OBJ        16  //max session count of one object
#define LEN_OF_SESSIONID                64  //legnth of session id 
#define DEFAULT_GROUP_CNT_INDEX         4   //have 4 groups default

/* per_auth lib debug macro. */
#define IM_PERAUTH_LOG_ERR              0x00000001
#define IM_PERAUTH_LOG_WARN             0x00000002
#define IM_PERAUTH_LOG_INFO             0x00000004
#define IM_PERAUTH_LOG_TRACE            0x00000008

/* Default, print the first three levels log */
#define IM_PERAUTH_LOG_FLAG             0x00000007

#define IM_PERAUTH_LOG(IMLogFlag, IMLogLevel, fmt, args...) do { \
    if ((IMLogFlag) & (IMLogLevel)) { \
        FILE *fp = fopen("/dev/console", "w"); \
    	if (fp) { \
            fprintf(fp, "[IM_PERAUTH][%s]-%d ", __FUNCTION__, __LINE__); \
    		fprintf(fp, fmt, ## args); \
    		fprintf(fp, "\n"); \
    		fclose(fp); \
    	} \
    } \
} while (0)

#define IM_MAX_PWD_LEN          64
#define IM_ROOT_PWD             "/etc/root_pwd"
#define IM_PER_AUTH_CONF        "/etc/config/per-auth"

/* config module example

    config group-0                      //the first(index 0) group
        option name 'root'              //group name
        option id '1'                   //group id
        option type '1'                 //group type,1,user group;2,process group
        option permissions '7'          //group permissions

    config 1-0                          //the first(index 0) object in root group (group id-object serial num)
        option name 'imove'             //object name,such as hostname, process name
        option index '1'                //object index in group
        option session '68686868'       //object session associated with name,such as session id
        option mac '11:22:33:44:55:66'  //object mac addr

    config group-1                      //the second group
        option name 'home'
        option id '2'
        option type '1'
        option permissions '5'

    config group-2                      //the third group
        option name 'basic'
        option id '8'
        option type '2'                 //group type,1,user group;2,process group
        option permissions '7'

    
    config 8-0                          //the first object in basic group
        option name 'mr2fc'             //object name,such as process name
        option index '1'
        option session '1234'           //session id,such as app id
        option mac ''                   //process not have mac,may be used as other
*/

/* Config model and options */
#define CONFIG_NAME         "per-auth"
#define K_OBJ_NAME          "name"
#define K_OBJ_INDEX         "index"
#define K_OBJ_SESS          "session"
#define K_OBJ_MAC           "mac"

#define K_GROUP             "group"
#define K_GROUP_ID          "id"
#define K_GROUP_NAME        "name"
#define K_GROUP_PERMS       "permissions"
#define K_GROUP_TYPE        "type"

#define DEFAULTE_ROOT_MAC   "ff:ff:ff:ff:ff:ff"

/* Bit operats */
#define IM_BIT_SET(Value, BitNo)    ((Value) != 1UL << (BitNo))  
#define IM_BIT_CLR(Value, BitNo)    ((Value) &= ~(1UL << (BitNo)))

/* Permissons bit flag */
#define IM_PERAUTH_FLAG_INTERNET_ACC    0x00000001  /* interner access */
#define IM_PERAUTH_FLAG_ROUTER_CTRL     0x00000002  /* router control */
#define IM_PERAUTH_FLAG_ROUTEDISC_ACC   0x00000004  /* router disc access */
#define IM_PERAUTH_FLAG_ROUTEDISC_CTRL  0x00000008  /* router disc control */
#define IM_PERAUTH_FLAG_PRIDISC_ACC     0x00000010  /* private disc access */
#define IM_PERAUTH_FLAG_PRIDISC_CTRL    0x00000020  /* private disc ctrol */

/* Internet access permission */
#define IM_GET_PER_INTERNET_ACC(Flags)  ((Flags) & IM_PERAUTH_FLAG_INTERNET_ACC)
#define IM_SET_PER_INTERNET_ACC(Flags)  ((Flags) |= IM_PERAUTH_FLAG_INTERNET_ACC)
#define IM_CLR_PER_INTERNET_ACC(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_INTERNET_ACC)

/* Router control permissson */
#define IM_GET_PER_ROUTER_CTRL(Flags)  ((Flags) & IM_PERAUTH_FLAG_ROUTER_CTRL)
#define IM_SET_PER_ROUTER_CTRL(Flags)  ((Flags) |= IM_PERAUTH_FLAG_ROUTER_CTRL)
#define IM_CLR_PER_ROUTER_CTRL(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_ROUTER_CTRL)

/* Router disc access permission */
#define IM_GET_PER_ROUTEDISC_ACC(Flags)  ((Flags) & IM_PERAUTH_FLAG_ROUTEDISC_ACC)
#define IM_SET_PER_ROUTEDISC_ACC(Flags)  ((Flags) |= IM_PERAUTH_FLAG_ROUTEDISC_ACC)
#define IM_CLR_PER_ROUTEDISC_ACC(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_ROUTEDISC_ACC)

/* Router disc control permisssion */
#define IM_GET_PER_ROUTEDISC_CTRL(Flags)  ((Flags) & IM_PERAUTH_FLAG_ROUTEDISC_CTRL)
#define IM_SET_PER_ROUTEDISC_CTRL(Flags)  ((Flags) |= IM_PERAUTH_FLAG_ROUTEDISC_CTRL)
#define IM_CLR_PER_ROUTEDISC_CTRL(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_ROUTEDISC_CTRL)

/* Private disc access permission */
#define IM_GET_PER_PRIDISC_ACC(Flags)  ((Flags) & IM_PERAUTH_FLAG_PRIDISC_ACC)
#define IM_SET_PER_PRIDISC_ACC(Flags)  ((Flags) |= IM_PERAUTH_FLAG_PRIDISC_ACC)
#define IM_CLR_PER_PRIDISC_ACC(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_PRIDISC_ACC)

/* Private disc control permission */
#define IM_GET_PER_PRIDISC_CTRL(Flags)  ((Flags) & IM_PERAUTH_FLAG_PRIDISC_CTRL)
#define IM_SET_PER_PRIDISC_CTRL(Flags)  ((Flags) |= IM_PERAUTH_FLAG_PRIDISC_CTRL)
#define IM_CLR_PER_PRIDISC_CTRL(Flags)  ((Flags) &= ~IM_PERAUTH_FLAG_PRIDISC_CTRL)

#ifndef ENABLE
#define ENABLE      1
#endif

#ifndef DISENABLE
#define DISENABLE   0
#endif

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
 *                                 ENUM                                       *
 ******************************************************************************/
/* permission types */
typedef enum
{
    PER_INTERNET_ACC    = 1,
    PER_ROUTER_CTRL     = 2,
    PER_ROUTERDISC_ACC  = 3,
    PER_ROUTERDISC_CTRL = 4,
    PER_PRIDISC_ACC     = 5,
    PER_PRIDISC_CTRL    = 6,
}enPermType;

/* object types */
typedef enum
{
    OBJ_TYPE_USER       = 1,
    OBJ_TYPE_PROCESS    = 2,
}enObjType;

/* user types, four user groups:root,home,visitor,black */
typedef enum
{
    USR_TYPE_ROOT       = 1,    // all permissions 
    USR_TYPE_HOME       = 2,    // internet access, router disc access, router disc control
    USR_TYPE_VISITOR    = 3,    // internet access
    USR_TYPE_BLACK      = 4,    // nothing
}enDefUsrType;

/* process types */
typedef enum
{
    PRC_TYPE_BASIC       = 1,
    PRC_TYPE_AUTHORIZE   = 2,
}enProcessType;

/******************************************************************************
 *                                STRUCT                                      *
 ******************************************************************************/
/* permission info */
typedef struct permission_info
{
    UINT8 ucInternetAccEnable;
    UINT8 ucRouterCtrlEnable;
    UINT8 ucRouterDiscAccEnable;
    UINT8 ucRouterDiscCtrlEnable;
    UINT8 ucPrivateDiscAccEnable;
    UINT8 ucPrivateDiscCtrlEnable;
}stPermsInfo, *pstPermsInfo;

/* object info */
typedef struct auth_obj_info
{
    SINT8  szName[PERAUTH_OBJ_NAME_LEN + 1]; //object name
    UINT32 nIndex;                           //object index
    SINT8  szSession[LEN_OF_SESSIONID + 1];  //sessions in object
    SINT8  szMacStr[MAC_STR_LEN + 1];
}stAuthObjInfo, *pstAuthObjInfo;

typedef struct group_info
{
    SINT8 szName[PERAUTH_GRP_NAME_LEN + 1];             //group name
    UINT32 nId;                                         //group id
    UINT8 ucType;                                       //goup type:user or process
    UINT32 nPermissons;                                 //permissions
    stPermsInfo stPermissons;                           //details of permissions
    UINT32 nObjCnt;                                     //object count of group
    stAuthObjInfo stObjInfo[GROUP_MAX_OBJECT_COUNT];    //object info in group
}stGrpDetailInfo, *pstGrpDetailInfo;

typedef struct group_cotent
{
    SINT8 szName[PERAUTH_GRP_NAME_LEN + 1];
    UINT32 nId;
}stGroupCotent, *pstGroupCotent;

typedef struct group_brief
{
    UINT32 nCount;
    stGroupCotent stGrpCot[MAX_GROUP_COUNT];
}stGroupBrief, *pstGroupBrief;

typedef struct obj_cotent
{
    SINT8 szGrpName[PERAUTH_GRP_NAME_LEN + 1];  //group name
    SINT8 szName[PERAUTH_OBJ_NAME_LEN + 1];     //object name
    SINT8 szMacStr[MAC_STR_LEN + 1];            //object mac
}stObjCotent, *pstObjCotent;

typedef struct obj_sample
{
    UINT32 nCount;  //object count
    stObjCotent stObjCot[MAX_GROUP_COUNT * GROUP_MAX_OBJECT_COUNT]; //object content
}stObjSample, *pstObjSample;

typedef struct obj_brief
{
    SINT8 szGrpName[PERAUTH_GRP_NAME_LEN + 1];
    UINT32 nGrpId;
    UINT32 nPermissons;
    SINT8  szName[PERAUTH_OBJ_NAME_LEN + 1]; //object name
    UINT32 nIndex;                           //object index
    SINT8  szSession[LEN_OF_SESSIONID + 1];  //sessions in object
    SINT8  szMacStr[MAC_STR_LEN + 1];
} stObjBrief, *pstObjBrief;

/******************************************************************************
 *                               FUNCTION                                     *
 ******************************************************************************/
 /*******************************************************************************
 * Function:
 *    SINT32 IM_System(SINT8 *pCommand, SINT32 iPrintFlag)
 * Description:
 *    A rewrite of system
 * Parameters:
 *    pCommand     (IN) String of command 
 *    iPrintFlag   (IN) 1,print the command;0,do not
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_System(SINT8 *pCommand, SINT32 iPrintFlag);

/*******************************************************************************
 * Function:
 *    SINT32 IM_RootPwdSet(const SINT8 *pPwd)
 * Description:
 *    Root password set
 * Parameters:
 *    pPwd     (IN) New password 
 * Returns:
 *    0,success;others,error
 *******************************************************************************/
SINT32 IM_RootPwdSet(const SINT8 *pPwd);

/*******************************************************************************
 * Function:
 *    SINT32 IM_RootPwdGet(SINT8 *pPwd)
 * Description:
 *    Get root password
 * Parameters:
 *    pPwd     (OUT) Root password 
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_RootPwdGet(SINT8 *pPwd);

/*******************************************************************************
 * Function:
 *    SINT32 IM_RootPwdAuth(SINT8 *pPwd)
 * Description:
 *    Root password auth
 * Parameters:
 *    pPwd     (IN) Login password 
 * Returns:
 *    0:auth pass;1,auth failed;others,error
 *******************************************************************************/
SINT32 IM_RootPwdAuth(SINT8 *pPwd);

/*******************************************************************************
 * Function:
 *    SINT32 IM_ApplyInternetAcc(const SINT8 *pMacStr, UINT8 ucPerValue)
 * Description:
 *    Apply internet access permission
 * Parameters:
 *    pMacStr      (IN) Mac of client,length should be 17 
 *    ucPerValue   (IN) Permission value,should be 0 or 1
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_ApplyInternetAcc(const SINT8 *pMacStr, UINT8 ucPerValue);

/*******************************************************************************
 * Function:
 *    SINT32 IM_CheckPermBySessionCmd(const SINT8 *pSession, UINT32 nCmd)
 * Description:
 *    Check object have permission to execute the cmd or not
 * Parameters:
 *    pSession     (IN) Session of object 
 *    nCmd         (IN) Cmd index
 * Returns:
 *    0:no permission;1,have permission,others,err
 *******************************************************************************/
SINT32 IM_CheckPermBySessionCmd(const SINT8 *pSession, UINT32 nCmd);

/*******************************************************************************
 * Function:
 *    stPermsInfo *IM_GetObjPermBySess(const SINT8 *pSession)
 * Description:
 *    get object permissions by session id
 * Parameters:
 *    pSession     (IN) Session of object 
 * Returns:
 *    NULL,err;others,permission info(struct stPermsInfo, should free after get)
 *******************************************************************************/
stPermsInfo *IM_GetObjPermBySess(const SINT8 *pSession);

/*******************************************************************************
 * Function:
 *    stObjBrief *IM_GetObjBrief(const SINT8 *pMacStr)
 * Description:
 *    get object info by mac
 * Parameters:
 *    pMacStr     (IN) Mac of object 
 * Returns:
 *    NULL,err;others,object info(struct stObjBrief, should free after get)
 *******************************************************************************/
stObjBrief *IM_GetObjBrief(const SINT8 *pMacStr);

/*******************************************************************************
 * Function:
 *    SINT32 IM_AddGrp(const SINT8 *pGrpName, UINT8 ucGrpType, UINT32 nPermissions)
 * Description:
 *    Add a new permisson auth group
 * Parameters:
 *    pGrpName     (IN) Group name 
 *    ucGrpType    (IN) Group type,1 for user;2 for process
 *    nPermissions (IN) Permissions of the group 
 * Returns:
 *    > 0:group id;-2,same group already exists;others,err
 *******************************************************************************/
SINT32 IM_AddGrp(const SINT8 *pGrpName, UINT8 ucGrpType, UINT32 nPermissions);

/*******************************************************************************
 * Function:
 *    SINT32 IM_DelGrp(UINT32 nGrpId)
 * Description:
 *    Delete a group
 * Parameters:
 *    nGrpId     (IN) Group id 
 * Returns:
 *    0:success,others,err
 *******************************************************************************/
SINT32 IM_DelGrp(UINT32 nGrpId);

/*******************************************************************************
 * Function:
 *    SINT32 IM_AddGrp(const SINT8 *pGrpName, UINT8 ucGrpType, UINT32 nPermissions)
 * Description:
 *    Add a new permisson auth group
 * Parameters:
 *    nGrpId       (IN) Group id
 *    pGrpName     (IN) Group name 
 *    nPermissions (IN) Permissions of the group 
 * Returns:
 *    0:success,others,err
 *******************************************************************************/
SINT32 IM_SetGrp(UINT32 nGrpId, const SINT8 *pGrpName, UINT32 nPermissions);

/*******************************************************************************
 * Function:
 *    SINT32 IM_SessBindMac(const SINT8 *pSession, const SINT8 *pMacStr)
 * Description:
 *    Bind a session to object(mac),when a session connect,should bind the session
 *    first,and then could get permission by the session id
 * Parameters:
 *    pSession     (IN) Session id
 *    pMacStr      (IN) Mac string 
 * Returns:
 *    0:success,others,err
 *******************************************************************************/
SINT32 IM_SessBindMac(const SINT8 *pSession, const SINT8 *pMacStr);

/*******************************************************************************
 * Function:
 *    SINT32 IM_SessUnbindMac(const SINT8 *pMacStr, const SINT8 *pSession)
 * Description:
 *    Unbind session to object(mac), when a session disconnect,should unbind
 *    the session
 * Parameters:
 *    pSession     (IN) Session id
 *    pMacStr      (IN) Mac string 
 * Returns:
 *    0:success,others,err
 *******************************************************************************/
SINT32 IM_SessUnbindMac(const SINT8 *pMacStr, const SINT8 *pSession);

/*******************************************************************************
 * Function:
 *    SINT32 IM_AllSessUnbindMac(const SINT8 *pMacStr)
 * Description:
 *    Unbind all sessions binded to object(mac)
 * Parameters:
 *    pMacStr      (IN) Mac string 
 * Returns:
 *    0:success,others,err
 *******************************************************************************/
SINT32 IM_AllSessUnbindMac(const SINT8 *pMacStr);

/*******************************************************************************
 * Function:
 *    SINT32 IM_AddObj2Grp(UINT32 nGrpId, const SINT8 *pObjName, const SINT8 *pMacStr)
 * Description:
 *    Add a object(mac) to group
 * Parameters:
 *    nGrpId       (IN) Group id
 *    pObjName     (IN) Object name
 *    pMacStr      (IN) Mac string 
 * Returns:
 *    0:success;-2,object already exists in one group;others,err
 *******************************************************************************/
SINT32 IM_AddObj2Grp(UINT32 nGrpId, const SINT8 *pObjName, const SINT8 *pMacStr);

/*******************************************************************************
 * Function:
 *    SINT32 IM_DelObjFromGrp(const SINT8 *pMacStr)
 * Description:
 *    Delete a object(mac) from group
 * Parameters:
 *    pMacStr      (IN) Mac string of object 
 * Returns:
 *    0:success;-2,odject does not exist;others,err
 *******************************************************************************/
SINT32 IM_DelObjFromGrp(const SINT8 *pMacStr);

/*******************************************************************************
 * Function:
 *    stGroupBrief *IM_GetGrpBrief(void)
 * Description:
 *    Get groups info
 * Parameters:
 *    void 
 * Returns:
 *    NULL:err,others,groups info(struct stGroupBrief, should free after get)
 *******************************************************************************/
stGroupBrief *IM_GetGrpBrief(void);

/*******************************************************************************
 * Function:
 *    stObjSample *IM_GetObjSample(void)
 * Description:
 *    Get all object sample info
 * Parameters:
 *    void 
 * Returns:
 *    NULL:err,others,object sample info(struct stObjSample, should free after get)
 *******************************************************************************/
stObjSample *IM_GetObjSample(void);

/*******************************************************************************
 * Function:
 *    stGrpDetailInfo *IM_GetObjsInfoInGroup(UINT32 nId)
 * Description:
 *    Get objects info in a group
 * Parameters:
 *    nId      (IN) Group id
 * Returns:
 *    NULL:err,others,groups info(struct stGrpDetailInfo, should free after get)
 *******************************************************************************/
stGrpDetailInfo *IM_GetObjsInfoInGroup(UINT32 nId);

/*******************************************************************************
 * Function:
 *    SINT32 IM_PerAuthInit(void)
 * Description:
 *    Init permission auth lib before use other functions
 * Parameters:
 *    void 
 * Returns:
 *    0:success;others,error
 *******************************************************************************/
SINT32 IM_PerAuthInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __PER_AUTH_H__ */
