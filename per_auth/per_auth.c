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
#
*************************************************************************/

#ifdef __cplusplus
#if __cplusplus
    extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

/******************************************************************************
 *                             INCLUDES                                       *
 ******************************************************************************/
#include "per_auth.h"

/******************************************************************************
 *                         GLOBAL VARIABLES                                   *
 ******************************************************************************/
static UINT32 g_GroupCount = 0;

static stGrpDetailInfo g_GroupInfo[MAX_GROUP_COUNT];
static UINT8 g_InitFlag = 0;
static struct uci_context *g_Ctx;

/******************************************************************************
 *                         PRIVATE FUNCTIONS                                  *
 ******************************************************************************/
static SINT32 IM_GetSystemInfo(SINT8 *pName, SINT8 *pValue, UINT32 nSize);
static void IM_DeleteSubstr(SINT8 *pStr, SINT8 *pSubstr);
static SINT32 IM_GrpCntCheck(void);
static void IM_GrpInit(stGrpDetailInfo *pstGrpInfo);
static UINT32 IM_CheckPermByCmd(UINT32 nCmd);
static SINT32 IM_GrpAndObjInfoGet(void);

/******************************************************************************
 *                               FUNCTIONS                                    *
 ******************************************************************************/
static SINT32 IM_GetSystemInfo(SINT8 *pName, SINT8 *pValue, UINT32 nSize)
{
    SINT8 szCmd[512] = {0};
    FILE *pFp = NULL;
    
    snprintf(szCmd, sizeof(szCmd) - 1, "%s", pName);
    pFp = popen(szCmd, "r");
    if (!pFp)
    {
    	return -1;
    }

	fgets(pValue, nSize, pFp);
	if (pValue[strlen(pValue)-1] == 0x0a)
		pValue[strlen(pValue)-1] = '\0';
    pclose(pFp);
    
    return 0;
}

static void IM_DeleteSubstr(SINT8 *pStr, SINT8 *pSubstr)
{
    SINT32 i = 0;
    SINT8 *pTempStr = pStr;
    SINT8 const *pTempSubstr = pSubstr;
    SINT32 iSubLen = strlen(pSubstr);
    
    while(1)
    {
        if(*pTempStr == *pTempSubstr)
        {
            pTempSubstr++;
            if(*pTempSubstr == '\0')
            {
                break;
            }
        }
        else
        {
            pTempSubstr = pSubstr;
        }
        
        if(*pTempStr == '\0')
        {
            return;
        }
        pTempStr++;
    }
    char *pReDel = pTempStr - (iSubLen - 1);
    while(*(pReDel + (i + iSubLen)) != '\0')
    {
        *(pReDel + i) = *(pReDel + (i + iSubLen));
        i++;
    }
    *(pReDel + i) = '\0';
}

static SINT32 IM_GrpCntCheck(void)
{
    SINT8 szValue[32] = {0};
    SINT8 szCmd[256] = {0};
    SINT32 i = 0;
    struct uci_ptr pUciPtr;

	for (i = 0; i < MAX_GROUP_COUNT; i++)
	{
	    snprintf(szCmd, sizeof(szCmd), "%s.@%s-%d[0]", CONFIG_NAME, K_GROUP, i);
        if (UCI_OK != uci_lookup_ptr(g_Ctx, &pUciPtr, szCmd, true))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "uci_lookup_ptr failed, cmd:%s!", szCmd);
            break;
        }
	}
	g_GroupCount = i;
	IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "g_GroupCount:%d!", g_GroupCount);

    /* Get object count e.g. uci show per-auth | grep permissions */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s -c", CONFIG_NAME, K_GROUP_PERMS);
    if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get group count,cmd:%s!", szCmd);
        return -1;
    }

    /* Check object count */
    g_GroupCount = strtoul(szValue, NULL, 10);
    if (g_GroupCount > MAX_GROUP_COUNT)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with too much group, count:%d!", g_GroupCount);
        return -1;
    }

    return 0;
}

static void IM_GrpInit(stGrpDetailInfo *pstGrpInfo)
{
    SINT32 i = 0;

    memset(pstGrpInfo->szName, 0, PERAUTH_GRP_NAME_LEN + 1);
    pstGrpInfo->nId = 0;
    pstGrpInfo->ucType = 0;
    pstGrpInfo->nPermissons = 0;
    pstGrpInfo->stPermissons.ucInternetAccEnable = 0;
    pstGrpInfo->stPermissons.ucPrivateDiscAccEnable = 0;
    pstGrpInfo->stPermissons.ucPrivateDiscCtrlEnable = 0;
    pstGrpInfo->stPermissons.ucRouterCtrlEnable = 0;
    pstGrpInfo->stPermissons.ucRouterDiscAccEnable = 0;
    pstGrpInfo->stPermissons.ucRouterDiscCtrlEnable = 0;
    pstGrpInfo->nObjCnt = 0;
    
    for (i = 0; i < GROUP_MAX_OBJECT_COUNT; i++)
    {
        memset(&pstGrpInfo->stObjInfo[i], 0, sizeof(stAuthObjInfo));
    }
}

static UINT32 IM_CheckPermByCmd(UINT32 nCmd)
{
    if (nCmd < 0x200)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "unkown cmd 0x%x!", nCmd);
        return 0;
    }
    else if (nCmd < 0x300)
    {
        return IM_PERAUTH_FLAG_ROUTER_CTRL;
    }
    else if (nCmd < 0x400)
    {
        return IM_PERAUTH_FLAG_ROUTEDISC_CTRL;
    }
    else if (nCmd < 0x500)
    {
        return IM_PERAUTH_FLAG_ROUTER_CTRL;
    }

    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "unkown cmd 0x%x!", nCmd);
    return 0;
}

SINT32 IM_GrpAndObjInfoGet(void)
{
    SINT8 szValue[64] = {0};
    SINT8 szCmd[256] = {0};
    SINT32 i = 0, j = 0;
    UINT32 nPermissons = 0;
    UINT32 nObjCnt = 0;

    for (i = 0; i < MAX_GROUP_COUNT; i++)
    {
        IM_GrpInit(&g_GroupInfo[i]);
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        /* Group Name e.g. uci show per-auth | grep group-0 | grep name | cut -d = -f 2 */
        snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s-%d | grep %s | cut -d = -f 2", 
            CONFIG_NAME, K_GROUP, i, K_GROUP_NAME);
        if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get group info,cmd:%s!", szCmd);
            return -1;
        }
        snprintf(g_GroupInfo[i].szName, sizeof(g_GroupInfo[i].szName), "%s", szValue);

        /* Group ID */
        snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s-%d | grep %s | cut -d = -f 2", 
            CONFIG_NAME, K_GROUP, i, K_GROUP_ID);
        if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get group info,cmd:%s!", szCmd);
            return -1;
        }
        g_GroupInfo[i].nId = strtoul(szValue, NULL, 10);

        /* Group Type */
        snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s-%d | grep %s | cut -d = -f 2", 
            CONFIG_NAME, K_GROUP, i, K_GROUP_TYPE);
        if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get group info,cmd:%s!", szCmd);
            return -1;
        }
        g_GroupInfo[i].ucType = (UINT8)strtoul(szValue, NULL, 10);

        /* Group Permissions */
        snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s-%d | grep %s | cut -d = -f 2", 
            CONFIG_NAME, K_GROUP, i, K_GROUP_PERMS);
        if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get group info,cmd:%s!", szCmd);
            return -1;
        }
        nPermissons = strtoul(szValue, NULL, 10);
        g_GroupInfo[i].nPermissons = nPermissons;
        g_GroupInfo[i].stPermissons.ucInternetAccEnable = (IM_GET_PER_INTERNET_ACC(nPermissons) != 0);
        g_GroupInfo[i].stPermissons.ucRouterCtrlEnable = (IM_GET_PER_ROUTER_CTRL(nPermissons) != 0);
        g_GroupInfo[i].stPermissons.ucRouterDiscAccEnable = (IM_GET_PER_ROUTEDISC_ACC(nPermissons) != 0);
        g_GroupInfo[i].stPermissons.ucRouterDiscCtrlEnable = (IM_GET_PER_ROUTEDISC_CTRL(nPermissons) != 0);
        g_GroupInfo[i].stPermissons.ucPrivateDiscAccEnable = (IM_GET_PER_PRIDISC_ACC(nPermissons) != 0);
        g_GroupInfo[i].stPermissons.ucPrivateDiscCtrlEnable = (IM_GET_PER_PRIDISC_CTRL(nPermissons) != 0);

        /* Get object count e.g. uci show per-auth | grep 1- | grep index -c */
        snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %s.@%d- | grep %s -c", 
            CONFIG_NAME, CONFIG_NAME, g_GroupInfo[i].nId, K_OBJ_INDEX);
        if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object count,cmd:%s!", szCmd);
            return -1;
        }
        nObjCnt = strtoul(szValue, NULL, 10);
        g_GroupInfo[i].nObjCnt = nObjCnt;

        for (j = 0; j < nObjCnt; j++)
        {
            /* Object Name e.g. uci show per-auth | grep 1-0 | grep name | cut -d = -f 2 */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %d-%d | grep %s | cut -d = -f 2", 
                CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_NAME);
            if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object info,cmd:%s!", szCmd);
                return -1;
            }
            snprintf(g_GroupInfo[i].stObjInfo[j].szName, PERAUTH_OBJ_NAME_LEN + 1, "%s", szValue);

            /* Object Index */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %d-%d | grep %s | cut -d = -f 2", 
                CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_INDEX);
            if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object info,cmd:%s!", szCmd);
                return -1;
            }
            g_GroupInfo[i].stObjInfo[j].nIndex = strtoul(szValue, NULL, 10);

            /* Object Session */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %d-%d | grep %s -c", 
                CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS);
            if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object info,cmd:%s!", szCmd);
                return -1;
            }
            
            if (atoi(szValue) > 0)
            {
                snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %d-%d | grep %s | cut -d = -f 2", 
                    CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS);
                if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object info,cmd:%s!", szCmd);
                    return -1;
                }
                
                if (strlen(szValue) > 0)
                {
                    snprintf(g_GroupInfo[i].stObjInfo[j].szSession, PERAUTH_OBJ_NAME_LEN + 1, "%s", szValue);
                }
            }

            /* Object mac */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci show %s | grep %d-%d | grep %s | cut -d = -f 2", 
                CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_MAC);
            if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Failed with get object info,cmd:%s!", szCmd);
                return -1;
            }
            snprintf(g_GroupInfo[i].stObjInfo[j].szMacStr, MAC_STR_LEN + 1, "%s", szValue);
        }
    }

    return 0;
}

SINT32 IM_System(SINT8 *pCommand, SINT32 iPrintFlag)
{
	SINT32 iPid = 0, iStatus = 0;
    time_t nStart, nCurrent;    
  	pid_t iPidRet=0;

    if(!pCommand)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Null Command, Error!");
        return -1;
    }

	iPid = fork();
  	if (-1 == iPid)
  	{
		return -1;
	}

  	if (0 == iPid)
  	{
        SINT8 *pszArgv[4];
    	pszArgv[0] = "sh";
    	pszArgv[1] = "-c";
    	pszArgv[2] = pCommand;
    	pszArgv[3] = 0;
    	if (iPrintFlag)
    	{
	        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_INFO, "%s", pCommand);
        }
    	execv("/bin/sh", pszArgv);
    	exit(127);
	}

  	nStart = time(NULL);
  	/* wait for child process return */
  	do
  	{
        iPidRet = waitpid(iPid, &iStatus, WNOHANG);
        if (iPidRet  < 0)
        {
            if (errno != EINTR)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "ERROR! exce %s error, pid_ret %d, status %d pid %d(father pid %d)", 
                    pCommand, iPidRet, iStatus, iPid, getpid());
                return -1;
            }
        }
        else if(0 == iPidRet)
        {
            // do nothing!
        }
        else
        {
            return iStatus;
        }

        nCurrent = time(NULL);
        if (IM_SYSTEM_TIME_OUT <= ((unsigned long)nCurrent - (unsigned long)nStart))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "ERROR! exce %s timeout[%lu more than %d], pid_ret %d, status %d pid %d(father pid %d).", 
                pCommand, ((unsigned long)nCurrent - (unsigned long)nStart), IM_SYSTEM_TIME_OUT, iPidRet, iStatus, iPid, getpid());
            break;
        }
	} 
	while (1);

	return iStatus;
}

SINT32 IM_RootPwdSet(const SINT8 *pPwd)
{
    FILE *pFd = NULL;
    char szCmd[128] = {0};
    SINT8 szValue[128] = {0};

    if (NULL == pPwd)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "null password!");
        return -1;
    }

    if (strlen(pPwd) > IM_MAX_PWD_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "password(%s) is too long(%d)!", pPwd, strlen(pPwd));
        return -1;
    }

    pFd = fopen(IM_ROOT_PWD, "w+");
    if (NULL == pFd)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "creat file %s failed!", IM_ROOT_PWD);
        return -1;
    }

    snprintf(szCmd, sizeof(szCmd), "echo -n %s | base64", pPwd);
    if (0 != IM_GetSystemInfo(szCmd, szValue, sizeof(szValue) - 1))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_GetSystemInfo failed,cmd:%s!", szCmd);
        return -1;
    }

    fprintf(pFd, "%s\n", szValue);
    fclose(pFd);

    return 0;
}

SINT32 IM_RootPwdGet(SINT8 *pPwd)
{
    FILE *pFd = NULL;
    char szCmd[128] = {0};
    SINT8 szValue[128] = {0};
    
    pFd = fopen(IM_ROOT_PWD, "r");
    if (NULL == pFd)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "open file %s failed!", IM_ROOT_PWD);
        return -1;
    }

    fgets(szValue, sizeof(szValue), pFd);
	if (szValue[strlen(szValue)-1] == 0x0a)
		szValue[strlen(szValue)-1] = '\0';
    fclose(pFd);

    snprintf(szCmd, sizeof(szCmd), "echo -n %s | base64 -d", szValue);
    if (0 != IM_GetSystemInfo(szCmd, pPwd, IM_MAX_PWD_LEN))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_GetSystemInfo failed,cmd:%s!", szCmd);
        return -1;
    }
    
    return 0;
}

SINT32 IM_RootPwdAuth(SINT8 *pPwd)
{
    char szPwd[IM_MAX_PWD_LEN] = {0};

    if (0 != IM_RootPwdGet(szPwd))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_RootPwdGet failed!");
        return -1;
    }

    return (0 != strcmp(szPwd, pPwd));
}

SINT32 IM_ApplyInternetAcc(const SINT8 *pMacStr, UINT8 ucPerValue)
{
    SINT8 szCmd[256] = {0};

    if (MAC_STR_LEN != strlen(pMacStr))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac %s!", pMacStr);
        return -1;
    }

    if (DISENABLE != ucPerValue && ENABLE != ucPerValue)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong permission value %d!", ucPerValue);
        return -1;
    }

    if (ucPerValue)
    {
        snprintf(szCmd, sizeof(szCmd) - 1, "iptables -D FORWARD -m mac --mac-source %s -j DROP", pMacStr);
    }
    else
    {
        snprintf(szCmd, sizeof(szCmd) - 1, "iptables -I FORWARD -m mac --mac-source %s -j DROP", pMacStr);
    }
    IM_System(szCmd, 1);

    return 0;
}

SINT32 IM_CheckPermBySessionCmd(const SINT8 *pSession, UINT32 nCmd)
{
    SINT32 i = 0, j = 0;
    UINT8 ucFlag = 0;
    UINT32 nPermFlag = 0;
    SINT32 iEnable = -1;

    if (NULL == pSession)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "null session!");
        return -1;
    }

    if (strlen(pSession) > LEN_OF_SESSIONID)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong session(%s), too long!", pSession);
        return -1;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }
    
    /* Init check */
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (strstr(g_GroupInfo[i].stObjInfo[j].szSession, pSession))
            {
                nPermFlag = IM_CheckPermByCmd(nCmd);
                iEnable = (g_GroupInfo[i].nPermissons & nPermFlag) != 0;
                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    return iEnable;
}

stPermsInfo *IM_GetObjPermBySess(const SINT8 *pSession)
{
    stPermsInfo *pstPerms = NULL;
    SINT32 i = 0, j = 0;
    UINT8 ucFlag = 0;

    if (NULL == pSession)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "null session!");
        return NULL;
    }

    if (strlen(pSession) > LEN_OF_SESSIONID)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong session(%s), too long!", pSession);
        return NULL;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return NULL;
    }
    
    /* Init check */
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return NULL;
    }

    pstPerms = (stPermsInfo *)malloc(sizeof(stPermsInfo));
    if (NULL == pstPerms)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstPerms, 0, sizeof(stPermsInfo));

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "group:%d,objcnt:%d,grp.sess:%s,grp.perm:%d,sess:%s",
                i, g_GroupInfo[i].nObjCnt, g_GroupInfo[i].stObjInfo[j].szSession, g_GroupInfo[i].nPermissons,pSession);
            if (strstr(g_GroupInfo[i].stObjInfo[j].szSession, pSession))
            {
                pstPerms->ucInternetAccEnable = g_GroupInfo[i].stPermissons.ucInternetAccEnable;
                pstPerms->ucPrivateDiscAccEnable = g_GroupInfo[i].stPermissons.ucPrivateDiscAccEnable;
                pstPerms->ucPrivateDiscCtrlEnable = g_GroupInfo[i].stPermissons.ucPrivateDiscCtrlEnable;
                pstPerms->ucRouterCtrlEnable = g_GroupInfo[i].stPermissons.ucRouterCtrlEnable;
                pstPerms->ucRouterDiscAccEnable = g_GroupInfo[i].stPermissons.ucRouterDiscAccEnable;
                pstPerms->ucRouterDiscCtrlEnable = g_GroupInfo[i].stPermissons.ucRouterDiscCtrlEnable;
                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    return pstPerms;
}

stObjBrief *IM_GetObjBrief(const SINT8 *pMacStr)
{
    stObjBrief *pstObjInfo = NULL;
    SINT32 i = 0, j = 0;
    UINT8 ucFlag = 0;

    if (NULL == pMacStr)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong paras,mac is null!");
        return NULL;
    }

    if (strlen(pMacStr) != MAC_STR_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac(%s)!", pMacStr);
        return NULL;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return NULL;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return NULL;
    }

    pstObjInfo = (stObjBrief *)malloc(sizeof(stObjBrief));
    if (NULL == pstObjInfo)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstObjInfo, 0, sizeof(stObjBrief));

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                pstObjInfo->nGrpId = g_GroupInfo[i].nId;
                pstObjInfo->nPermissons = g_GroupInfo[i].nPermissons;
                memcpy(pstObjInfo->szGrpName, g_GroupInfo[i].szName, PERAUTH_GRP_NAME_LEN + 1);
                memcpy(pstObjInfo->szName, g_GroupInfo[i].stObjInfo[j].szName, PERAUTH_OBJ_NAME_LEN + 1);
                memcpy(pstObjInfo->szMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr, MAC_STR_LEN + 1);
                memcpy(pstObjInfo->szSession, g_GroupInfo[i].stObjInfo[j].szSession, LEN_OF_SESSIONID + 1);
                pstObjInfo->nIndex = g_GroupInfo[i].stObjInfo[j].nIndex;
                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    return pstObjInfo;
}

SINT32 IM_AddGrp(const SINT8 *pGrpName, UINT8 ucGrpType, UINT32 nPermissions)
{
    SINT32 i = 0;
    SINT8 szCmd[256] = {0};

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }
    
    /* Init check */
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    /* Parameters check */
    if (!pGrpName)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "group name is null!");
        return -1;
    }

    if (strlen(pGrpName) > PERAUTH_GRP_NAME_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "group name is too long %d!", strlen(pGrpName));
        return -1;
    }

    if (OBJ_TYPE_USER != ucGrpType && OBJ_TYPE_PROCESS != ucGrpType)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "not support group type %d!", ucGrpType);
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        if (0 == strcmp(pGrpName, g_GroupInfo[i].szName))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Same group already exists!");
            return -2;
        }
    }

    /*e.g. uci add per-auth group-0 */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci add %s %s-%d", 
        CONFIG_NAME, K_GROUP, g_GroupCount);
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    
    /*e.g. uci set per-auth.@group-0[0].name=admin */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%s", 
        CONFIG_NAME, K_GROUP, g_GroupCount, K_GROUP_NAME, pGrpName);
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    
    /*e.g. uci set per-auth.@group-0[0].type=1 */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%d", 
        CONFIG_NAME, K_GROUP, g_GroupCount, K_GROUP_TYPE, ucGrpType);
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    
    /*e.g. uci set per-auth.@group-0[0].id=1 */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%d", 
        CONFIG_NAME, K_GROUP, g_GroupCount, K_GROUP_ID, g_GroupCount + 1);
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    
    /*e.g. uci set per-auth.@group-0[0].permissions=7 */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%d", 
        CONFIG_NAME, K_GROUP, g_GroupCount, K_GROUP_PERMS, nPermissions);
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    
    /*e.g. uci commit per-auth */
    snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
    if (IM_System(szCmd, 1) < 0)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
        return -1;
    }
    usleep(50000);
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }
    
    return g_GroupCount;
}

SINT32 IM_DelGrp(UINT32 nGrpId)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};
    UINT32 nId = nGrpId;

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    if (nGrpId > g_GroupCount)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong group id %d!", nGrpId);
        return -1;
    }

    if (nGrpId <= DEFAULT_GROUP_CNT_INDEX)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong group id %d,may be can not del default group!", nGrpId);
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        if (nGrpId == g_GroupInfo[i].nId)
        {
            /* delete group,e.g. uci delete per-auth.@group-0[0] */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci delete %s.@%s-%d[0]", 
                CONFIG_NAME, K_GROUP, i); 
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
            {
                /* delete objects in group,e.g. uci delete per-auth.@1-0[0] */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci delete %s.@%d-%d[0]", 
                    CONFIG_NAME, g_GroupInfo[i].nId, j); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
            }

            snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }
            usleep(50000);

            /* reorder config */
            while (nId < g_GroupCount)
            {
                /* e.g. uci set per-auth.@group-5[0].id=5 */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%d", 
                    CONFIG_NAME, K_GROUP, nId, K_GROUP_ID, nId);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                /* e.g. uci set per-auth.@group-5[0]=group-4 */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0]=%s-%d", 
                    CONFIG_NAME, K_GROUP, nId, K_GROUP, nId - 1);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                usleep(50000);
                nId++;
            }
            
            break;
        }
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_SetGrp(UINT32 nGrpId, const SINT8 *pGrpName, UINT32 nPermissions)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    if (nGrpId > g_GroupCount || NULL == pGrpName)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong group id %d or NULL group name!", nGrpId);
        return -1;
    }

    if (strlen(pGrpName) > PERAUTH_GRP_NAME_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "group name is too long %d!", strlen(pGrpName));
        return -1;
    }

    if (nGrpId <= DEFAULT_GROUP_CNT_INDEX)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong group id %d,may be can not change default group!", nGrpId);
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        if (nGrpId == g_GroupInfo[i].nId)
        {
            continue;
        }
        
        if (0 == strcmp(pGrpName, g_GroupInfo[i].szName))
        {
            IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "another same group name %s exist!!", pGrpName);
            return -1;
        }
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        if (nGrpId == g_GroupInfo[i].nId)
        {
            /* uci set per-auth.@group-0[0].name=sunlsm */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%s", 
                CONFIG_NAME, K_GROUP, i, K_GROUP_NAME, pGrpName);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

#if 0
            /* set group name to objects belong to this group */
            for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
            {
                /* uci set per-auth.@root-0[0]=sunlsm-0 */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0]=%s-%d", 
                    CONFIG_NAME, g_GroupInfo[i].szName, j, pGrpName, j);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
            }
#endif

            /* uci set per-auth.@group-0[0].permissions=1 */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%s-%d[0].%s=%d", 
                CONFIG_NAME, K_GROUP, i, K_GROUP_PERMS, nPermissions);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }
            usleep(50000);
            break;
        }

    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_SessBindMac(const SINT8 *pSession, const SINT8 *pMacStr)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};
    UINT8 ucFlag = 0;
    
    if (NULL == pSession || NULL == pMacStr)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong paras,session or mac is null!");
        return -1;
    }

    if (strlen(pSession) > LEN_OF_SESSIONID || strlen(pMacStr) != MAC_STR_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong session(%s) or mac(%s)!", pSession, pMacStr);
        return -1;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                /*e.g. uci set per-auth.@1-0[0].session=lastsession-thissession */
                if (strlen(g_GroupInfo[i].stObjInfo[j].szSession) > 0)
                {
                    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%s-%s", 
                        CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS, g_GroupInfo[i].stObjInfo[j].szSession, pSession);
                }
                else
                {
                    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=-%s", 
                        CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS, pSession);
                }
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }

                snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                usleep(50000);

                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    if (1 != ucFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "do not find this object(%s) in group!", pMacStr);
        return -1;
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_SessUnbindMac(const SINT8 *pMacStr, const SINT8 *pSession)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};
    UINT8 ucFlag = 0;
    SINT8 szTmp[128] = {0};
    
    if (NULL == pMacStr || NULL == pSession)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong paras,mac or session is null!");
        return -1;
    }

    if (strlen(pMacStr) != MAC_STR_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac(%s)!", pMacStr);
        return -1;
    }

    if (strlen(pSession) > LEN_OF_SESSIONID)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong session(%s), too long!", pSession);
        return -1;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                /* find session and delete */
                if (NULL == strstr(g_GroupInfo[i].stObjInfo[j].szSession, pSession))
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "session(%s) is not binded any mac!", pSession);
                    return -1;
                }
                sprintf(szTmp, "-%s", pSession);
                IM_DeleteSubstr(g_GroupInfo[i].stObjInfo[j].szSession, szTmp);
                
                /*e.g. uci set per-auth.@root-0[0].session=sunlsm */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%s", 
                    CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS, g_GroupInfo[i].stObjInfo[j].szSession);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }

                snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                usleep(50000);

                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    if (1 != ucFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "do not find this object(%s) in group!", pMacStr);
        return -1;
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_AllSessUnbindMac(const SINT8 *pMacStr)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};
    UINT8 ucFlag = 0;
    
    if (NULL == pMacStr)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong paras,mac is null!");
        return -1;
    }

    if (strlen(pMacStr) != MAC_STR_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac(%s)!", pMacStr);
        return -1;
    }

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                /*e.g. uci set per-auth.@1-0[0].session= */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=", 
                    CONFIG_NAME, g_GroupInfo[i].nId, j, K_OBJ_SESS);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }

                snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                usleep(50000);

                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    if (1 != ucFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "do not find this object(%s) in group!", pMacStr);
        return -1;
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_AddObj2Grp(UINT32 nGrpId, const SINT8 *pObjName, const SINT8 *pMacStr)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }
    
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    if (nGrpId > g_GroupCount || NULL == pMacStr || NULL == pObjName)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong group id %d or NULL mac or NULL object name!", nGrpId);
        return -1;
    }

    if (strlen(pMacStr) != MAC_STR_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac(%s)!", pMacStr);
        return -1;
    }

    if (strlen(pObjName) > PERAUTH_OBJ_NAME_LEN)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "object name is too long %d!", strlen(pObjName));
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "object exist in group %s, can not add to another group!", g_GroupInfo[i].szName);
                return -2;
            }
        }

    }

    for (i = 0; i < g_GroupCount; i++)
    {
        if (nGrpId == g_GroupInfo[i].nId)
        {
            if (g_GroupInfo[i].nObjCnt >= GROUP_MAX_OBJECT_COUNT)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "object count in group is max,can not add!");
                return -1;
            }
        
            /* e.g. uci add per-auth 1-0 */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci add %s %d-%d", 
                CONFIG_NAME, g_GroupInfo[i].nId, g_GroupInfo[i].nObjCnt);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            /* e.g. uci set per-auth.@1-0[0].name=imove */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%s", 
                CONFIG_NAME, g_GroupInfo[i].nId, g_GroupInfo[i].nObjCnt, K_OBJ_NAME, pObjName);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            /* e.g. uci set per-auth.@1-0[0].mac=11:22:33:11:22:33 */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%s", 
                CONFIG_NAME, g_GroupInfo[i].nId, g_GroupInfo[i].nObjCnt, K_OBJ_MAC, pMacStr);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            /* e.g. uci set per-auth.@1-0[0].index=1 */
            snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%d", 
                CONFIG_NAME, g_GroupInfo[i].nId, g_GroupInfo[i].nObjCnt, K_OBJ_INDEX, g_GroupInfo[i].nObjCnt + 1);
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }

            snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
            if (IM_System(szCmd, 1) < 0)
            {
                IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                return -1;
            }
            usleep(50000);

            break;
        }
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

SINT32 IM_DelObjFromGrp(const SINT8 *pMacStr)
{
    SINT32 i = 0, j = 0;
    SINT8 szCmd[256] = {0};
    UINT8 ucFlag = 0;
    SINT32 iIdx = 0;

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }
    
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return -1;
    }

    if (MAC_STR_LEN != strlen(pMacStr))
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "wrong mac(%d)!", strlen(pMacStr));
        return -1;
    }

    for (i = 0; i < g_GroupCount; i++)
    {
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
        {
            if (0 == strcmp(pMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr))
            {
                /* delete objects in group,e.g. uci delete per-auth.@1-0[0] */
                snprintf(szCmd, sizeof(szCmd) - 1, "uci delete %s.@%d-%d[0]", 
                    CONFIG_NAME, g_GroupInfo[i].nId, j); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }

                snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                    return -1;
                }
                usleep(50000);

                /* reorder config */
                iIdx = j;
                while ((++iIdx) < g_GroupInfo[i].nObjCnt)
                {
                    /* e.g. uci set per-auth.@1-2[0].index=2 */
                    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0].%s=%d", 
                        CONFIG_NAME, g_GroupInfo[i].nId, iIdx, K_OBJ_INDEX, iIdx);
                    if (IM_System(szCmd, 1) < 0)
                    {
                        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                        return -1;
                    }
                    /* e.g. uci set per-auth.@1-2[0]=2-1 */
                    snprintf(szCmd, sizeof(szCmd) - 1, "uci set %s.@%d-%d[0]=%d-%d", 
                        CONFIG_NAME, g_GroupInfo[i].nId, iIdx, g_GroupInfo[i].nId, iIdx - 1);
                    if (IM_System(szCmd, 1) < 0)
                    {
                        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                        return -1;
                    }

                    snprintf(szCmd, sizeof(szCmd) - 1, "uci commit %s", CONFIG_NAME); 
                    if (IM_System(szCmd, 1) < 0)
                    {
                        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "IM_System failed!");
                        return -1;
                    }
                    usleep(50000);
                }
                
                ucFlag = 1;
                break;
            }
        }

        if (1 == ucFlag)
        {
            break;
        }
    }

    if (1 != ucFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "do not find this object(%s) in group!", pMacStr);
        return -2;
    }
    g_InitFlag = 0;

    /* Reinit after set */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return -1;
    }

    return 0;
}

stGroupBrief *IM_GetGrpBrief(void)
{
    stGroupBrief *pstGrpBrief = NULL;
    SINT32 i = 0, j = 0;

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return NULL;
    }
    
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return NULL;
    }

    pstGrpBrief = (stGroupBrief *)malloc(sizeof(stGroupBrief));
    if (NULL == pstGrpBrief)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstGrpBrief, 0, sizeof(stGroupBrief));

    pstGrpBrief->nCount = g_GroupCount - 1; //do not static root group
    for (i = 1, j = 0; i < g_GroupCount; i++, j++)
    {
        pstGrpBrief->stGrpCot[j].nId = g_GroupInfo[i].nId;
        memcpy(pstGrpBrief->stGrpCot[j].szName, g_GroupInfo[i].szName, PERAUTH_GRP_NAME_LEN + 1);
    }

    return pstGrpBrief;
}

stObjSample *IM_GetObjSample(void)
{
    stObjSample *pstObjSample = NULL;
    SINT32 i = 0, j = 0, k = 0;

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return NULL;
    }
    
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return NULL;
    }

    pstObjSample = (stObjSample *)malloc(sizeof(stObjSample));
    if (NULL == pstObjSample)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstObjSample, 0, sizeof(stObjSample));

    for (i = 1; i < g_GroupCount; i++)//ignore root group
    {
        pstObjSample->nCount += g_GroupInfo[i].nObjCnt;
        for (j = 0; j < g_GroupInfo[i].nObjCnt; j++, k++)
        {
            memcpy(pstObjSample->stObjCot[k].szGrpName, g_GroupInfo[i].szName, PERAUTH_GRP_NAME_LEN + 1);
            memcpy(pstObjSample->stObjCot[k].szName, g_GroupInfo[i].stObjInfo[j].szName, PERAUTH_OBJ_NAME_LEN + 1);
            memcpy(pstObjSample->stObjCot[k].szMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr, MAC_STR_LEN + 1);
        }
    }

    return pstObjSample;
}

stGrpDetailInfo *IM_GetObjsInfoInGroup(UINT32 nId)
{
    stGrpDetailInfo *pstGrpObjsInfo = NULL;
    SINT32 i = 0, j = 0;;

    /* Reinit first */
    if (0 != IM_PerAuthInit())
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Reinit failed!");
        return NULL;
    }
    
    if (!g_InitFlag)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "permission auth lib not init success!");
        return NULL;
    }

    pstGrpObjsInfo = (stGroupBrief *)malloc(sizeof(stGrpDetailInfo));
    if (NULL == pstGrpObjsInfo)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstGrpObjsInfo, 0, sizeof(stGrpDetailInfo));

    for (i = 0; i < g_GroupCount; i++)
    {
        if (nId == g_GroupInfo[i].nId)
        {
            memcpy(pstGrpObjsInfo->szName, g_GroupInfo[i].szName, PERAUTH_GRP_NAME_LEN + 1);
            pstGrpObjsInfo->nId = g_GroupInfo[i].nId;
            pstGrpObjsInfo->ucType = g_GroupInfo[i].ucType;
            pstGrpObjsInfo->nPermissons = g_GroupInfo[i].nPermissons;
            pstGrpObjsInfo->stPermissons.ucInternetAccEnable = g_GroupInfo[i].stPermissons.ucInternetAccEnable;
            pstGrpObjsInfo->stPermissons.ucPrivateDiscAccEnable = g_GroupInfo[i].stPermissons.ucPrivateDiscAccEnable;
            pstGrpObjsInfo->stPermissons.ucPrivateDiscCtrlEnable = g_GroupInfo[i].stPermissons.ucPrivateDiscCtrlEnable;
            pstGrpObjsInfo->stPermissons.ucRouterCtrlEnable = g_GroupInfo[i].stPermissons.ucRouterCtrlEnable;
            pstGrpObjsInfo->stPermissons.ucRouterDiscAccEnable = g_GroupInfo[i].stPermissons.ucRouterDiscAccEnable;
            pstGrpObjsInfo->stPermissons.ucRouterDiscCtrlEnable = g_GroupInfo[i].stPermissons.ucRouterDiscCtrlEnable;
            pstGrpObjsInfo->nObjCnt = g_GroupInfo[i].nObjCnt;
            for (j = 0; j < g_GroupInfo[i].nObjCnt; j++)
            {
                memcpy(pstGrpObjsInfo->stObjInfo[j].szName, g_GroupInfo[i].stObjInfo[j].szName, PERAUTH_OBJ_NAME_LEN + 1);
                pstGrpObjsInfo->stObjInfo[j].nIndex = g_GroupInfo[i].stObjInfo[j].nIndex;
                memcpy(pstGrpObjsInfo->stObjInfo[j].szSession, g_GroupInfo[i].stObjInfo[j].szSession, LEN_OF_SESSIONID + 1);
                memcpy(pstGrpObjsInfo->stObjInfo[j].szMacStr, g_GroupInfo[i].stObjInfo[j].szMacStr, MAC_STR_LEN + 1);
            }
            break;
        }
    }

    return pstGrpObjsInfo;
}

SINT32 IM_PerAuthInit(void)
{
    SINT32 iRet = 0;

    g_Ctx = uci_alloc_context();
    if (NULL == g_Ctx)
    {
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Out of memory!");
        return -1;
    }
    
    iRet = IM_GrpCntCheck();
    if (0 != iRet)
    {
        g_InitFlag = 0;
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Group count check failed!");
        return -1;
    }

    iRet = IM_GrpAndObjInfoGet();
    if (0 != iRet)
    {
        g_InitFlag = 0;
        IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_ERR, "Object info get failed!");
        return -1;
    }
    
    g_InitFlag = 1;
    IM_PERAUTH_LOG(IM_PERAUTH_LOG_FLAG, IM_PERAUTH_LOG_INFO, "Init success, there are %d groups!", g_GroupCount);
    return 0;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */
