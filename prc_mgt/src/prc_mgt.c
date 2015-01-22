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
#include "prc_mgt.h"

static PmFdSet g_stPmFdSet = {0};
unsigned char g_ShmUseFlag[PROC_INFO_SHM_NUM] = {0};
pthread_mutex_t g_PrcExecuteMutex = PTHREAD_MUTEX_INITIALIZER;
static AppOpMsg g_stCurrMsgAppInfo = {0};
PmTimer g_PmTimers[PM_MAX_TIMERS] = {{0}};
unsigned long g_PmTick = 0;
int g_OnStat = 0;
int g_StopFlg = 0;

/******************************************************************************
 *                         PRIVATE FUNCTIONS                                  *
 ******************************************************************************/
static int IM_PrcMgtShmInit(void);
static int IM_PrcMgtInit(void);
static void IM_PrcMgtDeinit(void);
static int IM_PrcMgtGenProcInfoFromFile(const char *pFile, AppProcInfo *pstAppProcInfo);
static int IM_PrcMgtAddShmProcInfoNoBake(AppProcInfo stAppProcInfo);

/******************************************************************************
 *                               FUNCTIONS                                    *
 ******************************************************************************/
void IM_DelCharInStr(char *pDestStr, char *pDelCharStr)
{
    char szArray[256] = {0};
    char *pFast = NULL; 
    char *pSlow = NULL;

    if (NULL == pDestStr || NULL == pDelCharStr)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Paras NULL!");
        return;
    }

    while('\0' != *pDelCharStr) 
    {
        szArray[*pDelCharStr++] = 1; 
    }

    pFast = pSlow = pDestStr;

    while ('\0' != *pFast) 
    { 
        if(0 == szArray[*pFast]) 
        {
            *pSlow++ = *pFast++;
        }
        else
        {
            pFast++;
        }
    } 
    *pSlow = '\0'; 
}

static pid_t IM_PrcMgtGetPidByName(const char *pName)
{
    DIR *pDir = NULL;  
    struct dirent *pstDirEntry = NULL;
    FILE *pFd = NULL;
    pid_t Pid = -1;
    char *pTmp = NULL;
    char szBuf[512] = {0};
    char szProcName[64] = {0};
    char szCmd[128] = {0};

    if (NULL == (pDir = opendir("/proc")))
    {
        return -1;
    }
    
    chdir("/proc");
    while (NULL != (pstDirEntry = readdir(pDir)))
    {
        if (pstDirEntry->d_name[0] != '.')
        {   
            /* Check status file wheather exist. */
            snprintf(szCmd, sizeof(szCmd) - 1, "/proc/%s/status", pstDirEntry->d_name);
            if (access(szCmd, F_OK) < 0)
            {
                continue;
            }

            /* Parse status file to get pid. */
            snprintf(szCmd, sizeof(szCmd) - 1, "cat /proc/%s/status", pstDirEntry->d_name);
            if (NULL != (pFd = popen(szCmd, "r")))
            {                              
                while (TRUE)
                {
                    if(NULL == fgets(szBuf, sizeof(szBuf), pFd))
                    {
                        break;
                    }

                    pTmp = strstr(szBuf, "Name:");
                    if(NULL != pTmp)
                    {
                        snprintf(szProcName, sizeof(szProcName) - 1, "%s", pTmp + strlen("Name:"));
                        IM_DelCharInStr(szProcName, " \t\n\r\b");
                                                            
                        if(!strcmp(szProcName, pName))
                        {
                            Pid = atoi(pstDirEntry->d_name);
                            break;
                        }
                    }
                }
                IM_PCLOSE(pFd);
            }
        }
    }
    closedir(pDir);
    
    return Pid;
}

static int IM_PrcMgtGetPrcPri(pid_t Pid, int *piPri)
{
    int iPri;
    
    errno = 0;
    iPri = getpriority(PRIO_PROCESS, Pid);
    if (-1 == iPri && 0 != errno)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "getpriority failed, reason: %s", strerror(errno));
        return -1;
    }
    *piPri = iPri;
    
    return 0;
}

static int IM_DaemonInit(int iNoChdir, int iNoClose)
{
    pid_t pid;

    pid = fork();
    if (pid > 0)
    {
        /* father exit */
        exit(0);
    }
    /* create process fail */
    else if (pid < 0)
    {
        printf("%d:fork error pid:%d\n", __LINE__, pid);
        return -1;
    }

    /* Creates a new session. 
       使子进程独立:摆脱原会话限制，摆脱原进程组控制，摆脱控制终端的控制
     */
    if (setsid() < 0)
    {
        printf("%d:setsid error\n", __LINE__);
        return -1;
    }

    pid = fork();
    if (pid > 0)
    {
        /* father exit */
        exit(0);
    }
    else if (pid < 0)
    {
        printf("%d:fork error pid:%d\n", __LINE__, pid);
        return -1;

    }

    /* Change the working directory as root directory */
    if (!iNoChdir)
    {
        chdir("/");
    }

    /* redirect the standard in/out/err to /dev/console, and close others*/
    if (!iNoClose)
    {
        int fd;

        fd = open("/dev/console", O_RDWR, 0);
        if (fd != -1)
        {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);

            if (fd > 2)
            {
                close(fd);
            }
        }
    }

    /* Change the file mode mask, give all rights */
    umask(0);

    return 0;
}


static int IM_PrcMgtShmInit(void)
{
    int iRet;
    
    /* Create APP process information list share memory semaphore. */
    iRet = IM_PosixShmSemCreat(PM_SHM_SEM_NAME);
    if(iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Share memory semaphore create fail!");
        return -1;
    }

    /* Create APP process information list share memory. */
    iRet = IM_PosixShmCreat(PROC_INFO_SHM_SIZE, PM_SHM_NAME);
    if(iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Share memory create fail!");
        return -1;
    }

    return 0;
}

static int IM_PrcMgtDomainMsgInit(void)
{
    int iServerSkd = -1;

    iServerSkd = IM_DomainServerInit(PRC_MGT_MODULE);
    if(iServerSkd < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Socket init error! name:%s", PRC_MGT_MODULE);
        return -1;
    }
    g_stPmFdSet.iIpcListenFd = iServerSkd;

    return 0;
}

static int IM_PrcMgtPrcInfoInit(void)
{
    FILE *pFd = NULL;
    char *pBuf = NULL;
    unsigned int nCount = 0;
    unsigned int nItemLen = sizeof(AppProcInfo);
    int iRet = 0;
    int i = 0;

    if (0 != access(PM_PROC_INFO_LIST_FILE, F_OK))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "file %s does not exist!", PM_PROC_INFO_LIST_FILE);
        goto Out;
    }

    pFd = fopen(PM_PROC_INFO_LIST_FILE, "r");
    if(NULL == pFd)
    {
    	IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "fopen error!");
        iRet =  -1;
        goto Out;
    }

    pBuf = (char *)malloc(PROC_INFO_SHM_SIZE);
    if (NULL == pBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc error!");
        iRet =  -1;
        goto Out;
    }
    memset(pBuf, 0, PROC_INFO_SHM_SIZE);

    nCount = fread(pBuf, nItemLen, PROC_INFO_SHM_NUM, pFd);
    iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, pBuf, nItemLen * nCount, 0);
    if(0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
        iRet =  -1;
        goto Out;
    }

    pthread_mutex_lock(&g_PrcExecuteMutex);
    for(i = 0; i < nCount; i++)
    {
        g_ShmUseFlag[i] = 1;
    }
    pthread_mutex_unlock(&g_PrcExecuteMutex);

Out:
    IM_FCLOSE(pFd);
    IM_FREE(pBuf);
    
    return iRet;
}

static int IM_PrcMgtPrcsRunInit(void)
{
    int iRet = 0;
    FILE *pFd = NULL;
    char szPrcName[PM_APP_NAME_LEN + 1] = {0};
    unsigned int nOffset = 0;
    unsigned int nLastOffset = 0;
    char szCmd[PM_APP_NAME_LEN + 3] = {0};
    int i = 0;
    char *szBuf = NULL;
    unsigned int nItemLen = sizeof(AppProcInfo);
    AppProcInfo stAppProcInfo;
    pid_t pid;
    int iPri;
    char szTmp[128] = {0};

    /* Add basic module info to share memory */
    pFd = fopen(PM_PROC_BOOT_LIST_FILE, "a+");
    if(NULL == pFd)
    {
    	IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Open %s file failed!", PM_PROC_BOOT_LIST_FILE);
    	iRet =  -1;
    	goto Out;
    }

    while(!feof(pFd))
    {
        memset(&stAppProcInfo, 0, nItemLen);
        fgets(szPrcName, APP_NAME_LEN + 1, pFd);
        nOffset = ftell(pFd);
        if(nOffset == nLastOffset)
        {
            break;
        }
        nLastOffset = nOffset;

        if(strlen(szPrcName) > 0)
        {
            IM_DelCharInStr(szPrcName, " \t\n\r\b");
#if 0
            snprintf(szCmd, sizeof(szCmd) - 1, "%s &", szPrcName);
            iRet = IM_System(szCmd, 1);
            if (iRet < 0)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
                iRet = -1;
                goto Out;
            }
#endif
            /* Get basic module info from file */
            snprintf(szTmp, sizeof(szTmp), "%s%s", PM_PROC_INFO_BASE_FLIR, szPrcName);
            iRet = IM_PrcMgtGenProcInfoFromFile(szTmp, &stAppProcInfo);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGenProcInfoFromFile failed!");
                iRet = -1;
                goto Out;
            }
            
            /* Add proc info in share memory */
            iRet = IM_PrcMgtAddShmProcInfoNoBake(stAppProcInfo);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtAddShmProcInfo failed!");
                iRet = -1;
                goto Out;
            }
            
            iRet = 0;
        }
    }
    IM_FCLOSE(pFd);

    /* Run in_mem module */
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            szBuf = (char *)malloc(nItemLen);
            if (NULL == szBuf)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc fail!");
                iRet = -1;
                goto Out;
            }
            memset(szBuf, 0, nItemLen);
            
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, szBuf, nItemLen, i * nItemLen);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead fail!");
                goto Out;
            }
            
            /* Ignore processes not in control. */
            if(0 == ((pAppProcInfo)szBuf)->cInMemFlag || 0 == ((pAppProcInfo)szBuf)->cBootFlag)
            {
                continue;
            }

            /* Run im_mem processes with bootflag 1*/
            if(1 == ((pAppProcInfo)szBuf)->cInMemFlag && 1 == ((pAppProcInfo)szBuf)->cBootFlag)
            {
                snprintf(szCmd, sizeof(szCmd) - 1, "%s &", ((pAppProcInfo)szBuf)->szProcName);
                iRet = IM_System(szCmd, 1);
                if (iRet < 0)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
                    iRet = -1;
                    goto Out;
                }
                iRet = 0;
            }
            sleep(2);
            IM_FREE(szBuf);
        }
    }

Out:
    IM_FCLOSE(pFd);
    IM_FREE(szBuf);
    
    return iRet;
}

static int IM_PrcMgtPrcsIfoUpdate(void)
{
    int iRet = 0;
    char *szBuf = NULL;
    unsigned int nItemLen = sizeof(AppProcInfo);
    int i = 0;
    pid_t Pid = -1;
    int iPri = -1;

    szBuf = (char *)malloc(nItemLen);
    if (NULL == szBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc fail!");
        iRet = -1;
        goto Out;
    }

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            memset(szBuf, 0, nItemLen);
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, szBuf, nItemLen, i * nItemLen);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead fail!");
                goto Out;
            }

            /* Ignore processes not in control. */
            if(0 == ((pAppProcInfo)szBuf)->cInMemFlag || 0 == ((pAppProcInfo)szBuf)->cBootFlag)
            {
                continue;
            }

            /* Get process id. */
            Pid = IM_PrcMgtGetPidByName(((pAppProcInfo)szBuf)->szProcName);
            if(Pid < 0)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPidByName fail!");
                iRet = -1;
                goto Out;
            }
            ((pAppProcInfo)szBuf)->nProcId = Pid;

            /* Get process pri. */
            iRet = IM_PrcMgtGetPrcPri(Pid, &iPri);
            if(0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPrcPri fail!");
                iRet = -1;
                goto Out;
            }
            ((pAppProcInfo)szBuf)->nProcPri = iPri;

            /* Set process new id and pri. */
            iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, szBuf, nItemLen, i * nItemLen);
            if(iRet < 0)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite fail!");
                iRet = -1;
                goto Out;
            }
        }
    }

Out:
    IM_FREE(szBuf);
    return iRet;
}

static void IM_PrcMgtPrcsIfoDump(void)
{
    int i;
    int iCount = 0;
    int iRet = -1;
    AppProcInfo stProcInfo;    

    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "\n\nManaged Processes information list:\n");
    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "=============================================================\n");  
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if(1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stProcInfo, sizeof(AppProcInfo), sizeof(AppProcInfo)*i);
            if(iRet < 0)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                return;
            }
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "managed process index:[%d]", i);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "app_id:%d", stProcInfo.nAppId);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "app_name:%s", stProcInfo.szAppName);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "desc:%s", stProcInfo.szDesc);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "conf_path:%s", stProcInfo.szConfPath);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "conf_cmd:%s", stProcInfo.szConfCmd);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "version:%s", stProcInfo.szVersion);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "inMem_flag:%d", stProcInfo.cInMemFlag);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "boot_flag:%d", stProcInfo.cBootFlag);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "proc_name:%s", stProcInfo.szProcName);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "proc_id:%d", stProcInfo.nProcId);
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "Proc_pri:%d\n", stProcInfo.nProcPri);            
            ++iCount;
        }
    }
    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "=============================================================");
    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "Managed processes total count:%d\n", iCount);
}

static int IM_PrcMgtInit(void)
{
    int iRet = 0;;

    /* Share memory init */
    iRet = IM_PrcMgtShmInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtShmInit fail!");
        return -1;
    }

    /* Domain socket msg communicate init */
    iRet = IM_PrcMgtDomainMsgInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtDomainMsgInit fail!");
        return -1;
    }

    /* Recover app info to share memory from bake file */
    iRet = IM_PrcMgtPrcInfoInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtPrcInfoInit fail!");
        return -1;
    }

    /* Get basic module and run im_mem processes*/
    iRet = IM_PrcMgtPrcsRunInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtPrcsRunInit fail!");
        return -1;
    }

    /* Update processes info */
    iRet = IM_PrcMgtPrcsIfoUpdate();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtPrcsIfoUpdate fail!");
        return -1;
    }

    /* Printf processes info */
    IM_PrcMgtPrcsIfoDump();
    
    return iRet;
}

static int IM_PrcMgtAddFd2FdSet(fd_set *pFds)
{	
	int iMaxFd = 0;
	IpcAcceptFd *pstIpcAcceptFd = NULL;

	for(pstIpcAcceptFd = g_stPmFdSet.pstIpcAcceptFdList; pstIpcAcceptFd; pstIpcAcceptFd = pstIpcAcceptFd->pstNext)
    {
		FD_SET(pstIpcAcceptFd->iFd, pFds);
		if(iMaxFd < pstIpcAcceptFd->iFd)
		{
            iMaxFd = pstIpcAcceptFd->iFd;
		}
	}
	
	return iMaxFd;
}

static int IM_PrcMgtAddFd2FdList(int iFd)
{
	int iConnFd = 0;
	IpcAcceptFd *pstIpcAcceptFd = NULL;
    unsigned int nLen = sizeof(IpcAcceptFd);
	
	if((iConnFd = IM_ServerAcceptClient(iFd)) < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_ServerAcceptClient error!");
		return -1;
	}

    pstIpcAcceptFd = (IpcAcceptFd *)malloc(nLen);
    if(NULL == pstIpcAcceptFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "mallocl error!");
        return -1;
    }							
	memset(pstIpcAcceptFd, 0, nLen);

	/*add fd to the accept fd list*/
    pstIpcAcceptFd->iFd = iConnFd;
    pstIpcAcceptFd->pstNext = g_stPmFdSet.pstIpcAcceptFdList;
    g_stPmFdSet.pstIpcAcceptFdList = pstIpcAcceptFd;

    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "server accetp new fd:%d.", iConnFd);
     
	return 0;
    
}

static void  IM_PrcMgtDelAcpFd(int iFd)
{
	IpcAcceptFd *pstIpcAcceptFd = NULL;
    IpcAcceptFd *pstPrev = NULL; 
    IpcAcceptFd *pstTmp = NULL;
	
	IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "accept %d close!\n", iFd);
	for (pstIpcAcceptFd = g_stPmFdSet.pstIpcAcceptFdList; pstIpcAcceptFd; pstIpcAcceptFd = pstIpcAcceptFd->pstNext)
    {
		if (pstIpcAcceptFd->iFd == iFd) 
        {
            if(g_stPmFdSet.pstIpcAcceptFdList == pstIpcAcceptFd)
            {
                if(!g_stPmFdSet.pstIpcAcceptFdList->pstNext)
                {
                    g_stPmFdSet.pstIpcAcceptFdList = NULL;
                }
                else
                {
                    g_stPmFdSet.pstIpcAcceptFdList = g_stPmFdSet.pstIpcAcceptFdList->pstNext;
                }
            }
            else
            {
                pstPrev = g_stPmFdSet.pstIpcAcceptFdList;
                pstTmp = g_stPmFdSet.pstIpcAcceptFdList->pstNext;
                while(pstTmp)
                {
                    if(pstTmp == pstIpcAcceptFd)
                    {
                        pstPrev->pstNext = pstTmp->pstNext;
                        break;
                    }
                    pstPrev = pstTmp;
                    pstTmp = pstTmp->pstNext;
                }
            }
            
			close(pstIpcAcceptFd->iFd);
			free(pstIpcAcceptFd);			
		}
	}
}

static JsonHeadInfo *IM_PrcMgtCliMsgHeadParse(char *pMsg, int iLen)
{
    char *pMsgBuf = NULL;
    json_object *pMyObject = NULL;
    json_object *pHeadObject = NULL;
    json_object *pTmpObject = NULL;
    JsonHeadInfo *pstJsonHead = NULL;
    char *pSession = NULL;
    char *pSign = NULL;
    
    if (NULL == pMsg || iLen <= 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "wrong paras(iLen:%d)!", iLen);
        return NULL;
    }

    pMsgBuf = (char *)malloc(iLen);
    if (NULL == pMsgBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pMsgBuf, 0, iLen);

    pstJsonHead = (JsonHeadInfo *)malloc(sizeof(JsonHeadInfo));
    if (NULL == pstJsonHead)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc failed!");
        return NULL;
    }
    memset(pstJsonHead, 0, sizeof(JsonHeadInfo));

    /* parse json */
    memcpy(pMsgBuf, pMsg, iLen);
    pMyObject = json_tokener_parse(pMsgBuf);
    if (is_error(pMyObject))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_tokener_parse body failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }

    /* get header object */
    pHeadObject = json_object_object_get(pMyObject, K_HEAD);
    if (NULL == pHeadObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    IM_FREE_JSON_OBJ(pTmpObject);
    
    /* get cmd */
    pTmpObject = json_object_object_get(pHeadObject, K_CMD_ID);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iCmd = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get version */
    pTmpObject = json_object_object_get(pHeadObject, K_VERSION_NUM);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iVer = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get seq */
    pTmpObject = json_object_object_get(pHeadObject, K_SEQ_NUM);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iSeq = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_DEV_TYPE);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iDevice = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_APP_ID);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iAppId = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get device */
    pTmpObject = json_object_object_get(pHeadObject, K_RST_CODE);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        IM_FREE(pstJsonHead);
        goto Out;
    }
    pstJsonHead->iCode = json_object_get_int(pTmpObject);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* get session id in header */
    pTmpObject = json_object_object_get(pHeadObject, K_SESSION_ID);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
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
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
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

static int IM_PrcMgtCliMsgDataParse(char *pMsg, int iLen)
{
    int iRet = 0;
    char *pMsgBuf = NULL;
    json_object *pMyObject = NULL;
    json_object *pArrayObject = NULL;
    json_object *pDataOject = NULL;
    json_object *pTmpObject = NULL;
    char *pAppName = NULL;
    char *pAppVer = NULL;
    int iIMType = 0;
    int iOpType = 0;
    char *pAppUrl = NULL;
    char *pAppMd5 = NULL;
    char *pAppInfoUrl = NULL;
    char *pAppInfoMd5 = NULL;

    pMsgBuf = (char *)malloc(iLen);
    if (NULL == pMsgBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc failed!");
        return -1;
    }
    memset(pMsgBuf, 0, iLen);

    memcpy(pMsgBuf, pMsg, iLen);
    pMyObject = json_tokener_parse(pMsgBuf);
    if (is_error(pMyObject))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_tokener_parse body failed!");
        iRet = -1;
        goto Out;
    }
    /* Get data */
    pDataOject = json_object_object_get(pMyObject, K_DATA);
    if (NULL == pDataOject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }

    /* Get first array in data */
    pArrayObject = json_object_array_get_idx(pDataOject, 0);
    if (NULL == pArrayObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_array_get_idx failed!");
        iRet = -1;
        goto Out;
    }

    /* Init g_stCurrMsgAppInfo and then store app info in it */
    memset(&g_stCurrMsgAppInfo, 0, sizeof(AppOpMsg));

    /* Get APP name */
    pTmpObject = json_object_object_get(pArrayObject, K_APP_NAME);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppName = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szModName, PM_APP_NAME_LEN, "%s", pAppName);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP version */
    pTmpObject = json_object_object_get(pArrayObject, K_VERSION);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppVer = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szVersion, PM_VERSION_LEN, "%s", pAppVer);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP imove type */
    pTmpObject = json_object_object_get(pArrayObject, K_IM_TYPE);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    iIMType = json_object_get_int(pTmpObject);
    g_stCurrMsgAppInfo.im_type = iIMType;
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP operate type */
    pTmpObject = json_object_object_get(pArrayObject, K_OP_TYPE);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    iOpType = json_object_get_int(pTmpObject);
    g_stCurrMsgAppInfo.action_type = iOpType;
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP url */
    pTmpObject = json_object_object_get(pArrayObject, K_APP_URL);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppUrl = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szUrlIpk, PM_DOWNLOAD_URL_LEN, "%s", pAppUrl);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP md5 */
    pTmpObject = json_object_object_get(pArrayObject, K_APP_MD5);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppMd5 = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szMd5Ipk, PM_MD5_STR_LEN, "%s", pAppMd5);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP info url */
    pTmpObject = json_object_object_get(pArrayObject, K_INFO_URL);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppInfoUrl = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szUrlInfo, PM_DOWNLOAD_URL_LEN, "%s", pAppInfoUrl);
    IM_FREE_JSON_OBJ(pTmpObject);

    /* Get APP info md5 */
    pTmpObject = json_object_object_get(pArrayObject, K_INFO_MD5);
    if (NULL == pTmpObject)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "json_object_object_get failed!");
        iRet = -1;
        goto Out;
    }
    pAppInfoMd5 = (char *)json_object_get_string(pTmpObject);
    snprintf(g_stCurrMsgAppInfo.szMd5Info, PM_MD5_STR_LEN, "%s", pAppInfoMd5);

Out:
    IM_FREE_JSON_OBJ(pTmpObject);
    IM_FREE_JSON_OBJ(pArrayObject);
    IM_FREE_JSON_OBJ(pDataOject);
    IM_FREE_JSON_OBJ(pMyObject);
    IM_FREE(pMsgBuf);
    
    return iRet;
}

static int IM_PrcMgtFindStrInFile(const char *PFileName, const char *pStr)
{
    FILE *pFd = NULL;
    int iRet = -1;
    char szBuf[512] = {0};

    if (NULL == PFileName || NULL == pStr)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Invalid paras!");
        return -1;
    }

    pFd = fopen(PFileName, "r");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "fopen %s failed!", PFileName);
        return -1;
    }

    while (TRUE)
    {
        if(fgets(szBuf, sizeof(szBuf), pFd) == NULL)
        {
            break;
        }
        
        if(strstr(szBuf, pStr) != NULL)
        {
            iRet = 0;
            break;
        }
    }
    IM_FCLOSE(pFd);

    return iRet;
}

static int IM_PrcMgtGetFileMd5(const char *PFileName, char *pMd5Str)
{
    FILE *pFd = NULL;
    char szCmd[512] = {0};
    int iRet = -1;
    char szBuf[512] = {0};
    char *pTmp = NULL;
    int iLen = 0;
    char szTmpBuf[128] = {0};

    if (NULL == PFileName || NULL == pMd5Str)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Invalid paras!");
        return -1;
    }

    snprintf(szCmd, sizeof(szCmd), "md5sum %s", PFileName);
    pFd = popen(szCmd, "r");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "popen %s failed!", szCmd);
        return -1;
    }

    while (TRUE)
    {
        if(fgets(szBuf, sizeof(szBuf), pFd) == NULL)
        {
            break;
        }

        pTmp = strstr(szBuf, PFileName);
        if (NULL != pTmp)
        {
            iLen = pTmp - szBuf;
            memcpy(szTmpBuf, szBuf, iLen);
            IM_DelCharInStr(szTmpBuf, " \t\n\r\b");
            snprintf(pMd5Str, PM_MD5_STR_LEN, "%s", szTmpBuf);
            iRet = 0;
            break;
        }
    }
    IM_PCLOSE(pFd);

    return iRet;
}


static int IM_PrcMgtDownLoadFile(AppOpMsg *pstAppInfo, E_DownloadFileType enType)
{
    int iRet = 0;
    char szCmd[512] = {0};
    char szMd5[PM_MD5_STR_LEN] = {0};

    if (FILE_TYPE_INSTALL_PACKAGE == enType)
    {
        snprintf(szCmd, sizeof(szCmd) - 1, 
            "rm -f %s;/usr/bin/wget %s -O %s >%s 2>&1", 
            PM_APP_IPK_TMP_NAME, pstAppInfo->szUrlIpk, PM_APP_IPK_TMP_NAME, PM_APP_WGET_LOG_FILE);
    }
    else if (FILE_TYPE_APP_INFO_FILE == enType)
    {
        snprintf(szCmd, sizeof(szCmd) - 1, 
            "rm -f %s;/usr/bin/wget %s -O %s >%s 2>&1", 
            PM_APP_INFO_TMP_NAME, pstAppInfo->szUrlInfo, PM_APP_INFO_TMP_NAME, PM_APP_WGET_LOG_FILE);
    }
    else
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "unknown downlaod file type %d!", enType);
        return -1;
    }

    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        return iRet;
    }
    iRet = 0;

    if (0 == IM_PrcMgtFindStrInFile(PM_APP_WGET_LOG_FILE, "100%"))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "download file success!");
    }
    else
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "download file failed!");
    }

    if (FILE_TYPE_INSTALL_PACKAGE == enType)
    {
        iRet = IM_PrcMgtGetFileMd5(PM_APP_IPK_TMP_NAME, szMd5);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetFileMd5 failed!");
        }

        if (strcmp(szMd5, pstAppInfo->szMd5Ipk))
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Install ipk md5 value not equal!");
            iRet = -1;
        }
    }
    else if (FILE_TYPE_APP_INFO_FILE == enType)
    {
        iRet = IM_PrcMgtGetFileMd5(PM_APP_INFO_TMP_NAME, szMd5);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetFileMd5 failed!");
        }

        if (strcmp(szMd5, pstAppInfo->szMd5Info))
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Install ipk md5 value not equal!");
            iRet = -1;
        }
    }

    return iRet;
}

static int IM_PrcMgtGenProcInfo(AppOpMsg *pstAppInfo, AppProcInfo *pstAppProcInfo)
{
    int iRet = 0;
    FILE *pFp = NULL;
    char szCmd[256] = {0};
    char szBuf[256] = {0};
    char *pCurr = NULL;

    pFp = fopen(PM_APP_INFO_TMP_NAME, "r");
    if (NULL == pFp)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "fopen %s failed!", PM_APP_INFO_TMP_NAME);
        return -1;
    }

    while (!feof(pFp))
    {
        fgets(szBuf, sizeof(szBuf), pFp);
        /* Get name */
        pCurr = strstr(szBuf, K_APP_INFO_NAME);
        if (NULL != pCurr)
        {
            /* add 1 for = */
            memcpy(pstAppInfo->szModName, pCurr + strlen(K_APP_INFO_NAME) + 1, strlen(pCurr + strlen(K_APP_INFO_NAME) + 1) - 2);
            memcpy(pstAppProcInfo->szAppName, pCurr + strlen(K_APP_INFO_NAME) + 1, strlen(pCurr + strlen(K_APP_INFO_NAME) + 1) - 2);
        }

        /* Get imove type */
        pCurr = strstr(szBuf, K_APP_IMOVE_TYPE);
        if (NULL != pCurr)
        {
            pstAppInfo->im_type = atoi(pCurr + strlen(K_APP_IMOVE_TYPE) + 1);
            pstAppProcInfo->cIMType = pstAppInfo->im_type;
        }

        /* Get description */
        pCurr = strstr(szBuf, K_APP_INFO_DES);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szDesc, pCurr + strlen(K_APP_INFO_DES) + 1, strlen(pCurr + strlen(K_APP_INFO_DES) + 1) - 2);
        }

        /* Get version */
        pCurr = strstr(szBuf, K_APP_INFO_VERSION);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szVersion, pCurr + strlen(K_APP_INFO_VERSION) + 1, strlen(pCurr + strlen(K_APP_INFO_VERSION) + 1) - 2);
        }

        /* Get id*/
        pCurr = strstr(szBuf, K_APP_INFO_ID);
        if (NULL != pCurr)
        {
            pstAppInfo->nModId = atoi(pCurr + strlen(K_APP_INFO_ID) + 1);
            pstAppProcInfo->nAppId = pstAppInfo->nModId;
        }

        /* Get config path */
        pCurr = strstr(szBuf, K_APP_INFO_CONF_PATH);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szConfPath, pCurr + strlen(K_APP_INFO_CONF_PATH) + 1, strlen(pCurr + strlen(K_APP_INFO_CONF_PATH) + 1) - 2);
        }

        /* Get config cmd */
        pCurr = strstr(szBuf, K_APP_INFO_CONF_CMD);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szConfCmd, pCurr + strlen(K_APP_INFO_CONF_CMD) + 1, strlen(pCurr + strlen(K_APP_INFO_CONF_CMD) + 1) - 2);
        }

        /* Get in mem flag */
        pCurr = strstr(szBuf, K_APP_INFO_INMEM_FLAG);
        if (NULL != pCurr)
        {
            pstAppProcInfo->cInMemFlag = atoi(pCurr + strlen(K_APP_INFO_INMEM_FLAG) + 1);
        }

        /* Get boot flag */
        pCurr = strstr(szBuf, K_APP_INFO_BOOT_FLAG);
        if (NULL != pCurr)
        {
            pstAppProcInfo->cBootFlag = atoi(pCurr + strlen(K_APP_INFO_BOOT_FLAG) + 1);
        }

        /* Get process name */
        pCurr = strstr(szBuf, K_APP_INFO_PRC_NAME);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szProcName, pCurr + strlen(K_APP_INFO_PRC_NAME) + 1, strlen(pCurr + strlen(K_APP_INFO_PRC_NAME) + 1) - 2);
        }
    }
    IM_FCLOSE(pFp);

    snprintf(szCmd, sizeof(szCmd), "rm -f %s", PM_APP_INFO_TMP_NAME);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        return iRet;
    }

    return 0;
}

static int IM_PrcMgtGenProcInfoFromFile(const char *pFile, AppProcInfo *pstAppProcInfo)
{
    int iRet = 0;
    FILE *pFp = NULL;
    char szCmd[256] = {0};
    char szBuf[256] = {0};
    char *pCurr = NULL;

    if (NULL == pFile)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "file is null!");
        return -1;
    }

    if (0 != access(pFile, F_OK))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "file %s does not exist!", pFile);
        return 0;
    }

    pFp = fopen(pFile, "r");
    if (NULL == pFp)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "fopen %s failed!", pFile);
        return -1;
    }

    while (!feof(pFp))
    {
        fgets(szBuf, sizeof(szBuf), pFp);
        /* Get name */
        pCurr = strstr(szBuf, K_APP_INFO_NAME);
        if (NULL != pCurr)
        {
            /* add 1 for = */
            memcpy(pstAppProcInfo->szAppName, pCurr + strlen(K_APP_INFO_NAME) + 1, strlen(pCurr + strlen(K_APP_INFO_NAME) + 1) - 1);
        }

        /* Get imove type */
        pCurr = strstr(szBuf, K_APP_IMOVE_TYPE);
        if (NULL != pCurr)
        {
            pstAppProcInfo->cIMType = atoi(pCurr + strlen(K_APP_IMOVE_TYPE) + 1);
        }

        /* Get description */
        pCurr = strstr(szBuf, K_APP_INFO_DES);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szDesc, pCurr + strlen(K_APP_INFO_DES) + 1, strlen(pCurr + strlen(K_APP_INFO_DES) + 1) - 1);
        }

        /* Get version */
        pCurr = strstr(szBuf, K_APP_INFO_VERSION);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szVersion, pCurr + strlen(K_APP_INFO_VERSION) + 1, strlen(pCurr + strlen(K_APP_INFO_VERSION) + 1) - 1);
        }

        /* Get id*/
        pCurr = strstr(szBuf, K_APP_INFO_ID);
        if (NULL != pCurr)
        {
            pstAppProcInfo->nAppId = atoi(pCurr + strlen(K_APP_INFO_ID) + 1);
        }

        /* Get config path */
        pCurr = strstr(szBuf, K_APP_INFO_CONF_PATH);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szConfPath, pCurr + strlen(K_APP_INFO_CONF_PATH) + 1, strlen(pCurr + strlen(K_APP_INFO_CONF_PATH) + 1) - 1);
        }

        /* Get config cmd */
        pCurr = strstr(szBuf, K_APP_INFO_CONF_CMD);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szConfCmd, pCurr + strlen(K_APP_INFO_CONF_CMD) + 1, strlen(pCurr + strlen(K_APP_INFO_CONF_CMD) + 1) - 1);
        }

        /* Get in mem flag */
        pCurr = strstr(szBuf, K_APP_INFO_INMEM_FLAG);
        if (NULL != pCurr)
        {
            pstAppProcInfo->cInMemFlag = atoi(pCurr + strlen(K_APP_INFO_INMEM_FLAG) + 1);
        }

        /* Get boot flag */
        pCurr = strstr(szBuf, K_APP_INFO_BOOT_FLAG);
        if (NULL != pCurr)
        {
            pstAppProcInfo->cBootFlag = atoi(pCurr + strlen(K_APP_INFO_BOOT_FLAG) + 1);
        }

        /* Get process name */
        pCurr = strstr(szBuf, K_APP_INFO_PRC_NAME);
        if (NULL != pCurr)
        {
            memcpy(pstAppProcInfo->szProcName, pCurr + strlen(K_APP_INFO_PRC_NAME) + 1, strlen(pCurr + strlen(K_APP_INFO_PRC_NAME) + 1) - 1);
        }
    }
    IM_FCLOSE(pFp);

    return 0;
}

static int IM_PrcMgtDelLineInFile(const char *pFileName, const char *pStr)
{
    FILE *pFd = NULL;
    FILE *pFdTmp = NULL;
    int iRet = 0;
    char szRdBuf[512] = {0};
    char szWtBuf[512] = {0};
    int iOffset = 0;
    int iLen = 0;
    int iRdLen = 0;

    if (NULL != pFileName || NULL != pStr)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "invalid paras!");
        iRet = -1;
        goto Out;
    }

    pFd = fopen(pFileName, "r+");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "open %s failed!", pFileName);
        iRet = -1;
        goto Out;
    }

    pFdTmp = fopen("/tmp/file_save_tmp", "w+");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "open /tmp/file_save_tmp failed!");
        iRet = -1;
        goto Out;
    }

    while (TRUE)
    {
        if(fgets(szRdBuf, sizeof(szRdBuf), pFd) == NULL)
        {
            break;
        }

        if(NULL != strstr(szRdBuf, pStr))
        {
            iOffset = ftell(pFd);
            iLen = iOffset - strlen(szRdBuf) - 2;
            while (!feof(pFd))
            {
                iRdLen = fread(szWtBuf, 1, sizeof(szWtBuf), pFd);
                if (sizeof(szWtBuf) != iRdLen && !feof(pFd))
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "read file %s err!", pFileName);
                    iRet = -1;
                    goto Out;
                }
                fwrite(szWtBuf, 1, iRdLen, pFdTmp);
            }
            fflush(pFdTmp);

            fseek(pFdTmp, 0, SEEK_SET);
            fseek(pFd, 0, SEEK_SET);
            
            iRet = ftruncate(fileno(pFd), iLen);
            if(0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "ftruncate err:%s!", strerror(errno));
                iRet = -1;
                goto Out;
            }

            fseek(pFd, iLen, SEEK_SET);
            while(!feof(pFdTmp))
            {
                iRdLen = fread(szWtBuf, 1, sizeof(szWtBuf), pFdTmp);
                if(sizeof(szWtBuf) != iRdLen && !feof(pFdTmp))
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "read file /tmp/file_save_tmp err!");
                    iRet = -1;
                    goto Out;
                }            
                fwrite(szWtBuf, 1, iRdLen, pFd);
            }
            
            iRet = 0;
            break;
        }
    }

Out:
    IM_FCLOSE(pFd);
    IM_FCLOSE(pFdTmp);
    return iRet;
}

static int IM_PrcMgtAddLineInFile(const char *pFileName, const char *pStr)
{
    char *pBuf = NULL;
    int iLen = strlen(pStr) + 2;
    FILE *pFd = NULL;
    int iRet = 0;
    
    if (NULL != pFileName || NULL != pStr)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "invalid paras!");
        iRet = -1;
        goto Out;
    }

    pBuf = (char *)malloc(iLen);
    if (NULL == pBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc failed!");
        iRet = -1;
        goto Out;
    }
    memset(pBuf, 0, iLen);

    snprintf(pBuf, iLen, "%s", pStr);
    memset(pBuf + strlen(pStr) + 1, "\n", 1);

    pFd = fopen(pFileName, "a+");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "open file %s failed!", pFileName);
        iRet = -1;
        goto Out;
    }

    fwrite(pBuf, iLen, 1, pFd);
    fflush(pFd);

Out:
    IM_FREE(pBuf);
    IM_FCLOSE(pFd);

    return iRet;
}

static int IM_PrcMgtBakeProcInfo(void)
{
    FILE *pFd;
    char *pBuf = NULL;
    int iLen = sizeof(AppProcInfo);
    int i = 0;
    int iRet = 0;

    pFd = fopen(PM_PROC_INFO_LIST_FILE, "w+");
    if (NULL == pFd)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "open file %s failed!", PM_PROC_INFO_LIST_FILE);
        iRet = -1;
        goto Out;
    }

    pBuf = (char *)malloc(iLen);
    if (NULL == pBuf)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc failed!");
        iRet = -1;
        goto Out;
    }

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            memset(pBuf, 0, iLen);
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, pBuf, iLen, iLen*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                iRet = -1;
                goto Out;
            }
            fwrite(pBuf, 1, iLen, pFd);
        }
    }
    fflush(pFd);

Out:
    IM_FREE(pBuf);
    IM_FCLOSE(pFd);
    return iRet;
}

static int IM_PrcMgtRemoveShmProcInfo(AppOpMsg *pstAppInfo)
{
    int iRet = 0;
    int i = 0;
    AppProcInfo stAppProcInfo;

    memset(&stAppProcInfo, 0, sizeof(AppProcInfo));
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stAppProcInfo, sizeof(AppProcInfo), sizeof(AppProcInfo)*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                return -1;
            }

            if(!strcmp(pstAppInfo->szModName, stAppProcInfo.szAppName))
            {
                memset(&stAppProcInfo, 0, sizeof(AppProcInfo));
                iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, sizeof(AppProcInfo), i * sizeof(AppProcInfo));
                if (0 != iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                    return -1;
                }
                g_ShmUseFlag[i] = 0;
                break;
            }
        }
    }

    iRet = IM_PrcMgtBakeProcInfo();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtBakeProcInfo failed!");
        return -1;
    }

    return iRet;
}

static int IM_PrcMgtAddShmProcInfo(AppProcInfo stAppProcInfo)
{
    int i = 0;
    int iRet = 0;

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (0 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, sizeof(AppProcInfo), i * sizeof(AppProcInfo));
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                return -1;
            }

            g_ShmUseFlag[i] = 1;
            break;
        }
    }

    iRet = IM_PrcMgtBakeProcInfo();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtBakeProcInfo failed!");
        return -1;
    }

    return iRet;
}

static int IM_PrcMgtAddShmProcInfoNoBake(AppProcInfo stAppProcInfo)
{
    int i = 0;
    int iRet = 0;
    AppProcInfo stAppProcInfoCurr;

    memset(&stAppProcInfoCurr, 0, sizeof(AppProcInfo));
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stAppProcInfoCurr, sizeof(AppProcInfo), sizeof(AppProcInfo)*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                return -1;
            }

            if (stAppProcInfoCurr.nAppId == stAppProcInfo.nAppId)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "same app(%d) exist in mem!", stAppProcInfo.nAppId);
                return 0;
            }
        }
    }

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (0 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, sizeof(AppProcInfo), i * sizeof(AppProcInfo));
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                return -1;
            }

            g_ShmUseFlag[i] = 1;
            break;
        }
    }

    return iRet;
}

static int IM_PrcMgtUpdateShmProcInfo(AppOpMsg *pstAppInfo)
{
    int iRet = 0;
    int i = 0;
    AppProcInfo stAppProcInfo;

    memset(&stAppProcInfo, 0, sizeof(AppProcInfo));
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stAppProcInfo, sizeof(AppProcInfo), sizeof(AppProcInfo)*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                return -1;
            }

            if(!strcmp(pstAppInfo->szModName, stAppProcInfo.szAppName))
            {
                iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, sizeof(AppProcInfo), i * sizeof(AppProcInfo));
                if (0 != iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                    return -1;
                }
                g_ShmUseFlag[i] = 0;
                break;
            }
        }
    }

    iRet = IM_PrcMgtBakeProcInfo();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtBakeProcInfo failed!");
        return -1;
    }

    return iRet;
}

static int IM_PrcMgtAppInstall(AppOpMsg *pstAppInfo)
{
    int iRet = 0;
    AppProcInfo stAppProcInfo;
    char szCmd[512] = {0};
    pid_t pid;
    int iPri;

    pthread_mutex_lock(&g_PrcExecuteMutex);
    memset(&stAppProcInfo, 0, sizeof(AppProcInfo));

    /* download install ipk file */
    iRet = IM_PrcMgtDownLoadFile(pstAppInfo, FILE_TYPE_INSTALL_PACKAGE);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Download ikp failed!");
       iRet = -1;
       goto Out;
    }

    /* download app info file */
    iRet = IM_PrcMgtDownLoadFile(pstAppInfo, FILE_TYPE_APP_INFO_FILE);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Download info failed!");
       iRet = -1;
       goto Out;
    }

    /* generate app process info */
    iRet = IM_PrcMgtGenProcInfo(pstAppInfo, &stAppProcInfo);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGenProcInfo failed!");
       iRet = -1;
       goto Out;
    }

    /* install ipk */
    snprintf(szCmd, sizeof(szCmd), "killall -9 %s;opkg remove %s;opkg install %s",
        stAppProcInfo.szProcName, stAppProcInfo.szAppName, PM_APP_IPK_TMP_NAME);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        iRet = -1;
        goto Out;
    }
    iRet = 0;

    /* delete ipk file after install */
    snprintf(szCmd, sizeof(szCmd), "rm -f %s", PM_APP_IPK_TMP_NAME);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        iRet = -1;
        goto Out;
    }
    iRet = 0;

    /* run process with in mem flag 1 */
    if (1 == stAppProcInfo.cInMemFlag)
    {
        snprintf(szCmd, sizeof(szCmd), "%s &", stAppProcInfo.szProcName);
        iRet = IM_System(szCmd, 1);
        if (iRet < 0)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
            iRet = -1;
            goto Out;
        }
        iRet = 0;
        
        pid = IM_PrcMgtGetPidByName(stAppProcInfo.szProcName);
        if (pid < 0)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPidByName failed!");
            iRet = -1;
            goto Out;
        }

        iRet = IM_PrcMgtGetPrcPri(pid, &iPri);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPrcPri failed!");
            iRet = -1;
            goto Out;
        }

        stAppProcInfo.nProcId = pid;
        stAppProcInfo.nProcPri = iPri;
    }

#if 0
    /* Delete prco info in boot list file */
    iRet = IM_PrcMgtDelLineInFile(PM_PROC_BOOT_LIST_FILE, stAppProcInfo.szProcName);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtDelLineInFile failed!");
        iRet = -1;
        goto Out;
    }
#endif

#if 0
    /* Add proc info to boot list file with boot flag 1*/
    if (1 == stAppProcInfo.cBootFlag)
    {
        iRet = IM_PrcMgtAddLineInFile(PM_PROC_BOOT_LIST_FILE, stAppProcInfo.szProcName);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtAddLineInFile failed!");
            iRet = -1;
            goto Out;
        }
    }
#endif
#if 1
    /* Delete proc info in share memory and bake */
    iRet = IM_PrcMgtRemoveShmProcInfo(pstAppInfo);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtRemoveShmProcInfo failed!");
        iRet = -1;
        goto Out;
    }

    /* Add proc info in share memory and bake */
    iRet = IM_PrcMgtAddShmProcInfo(stAppProcInfo);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtAddShmProcInfo failed!");
        iRet = -1;
        goto Out;
    }
#else
     /* Update proc info in share memory and bake */
    iRet = IM_PrcMgtUpdateShmProcInfo(pstAppInfo);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtUpdateShmProcInfo failed!");
        iRet = -1;
        goto Out;
    }
#endif

Out:
    pthread_mutex_unlock(&g_PrcExecuteMutex);
    return iRet;
}

static int IM_PrcMgtGetAppPrcName(AppOpMsg *pstAppInfo, char *pBuf, unsigned int nSize)
{
    int i = 0;
    int iRet = -1;
    AppProcInfo stAppProcInfo;

    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stAppProcInfo, sizeof(AppProcInfo), sizeof(AppProcInfo)*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                return -1;
            }

            if(!strcmp(pstAppInfo->szModName, stAppProcInfo.szAppName))
            {
                snprintf(pBuf, nSize, "%s", stAppProcInfo.szProcName);
                iRet = 0;
                break;
            }
        }
    }

    return iRet;
}

static int IM_PrcMgtAppUninstall(AppOpMsg *pstAppInfo)
{
    int iRet = 0, i = 0;
    char szCmd[512] = {0};
    char szPrcName[PM_APP_PROCESS_LEN] = {0};

    pthread_mutex_lock(&g_PrcExecuteMutex);

    /* find process name of the app in share memory */
    iRet = IM_PrcMgtGetAppPrcName(pstAppInfo, szPrcName, sizeof(szPrcName));
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetAppPrcName err!");
        iRet = -1;
        goto Out;
    }

    /* kill the process and remove the app */
    snprintf(szCmd, sizeof(szCmd), "killall -9 %s;opkg remove %s", 
        szPrcName, pstAppInfo->szModName);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        iRet = -1;
        goto Out;
    }
    iRet = 0;

#if 0
    /* delete info in boot list */
    iRet = IM_PrcMgtDelLineInFile(PM_PROC_BOOT_LIST_FILE, szPrcName);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtDelLineInFile failed!");
        iRet = -1;
        goto Out;
    }
#endif    
    /* Delete proc info in share memory and bake */
    iRet = IM_PrcMgtRemoveShmProcInfo(pstAppInfo);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtRemoveShmProcInfo failed!");
        iRet = -1;
        goto Out;
    }

Out:
    pthread_mutex_unlock(&g_PrcExecuteMutex);
    return iRet;
}

static int IM_PrcMgtAppUpgrade(AppOpMsg *pstAppInfo)
{
    int iRet = 0;
    AppProcInfo stAppProcInfo, stAppProcInfoOld;
    char szCmd[512] = {0};
    pid_t pid;
    int iPri;

    pthread_mutex_lock(&g_PrcExecuteMutex);
    memset(&stAppProcInfo, 0, sizeof(AppProcInfo));
    memset(&stAppProcInfoOld, 0, sizeof(AppProcInfo));

    /* download install ipk file */
    iRet = IM_PrcMgtDownLoadFile(pstAppInfo, FILE_TYPE_INSTALL_PACKAGE);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Download ikp failed!");
       iRet = -1;
       goto Out;
    }

    /* download app info file */
    iRet = IM_PrcMgtDownLoadFile(pstAppInfo, FILE_TYPE_APP_INFO_FILE);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Download info failed!");
       iRet = -1;
       goto Out;
    }

    /* generate app process info */
    iRet = IM_PrcMgtGenProcInfo(pstAppInfo, &stAppProcInfo);
    if (0 != iRet)
    {
       IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGenProcInfo failed!");
       iRet = -1;
       goto Out;
    }

    /* install ipk */
    snprintf(szCmd, sizeof(szCmd), "killall -9 %s;opkg remove %s;opkg install %s",
        stAppProcInfo.szProcName, stAppProcInfo.szAppName, PM_APP_IPK_TMP_NAME);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        iRet = -1;
        goto Out;
    }
    iRet = 0;

    /* delete ipk file after install */
    snprintf(szCmd, sizeof(szCmd), "rm -f %s", PM_APP_IPK_TMP_NAME);
    iRet = IM_System(szCmd, 1);
    if (iRet < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
        iRet = -1;
        goto Out;
    }
    iRet = 0;

    /* run process with in mem flag 1 */
    if (1 == stAppProcInfo.cInMemFlag)
    {
        snprintf(szCmd, sizeof(szCmd), "%s &", stAppProcInfo.szProcName);
        iRet = IM_System(szCmd, 1);
        if (iRet < 0)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
            iRet = -1;
            goto Out;
        }
        iRet = 0;
        
        pid = IM_PrcMgtGetPidByName(stAppProcInfo.szProcName);
        if (pid < 0)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPidByName failed!");
            iRet = -1;
            goto Out;
        }

        iRet = IM_PrcMgtGetPrcPri(pid, &iPri);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPrcPri failed!");
            iRet = -1;
            goto Out;
        }

        stAppProcInfo.nProcId = pid;
        stAppProcInfo.nProcPri = iPri;
    }
#if 0
    /* Delete prco info in boot list file */
    iRet = IM_PrcMgtDelLineInFile(PM_PROC_BOOT_LIST_FILE, stAppProcInfo.szProcName);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtDelLineInFile failed!");
        iRet = -1;
        goto Out;
    }
#endif
#if 0
    /* Add proc info to boot list file with boot flag 1*/
    if (1 == stAppProcInfo.cBootFlag)
    {
        iRet = IM_PrcMgtAddLineInFile(PM_PROC_BOOT_LIST_FILE, stAppProcInfo.szProcName);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtAddLineInFile failed!");
            iRet = -1;
            goto Out;
        }
    }
#endif
#if 1
        /* Delete proc info in share memory and bake */
        iRet = IM_PrcMgtRemoveShmProcInfo(pstAppInfo);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtRemoveShmProcInfo failed!");
            iRet = -1;
            goto Out;
        }
    
        /* Add proc info in share memory and bake */
        iRet = IM_PrcMgtAddShmProcInfo(stAppProcInfo);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtAddShmProcInfo failed!");
            iRet = -1;
            goto Out;
        }
#else
         /* Update proc info in share memory and bake */
        iRet = IM_PrcMgtUpdateShmProcInfo(pstAppInfo);
        if (0 != iRet)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtUpdateShmProcInfo failed!");
            iRet = -1;
            goto Out;
        }
#endif

Out:
    pthread_mutex_unlock(&g_PrcExecuteMutex);
    return iRet;
}

static void IM_PrcMgtSetRetMsg(char *pRetMsg, int iRet)
{
    switch (iRet)
    {
        case RET_CODE_SUCCESS:
            sprintf(pRetMsg, "%s", RET_MSG_SUCC);
            break;
        case RET_CODE_WRONG_HEAD:
            sprintf(pRetMsg, "%s", RET_MSG_WRONG_HEAD);
            break;
        case RET_CODE_WRONG_DATA:
            sprintf(pRetMsg, "%s", RET_MSG_WRONG_DATA);
            break;
        default:
            sprintf(pRetMsg, "%s", RET_MSG_UNKNOWN);
            break;
    }
}

static int IM_PrcMgtCliMsgRes(JsonHeadInfo *pstJsonHead, int iRet, int iFd)
{
    json_object *pHeadObj = NULL;
    json_object *pDataObj = NULL;
    json_object *pDataArrayObj = NULL;
    json_object *pRespObj = NULL;
    char *pRespStr = NULL;
    int iLen = 0;
    int iRslt = 0;
    char szRetMsg[128] = {0};

    pRespObj = json_object_new_object();
    /* create response json header */
    pHeadObj = json_object_new_object();
    json_object_object_add(pHeadObj, K_CMD_ID, json_object_new_int(pstJsonHead->iCmd));
    json_object_object_add(pHeadObj, K_VERSION_NUM, json_object_new_int(pstJsonHead->iVer));
    json_object_object_add(pHeadObj, K_SEQ_NUM, json_object_new_int(pstJsonHead->iSeq));
    json_object_object_add(pHeadObj, K_DEV_TYPE, json_object_new_int(pstJsonHead->iDevice));
    json_object_object_add(pHeadObj, K_APP_ID, json_object_new_int(pstJsonHead->iAppId));
    json_object_object_add(pHeadObj, K_RST_CODE, json_object_new_int(iRet));
    json_object_object_add(pHeadObj, K_SESSION_ID, json_object_new_string(pstJsonHead->szSession));
    json_object_object_add(pHeadObj, K_SIGN, json_object_new_string(pstJsonHead->szSign));
    json_object_object_add(pRespObj, K_HEAD, pHeadObj);

    /* create response json data */
    pDataObj = json_object_new_object();
    json_object_object_add(pDataObj, K_RET_CODE, json_object_new_int(iRet));
    IM_PrcMgtSetRetMsg(szRetMsg, iRet);
    json_object_object_add(pDataObj, K_RET_MSG, json_object_new_string(szRetMsg));
    pDataArrayObj = json_object_new_array();
    json_object_array_add(pDataArrayObj, pDataObj);
    json_object_object_add(pRespObj, K_DATA, pDataArrayObj);

    /* create reponse json string and send to cloud server */
    pRespStr = (char *)json_object_to_json_string(pRespObj);
    iLen = strlen(pRespStr);
    IM_MsgPrintf(pRespStr, "reply msg to cloud server", iLen, 2);
    iRslt = IM_MsgSend(iFd, pRespStr, iLen);

    /* free source */
    IM_FREE_JSON_OBJ(pHeadObj);
    IM_FREE_JSON_OBJ(pDataObj);
    IM_FREE_JSON_OBJ(pDataArrayObj);
    IM_FREE_JSON_OBJ(pRespObj);

    return iRslt;
}

static int IM_PrcMgtCliMsgPrc(char *pMsg, int iLen, int iFd)
{
    int iRet = 0;
    JsonHeadInfo *pstJsonHead = NULL;

    pstJsonHead = IM_PrcMgtCliMsgHeadParse(pMsg, iLen);
    if (NULL == pstJsonHead)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgHeadParse err!");
        iRet = -1;
        if (0 != IM_PrcMgtCliMsgRes(pstJsonHead, iRet, iFd))
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgRes err!");
        }
        goto Out;
    }

    iRet = IM_PrcMgtCliMsgDataParse(pMsg, iLen);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgDataParse err!");
        iRet = -2;
        if (0 != IM_PrcMgtCliMsgRes(pstJsonHead, iRet, iFd))
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgRes err!");
        }
        goto Out;
    }

    if (0 != IM_PrcMgtCliMsgRes(pstJsonHead, iRet, iFd))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgRes err!");
    }
    
    switch (g_stCurrMsgAppInfo.action_type)
    {
        case OPERATE_TYPE_INSTALL:
            iRet = IM_PrcMgtAppInstall(&g_stCurrMsgAppInfo);
            break;
        case OPERATE_TYPE_UNINSTALL:
            iRet = IM_PrcMgtAppUninstall(&g_stCurrMsgAppInfo);
            break;
        case OPERATE_TYPE_UPGRADE:
            iRet = IM_PrcMgtAppUpgrade(&g_stCurrMsgAppInfo);
            break;
        default:
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "wrong action type %d!", g_stCurrMsgAppInfo.action_type);
            iRet = -1;
            break;
    }

Out:
    IM_FREE(pstJsonHead);
    IM_FREE(pMsg);
    return iRet;
}

static int IM_PrcMgtPrcCli(fd_set *pFds)
{
    int iRet = 0;
    IpcAcceptFd *pstIpcAcceptFd = NULL;
    int iFd;
    char *pRevMsg = NULL;
    unsigned int nTimeOut = PM_MSG_REV_TIMEOUT;
    int iRetryCnt = 0;

    for(pstIpcAcceptFd = g_stPmFdSet.pstIpcAcceptFdList; pstIpcAcceptFd; pstIpcAcceptFd = pstIpcAcceptFd->pstNext)
    {
        if (pstIpcAcceptFd->iFd >= 0 && FD_ISSET(pstIpcAcceptFd->iFd, pFds))
        {
            iFd = pstIpcAcceptFd->iFd;
            while (TRUE)
            {
                iRet = IM_MsgReceive(iFd, &pRevMsg, &nTimeOut);
                if (iRet < 0)
                {
                    iRetryCnt++;
                    if (iRetryCnt > 10)
                    {
                        iRetryCnt = 0;
                        break;
                    }
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_MsgReceive failed!");
                    usleep(100);
                    continue;
                }
                else if (0 == iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_WARN, "IM_MsgReceive data length is 0!");
                    break;
                }
                /* Process msg recieve from mr2f */
                else
                {
                    IM_MsgPrintf((void *)pRevMsg, "message from client module", iRet, 1);

                    iRet = IM_PrcMgtCliMsgPrc(pRevMsg, iRet, iFd);
                    if (0 != iRet)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtCliMsgPrc failed!");
                    }
                    break;
                }
            }
            IM_FREE(pRevMsg);
            IM_PrcMgtDelAcpFd(iFd);
        }
    }

    return iRet;
}

static void IM_PrcMgtRun(void)
{
    int iReadFdsMax = 0;
    fd_set ReadFds;
    int iMaxFd = 0;
    struct timeval stTv;
    int iTimeOut = PM_MSG_TIMEOUT;
    int iRet = 0;
    
    while (TRUE)
    {
        FD_ZERO(&ReadFds);
        
        if (g_stPmFdSet.iIpcListenFd >= 0)
        {
            FD_SET(g_stPmFdSet.iIpcListenFd, &ReadFds);
            iReadFdsMax = g_stPmFdSet.iIpcListenFd;
        }

        if (g_stPmFdSet.iIpcMr2fFd >= 0)
        {
            FD_SET(g_stPmFdSet.iIpcMr2fFd, &ReadFds);
            if (iReadFdsMax < g_stPmFdSet.iIpcMr2fFd)
            {
                iReadFdsMax = g_stPmFdSet.iIpcMr2fFd;
            }
        }

        iMaxFd = IM_PrcMgtAddFd2FdSet(&ReadFds);
        if(iMaxFd > iReadFdsMax)
        {
            iReadFdsMax = iMaxFd;
        }

        stTv.tv_sec = iTimeOut;
        stTv.tv_usec = 0;
        errno = 0;
        
        iRet = select(iReadFdsMax + 1, &ReadFds, NULL, NULL, &stTv);
        if (iRet < 0)
        {
            if (errno == EINTR)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "select EINTR!");
                continue;
            }
            else
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "select fail, reason:%s!", strerror(errno)); 
                break;
            }
        }
        else if (0 == iRet)
        {
            /* time out */
            continue;
        }

        /* process the message */
        if(NULL != g_stPmFdSet.pstIpcAcceptFdList)
        {
            /* process messages form client */
            if (0 != IM_PrcMgtPrcCli(&ReadFds))
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtPrcCli fail!");
            }
        }
        if(g_stPmFdSet.iIpcListenFd >= 0 && FD_ISSET(g_stPmFdSet.iIpcListenFd, &ReadFds))
        {
            IM_PrcMgtAddFd2FdList(g_stPmFdSet.iIpcListenFd);
        }
        if(g_stPmFdSet.iIpcMr2fFd >= 0 && FD_ISSET(g_stPmFdSet.iIpcMr2fFd, &ReadFds))
        {
            ;/* TODO: message from MR2FC. */
        }
    }
}

static void IM_PrcMgtCloseAllAccepts(void)
{
    IpcAcceptFd *p, *q;

    for(p = g_stPmFdSet.pstIpcAcceptFdList; p;)
    {       
        q = p;
        p = p->pstNext;
        close(q->iFd);
        free(q);
    }
    g_stPmFdSet.pstIpcAcceptFdList = NULL;
}

static void IM_PrcMgtDeinit(void)
{
    IM_PosixShmDestroy(PM_SHM_NAME, PM_SHM_SEM_NAME);
    IM_PosixShmSemDestroy(PM_SHM_SEM_NAME);
    IM_PrcMgtCloseAllAccepts();
    IM_DomainServerDeinit(g_stPmFdSet.iIpcListenFd);
    IM_DomainClientDeinit(g_stPmFdSet.iIpcMr2fFd);
}

#if 0
static void IM_PrcMgtSigRoutine(int iSigNo)
{ 
   switch (iSigNo)
   { 
       case SIGALRM:
           g_OnStat = 0;
           break; 
       case SIGVTALRM: 
           break; 
        default:
            break;
   } 
}

static int IM_PrcMgtTimerInit(void)
{
    struct itimerval stValue, stOvalue; 
    struct sigaction stAct;  

    sigemptyset(&stAct.sa_mask);
    stAct.sa_flags = SA_RESTART;
    stAct.sa_handler = IM_PrcMgtSigRoutine;
    if (sigaction(SIGALRM, &stAct, NULL) < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "PM install signal fail!");
        return -1;
    }
    
    stValue.it_value.tv_sec = 0; 
    stValue.it_value.tv_usec = PM_TIMER_BASE;
    stValue.it_interval.tv_sec = 0; 
    stValue.it_interval.tv_usec = PM_TIMER_BASE;
    setitimer(ITIMER_REAL, &stValue, &stOvalue); 
 
    return 0;
}
#else
static void IM_PrcMgtSigRoutine(int iSigNo)
{
    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "timer signal");
    if (iSigNo != SIGALRM)
    {
        return;
    }

    g_OnStat = 0;
    alarm(PM_TIMER_BASE);
}

static int IM_PrcMgtTimerInit(void)
{
    struct sigaction sa;

    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigaddset(&sa.sa_mask, SIGPIPE);
    sigaddset(&sa.sa_mask, SIGALRM);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = IM_PrcMgtSigRoutine;
    sigaction(SIGALRM, &sa, NULL);
}
#endif
static int IM_PrcMgtRegTimer(unsigned char ucType, unsigned long ulStart, unsigned long ulPeriod, void (*pfnProc)(void *), void *pArgs, unsigned long ulArgsLen)
{
    int iRet = 0;
    void *pTemArgs = NULL;
    int iCurrentTimer = 0; /* 当前定时器 */

    /* 入参判断 */
    if (NULL == pfnProc)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "no timer process func!");
        iRet = -1;
        goto EXIT;
    }

    /* 分配私有数据 */
    if ((NULL != pArgs) && (ulArgsLen > 0))
    {
        pTemArgs = malloc(ulArgsLen);
        if (NULL == pTemArgs)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "malloc fail!");
            iRet = -2;
            goto EXIT;
        }
        memcpy(pTemArgs, pArgs, ulArgsLen);
    }


    while (iCurrentTimer < PM_MAX_TIMERS)
    {
        if (1 == g_PmTimers[iCurrentTimer].ucEnable) /* 当前定时器已使用 */
        {
            iCurrentTimer ++; /* 下一个 */
            continue;
        }

        /* 分配定时器 */
        g_PmTimers[iCurrentTimer].ulStart = ulStart;        
        g_PmTimers[iCurrentTimer].ulPeriod = ulPeriod;
        g_PmTimers[iCurrentTimer].ulCount = g_PmTick + ulStart + ulPeriod; /* 到期tick */
        g_PmTimers[iCurrentTimer].pfnTimerProc = pfnProc;
        g_PmTimers[iCurrentTimer].pArgs = pTemArgs;
        g_PmTimers[iCurrentTimer].ucTimerType = ucType;
        g_PmTimers[iCurrentTimer].ucEnable = 1;
        break;
    }

    if (PM_MAX_TIMERS == iCurrentTimer) /* 定时器个数已满，不能注册新定时器 */
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "timer full!");
        iRet = -3;
        goto EXIT;        
    }

    iRet = iCurrentTimer;

EXIT:
    return iRet;
}

#if 0
static int IM_PrcMgtDetectLive(pid_t Pid)
{
    int iRet = 0;
    char szCmd[128] = {0};
    
    if (Pid < 0)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "invalid pid:%d", Pid);
        return -1;
    }

    iRet = kill(Pid, 0);
    if (iRet < 0 && ESRCH == errno)
    {
        snprintf(szCmd, sizeof(szCmd) - 1, "kill -9 %d", Pid);
        if (IM_System(szCmd, 1) < 0)
        {
            IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
            return -2;
        }
        iRet = -1;
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "process is not available, pid:%d!", Pid);
    }

    return iRet;
}
#else
static int IM_PrcMgtDetectLive(char *process_name)
{
    FILE* fp = NULL;
    char buff[512] = {0};
    char cmd[128] = {0};
    
    snprintf(cmd, sizeof(cmd) - 1, "ps | grep -c %s", process_name);
    fp = popen(cmd, "r");
    if (!fp)
    {
    	return -2;
    }

    fgets(buff, sizeof(buff) - 1, fp);
	if (buff[strlen(buff)-1] == 0x0a)
		buff[strlen(buff)-1] = '\0';
    pclose(fp);
    
    if (atoi(buff) > 2)
    {
        return atoi(buff);
    }
    
    return -1;
}
#endif
#if 0
static void IM_PrcMgtMonitorTask(void *pArg)
{
    int i = 0;
    int iRet = 0;
    AppProcInfo stAppProcInfo;
    int iItemLen = sizeof(AppProcInfo);
    char szCmd[128] = {0};
    int Pid = -1;
    int iPri = 0;

    pthread_mutex_lock(&g_PrcExecuteMutex);
    for (i = 0; i < PROC_INFO_SHM_NUM; i++)
    {
        if (1 == g_ShmUseFlag[i])
        {
            iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                (char *)&stAppProcInfo, iItemLen, iItemLen*i);
            if (0 != iRet)
            {
                IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                break;
            }

            iRet = IM_PrcMgtDetectLive(stAppProcInfo.nProcId);
            if (iRet < 0)
            {
                if (-2 == iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "system failed!");
                    break;
                }
                
                snprintf(szCmd, sizeof(szCmd) - 1, "%s &", stAppProcInfo.szProcName);
                if (IM_System(szCmd, 1) < 0)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
                    break;
                }

                Pid = IM_PrcMgtGetPidByName(stAppProcInfo.szProcName);
                if (Pid < 0)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPidByName failed!");
                    break;
                }
                stAppProcInfo.nProcId = Pid;

                iRet = IM_PrcMgtGetPrcPri(Pid, &iPri);
                if (0 != iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPrcPri failed!");
                    break;
                }
                stAppProcInfo.nProcPri = iPri;

                iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, iItemLen, i * iItemLen);
                if (0 != iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_PrcExecuteMutex);
}
#else
static void IM_PrcMgtMonitorTask(void)
{
    int i = 0;
    int iRet = 0;
    AppProcInfo stAppProcInfo;
    int iItemLen = sizeof(AppProcInfo);
    char szCmd[128] = {0};
    int Pid = -1;
    int iPri = 0;

    while (1)
    {
        sleep(PM_PRC_DETECT_INTERVAL);
        pthread_mutex_lock(&g_PrcExecuteMutex);
        for (i = 0; i < PROC_INFO_SHM_NUM; i++)
        {
            if (1 == g_ShmUseFlag[i])
            {
                memset(&stAppProcInfo, 0, sizeof(AppProcInfo));
                iRet = IM_PosixShmRead(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                    (char *)&stAppProcInfo, iItemLen, iItemLen * i);
                if (0 != iRet)
                {
                    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmRead failed!");
                    break;
                }

                if (1 != stAppProcInfo.cInMemFlag)
                {
                    continue;
                }

                iRet = IM_PrcMgtDetectLive(stAppProcInfo.szProcName);
                if (iRet < 0)
                {
                    if (-2 == iRet)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "system failed!");
                        break;
                    }

                    /* kill before restart */
                    snprintf(szCmd, sizeof(szCmd) - 1, "killall -9 %s", stAppProcInfo.szProcName);
                    if (IM_System(szCmd, 1) < 0)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
                        break;
                    }
                    
                    snprintf(szCmd, sizeof(szCmd) - 1, "%s &", stAppProcInfo.szProcName);
                    if (IM_System(szCmd, 1) < 0)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_System failed!");
                        break;
                    }

                    Pid = IM_PrcMgtGetPidByName(stAppProcInfo.szProcName);
                    if (Pid < 0)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPidByName failed!");
                        break;
                    }
                    stAppProcInfo.nProcId= Pid;

                    iRet = IM_PrcMgtGetPrcPri(Pid, &iPri);
                    if (0 != iRet)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtGetPrcPri failed!");
                        break;
                    }
                    stAppProcInfo.nProcPri = iPri;

                    iRet = IM_PosixShmWrite(PM_SHM_SEM_NAME, PM_SHM_NAME, 
                        (char *)&stAppProcInfo, iItemLen, i * iItemLen);
                    if (0 != iRet)
                    {
                        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PosixShmWrite failed!");
                        break;
                    }
                    
                    /* Dump current app info */
                    IM_PrcMgtPrcsIfoDump();
                }
            }
        }
        pthread_mutex_unlock(&g_PrcExecuteMutex);
    }
    pthread_exit(NULL);
}
#endif
static int IM_PrcMgtTimersReg(void)
{
    int iRet = 0;
    int iTimerPeriod = 5 * PM_TIMER_BASE;
    
    iRet = IM_PrcMgtRegTimer(CIRCLE_TIMER, 0, iTimerPeriod, IM_PrcMgtMonitorTask, NULL, 0);
    if (0 > iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_PrcMgtRegTimer fail!");
        return iRet;
    }

    return iRet;
}

static void IM_PrcMgtDelTimer(int iTimerHandle)
{
    /* 参数有效性判断 */
    if ((iTimerHandle < 0) || (iTimerHandle >= PM_MAX_TIMERS))
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "error:bad timer handle.");
        return;
    }

    IM_FREE(g_PmTimers[iTimerHandle].pArgs);

    /* 清除定时器配置 */
    g_PmTimers[iTimerHandle].ulCount = 0; 
    g_PmTimers[iTimerHandle].ulStart = 0; 
    g_PmTimers[iTimerHandle].ulPeriod = 0;
    g_PmTimers[iTimerHandle].pfnTimerProc = NULL;
    g_PmTimers[iTimerHandle].pArgs = NULL;
    g_PmTimers[iTimerHandle].ucTimerType = 0;
    g_PmTimers[iTimerHandle].ucEnable = 0;
}

static void IM_PrcMgtDestroyTimer(void)
{
    int i;

    for (i=0; i < PM_MAX_TIMERS; i++)
    {
        IM_PrcMgtDelTimer(i);
    }
}

static void IM_PrcMgtRunTimer(void)
{
    int i;
    
    g_PmTick ++;
    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "PM timer g_PmTick:%d", g_PmTick);
    for (i = 0; i < PM_MAX_TIMERS; i++)
    {
        /* 定时器时间到 */
        if ((g_PmTimers[i].ucEnable) && (g_PmTick >= g_PmTimers[i].ulCount)) 
        {
            g_PmTimers[i].pfnTimerProc(g_PmTimers[i].pArgs); /* 运行回调函数 */

            if (ONE_TIME_TIMER == g_PmTimers[i].ucTimerType) /*一次性定时器，到期删除 */
            {
                IM_PrcMgtDelTimer(i);
            }
            else /* 周期性定时器，找到下一次到期tick */
            {
                g_PmTimers[i].ulCount = g_PmTick + g_PmTimers[i].ulPeriod;
            }
        }       
    }

    /* 防止 tick 反转，一般不进入此分支，如果PM_TIMER_BASE为200*1000 (200ms)，则约4900天进入一次 */
    if (g_PmTick > 0xffffffff/2)
    {
        for (i=0; i < PM_MAX_TIMERS; i++)
        {
            if (g_PmTimers[i].ucEnable)
            {
                g_PmTimers[i].ulCount = g_PmTimers[i].ulCount - g_PmTick; /*重新计算到期时间*/
            }
        }
        
        g_PmTick = 0; 
    }
    
    return;
}

static void IM_PrcMgtTimersProcess(void)
{
    int iRet = 0;

    /* init timer for process monitoring */
    iRet = IM_PrcMgtTimerInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "PM timer init fail!");
        goto Exit;
    }

    /* regidet timers for process monitoring */
    iRet = IM_PrcMgtTimersReg();
    if (0 > iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "PM timer regidet fail!");
        goto Exit;
    }

    /* run time wheel */
    while (!g_StopFlg)
    {
#if 0
        /* wait until tick arrived */
        if (1 == g_OnStat) 
        {

            /* wake up only timer interrupt */
            pause(); 
            continue;
        }
#else
        if (1 == g_OnStat)
        {
            continue;
        }
#endif
        g_OnStat = 1;
        
        /* run time wheel */
        IM_PrcMgtRunTimer(); 
    }
    iRet = 0;
    
Exit:
    IM_PrcMgtDestroyTimer();
    pthread_exit(0);
}

int main(int iArgc, const char *pszArgv[])
{
    int iRet = 0;
    pthread_t DetectTid;

    IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_INFO, "prc_mgt version:%s!", PRC_MGT_VER);

    /* init daemon */
    iRet = IM_DaemonInit(0, 0);
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "IM_DaemonInit fail!");
        goto Out;
    }

    /* init process management */
	iRet = IM_PrcMgtInit();
    if (0 != iRet)
    {
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "PM modul init fail!");
        goto Exit;
    }
#if 0
    /* task for timers */
    if (0 != (iRet = pthread_create(&DetectTid, NULL, (void *)IM_PrcMgtTimersProcess, NULL)))
    { 
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Create timer prcs thread failed!");
        iRet = -1;
        goto Exit;
    }
    pthread_detach(DetectTid);
#else
    /* task for detect process */
    if (0 != (iRet = pthread_create(&DetectTid, NULL, (void *)IM_PrcMgtMonitorTask, NULL)))
    { 
        IM_PM_LOG(IM_PM_LOG_FLAG, IM_PM_LOG_ERR, "Create timer prcs thread failed!");
        iRet = -1;
        goto Exit;
    }
    pthread_detach(DetectTid);
#endif    
    /* run process manage:main loop */
    IM_PrcMgtRun();

Exit:
    IM_PrcMgtDeinit();

Out:
	return iRet;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */
