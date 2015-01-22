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
#
*************************************************************************/

#ifdef __cplusplus
#if __cplusplus
    extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */

#include "shm.h"

/******************************************************************************
 *                         PRIVATE FUNCTIONS                                  *
 ******************************************************************************/
static SINT32 IM_PosixSemCreat(const SINT8 *pSemName);
static SINT32 IM_PosixSemDestroy(const SINT8 *pSemName);
static sem_t *IM_PosixSemOpen(const SINT8 *pSemName);
static SINT32 IM_PosixSemClose(sem_t *pSem);
static SINT32 IM_PosixSemLock(sem_t *pSem);
static SINT32 IM_PosixSemUnlock(sem_t *pSem);

/******************************************************************************
 *                               FUNCTIONS                                    *
 ******************************************************************************/
static SINT32 IM_PosixSemCreat(const SINT8 *pSemName)
{
    sem_t *pSem;
    SINT32 iRet;

    if (NULL == pSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore name is null!");
        return -1;
    }
    
    pSem = sem_open(pSemName, O_CREAT, 0644, 1);
    if (SEM_FAILED == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Creat semaphore failed. Name: %s, Reason: %s", 
            pSemName, strerror(errno));
        return -1;
    }
    
    iRet = sem_close(pSem);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_close failed. Reason: %s", 
            strerror(errno));
        return -1;
    }
    
    return 0;
}

static SINT32 IM_PosixSemDestroy(const SINT8 *pSemName)
{
    sem_t *pSem;
    SINT32 iRet;

    if (NULL == pSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore name is null!");
        return -1;
    }
    
    pSem = sem_open(pSemName, 0);
    if (SEM_FAILED == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Open semaphore failed. Name: %s, Reason: %s", 
            pSemName, strerror(errno));
        return -1;
    }
    
    iRet = sem_close(pSem);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_close failed. Reason: %s", 
            strerror(errno));
        return -1;
    }

    iRet = sem_unlink(pSemName);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_unlink failed. Reason: %s", 
            strerror(errno));
        return -1;
    }
    
    return 0;
}

static sem_t *IM_PosixSemOpen(const SINT8 *pSemName)
{
    sem_t *pSem;

    if (NULL == pSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore name is null!");
        return NULL;
    }
    
    pSem = sem_open(pSemName, 0);
    if (SEM_FAILED == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Open semaphore %s failed. Reason: %s", 
            pSemName, strerror(errno));
        return NULL;
    }
    
    return pSem;
}

static SINT32 IM_PosixSemClose(sem_t *pSem)
{
    SINT32 iRet;

    if (NULL == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore ptr is null!");
        return -1;
    }
    
    iRet = sem_close(pSem);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_close failed. Reason: %s", 
            strerror(errno));
        return -1;
    }
    
    return 0;
}

static SINT32 IM_PosixSemLock(sem_t *pSem)
{
    SINT32 iRet;

    if (NULL == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore ptr is null!");
        return -1;
    }
    
    iRet = sem_wait(pSem);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_wait failed. Reason: %s", 
            strerror(errno));
        return -1;
    }
    
    return 0;
}

static SINT32 IM_PosixSemUnlock(sem_t *pSem)
{
    SINT32 iRet;

    if (NULL == pSem)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Semaphore ptr is null!");
        return -1;
    }
    
    iRet = sem_post(pSem);
    if (-1 == iRet)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Call sem_post failed, this is FATAL, maybe cause deadlock. Reason: %s", 
            strerror(errno));
        return -1;
    }
    
    return 0;
}

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
SINT32 IM_PosixShmCreat(UINT32 nShmSize, const SINT8 *pShmName)
{
    SINT32 iFd;
    SINT32 iRet;
    SINT8 *pShm;

    if (NULL == pShmName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory name is null!");
        return -1;
    }
    
    iFd = shm_open(pShmName, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (iFd < 0)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Creat writable share memory fail!  name:%s.", 
            pShmName);
        return -1;
    }
    ftruncate(iFd, nShmSize);
    
    pShm = mmap(NULL, nShmSize, PROT_READ | PROT_WRITE, MAP_SHARED, iFd, 0);
    close(iFd);
    if (MAP_FAILED == pShm)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory map error!");
        return -1;
    }

    iRet = munmap(pShm, nShmSize);  
    if (iRet < 0)
    {  
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "munmap error:%s", 
            strerror(errno)); 
        return -1; 
    }  
  
    return 0;
}

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
SINT32 IM_PosixShmDestroy(const SINT8 *pShmName, const SINT8 *pShmSemName)
{
    SINT32 iRet;
    sem_t *pSem;

    if (NULL == pShmName || NULL == pShmSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory name or share memory semaphore name is null!");
        return -1;
    }

    pSem = IM_PosixSemOpen(pShmSemName);
    if (NULL == pSem)
        return -1;
    
    iRet = IM_PosixSemLock(pSem);
    if (iRet < 0)
        return -1;
    
    iRet = shm_unlink(pShmName);
    if (iRet < 0)
        return -1;
    
    iRet = IM_PosixSemUnlock(pSem);
    if (iRet < 0)
        return -1;

    iRet = IM_PosixSemClose(pSem);
    if (iRet < 0)
        return -1;

    return 0;
}

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
    SINT8 *pRetBuf, UINT32 nReadLen, UINT32 nOffset)
{
    sem_t *pSem;
    SINT8 *pShm;
    SINT32 iRet;
    SINT32 iFd;
    struct stat stFileStat;

    if (NULL == PShmName || NULL == pShmSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory name or share memory semaphore name is null!");
        return -1;
    }

    if (NULL == pRetBuf)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "ret_buf is NULL!");
        return -1;
    }

    pSem = IM_PosixSemOpen(pShmSemName);
    if (NULL == pSem)
        return -1;

    iRet = IM_PosixSemLock(pSem);
    if (iRet < 0)
        return -1;
    
    iFd = shm_open(PShmName, O_RDONLY, 0);
    if (iFd < 0)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Open share memory fail!  name:%s.", 
            PShmName);
        return -1;
    }
    fstat(iFd, &stFileStat);
    
    pShm = (SINT8 *)mmap(NULL, stFileStat.st_size, PROT_READ, MAP_SHARED, iFd, 0);
    close(iFd);
    if (MAP_FAILED  == pShm)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory map error!");
        return -1;
    }

    if (nReadLen > stFileStat.st_size)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Read length larger than share memory size!");
        return -1;
    }

    memcpy(pRetBuf, pShm + nOffset, nReadLen);

    iRet = munmap(pShm, stFileStat.st_size);  
    if (iRet < 0)
    {  
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "munmap error:%s", 
            strerror(errno)); 
        return -1; 
    }  
    
    iRet = IM_PosixSemUnlock(pSem);
    if (iRet < 0)
        return -1;

    iRet = IM_PosixSemClose(pSem);
    if (iRet < 0)
        return -1;

    return 0;
}

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
    SINT8 *pFromBuf, UINT32 nWriteLen, UINT32 nOffset)
{
    sem_t *pSem;
    SINT8 *pShm;
    SINT32 iRet;
    SINT32 iFd;
    struct stat stFileStat;

    if (NULL == pShmName || NULL == pShmSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory name or share memory semaphore name is null!");
        return -1;
    }

    if (NULL == pFromBuf)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "ret_buf is NULL!");
        return -1;
    }

    pSem = IM_PosixSemOpen(pShmSemName);
    if (NULL == pSem)
        return -1;

    iRet = IM_PosixSemLock(pSem);
    if (iRet < 0)
        return -1;
    
    iFd = shm_open(pShmName, O_RDWR, 0);
    if (iFd < 0)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Open share memory fail!  name:%s.", 
            pShmName);
        return -1;
    }
    fstat(iFd, &stFileStat);
    
    pShm = (SINT8 *)mmap(NULL, stFileStat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, iFd, 0);
    close(iFd);
    if (pShm  == MAP_FAILED)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory map error!");
        return -1;
    }

    if (nWriteLen > stFileStat.st_size)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Write length larger than share memory size!");
        return -1;
    }
 
    memcpy(pShm + nOffset, pFromBuf, nWriteLen);

    iRet = munmap(pShm, stFileStat.st_size);
    if (iRet < 0)
    {  
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "munmap error:%s", 
            strerror(errno)); 
        return -1; 
    }  
    
    iRet = IM_PosixSemUnlock(pSem);
    if (iRet < 0)
        return -1;

    iRet = IM_PosixSemClose(pSem);
    if (iRet < 0)
        return -1;

    return 0;
}

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
SINT32 IM_PosixShmSemCreat(const SINT8 *pShmSemName)
{
    SINT32 iRet;

    if(NULL == pShmSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory semaphore name is null!");
        return -1;
    }    
    
    iRet = IM_PosixSemCreat(pShmSemName);
    if(iRet < 0)
        return -1;

    return 0;
}

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
SINT32 IM_PosixShmSemDestroy(const SINT8 *pShmSemName)
{
    SINT32 iRet;

    if (NULL == pShmSemName)
    {
        IM_SHM_LOG(IM_SHM_LOG_FLAG, IM_SHM_LOG_ERR, "Share memory semaphore name is null!");
        return -1;
    }    
    
    iRet = IM_PosixSemDestroy(pShmSemName);
    if (iRet < 0)
        return -1;

    return 0;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */
