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

#ifndef __MSG_H__
#define __MSG_H__

/******************************************************************************
 *                               INCLUDES                                     *
 ******************************************************************************/

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

/* Definitions for some generic name and path. */
#define APP_MESSAGE_PATH            "/tmp/app_messaging_server_addr/"

/*
 * This is the number of fully connected connections that can be queued
 *  up at the message server socket.
 *
 *  It is highly unlikely that this needs to be changed.
 */
#define APP_MESSAGE_BACKLOG  3

/* MSG lib debug macro. */
#define IM_MSG_LOG_ERR              0x00000001
#define IM_MSG_LOG_WARN             0x00000002
#define IM_MSG_LOG_INFO             0x00000004
#define IM_MSG_LOG_TRACE            0x00000008

/* Default, print the first three levels log */
#define IM_MSG_LOG_FLAG             0x00000007

#define IM_LOG(IMLogFlag, IMLogLevel, fmt, args...) do { \
    if ((IMLogFlag) & (IMLogLevel)) { \
        FILE *fp = fopen("/dev/console", "w"); \
    	if (fp) { \
            fprintf(fp, "[IM_MSG][%s]-%d ", __FUNCTION__, __LINE__); \
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

/** Number of micro-seconds in a milli-second. */
#define USECS_IN_MSEC 1000

/** Number of milliseconds in 1 second */
#define MSECS_IN_SEC  1000

/** Invalid file descriptor number. */
#define MSG_INVALID_FD  (-1)

/** Free a buffer and set the pointer to null. */
#define IM_FREE(p) \
   do { \
      if ((p) != NULL) {free((p)); (p) = NULL;}   \
   } while (0)

#define flags_event        flags.bits.event                         /**< Convenience macro for accessing event bit in msg hdr */
#define flags_request      flags.bits.request                       /**< Convenience macro for accessing request bit in msg hdr */
#define flags_response     flags.bits.response                      /**< Convenience macro for accessing response bit in msg hdr */
#define EMPTY_MSG_HEADER   {{0}, {0}, {0}, {0}, 0, 0, 0, 0, 0}      /**< Initialize msg header to empty */

/* Size definition for APP process information table's member. */
#define APP_NAME_LEN        64
#define CPD_NAME_LEN        64
#define APP_PROCESS_LEN     64
#define CONFIG_PATH_LEN     128
#define CONFIG_PATH_LEN     128
#define CONFIG_CMD_LEN      256
#define MSG_ID_LEN          36

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

/* MSG lib return value definition. */
typedef enum
{
	MSGRET_SUCCESS              = 0,
	MSGRET_RESOURCE_EXCEEDED    = -9001,
	MSGRET_INTERNAL_ERROR       = -9002,
	MSGRET_DISCONNECTED         = -9003,
	MSGRET_TIMED_OUT            = -9004,
	MSGRET_INVALID_ARGUMENTS    = -9005,
}MsgRet;

/* MSG header action type definition. */
typedef enum
{
    ACTION_SET = 1,
    ACTION_GET = 2,
    ACTION_ADD = 3,
    ACTION_DEL = 4,
}ActionType;

/******************************************************************************
 *                                STRUCT                                      *
 ******************************************************************************/

/*
 * This header must be at the beginning of every message.
 * The header may then be followed by additional optional data.
 */
typedef struct msg_header
{
   SINT8 src[APP_NAME_LEN];     /**< Source APP's name. */
   SINT8 dst[APP_NAME_LEN];     /**< Destination APP's name, maybe include submodule name with the dot separated. */
   SINT8 messageId[MSG_ID_LEN]; /**< Effective length is 32, from cloud server and return to it the same. */
   union {
      UINT16 all;     /**< All 16 bits of the flags at once. */
      struct {
         UINT16 event:1;    /**< This is a event msg. */
         UINT16 request:1;  /**< This is a request msg. */
         UINT16 response:1; /**< This is a response msg. */
         UINT16 unused:13;  /**< For future expansion. */
      } bits;
   } flags;  /**< Modifiers to the type of message. */
   ActionType actionType;     /**< Action type :  set, get, add, del. */
   UINT16 sequenceNumber;     /**< "Optional", but read the explanation below.
                               *
                               * Senders of request or event message types
                               * are free to set this to whatever
                               * they want, or leave it uninitialized.  Senders
                               * are not required to increment the sequence
                               * number with every new message sent.
                               * However, response messages must 
                               * return the same sequence number as the
                               * request message.
                               * 
                               */
   struct msg_header *next;   /**< Allows MsgHeaders to be chained. */
   UINT32 wordData;   /**< As an optimization, allow one word of user
                       *   data in msg hdr.
                       *
                       * For messages that have only one word of data,
                       * we can just put the data in this field.
                       * One good use is for response messages that just
                       * need to return a status code.  The message type
                       * determines whether this field is used or not.
                       */
   UINT32 dataLength; /**< Amount of data following the header.  0 if no additional data. */
} MsgHeader;

/******************************************************************************
 *                               FUNCTION                                     *
 ******************************************************************************/

/** Internet socket **/

/*******************************************************************************
 * Function:
 *    SINT32 IM_InetServerInit(SINT32 iDomain, SINT32 iPort, SINT32 iType, SINT32 iBackLog)
 * Description:
 *    This function creates and initializes a TCP or UDP listening socket
 *    for an application.
 * Parameters:
 *    iDomain  (IN) Specifies whether it is a client-side socket or 
 *                  server-side socket.
 *    iPort    (IN) The application TCP or UDP port.
 *    iType    (IN) The socket type, either SOCK_STREAM or SOCK_DGRAM.
 *    iBackLog (IN) Number of connections to queue. 
 * Returns:
 *    The socket file descriptor
 *******************************************************************************/
SINT32 IM_InetServerInit(SINT32 iDomain, SINT32 iPort, SINT32 iType, SINT32 iBackLog);

/*******************************************************************************
 * Function:
 *    void IM_InetServerDeinit(SINT32 iFd)
 * Description:
 *    This function deinit the socket created for internet server
 * Parameters:
 *    iFd    (IN) The socket file descriptor 
 * Returns:
 *    void
 *******************************************************************************/
void IM_InetServerDeinit(SINT32 iFd);

/** Domain socket **/
/*******************************************************************************
 * Function:
 *    SINT32 IM_DomainServerInit(const SINT8 *pName)
 * Description:
 *    This function creates a socket, binds server with path and listen
 * Parameters:
 *    pName   (IN) Name of process used as a server 
 * Returns:
 *    The socket file descriptor
 *******************************************************************************/
SINT32 IM_DomainServerInit(const SINT8 *pName);

/*******************************************************************************
 * Function:
 *    void IM_DomainServerDeinit(SINT32 iFd)
 * Description:
 *    This function deinit the socket created for domain(local) server
 * Parameters:
 *    iFd    (IN) The socket file descriptor 
 * Returns:
 *    void
 *******************************************************************************/
void IM_DomainServerDeinit(SINT32 iFd);

/*******************************************************************************
 * Function:
 *    SINT32 IM_DomainClientInit(const SINT8 *pServerName)
 * Description:
 *    This function creates a socket, connects to server
 * Parameters:
 *    pServerName   (IN) Name of server process 
 * Returns:
 *    The socket file descriptor
 *******************************************************************************/
SINT32 IM_DomainClientInit(const SINT8 *pServerName);

/*******************************************************************************
 * Function:
 *    void IM_DomainClientDeinit(SINT32 iFd)
 * Description:
 *    This function deinit the socket created for domain(local) client
 * Parameters:
 *    iFd    (IN) The socket file descriptor 
 * Returns:
 *    void
 *******************************************************************************/
void IM_DomainClientDeinit(SINT32 iFd);

/*******************************************************************************
 * Function:
 *    SINT32 IM_ServerAcceptClient(SINT32 iListenFd)
 * Description:
 *    Before server recieve or send message,server should accept a client
 * Parameters:
 *    iFd    (IN) The listening socket file descriptor 
 * Returns:
 *    The accept socket file descriptor
 *******************************************************************************/
SINT32 IM_ServerAcceptClient(SINT32 iListenFd);

/*******************************************************************************
 * Function:
 *    UINT32 IM_MsgSend(SINT32 iFd, const SINT8 *pBuf, UINT32 nLen)
 * Description:
 *    Use this function,client send message to server,
 *    or server send response message to client
 * Parameters:
 *    iFd    (IN) The socket file descriptor used to send message
 *    pBuf   (IN) Message for sending 
 *    nLen   (IN) Message length
 * Returns:
 *    The sending result
 *    0:success;others,error
 *******************************************************************************/
UINT32 IM_MsgSend(SINT32 iFd, const SINT8 *pBuf, UINT32 nLen);

/*******************************************************************************
 * Function:
 *    UINT32 IM_MsgReceive(SINT32 iFd, SINT8 **pBuf, UINT32 *pnTimeOut)
 * Description:
 *    Use this function,server recieve message from client,
 *    or client recieve response message from server
 * Parameters:
 *    iFd         (IN)  The socket file descriptor used to recieve message
 *    pBuf        (OUT) The recieve message buf 
 *    pnTimeOut   (IN)  Timeout for recieving
 * Returns:
 *    When > 0,the recieved message bytes;or not,recieve error
 *******************************************************************************/
UINT32 IM_MsgReceive(SINT32 iFd, SINT8 **pBuf, UINT32 *pnTimeOut);

/*******************************************************************************
 * Function:
 *    void IM_TimeToString(time_t stWhen, SINT8 *pBuffer, UINT32 nSize)
 * Description:
 *    convert time to string
 * Parameters:
 *    stWhen      (IN)  The time
 *    pBuffer     (OUT) String buffer 
 *    nSize       (IN)  Size of string buffer
 * Returns:
 *    void
 *******************************************************************************/
void IM_TimeToString(time_t stWhen, SINT8 *pBuffer, UINT32 nSize);

/*******************************************************************************
 * Function:
 *    void IM_MsgPrintf(const void *pBuf, SINT8 *pszDscrptn, UINT32 nLen, SINT32 iFlag)
 * Description:
 *    printf message recieved or for sending
 * Parameters:
 *    pBuf        (IN)  Message buf
 *    pszDscrptn  (IN)  Message description 
 *    nLen        (IN)  Message length
 *    iFlag       (IN)  Message flag:1,RX;2:TX;other,unkown
 * Returns:
 *    void
 *******************************************************************************/
void IM_MsgPrintf(const void *pBuf, SINT8 *pszDscrptn, UINT32 nLen, SINT32 iFlag);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif /* __MSG_H__ */
