/*
 * =============================================================================
 *
 *       Filename:  thread_pool.c
 *
 *    Description:  longsys sever module.
 *
 *        Version:  1.0
 *        Created:  2014/10/29 14:51:25
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Oliver (), 515296288jf@163.com
 *   Organization:  
 *
 * =============================================================================
 */
#include "msg_server.h"


Thread_pool * pool_init(int thread_max_num )
{
  Thread_pool *pool = NULL;
  pool = (Thread_pool *)malloc(sizeof(Thread_pool));
  pthread_mutex_init(&(pool->pool_mutex),NULL);
  pthread_cond_init(&(pool->pool_cond),NULL);
  pool->is_destory = 0;
  pool->worker_queue_head = NULL;
  pool->thread_max_num = thread_max_num;
  pool->cur_queue_size = 0;
  pool->thread_id = (pthread_t *)malloc(sizeof(pthread_t)*thread_max_num);
  
  int i = 0;  
  int thread_ret = 0;
  for (; i < thread_max_num; i++)  
  {	
  	 thread_ret = pthread_create(&(pool->thread_id[i]), NULL, thread_routine, pool);
	 if(thread_ret != 0)
	 {
		p_debug("DM starting thread 0x%x",thread_ret);
	 }
  }
  return pool; 
}
void * thread_routine(Thread_pool *pool)
{
  p_debug("DM starting thread 0x%x", pthread_self());
  while (1)  
  {  
  		  /*如果等待队列为0并且不销毁线程池，则处于阻塞状态; 注意 
  		   pthread_cond_wait是一个原子操作，等待前会解锁，唤醒后会加锁*/  
  		  pthread_mutex_lock(&(pool->pool_mutex));	
  		  while (pool->cur_queue_size == 0 && !pool->is_destory)  
  		  {  
			  p_debug("DM thread 0x%x is waiting", pthread_self());
  			  pthread_cond_wait(&(pool->pool_cond), &(pool->pool_mutex));  
  		  }  
  			/*线程池要销毁了*/	
  		  if (pool->is_destory)  
  		  {  
  			  pthread_mutex_unlock(&(pool->pool_mutex));   
			  p_debug("DM thread 0x%x will exit", pthread_self());
  			  pthread_exit(NULL );	
  		  }  
  	      p_debug("DM thread 0x%x is starting to work", pthread_self());
  		  assert(pool->cur_queue_size!=0);	
  		  assert(pool->worker_queue_head!=NULL);  
  		  pool->cur_queue_size--;  
  		  Thread_worker *worker = pool->worker_queue_head;	
  		  pool->worker_queue_head = worker->next;  
  		  pthread_mutex_unlock(&(pool->pool_mutex));  
  		  /*调用回调函数，执行任务*/  
  		  (*(worker->process_interface))(worker->arg,worker->_acc_fd,worker->_header,worker->_threadStatus);	
  		  free(worker);  
  		  worker = NULL;  
  	  }  
  	  pthread_exit(NULL );	
  
}
/*****************************************************************************
Function name:pool_add_worker
Parameter        
      process:callback function ,processing command
      args:input,command
      accfd:socket fd
      header:command header
      pool :input,the thread pool
      threadStatus:thread info
Description      :该函数的作用是对其引脚进行初始化
Return              : int
Argument         : void
Autor & data    :henry
*********************************************************************************/

int pool_add_worker(void*(*process)(void *args),void *args,void *acc_fd,void *header,Thread_pool *pool,void* threadStatus)
{
  Thread_worker * new_worker = (Thread_worker *)malloc(sizeof(Thread_worker));
  new_worker->process_interface = process;
  new_worker->arg = args;
  new_worker->_acc_fd = acc_fd;
  new_worker->_header = header;
  new_worker->_threadStatus = threadStatus;
  //printf("new_worker->_header->cmd = %s\n",new_worker->_header->cmd);
  new_worker->next = NULL;
  /*将任务加入到等待队列中*/ 
  pthread_mutex_lock(&(pool->pool_mutex));
  Thread_worker *member = pool->worker_queue_head;
  if (member != NULL )	
  {  
     while (member->next != NULL )  
  		  member = member->next;  
  	  member->next = new_worker;  
  }  
  else	
  {  
	  pool->worker_queue_head = new_worker;  
  } 
  assert(pool->worker_queue_head!=NULL);
  pool->cur_queue_size++;
  pthread_mutex_unlock(&(pool->pool_mutex));
  /*好了，等待队列中有任务了，唤醒一个等待线程；*/  
  pthread_cond_signal(&(pool->pool_cond));
  return 0;
}
int pool_destory(Thread_pool *pool)
{
  if(pool->is_destory)
  	return -1;
  pool->is_destory = 1;
  /*唤醒所有等待线程，线程池要销毁了*/  
  pthread_cond_broadcast(&(pool->pool_cond));
  int i;
  for (i = 0; i < pool->thread_max_num; i++)  
  	pthread_join(pool->thread_id[i], NULL );  
  /*销毁各种变量*/  
  free(pool->thread_id);
  Thread_worker *temp = NULL;
  
  while (pool->worker_queue_head != NULL )	
  {  
	  temp = pool->worker_queue_head;  
	  pool->worker_queue_head = pool->worker_queue_head->next;	
	  free(temp);  
  }
  
  pthread_mutex_destroy(&(pool->pool_mutex));  
  pthread_cond_destroy(&(pool->pool_cond));
  free(pool);
  pool = NULL;
  return 0;
}
///////////////////////////////////////  
//将耗时的操作线程信息封装成JSON数据发送出去
///////////////////////////////////////  

void *encapsu_json(header_info *_header,char *encapsu_ret)
{
	JObj* header_json=JSON_NEW_EMPTY_OBJECT();
	JObj* response_json=JSON_NEW_EMPTY_OBJECT();
	JObj *response_data_array = JSON_NEW_ARRAY();
	JObj* response_event_json=JSON_NEW_EMPTY_OBJECT();
	JSON_ADD_OBJECT(response_event_json, "event_id", JSON_NEW_OBJECT(pthread_self(),int));
	JSON_ARRAY_ADD_OBJECT(response_data_array,response_event_json);
	JSON_ADD_OBJECT(header_json, "cmd", JSON_NEW_OBJECT(_header->cmd,int));
	JSON_ADD_OBJECT(header_json, "ver", JSON_NEW_OBJECT(_header->ver,int));
	JSON_ADD_OBJECT(header_json, "seq", JSON_NEW_OBJECT(_header->seq,int));
	JSON_ADD_OBJECT(header_json, "device", JSON_NEW_OBJECT(_header->device,int));
	JSON_ADD_OBJECT(header_json, "appid", JSON_NEW_OBJECT(_header->appid,int));
	JSON_ADD_OBJECT(header_json, "code", JSON_NEW_OBJECT(_header->code,int));
	JSON_ADD_OBJECT(header_json, "sessionid", JSON_NEW_OBJECT(_header->sessionid,string));
	JSON_ADD_OBJECT(header_json, "sign", JSON_NEW_OBJECT(_header->sign,string));
	JSON_ADD_OBJECT(response_json, "header", header_json);
	JSON_ADD_OBJECT(response_json, "data", response_data_array);
	strcpy(encapsu_ret,JSON_TO_STRING(response_json));
	JSON_PUT_OBJECT(response_json);
   	return NULL;
}
void ServerExit_SIGPIPE(int sig)
{
   p_debug("Be careful,the server is SIGPIPE1");
   //exit(0);
}
void ServerExit_SIGINT(int sig)
{
   p_debug("Be careful,the server is SIGINT");
   exit(0);
}
void ServerExit_SIGTERM(int sig)
{
   p_debug("Be careful,the server is SIGTERM");
   exit(0);
}
void ServerExit_SIGSEGV(int sig)
{
   p_debug("Be careful,the server is SIGSEGV");
   exit(0);
}
void ServerExit_SIGBUS(int sig)
{
   p_debug("Be careful,the server is SIGBUS");
   exit(0);
}




///////////////////////////////////////  
//下面的代码就是如何调用thread pool  
///////////////////////////////////////  
 
void * consume_process(void *arg,void *_acc_fd,void *header,void *threadStatus)  
{
	uint8_t ret = 0;
	uint8_t acc_fd = 0;
	char retstr[MSG_SERVER_CONSUME_RET_LEN] = {0};
	//strcpy(&acc_fd,_acc_fd);
	acc_fd = *(int *)_acc_fd;
	header_info *_header = header;
	//signal(SIGPIPE, &ServerExit_SIGPIPE);//pipe broken    
	signal(SIGPIPE, SIG_IGN);//pipe broken
	signal(SIGINT,  &ServerExit_SIGINT);//ctrl+c    
	signal(SIGTERM, &ServerExit_SIGTERM);//kill    
	signal(SIGSEGV, &ServerExit_SIGSEGV);//segmentfault    
	signal(SIGBUS,  &ServerExit_SIGBUS);//bus error
	
	p_debug("DM Thread_id is %u , working on task %d\n",(unsigned int )pthread_self(),acc_fd); 
	int auth_ret = _authority_filter(_header->sessionid,_header->cmd);
	p_debug("DM auth_ret = %d",auth_ret);
	if(auth_ret == HAVE_PERMISSION_OPRATION)
	{
		encapsu_json(_header,retstr);
		ret = IM_MsgSend(acc_fd, retstr, strlen(retstr));
		if (ret != 0)
		{
			p_debug("msg send failed with %d",ret);
		}
		memset(retstr,0,MSG_SERVER_CONSUME_RET_LEN);
		api_process(arg,retstr,_header,threadStatus);
	}else 
	{
	    if(auth_ret == HAVE_NO_PERMISSION)
		{
		   _header->code = ERROR_CODE_AUTH;
		   api_response(retstr,_header);
		}else{
		   _header->code = ERROR_CODE_AUTH;//ERROR_CODE_UNKNOW;
		   api_response(retstr,_header);
		}
		ret = IM_MsgSend(acc_fd, retstr, strlen(retstr));
		if (ret != 0)
		{
			p_debug("msg send failed with %d",ret);
		}
	}
	IM_DomainServerDeinit(acc_fd);
	p_debug("retstr = %s",retstr);
	return NULL ;  
}  
void * unconsume_process(void *arg,void *_acc_fd,void *header,void *threadStatus)  
{
	uint8_t ret = 0;
	int acc_fd = 0;
	//strcpy(&acc_fd,(int *)_acc_fd);
	p_debug("DM acc_fd1 = %d",acc_fd);
	char retstr[MSG_SERVER_UNCONSUME_RET_LEN] = {0};
	header_info *_header = header;
	acc_fd = *(int *)_acc_fd;
	//signal(SIGPIPE, &ServerExit_SIGPIPE);//pipe broken
	signal(SIGPIPE, SIG_IGN);//pipe broken
	signal(SIGINT,  &ServerExit_SIGINT);//ctrl+c    
	signal(SIGTERM, &ServerExit_SIGTERM);//kill    
	signal(SIGSEGV, &ServerExit_SIGSEGV);//segmentfault    
	signal(SIGBUS,  &ServerExit_SIGBUS);//bus error
	
	p_debug("DM Thread_id is %u , working on task %d",(unsigned int )pthread_self(),acc_fd);
	int auth_ret = _authority_filter(_header->sessionid,_header->cmd);
	p_debug("DM auth_ret = %d",auth_ret);
	if(auth_ret == HAVE_PERMISSION_OPRATION)
	{
		api_process(arg,retstr,_header,threadStatus);
		
	}else if(auth_ret == HAVE_NO_PERMISSION)
	{
	   _header->code = ERROR_CODE_AUTH;
       api_response(retstr,_header);
	}else{
	   _header->code = ERROR_CODE_AUTH;//ERROR_CODE_UNKNOW;
       api_response(retstr,_header);
	}
	p_debug("DM send:  %s, acc_fd: %d",retstr, acc_fd);
    ret = IM_MsgSend(acc_fd, retstr, strlen(retstr));
	if (ret != 0)
	{
		p_debug("DM send failed with %d",ret);
	}
	IM_DomainServerDeinit(acc_fd);
	sleep(1);  
	return NULL ;  
}  


