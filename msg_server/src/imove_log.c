#include "imove_msg_server.h"

/***
打开文件
params:
	spec:[in] file, i.e: /var/log/msg_server.log
return:
	fd;
***/
int imove_open_gen_fd(char *spec)
{
	int fd = 0;

	if (spec == NULL)
	{
		return -1;
	}

	fd = open(spec,
                  O_WRONLY | O_CREAT | O_APPEND,
                  S_IRUSR | S_IWUSR | S_IROTH | S_IRGRP);
	return fd;
}

/***
打开日志文件，用于记录日志
params:
	none
return
	none
***/
void imove_open_logs(void)
{
	int error_log;

	error_log = imove_open_gen_fd(ERROR_LOG_FILE);
	if (error_log < 0)
	{
		DIE("open error log file failed");
	}
	
	/* redirect stderr to error_log */
       if (dup2(error_log, STDERR_FILENO) == -1) 
	{
            DIE("unable to dup2 the error log");
       }

	close(error_log);

	/* set the close-on-exec to true */
    	if (fcntl(STDERR_FILENO, F_SETFD, 1) == -1) {
        DIE("unable to fcntl the error log");
    	}
		
	return;
}


/***
打印日志到stderr
***/
void imove_log_error_mesg(char *file, int line, char *mesg)
{
    int errno_save = errno;
    fprintf(stderr, "%s:%d - %s",  file, line, mesg);
    errno = errno_save;
//    perror(mesg);
//    errno = errno_save;
}



