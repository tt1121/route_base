/** 文 件 名: im_download.c
** Copyright (c), imove(SHENTHEN) Co., Ltd.
** 日    期: 2014-12-8
** 描    述:
** 版    本:
** 修改历史:
** 2014-12-8   张斌创建本文件；
##############################################################################*/
#include "im_download.h"

#define IM_DOWNLOAD_FILE   "/tmp/tmp_update.bin"

size_t im_write_data(void *ptr, size_t size, size_t nmemb, void *stream)  
{
	int written = fwrite(ptr, size, nmemb, (FILE *)stream);
	return written;
}

int im_curl_init(CURL **curlhandle)
{
	CURLcode res;

	if (curlhandle == NULL)
	{
		IM_DEBUG("PARAM ERROR");
		return -1;
	}
	
	res = curl_global_init(CURL_GLOBAL_ALL);
	if (res != CURLE_OK)
	{
		IM_DEBUG("curl_global_init fail:%s", curl_easy_strerror(res));	
		return -1;
	}
	
	*curlhandle = curl_easy_init(); 
	if (*curlhandle == NULL)
	{
		IM_DEBUG("curl_easy_init error");
		return -1;
	}

	return res;
}


int im_curl_clean(CURL *curlhandle)
{
	if (curlhandle == NULL)
	{
		IM_DEBUG("PARAM ERROR");
		return -1;
	}
	
	curl_easy_cleanup(curlhandle);
	curl_global_cleanup();
}

int im_progress_func(char *progress_data,
                     double t, /* dltotal */
                     double d, /* dlnow */
                     double ultotal,
                     double ulnow)
{
	int per = (int)(d*100.0/t);
	long dlen = (long) (d);
	long tlen = (long) (t);
	
	S_IM_MSG_FIRMWARE *firmware = (S_IM_MSG_FIRMWARE *)progress_data;
	
	firmware->dlen = dlen;
	firmware->tlen = tlen;

	if (firmware->dlen != firmware->tlen)
		firmware->state = DOWN_LOADING_STATE;
	
  return 0;
}


/*********************************************
function:   下载指定文件
params:
[IN]firmware:    下载的文件信息
[IN] sw_name  :    指定保存文件的名字
return: -1，0
***********************************************/

int im_download_curl(S_IM_MSG_FIRMWARE *firmware, char *sw_name)
{
	CURL *curlhandle = NULL;             //定义CURL类型的指针  
	CURLcode res;           //定义CURLcode类型的变量，保存返回状态码
	FILE *file = NULL;
	long retcode = 0;
	int err = 0;
	struct stat file_info;
	curl_off_t local_file_len = -1 ;
	int use_resume = 0;

	if ((NULL == firmware)||(NULL == sw_name))
	{
	    IM_DEBUG("Bad argument");
	    return -1;
	}
	
	err = im_curl_init(&curlhandle);
	if (err < 0)
	{
		IM_DEBUG("im_curl_init");
		return err;
	}

	if(stat(sw_name, &file_info) == 0) 
	{
		local_file_len =  file_info.st_size;
		use_resume  = 1;
	}

	file = fopen(sw_name, "ab+"); 
	if (file == NULL) 
	{
		IM_DEBUG("open file %s fail", sw_name);
		err = -1;
		goto openfile_err;
	}

	curl_easy_setopt(curlhandle, CURLOPT_URL, firmware->im_url);
	curl_easy_setopt(curlhandle, CURLOPT_CONNECTTIMEOUT, 5);  // 设置连接超时，单位秒

	// 设置文件续传的位置给libcurl
	curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM_LARGE, use_resume?local_file_len:0);
	curl_easy_setopt(curlhandle, CURLOPT_NOPROGRESS, 1L);

	curl_easy_setopt(curlhandle, CURLOPT_WRITEDATA, file);
	curl_easy_setopt(curlhandle, CURLOPT_WRITEFUNCTION, im_write_data);
	//跟踪下载进度
	curl_easy_setopt(curlhandle, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curlhandle, CURLOPT_PROGRESSFUNCTION, im_progress_func);
	curl_easy_setopt(curlhandle, CURLOPT_PROGRESSDATA, firmware);

	curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 0L);

	res = curl_easy_perform(curlhandle);
	if (res != CURLE_OK)
	{
		  IM_DEBUG("%s", curl_easy_strerror(res));
		  err = -1;
		  goto out;
	}

	res = curl_easy_getinfo(curlhandle, CURLINFO_RESPONSE_CODE , &retcode);
	if ((res == CURLE_OK)&& ((retcode == 200) || (206 == retcode)))
	{
		IM_DEBUG("download ok");
	}
	else if((res == CURLE_OK)&& (retcode == 416)) //断点续传下载
	{
		IM_DEBUG("%s retcode:%d ", curl_easy_strerror(res), retcode);
	}
	else 
	{
		IM_DEBUG("fail %s retcode:%d ", curl_easy_strerror(res), retcode);
		err = -1;
	}


out:
		fclose(file);
openfile_err:
		im_curl_clean(curlhandle);
	
	return err;
}



/*********************************************
function:   获取执行命令的返回结果
params:
[IN]name:    执行的命令名
[OUT] value  :    返回的字符串
return: -1，0
***********************************************/
int im_get_cmd_value(char *name, char *value)
{
    char cmd[MAX_URL_LEN] = {0};
    FILE* fp = NULL;

	if (!value ||!name)
	{
		IM_DEBUG("param error");
		return -1;
	}
	
    snprintf(cmd, sizeof(cmd) - 1, "%s", name);
    fp = popen(cmd, "r");
    if (!fp)
    {
    	IM_DEBUG("popen fail");
    	return -1;
    }

	fgets(value, MAX_STAS_LEN - 1, fp);
	if (value[strlen(value)-1] == 0x0a)
		value[strlen(value)-1] = '\0';
    pclose(fp);
    
    return 0;
}


/*********************************************
function:   比较MD5是否匹配
params:
[IN]MD5:    正确的MD5值
[IN] sw_name  :    要比较MD5的文件名
return: -1，0
***********************************************/
int im_check_md5(char *md5, char *sw_name)
{
	char cmd[MAX_URL_LEN] = {0};
    char md5_str[64] = {0};
	int ret = -1;

	if (!md5 ||!sw_name)
	{
		IM_DEBUG("param error");
		return -1;
	}
	
	snprintf(cmd, MAX_URL_LEN-1, "md5sum %s | cut -d ' ' -f 1", sw_name);
	ret = im_get_cmd_value(cmd, md5_str);
	if (ret != 0)
	{
		IM_DEBUG("(%s) failed!", cmd);
		return -1;
	}

	if (strcmp(md5, md5_str) != 0)
	{
		IM_DEBUG("MD5 not match");
		return -1;
	}


	return 0;
}


int im_upgrade_firmware(S_IM_MSG_FIRMWARE *firmware, pfunc_upgrade im_upgrade)
{
	int ret = -1;
	char cmd[MAX_URL_LEN] = {0};

	if (!firmware && !im_upgrade)
	{
		IM_DEBUG("param error");
		return -1;
	}
	
	//下载需要更新的文件
	ret = im_download_curl(firmware, IM_DOWNLOAD_FILE);
	if (ret != 0)
	{
		firmware->state = UPGRADE_FAILED;
		IM_DEBUG("download file fail");
		return -1;
	}
	//比较MD5是否正确
	ret = im_check_md5(firmware->im_md5, IM_DOWNLOAD_FILE);
	if (ret != 0)
	{
		firmware->state = UPGRADE_FAILED;
		unlink(IM_DOWNLOAD_FILE);	//MD5错误删除文件
		return -1;
	}

	rename(IM_DOWNLOAD_FILE, FIRMWARE_NAME);

	firmware->state = UPGRADE_SUCCESS;

retry:
	
	if (firmware->up_flag == 0)
	{
		sleep(3);
		goto retry;
	}

	IM_DEBUG("is going to upgrade !!!\n");
	if (im_upgrade)
		ret = im_upgrade();
	
	return ret;
}

int im_upgrade(void)
{
	IM_DEBUG("start upgrade!!!!");
}

/***
获取最新固件的信息
params:
	file_path: [IN] 最新固件信息保存所在的文件.决定路径
	firmware: [IN] 固件信息
return:
	0:	sucess
	!0:	failed
***/
int im_fw_info(char *file_path, S_IM_MSG_FIRMWARE *firmware)
{
#define DEFAULT_FILE_PATH	"/var/newest_fw_info"

	FILE *fp = NULL;
	int ret = -1;

	assert(firmware);
	
	if (file_path == NULL)
		fp = fopen(DEFAULT_FILE_PATH, "rb");
	else
		fp = fopen(file_path, "rb");

	if (fp == NULL)
	{
		IM_DEBUG("open file failed, errno:%d\n", errno);
		goto out;
	}

	if (fgets(firmware->im_url, sizeof(firmware->im_url), fp) == NULL)
	{
		IM_DEBUG("fgets failed, errno:%d\n", errno);
		goto out;
	}

	if (fgets(firmware->im_md5, sizeof(firmware->im_md5), fp) == NULL)
	{
		IM_DEBUG("fgets failed, errno:%d\n", errno);
		goto out;
	}

	IM_DEBUG("get file success,url:%s md5:%s\n", firmware->im_url, firmware->im_md5);
	ret = 0;
out:
	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

