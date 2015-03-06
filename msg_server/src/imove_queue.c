#include "imove_msg_server.h"

extern IM_ST_request *request_free_list; 
void imove_dequeue(IM_ST_request **head, IM_ST_request *req)
{
	assert(req != NULL);
	if (*head == req)
		*head = req->next;

	if (req->prev)
		req->prev->next = req->next;
	if (req->next)
		req->next->prev = req->prev;

	req->next = NULL;
	req->prev = NULL;
}

void imove_enqueue(IM_ST_request **head, IM_ST_request *req)
{
	assert(req != NULL);
	if (*head)
	{
		(*head)->prev = req;
	}

	req->next = *head;
	req->prev = NULL;
	*head = req;
}

void imove_free_requests(void)
{
	IM_ST_request *ptr, *next;

    	ptr = request_free_list;
    	while (ptr != NULL) {
        	next = ptr->next;
        	free(ptr);
        	ptr = next;
    	}
    	request_free_list = NULL;
}