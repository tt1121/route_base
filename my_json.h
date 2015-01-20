/*
 * =============================================================================
 *
 *       Filename:  my_json.h
 *
 *    Description:  Just wrapper of json library.
 *
 *        Version:  1.0
 *        Created:  2014/10/27 15:54:19
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Oliver (), 515296288jf@163.com
 *   Organization:  
 *
 * =============================================================================
 */
#ifndef _MY_WRAPPER_JSON_H_
#define _MY_WRAPPER_JSON_H_

#include <json-c/json.h>

     
#ifdef __cplusplus
extern "C"{
#endif

typedef struct json_object JObj;
// typedef struct json_object * PJObj;
//boolean json_object_get_boolean

#define JSON_PARSE(json_str) json_tokener_parse(json_str)
#define JSON_GET_OBJECT(r_json, member) json_object_object_get(r_json, member)  
#define JSON_GET_OBJECT_VALUE(p_json, type) json_object_get_##type(p_json)
#define JSON_TO_STRING(p_json) json_object_to_json_string(p_json)
#define JSON_NEW_EMPTY_OBJECT() json_object_new_object()
#define JSON_NEW_OBJECT(member, type) json_object_new_##type(member)
#define JSON_NEW_ARRAY() json_object_new_array()
#define JSON_ADD_OBJECT(p_json, member, member_json) json_object_object_add(p_json, member, member_json) 
#define JSON_ARRAY_ADD_OBJECT(p_json, member_json) json_object_array_add(p_json, member_json)
#define JSON_PUT_OBJECT(jo) do{\
	if((jo) != NULL)\
	{\
		json_object_put((jo));\
		(jo) = NULL;\
	}\
	}while(0)

#define JSON_IS_JOBJ(p_json) json_object_is_type((p_json), json_type_object) 

// for json array
#define JSON_IS_ARRAY(p_json) json_object_is_type((p_json), json_type_array)
#define JSON_GET_ARRAY_LIST(p_json) json_object_get_array((p_json))
#define JSON_GET_ARRAY_LEN(p_json) json_object_array_length((p_json))
#define JSON_GET_ARRAY_MEMBER_BY_ID(p_json, idx) json_object_array_get_idx((p_json), idx)
#define JSON_ADD_ARRAY_MEMBER_BY_ID(p_json, idx, member) json_object_array_put_idx((p_json), idx, (member))


#if 0
#define JSON_GET_OBJECT_FAILE_RET(r_json, member, save) do{\
    save = json_object_object_get(r_json, member);\
    if(save == NULL)\
    {\
        log_error("No " #member);\
        return -1;\
    }\
    }while(0)
    
#endif

#ifdef __cplusplus
}
#endif


#endif

