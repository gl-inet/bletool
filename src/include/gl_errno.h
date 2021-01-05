/*****************************************************************************
 Copyright 2020 GL-iNet. https://www.gl-inet.com/

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 ******************************************************************************/
#ifndef _GL_ERRNO_H_
#define _GL_ERRNO_H_

/*
 * 0x0000 - 0x00FF    Error code defined by GL-iNet
 * 0x0100 - 0xFFFF    Error code defined by ble module manufacturer
 * Error code defined by Silabs: \src\daemon\bledriver\silabs\bg_errorcodes.h
 * 
*/

#define MANUFACTURER_CODE_BASE						  0x0100

enum gl_error_spaces {
	GL_ERRSPC_GENERAL	= 0,
	GL_ERRSPC_UBUS 		= 20,
};

typedef enum gl_error {
	GL_SUCCESS      	   			= GL_ERRSPC_GENERAL + 0,            // No error
	GL_ERR_RESP_MISSING				= GL_ERRSPC_GENERAL	+ 1, 			// Response missing
	GL_ERR_EVENT_MISSING			= GL_ERRSPC_GENERAL + 2, 			// Event missing
	GL_ERR_PARAM_MISSING			= GL_ERRSPC_GENERAL + 3, 			// Param missing
	GL_ERR_MSG						= GL_ERRSPC_GENERAL + 4, 			// Message error
	GL_ERR_PARAM					= GL_ERRSPC_GENERAL	+ 5, 			// Param error

	GL_ERR_UBUS_CONNECT				= GL_ERRSPC_UBUS	+ 1,            // UBUS connect error
	GL_ERR_UBUS_LOOKUP				= GL_ERRSPC_UBUS	+ 2,			// UBUS lookup ID error
	GL_ERR_UBUS_SUBSCRIBE			= GL_ERRSPC_UBUS	+ 3,			// UBUS subscribe error
	GL_ERR_UBUS_INVOKE				= GL_ERRSPC_UBUS	+ 4,			// UBUS invoke error
	GL_ERR_UBUS_REGISTER			= GL_ERRSPC_UBUS	+ 5,			// UBUS register error
	GL_ERR_UBUS_CALL_STR			= GL_ERRSPC_UBUS	+ 6,            // UBUS CALL return error
	GL_ERR_UBUS_JSON_PARSE			= GL_ERRSPC_UBUS	+ 7,			// UBUS return json parse error
	GL_ERR_UBUS_UNSUBSCRIBE			= GL_ERRSPC_UBUS	+ 8,			// UBUS unsubscribe error
}errcode_t;

#endif