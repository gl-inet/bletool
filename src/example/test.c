/*****************************************************************************
 * @file  test.c
 * @brief Start the BLE discovery and subscribe the BLE event
 *******************************************************************************
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
#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include <json-c/json.h>
#include <gl/libglbleapi.h>
void print(json_object* obj)
{
	char* str;
	if(obj)
	{
		str = json_object_to_json_string(obj);
	}
	printf("%s\n",str);
	json_object_put(obj);
}
int main()
{
	uloop_init();
	gl_ble_init();
	gl_ble_subscribe(print);


	gl_ble_discovery(NULL,1,16,16,0,1);


	uloop_run();
	gl_ble_free();
	return 0;
}
