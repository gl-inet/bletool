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
#include "gl_dev_mgr.h"
#include "gl_log.h"

int main()
{
	gl_ble_get_mac_rsp_t mac_rsp;
	gl_ble_get_mac(&mac_rsp);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac_rsp.address[5],mac_rsp.address[4],mac_rsp.address[3],
		mac_rsp.address[2],mac_rsp.address[1],mac_rsp.address[0]);
	return 0;
}
