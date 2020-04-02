/*****************************************************************************
 * @file 
 * @brief 
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

#ifndef _LIBGLBLEAPI_H
#define _LIBGLBLEAPI_H

#include <json-c/json.h>

typedef void (*method_handler_t) (json_object* msg);

int gl_ble_init(struct ubus_context *CTX);
int gl_ble_free(void);
int gl_ble_subscribe(method_handler_t cb);
int gl_ble_unsubscribe(void);


/* BLE System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(method_handler_t cb);

/*Enable or disable the BLE module*/
int gl_ble_enable(method_handler_t cb,int enable);

/*Set the global power level*/
int gl_ble_set_power(method_handler_t cb,int power);


/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
int gl_ble_discovery(method_handler_t cb,int phys,int interval,int window,int type,int mode);

/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(method_handler_t cb);

/*Act as master, Start connect to a remote BLE device*/
int gl_ble_connect(method_handler_t cb,char* address,int address_type,int phy);

/*Act as master, disconnect with remote device*/
int gl_ble_disconnect(method_handler_t cb,int connection);

/*Act as master, Get rssi of connection with remote device*/
int gl_ble_get_rssi(method_handler_t cb,int connection);

/*Act as master, Get service list of a remote GATT server*/
int gl_ble_get_service(method_handler_t cb, int connection);

/*Act as master, Get characteristic list of a remote GATT server*/
int gl_ble_get_char(method_handler_t cb, int connection, int service_handle);

/*Act as master, Read value of specified characteristic in a remote gatt server*/
int gl_ble_read_char(method_handler_t cb, int connection, int char_handle);

/*Act as master, Write value to specified characteristic in a remote gatt server*/
int gl_ble_write_char(method_handler_t cb, int connection, int char_handle,char* value,int res);

/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
int gl_ble_set_notify(method_handler_t cb, int connection, int char_handle,int flag);


/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
int gl_ble_adv(method_handler_t cb, int phys, int interval_min,int interval_max,int discover,int connect);

/*Act as BLE slave, Set customized advertising data*/
int gl_ble_adv_data(method_handler_t cb, int flag, char* data);

/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(method_handler_t cb);

/*Act as BLE slave, Send Notification*/
int gl_ble_send_notify(method_handler_t cb,int connection,int char_handle, char* value);

#endif