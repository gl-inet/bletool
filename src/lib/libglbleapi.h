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

#include "glble_type.h"
#include "glble_errno.h"
#include <json-c/json.h>


int gl_ble_subscribe(gl_ble_cbs *callback);
int gl_ble_unsubscribe(void);

/* BLE System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(gl_ble_get_mac_rsp_t *rsp);

/*Enable or disable the BLE module*/
int gl_ble_enable(int enable);

/*Set the global power level*/
int gl_ble_set_power(gl_ble_set_power_rsp_t *rsp, int power);

/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
int gl_ble_discovery(int phys, int interval, int window, int type, int mode);

/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(void);

/*Act as master, Start connect to a remote BLE device*/
int gl_ble_connect(gl_ble_connect_rsp_t *rsp, char *address, int address_type, int phy);

/*Act as master, disconnect with remote device*/
int gl_ble_disconnect(int connection);

/*Act as master, Get rssi of connection with remote device*/
int gl_ble_get_rssi(gl_ble_get_rssi_rsp_t *rsp, char *address);

/*Act as master, Get service list of a remote GATT server*/
int gl_ble_get_service(gl_ble_get_service_rsp_t *rsp, int connection);

/*Act as master, Get characteristic list of a remote GATT server*/
int gl_ble_get_char(gl_ble_get_char_rsp_t *rsp, int connection, int service_handle);

/*Act as master, Read value of specified characteristic in a remote gatt server*/
int gl_ble_read_char(gl_ble_char_read_rsp_t *rsp, int connection, int char_handle);

/*Act as master, Write value to specified characteristic in a remote gatt server*/
int gl_ble_write_char(gl_ble_write_char_rsp_t *rsp, int connection, int char_handle, char *value, int res);

/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
int gl_ble_set_notify(int connection, int char_handle, int flag);

/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
int gl_ble_adv(int phys, int interval_min, int interval_max, int discover, int connect);

/*Act as BLE slave, Set customized advertising data*/
int gl_ble_adv_data(int flag, char *data);

/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(void);

/*Act as BLE slave, Send Notification*/
int gl_ble_send_notify(gl_ble_send_notify_rsp_t *rsp, int connection, int char_handle, char *value);

/*DTM test, tx*/
int gl_ble_dtm_tx(gl_ble_dtm_test_rsp_t *rsp, int packet_type, int length, int channel, int phy);

/*DTM test, rx*/
int gl_ble_dtm_rx(gl_ble_dtm_test_rsp_t *rsp, int channel, int phy);

/*DTM test, end*/
int gl_ble_dtm_end(gl_ble_dtm_test_rsp_t *rsp);

#endif