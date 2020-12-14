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

#ifndef _SILABS_BLEAPI_H
#define _SILABS_BLEAPI_H

#include <json-c/json.h>

json_object* silabs_get_notify(void);
json_object* silabs_ble_enable(int);
json_object* silabs_ble_local_mac(void);
json_object* silabs_ble_discovery(int phys,int interval,int window,int type,int mode);
json_object* silabs_ble_stop(void);
json_object* silabs_ble_adv(int adv_phys,int adv_interval_min,int adv_interval_max,int adv_discover,int adv_conn);
json_object* silabs_ble_adv_data(int adv_data_flag,char* adv_data);
json_object* silabs_ble_stop_adv(void);
json_object* silabs_ble_send_notify(int send_noti_conn,int send_noti_char,char* send_noti_value);
json_object* silabs_ble_connect(char* address,int address_type,int conn_phy);
json_object* silabs_ble_disconnect(int connection);
json_object* silabs_ble_get_rssi(int connection);
json_object* silabs_ble_get_service(int connection);
json_object* silabs_ble_get_char(int connection,int service_handle);
json_object* silabs_ble_set_power(int power);
json_object* silabs_ble_read_char(int connection,int char_handle);
json_object* silabs_ble_write_char(int connection,int char_handle,char* value,int write_res);
json_object* silabs_ble_set_notify(int connection,int char_handle,int flag);
json_object* silabs_ble_dtm_tx(int packet_type,int length, int channel, int phy);
json_object* silabs_ble_dtm_rx(int channel, int phy);
json_object* silabs_ble_dtm_end(void);

#endif