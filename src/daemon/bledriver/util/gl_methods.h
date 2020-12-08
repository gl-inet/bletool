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

#ifndef GL_METHODS_H
#define GL_METHODS_H

#define SILABS_EFR32

#ifdef SILABS_EFR32

#define serial_msg_callback             silabs_get_notify
#define ble_enable                      silabs_ble_enable
#define ble_local_mac                   silabs_ble_local_mac
#define ble_set_power                   silabs_ble_set_power
#define ble_discovery                   silabs_ble_discovery
#define ble_stop                        silabs_ble_stop
#define ble_adv                         silabs_ble_adv
#define ble_adv_data                    silabs_ble_adv_data
#define ble_stop_adv                    silabs_ble_stop_adv
#define ble_send_notify                 silabs_ble_send_notify
#define ble_connect                     silabs_ble_connect
#define ble_disconnect                  silabs_ble_disconnect
#define ble_get_rssi                    silabs_ble_get_rssi
#define ble_get_service                 silabs_ble_get_service
#define ble_get_char                    silabs_ble_get_char
#define ble_read_char                   silabs_ble_read_char
#define ble_write_char                  silabs_ble_write_char
#define ble_set_notify                  silabs_ble_set_notify
#define ble_dtm_tx                      silabs_ble_dtm_tx
#define ble_dtm_rx                      silabs_ble_dtm_rx
#define ble_dtm_end                     silabs_ble_dtm_end

#endif

#ifdef TELINK_8051
#endif


#endif