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

#ifndef _GLBLEAPI_H
#define _GLBLEAPI_H

/**
 * @addtogroup USER API
 * @{
 */

#include "gl_type.h"
#include "gl_errno.h"
#include <json-c/json.h>

/**
 *  @brief  This function will subscribe events generate from BLE module. 
 * 
 *  @warning  Note that it is a loop , it will continuously pass events to function callback.
 * 
 *  @param callback: This callback will be called when module receive a system boot, GAP and GATT event. 
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_subscribe(gl_ble_cbs *callback);

/**
 *  @brief  This function will unsubscribe events generate from BLE module. 
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_unsubscribe(void);

/**
 *  @brief  Enable or disable the BLE module.
 * 
 *  @note   When you need to use the BLE module, you should call this API.
 * 
 *  @param enable : The value to enable or disable the BLE module.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_enable(int enable);

/**
 *  @brief  This command can be used to read the Bluetooth public address used by the device. 
 * 
 *  @param mac: Device's BLE MAC address.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_get_mac(BLE_MAC mac);

/**
 *  @brief  This command can be used to set the global maximum TX power for Bluetooth. 
 * 
 *  @note   By default, the global maximum TX power value is 8 dBm. This command should not
 *          be used while advertising, scanning or during connection. 
 * 
 *  @param power : TX power in 0.1 dBm steps, for example the value of 10 is 1dBm and 55 is 
 *                 5.5 dBm.
 *  @param current_power : The selected maximum output power level after applying RF path compensation. 
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_set_power(int power, int *current_power);

/**
 *  @brief  Act as BLE slave, set user defined data in advertising packets, scan response packets
 *          or periodic advertising packets.
 * 
 *  @param flag : Adv data flag. This value selects if the data is intended for advertising 
 *                    packets, scan response packets or advertising packet in OTA.
 *                    0: Advertising packets, 1: Scan response packets
 *                    2: OTA advertising packets, 4: OTA scan response packets
 *  @param data : Customized advertising data. Must be hexadecimal ASCII. Like “020106” 
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_adv_data(int flag, char *data);

/**
 *  @brief  Act as BLE slave, Set and Start Avertising.
 * 
 *  @note   interval_max should be bigger than interval_min.
 * 
 *  @param phys : The PHY on which the advertising packets are transmitted on.
 *                     1: LE 1M PHY, 4: LE Coded PHY
 *  @param interval_min : Minimum advertising interval. Value in units of 0.625 ms
 *                     Range: 0x20 to 0xFFFF, Time range: 20 ms to 40.96 s
 *  @param interval_max : Maximum advertising interval. Value in units of 0.625 ms
 *                     Range: 0x20 to 0xFFFF, Time range: 20 ms to 40.96 s
 *  @param discover : Define the discoverable mode.
 *                     0: Not discoverable,
 *                     1: Discoverable using both limited and general discovery procedures
 *                     2: Discoverable using general discovery procedure
 *                     3: Device is not discoverable in either limited or generic discovery
 *                        procedure, but may be discovered by using the Observation procedure
 *                     4: Send advertising and/or scan response data defined by the user.
 *                        The limited/general discoverable flags are defined by the user.
 *  @param adv_conn : Define the connectable mode.
 *                     0: Non-connectable non-scannable
 *                     1: Directed connectable (RESERVED, DO NOT USE)
 *                     2: Undirected connectable scannable (This mode can only be used
 *                        in legacy advertising PDUs)
 *                     3: Undirected scannable (Non-connectable but responds to
 *                        scan requests)
 *                     4: Undirected connectable non-scannable. This mode can
 *                        only be used in extended advertising PDUs
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_adv(int phys, int interval_min, int interval_max, int discover, int adv_conn);

/**
 *  @brief  Act as BLE slave, stop the advertising of the given advertising set.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_stop_adv(void);

/**
 *  @brief  Act as BLE slave, send notifications or indications to one or more remote GATT clients.
 * 
 *  @param address : Address of the connection over which the notification or indication is sent.
 *                   Like “11:22:33:44:55:66”.
 *  @param char_handle : GATT characteristic handle. 
 *  @param value : Value to be notified or indicated.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_send_notify(BLE_MAC address, int char_handle, char *value);

/**
 *  @brief  Act as master, Set and start the BLE discovery.
 * 
 *  @param phys : The PHY on which the advertising packets are transmitted on.
 *                    1: LE 1M PHY, 4: LE Coded PHY.
 *  @param interval : Scan interval. Time = Value x 0.625 ms.
 *                        Range: 0x0004 to 0xFFFF, Time Range: 2.5 ms to 40.96 s.
 *  @param window : Scan window. Time = Value x 0.625 ms.
 *                        Range: 0x0004 to 0xFFFF, Time Range: 2.5 ms to 40.96 s.
 *  @param type : Scan type. Values:
 *                        0: Passive scanning, 1: Active scanning.
 *                        In passive scanning mode, the device only listens to advertising 
 *                        packets and does not transmit packets.
 *                        In active scanning mode, the device sends out a scan request packet upon 
 *                        receiving an advertising packet from a remote device. Then, 
 *                        it listens to the scan response packet from the remote device.
 *  @param mode : Bluetooth discovery Mode.
 *                    0: Discover only limited discoverable devices
 *                    1: Discover limited and generic discoverable devices
 *                    2: Discover all devices
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_discovery(int phys, int interval, int window, int type, int mode);

/**
 *  @brief  Act as master, End the current GAP discovery procedure.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_stop_discovery(void);

/**
 *  @brief  Act as master, Start connect to a remote BLE device.
 * 
 *  @param address : Address of the device to connect to. Like “11:22:33:44:55:66”.
 *  @param address_type : Address type of the device to connect to. Values:
 *                            0: Public address, 1: Random address
 *                            2: Public identity address resolved by stack
 *                            3: Random identity address resolved by stack
 *  @param phys : The PHY on which the advertising packets are transmitted on.
 *                    1: LE 1M PHY, 4: LE Coded PHY.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_connect(BLE_MAC address, int address_type, int phy);

/**
 *  @brief  Act as master, disconnect with remote device.
 * 
 *  @param address : Address of the device to disconnect. Like “11:22:33:44:55:66”.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_disconnect(BLE_MAC address);

/**
 *  @brief  Act as master, get the latest RSSI value of a Bluetooth connection.
 * 
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  @param rssi : The RSSI value for the remote device.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_get_rssi(BLE_MAC address, int32_t *rssi);

/**
 *  @brief  Act as master, Get service list of a remote GATT server.
 * 
 *  @param service_list : The service list of the remote GATT server.
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_get_service(gl_ble_service_list_t *service_list, BLE_MAC address);

/**
 *  @brief  Act as master, Get characteristic list of a remote GATT server.
 * 
 *  @param char_list : The characteristic list of the remote GATT server.
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  @param service_handle : The service handle of connection with remote device.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_get_char(gl_ble_char_list_t *char_list, BLE_MAC address, int service_handle);

/**
 *  @brief  Act as master, Read value of specified characteristic in a remote gatt server.
 * 
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  @param char_handle : The characteristic handle of connection with remote device.
 *  @param value : The value of specified characteristic.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_read_char(BLE_MAC address, int char_handle, char *value);

/**
 *  @brief  Act as master, Write value to specified characteristic in a remote gatt server.
 * 
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  @param char_handle : The characteristic handle of connection with remote device.
 *  @param value : Data value to be wrote.
 *  @param res : Response flag. 0: Write with no response, 1: Write with response.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_write_char(BLE_MAC address, int char_handle, char *value, int res);

/**
 *  @brief  Act as master, Enable or disable the notification or indication of a remote gatt server.
 * 
 *  @param address : Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  @param char_handle : The characteristic handle of connection with remote device.
 *  @param flag : Notification flag.
 *                      0: disable, 1: notification, 2: indication.
 * 
 *  @retval  GL-RETURN 
 */
GL_RET gl_ble_set_notify(BLE_MAC address, int char_handle, int flag);


#endif