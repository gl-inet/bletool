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

#include "gl_type.h"
#include "gl_errno.h"
#include <json-c/json.h>

/***********************************************************************************************//**
 *  \brief  This function will subscribe events generate from BLE module. 
 *          Note that it must be followed by uloop_run(), it will continuously pass events to 
 *          function callback.
 *  \param[in]  callback This callback will be called when module receive a system boot, GAP and GATT event. 
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_subscribe(gl_ble_cbs *callback);

/***********************************************************************************************//**
 *  \brief  This function will unsubscribe events generate from BLE module. 
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_unsubscribe(void);

/***********************************************************************************************//**
 *  \brief  Enable or disable the BLE module.
 *  \note   When you need to use the BLE module, you should call this API.
 *  \param[in]   enable The value to enable or disable the BLE module.
 *  \return 0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_enable(int enable);

/***********************************************************************************************//**
 *  \brief  This command can be used to read the Bluetooth public address used by the device. 
 *  \param[out]  rsp  A response structure used for storing the MAC address.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_get_mac(gl_ble_get_mac_rsp_t *rsp);

/***********************************************************************************************//**
 *  \brief  This command can be used to set the global maximum TX power for Bluetooth. 
 *  \note   By default, the global maximum TX power value is 8 dBm.
 *          This command should not be used while advertising, scanning or during connection.
 *  \param[in]   power TX power in 0.1 dBm steps, for example the value of 10 is 1dBm
 *                     and 55 is 5.5 dBm.
 *  \param[out]  rsp   The returned value in the response is the selected maximum output power 
 *                     level after applying RF path compensation. If the GATT server contains a
 *                     Tx Power service, the Tx Power Level attribute of the service will be 
 *                     updated accordingly. 
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_set_power(gl_ble_set_power_rsp_t *rsp, int power);

/***********************************************************************************************//**
 *  \brief  Act as BLE slave, set user defined data in advertising packets, scan response packets
 *          or periodic advertising packets.
 *  \note
 *  \param[in]  flag  Adv data flag. This value selects if the data is intended for advertising 
 *                    packets, scan response packets or advertising packet in OTA.
 *                    0: Advertising packets, 1: Scan response packets
 *                    2: OTA advertising packets, 4: OTA scan response packets
 *  \param[out]  data Customized advertising data. Must be hexadecimal ASCII. Like “020106” 
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_adv_data(int flag, char *data);

/***********************************************************************************************//**
 *  \brief  Act as BLE slave, Set and Start Avertising.
 *  \note   interval_max should be bigger than interval_min.
 *  \param[in]   phys  The PHY on which the advertising packets are transmitted on.
 *                     1: LE 1M PHY, 4: LE Coded PHY
 *  \param[in]   interval_min Minimum advertising interval. Value in units of 0.625 ms
 *                     Range: 0x20 to 0xFFFF, Time range: 20 ms to 40.96 s
 *  \param[in]   interval_max Maximum advertising interval. Value in units of 0.625 ms
 *                     Range: 0x20 to 0xFFFF, Time range: 20 ms to 40.96 s
 *  \param[in]   discover Define the discoverable mode.
 *                     0: Not discoverable,
 *                     1: Discoverable using both limited and general discovery procedures
 *                     2: Discoverable using general discovery procedure
 *                     3: Device is not discoverable in either limited or generic discovery
 *                        procedure, but may be discovered by using the Observation procedure
 *                     4: Send advertising and/or scan response data defined by the user.
 *                        The limited/general discoverable flags are defined by the user.
 *  \param[in]   adv_conn Define the connectable mode.
 *                     0: Non-connectable non-scannable
 *                     1: Directed connectable (RESERVED, DO NOT USE)
 *                     2: Undirected connectable scannable (This mode can only be used
 *                        in legacy advertising PDUs)
 *                     3: Undirected scannable (Non-connectable but responds to
 *                        scan requests)
 *                     4: Undirected connectable non-scannable. This mode can
 *                        only be used in extended advertising PDUs
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_adv(int phys, int interval_min, int interval_max, int discover, int adv_conn);

/***********************************************************************************************//**
 *  \brief  Act as BLE slave, stop the advertising of the given advertising set.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_stop_adv(void);

/***********************************************************************************************//**
 *  \brief  Act as BLE slave, send notifications or indications to one or more remote GATT clients.
 *  \note
 *  \param[in]  address Address of the connection over which the notification or indication is sent.
 *                      Like “11:22:33:44:55:66”.
 *  \param[in]  char_handle  GATT characteristic handle. 
 *  \param[in]  value   Value to be notified or indicated.
 *  \param[out]  rsp    A response structure used for storing the length of the notification 
 *                      or indication.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_send_notify(gl_ble_send_notify_rsp_t *rsp, uint8_t *address, int char_handle, char *value);

/***********************************************************************************************//**
 *  \brief  Act as master, Set and start the BLE discovery.
 *  \param[in]  phys  The PHY on which the advertising packets are transmitted on.
 *                    1: LE 1M PHY, 4: LE Coded PHY.
 *  \param[in]  interval  Scan interval. Time = Value x 0.625 ms.
 *                        Range: 0x0004 to 0xFFFF, Time Range: 2.5 ms to 40.96 s.
 *  \param[in]  window    Scan window. Time = Value x 0.625 ms.
 *                        Range: 0x0004 to 0xFFFF, Time Range: 2.5 ms to 40.96 s.
 *  \param[in]  type  Scan type. Values:
 *                        0: Passive scanning, 1: Active scanning.
 *                        In passive scanning mode, the device only listens to advertising 
 *                        packets and does not transmit packets.
 *                        In active scanning mode, the device sends out a scan request packet upon 
 *                        receiving an advertising packet from a remote device. Then, 
 *                        it listens to the scan response packet from the remote device.
 *  \param[in]  mode  Bluetooth discovery Mode.
 *                    0: Discover only limited discoverable devices
 *                    1: Discover limited and generic discoverable devices
 *                    2: Discover all devices
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_discovery(int phys, int interval, int window, int type, int mode);

/***********************************************************************************************//**
 *  \brief  Act as master, End the current GAP discovery procedure.
 *  \return 0 on success, -1 on failure.
 **************************************************************************************************/
GL_RET gl_ble_stop(void);

/***********************************************************************************************//**
 *  \brief  Act as master, Start connect to a remote BLE device.
 *  \param[in]  address  Address of the device to connect to. Like “11:22:33:44:55:66”.
 *  \param[in]  address_type Address type of the device to connect to. Values:
 *                            0: Public address, 1: Random address
 *                            2: Public identity address resolved by stack
 *                            3: Random identity address resolved by stack
 *  \param[in]  phys  The PHY on which the advertising packets are transmitted on.
 *                    1: LE 1M PHY, 4: LE Coded PHY.
 *  \param[out]  rsp  A response structure used for storing the connect parameters of the remote device.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_connect(gl_ble_connect_rsp_t *rsp, uint8_t *address, int address_type, int phy);

/***********************************************************************************************//**
 *  \brief  Act as master, disconnect with remote device.
 *  \param[in]  address  Address of the device to disconnect. Like “11:22:33:44:55:66”.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_disconnect(uint8_t *address);

/***********************************************************************************************//**
 *  \brief  Act as master, get the latest RSSI value of a Bluetooth connection.
 *  \note
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[out] rsp  A response structure used for storing the connection with remote device.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_get_rssi(gl_ble_get_rssi_rsp_t *rsp, uint8_t *address);

/***********************************************************************************************//**
 *  \brief  Act as master, Get service list of a remote GATT server.
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[out] rsp  A response structure used for storing the  service list of a remote GATT server.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_get_service(gl_ble_get_service_rsp_t *rsp, uint8_t *address);

/***********************************************************************************************//**
 *  \brief  Act as master, Get characteristic list of a remote GATT server.
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[in]  service_handle  The service handle of connection with remote device.
 *  \param[out] rsp  A response structure used for storing the characteristic 
 *                   list of a remote GATT server.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_get_char(gl_ble_get_char_rsp_t *rsp, uint8_t *address, int service_handle);

/***********************************************************************************************//**
 *  \brief  Act as master, Read value of specified characteristic in a remote gatt server.
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[in]  char_handle  The characteristic handle of connection with remote device.
 *  \param[out] rsp  A response structure used for storing the value of specified characteristic.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_read_char(gl_ble_char_read_rsp_t *rsp, uint8_t *address, int char_handle);

/***********************************************************************************************//**
 *  \brief  Act as master, Write value to specified characteristic in a remote gatt server.
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[in]  char_handle  The characteristic handle of connection with remote device.
 *  \param[in]  value  Data value to be wrote.
 *  \param[in]  res  Response flag. 0: Write with no response, 1: Write with response.
 *  \param[out] rsp  A response structure used for storing the length of value to be wrote.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_write_char(gl_ble_write_char_rsp_t *rsp, uint8_t *address, int char_handle, char *value, int res);

/***********************************************************************************************//**
 *  \brief  Act as master, Enable or disable the notification or indication of a remote gatt server.
 *  \param[in]  address Remote BLE device MAC address. Like “11:22:33:44:55:66”.
 *  \param[in]  char_handle  The characteristic handle of connection with remote device.
 *  \param[in]  flag    Notification flag.
 *                      0: disable, 1: notification, 2: indication.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_set_notify(uint8_t *address, int char_handle, int flag);

/***********************************************************************************************//**
 *  \brief  This command can be used to start a transmitter test.
 *  \param[in]   packet_type - 0: Advertising packets,      - 1: Scan response packets
 *                           - 2: OTA advertising packets,  - 4: OTA scan response packets
 *  \param[in]   length   Packet length in bytes, Range: 0-255
 *  \param[in]   channel  Bluetooth channel, Range: 0-39, Channel is (F - 2402) / 2, where F is frequency in MHz
 *  \param[in]   phy      Parameter phy specifies which PHY is used to transmit the packets. 
 *                        All devices support at least the 1M PHY.
 *  \param[out]  A response structure used for storing the number of the packet.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_dtm_tx(gl_ble_dtm_test_rsp_t *rsp, int packet_type, int length, int channel, int phy);

/***********************************************************************************************//**
 *  \brief  This command can be used to start a receiver test. 
 *  \param[in]   channel  Bluetooth channel, Range: 0-39, Channel is (F - 2402) / 2, where F is frequency in MHz
 *  \param[in]   phy      Parameter phy specifies which PHY is used to transmit the packets. 
 *                        All devices support at least the 1M PHY.
 *  \param[out]  A response structure used for storing the number of the packet.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_dtm_rx(gl_ble_dtm_test_rsp_t *rsp, int channel, int phy);

/***********************************************************************************************//**
 *  \brief  This command can be used to end a transmitter or a receiver test.
 *  \param[out]  A response structure used for storing the number of the packet.
 *  \return  0 means success, None-zero means failed.
 **************************************************************************************************/
GL_RET gl_ble_dtm_end(gl_ble_dtm_test_rsp_t *rsp);

#endif