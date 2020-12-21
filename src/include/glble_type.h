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
#ifndef _GLBLE_TYPE_H_
#define _GLBLE_TYPE_H_

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json.h>

#define UUID_MAX                    128
#define LIST_LENGTHE_MAX            16
#define CHAR_VALUE_MAX              256
#define DEVICE_MAC_LEN              6
#define BLE_MAC_LEN                 18
#define MAX_VALUE_DATA_LEN          255
#define MAX_ADV_DATA_LEN            255
#define MAX_HASH_DATA_LEN           255

// typedef enum {
//     DISABLE = 0,
//     ENABLE,
// }gl_ble;

typedef struct {
    int handle;
    char uuid[UUID_MAX];
} ble_service_list_t;

typedef struct {
    int handle;
    char uuid[UUID_MAX];
    uint8_t properties;
} ble_characteristic_list_t;

typedef struct {
    uint8_t addr[DEVICE_MAC_LEN];
} gl_ble_get_mac_rsp_t;

typedef struct {
    int current_power;
} gl_ble_set_power_rsp_t;

typedef struct {
    uint8_t addr[DEVICE_MAC_LEN];
    uint8_t address_type;
    uint8_t master;
    uint8_t bonding;
    uint8_t advertiser;
} gl_ble_connect_rsp_t;

typedef struct {
    uint8_t addr[DEVICE_MAC_LEN];
    int rssi;
} gl_ble_get_rssi_rsp_t;

typedef struct {
    uint8_t addr[DEVICE_MAC_LEN];
    uint8_t list_len;
    ble_service_list_t list[LIST_LENGTHE_MAX];
} gl_ble_get_service_rsp_t;

typedef struct {
    // uint8_t connection;
    uint8_t addr[DEVICE_MAC_LEN];
    uint8_t list_len;
    ble_characteristic_list_t list[LIST_LENGTHE_MAX];
} gl_ble_get_char_rsp_t;

typedef struct {
    // uint8_t connection;
    uint8_t addr[DEVICE_MAC_LEN];
    int handle;
    uint8_t att_opcode;
    int offset;
    uint8_t value[CHAR_VALUE_MAX];
} gl_ble_char_read_rsp_t;

typedef struct {
    int sent_len;
} gl_ble_write_char_rsp_t;

typedef struct {
    int sent_len;
} gl_ble_send_notify_rsp_t;

typedef struct {
    int number_of_packets;
} gl_ble_dtm_test_rsp_t;

typedef struct {
    ubus_handler_t cb;
    ubus_remove_handler_t remove_cb;
} ubus_subscriber_cb_t;

// module callback event type
typedef enum {
    // MODULE_BOOT = 0,
    MODULE_BLE_SYSTEM_BOOT_EVT = 0,
    MODULE_EVT_MAX,
} gl_ble_module_event_t;

typedef union {
    struct ble_system_boot_data {
        int major;
        int minor;
        int patch;
        int build;
        int bootloader;
        int hw;
        char ble_hash[MAX_HASH_DATA_LEN];
    } system_boot_data;

} gl_ble_module_data_t;

/// GAP BLE callback event type
typedef enum {
    GAP_BLE_SCAN_RESULT_EVT = 0,
    GAP_BLE_UPDATE_CONN_EVT,
    GAP_BLE_CONNECT_EVT,
    GAP_BLE_DISCONNECT_EVT,
    GAP_BLE_EVT_MAX,
} gl_ble_gap_event_t;

/// BLE device address type
typedef enum {
    BLE_ADDR_TYPE_PUBLIC = 0x00,
    BLE_ADDR_TYPE_RANDOM = 0x01,
    BLE_ANONYMOUS_ADVERTISING = 0xff,

} gl_ble_addr_type_t;

typedef union {
    struct ble_scan_result_evt_data {
        char addr[BLE_MAC_LEN]; /*!< Bluetooth device address which has been searched */
        gl_ble_addr_type_t ble_addr_type; /*!< Ble device address type */
        int packet_type;                  /*!< Ble scan result packet type */
        int rssi;                         /*!< Searched device's RSSI */
        char ble_adv[MAX_ADV_DATA_LEN];   /*!< Received EIR */
        int bonding;
    } scan_rst; /*!< Event parameter of ESP_GAP_BLE_SCAN_RESULT_EVT */

    struct ble_update_conn_evt_data {
        int connection; /*!< Bluetooth device address */
        int interval;   /*!< Min connection interval */
        int latency;    /*!< Slave latency for the connection in number of connection events. Range: 0x0000 to 0x01F3 */
        int timeout;
        int security_mode;
        int txsize;
    } update_conn_data;

    struct ble_connect_open_evt_data {
        char addr[BLE_MAC_LEN];
        gl_ble_addr_type_t ble_addr_type;
        int conn_role;
        int connection;
        int bonding;
        int advertiser;
    } connect_open_data;

    struct ble_disconnect_evt_data {
        uint8_t address[DEVICE_MAC_LEN];
        int reason;
    } disconnect_data;
} gl_ble_gap_data_t;

// GATT BLE callback event type
typedef enum {
    GATT_BLE_REMOTE_NOTIFY_EVT = 0,
    GATT_BLE_REMOTE_WRITE_EVT,
    GATT_BLE_REMOTE_SET_EVT,
    GATT_EVT_MAX,
} gl_ble_gatt_event_t;

typedef union {
    struct ble_remote_notify_evt_data {
        int connection;
        int characteristic;
        int att_opcode;
        int offset;
        char value[MAX_VALUE_DATA_LEN];

    } remote_notify;
    struct ble_remote_wirte_evt_data {
        int connection;
        int attribute;
        int att_opcode;
        int offset;
        char value[MAX_VALUE_DATA_LEN];

    } remote_write;
    struct ble_remote_set_evt_data {
        int connection;
        int characteristic;
        int status_flags;
        int client_config_flags;
    } remote_set;

} gl_ble_gatt_data_t;

typedef struct {
    int (*ble_module_event)(gl_ble_module_event_t event, gl_ble_module_data_t *data);
    int (*ble_gap_event)(gl_ble_gap_event_t event, gl_ble_gap_data_t *data);
    int (*ble_gatt_event)(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);

} gl_ble_cbs;

#endif