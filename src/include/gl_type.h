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

#ifndef _GL_TYPE_H_
#define _GL_TYPE_H_

#include <stdbool.h>
#include <stdint.h>
#include <json-c/json.h>

typedef int32_t GL_RET;

#define UUID_MAX                    128
#define LIST_LENGTHE_MAX            16
#define CHAR_VALUE_MAX              256
#define DEVICE_MAC_LEN              6
#define BLE_MAC_LEN                 18
#define MAX_VALUE_DATA_LEN          255
#define MAX_ADV_DATA_LEN            255
#define MAX_HASH_DATA_LEN           255

typedef struct {
    int32_t handle;
    char uuid[UUID_MAX];
} ble_service_list_t;

typedef struct {
    int32_t handle;
    char uuid[UUID_MAX];
    uint8_t properties;
} ble_characteristic_list_t;

// typedef enum {
//     DISABLE = 0,
//     ENABLE,
// }gl_ble_e;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
} gl_ble_get_mac_rsp_t;

typedef struct {
    int32_t current_power;
} gl_ble_set_power_rsp_t;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
    uint8_t address_type;
    uint8_t master;
    uint8_t bonding;
    uint8_t advertiser;
} gl_ble_connect_rsp_t;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
    int32_t rssi;
} gl_ble_get_rssi_rsp_t;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
    uint8_t list_len;
    ble_service_list_t list[LIST_LENGTHE_MAX];
} gl_ble_get_service_rsp_t;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
    uint8_t list_len;
    ble_characteristic_list_t list[LIST_LENGTHE_MAX];
} gl_ble_get_char_rsp_t;

typedef struct {
    uint8_t address[DEVICE_MAC_LEN];
    int32_t handle;
    uint8_t att_opcode;
    int32_t offset;
    char value[CHAR_VALUE_MAX];
} gl_ble_char_read_rsp_t;

typedef struct {
    int32_t sent_len;
} gl_ble_write_char_rsp_t;

typedef struct {
    int32_t sent_len;
} gl_ble_send_notify_rsp_t;

typedef struct {
    int32_t number_of_packets;
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
        int32_t major;
        int32_t minor;
        int32_t patch;
        int32_t build;
        int32_t bootloader;
        int32_t hw;
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
        uint8_t address[DEVICE_MAC_LEN]; 
        gl_ble_addr_type_t ble_addr_type; 
        int32_t packet_type;  
        int32_t rssi;  
        char ble_adv[MAX_ADV_DATA_LEN];
        int32_t bonding;
    } scan_rst;

    struct ble_update_conn_evt_data {
        uint8_t address[DEVICE_MAC_LEN];
        int32_t interval; 
        int32_t latency;
        int32_t timeout;
        int32_t security_mode;
        int32_t txsize;
    } update_conn_data;

    struct ble_connect_open_evt_data {
        uint8_t address[DEVICE_MAC_LEN]; 
        gl_ble_addr_type_t ble_addr_type;
        int32_t conn_role;
        int32_t connection;
        int32_t bonding;
        int32_t advertiser;
    } connect_open_data;

    struct ble_disconnect_evt_data {
        uint8_t address[DEVICE_MAC_LEN];
        int32_t reason;
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
        uint8_t address[DEVICE_MAC_LEN];
        int32_t characteristic;
        int32_t att_opcode;
        int32_t offset;
        char value[MAX_VALUE_DATA_LEN];

    } remote_notify;
    struct ble_remote_write_evt_data {
        uint8_t address[DEVICE_MAC_LEN];
        int32_t attribute;
        int32_t att_opcode;
        int32_t offset;
        char value[MAX_VALUE_DATA_LEN];

    } remote_write;
    struct ble_remote_set_evt_data {
        uint8_t address[DEVICE_MAC_LEN];
        int32_t characteristic;
        int32_t status_flags;
        int32_t client_config_flags;
    } remote_set;

} gl_ble_gatt_data_t;

typedef struct {
    int32_t (*ble_module_event)(gl_ble_module_event_t event, gl_ble_module_data_t *data);
    int32_t (*ble_gap_event)(gl_ble_gap_event_t event, gl_ble_gap_data_t *data);
    int32_t (*ble_gatt_event)(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);

} gl_ble_cbs;

#endif