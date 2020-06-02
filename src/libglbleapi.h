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

#define UUID_MAX                32
#define LIST_LENGTHE_MAX        16
#define CHAR_VALUE_MAX          256

typedef struct {
    int handle;
    char uuid[UUID_MAX];
}ble_service_list_t;

typedef struct {
    int handle;
    char uuid[UUID_MAX];
    uint8_t properties;
}ble_characteristic_list_t;

typedef struct {
    uint8_t addr[6];
}gl_ble_get_mac_rsp_t;

typedef struct {
    int current_power;
}gl_ble_set_power_rsp_t;

typedef struct {
    uint8_t connection;
    uint8_t addr[6];
    uint8_t address_type;
    uint8_t master;
    uint8_t bonding;
    uint8_t advertiser;
}gl_ble_connect_rsp_t;

typedef struct {
    uint8_t connection;
    int rssi;
}gl_ble_get_rssi_rsp_t;

typedef struct {
    uint8_t connection;
    uint8_t list_len;
    ble_service_list_t list[LIST_LENGTHE_MAX];
}gl_ble_get_service_rsp_t;

typedef struct {
    uint8_t connection;
    uint8_t list_len;
    ble_characteristic_list_t list[LIST_LENGTHE_MAX];
}gl_ble_get_char_rsp_t;

typedef struct {
    uint8_t connection;
    int handle;
    uint8_t att_opcode;
    int offset;
    uint8_t value[CHAR_VALUE_MAX];
}gl_ble_char_read_rsp_t;

typedef struct {
    int sent_len;
}gl_ble_write_char_rsp_t;

typedef struct {
    int sent_len;
}gl_ble_send_notify_rsp_t;

typedef struct {
    int number_of_packets;
}gl_ble_dtm_test_rsp_t;





typedef struct {
    ubus_handler_t cb;
    ubus_remove_handler_t remove_cb;
} ubus_subscriber_cb_t;


/// module callback event type
// typedef enum {
//     MODULE_BOOT = 0,
// 	MODULE_EVT_MAX,
// } gl_ble_module_event_t;

// typedef union {

// } gl_ble_module_data_t;

/// GAP BLE callback event type
typedef enum {
    GAP_BLE_SCAN_RESULT_EVT = 0,
	GAP_BLE_UPDATE_CONN_EVT,
	GAP_BLE_CONNECT_EVT,
	GAP_BLE_DISCONNECT_EVT,
    GAP_BLE_EVT_MAX,
} gl_ble_gap_evrnt_t;

/// BLE device address type
typedef enum {
    BLE_ADDR_TYPE_PUBLIC        = 0x00,
    BLE_ADDR_TYPE_RANDOM        = 0x01,
	BLE_ANONYMOUS_ADVERTISING	= 0xff,
} gl_ble_addr_type_t;

#define BLE_MAC_LEN					18
#define MAX_ADV_DATA_LEN			255
typedef union {
	struct ble_scan_result_evt_data {
		char addr[BLE_MAC_LEN];                          /*!< Bluetooth device address which has been searched */
		gl_ble_addr_type_t ble_addr_type;          /*!< Ble device address type */
		int packet_type;            		/*!< Ble scan result packet type */
		int rssi;                                   /*!< Searched device's RSSI */
		char ble_adv[MAX_ADV_DATA_LEN];    				 /*!< Received EIR */
		int bonding;							
    } scan_rst;                                     /*!< Event parameter of ESP_GAP_BLE_SCAN_RESULT_EVT */

    struct ble_update_conn_evt_data {
        int connection;                         	/*!< Bluetooth device address */
        int interval;                          /*!< Min connection interval */
        int latency;                          /*!< Slave latency for the connection in number of connection events. Range: 0x0000 to 0x01F3 */
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
		int connection;
		int reason;
	} disconnect_data;
} gl_ble_gap_data_t;

/// GATT BLE callback event type
// typedef enum {
// 	GATT_EVT_MAX,
// } gl_ble_gatt_event_t;

// typedef union {

// } gl_ble_gatt_data_t;

typedef struct {
	// int (*ble_module_event)(gl_ble_module_event_t event, gl_ble_module_data_t *data);
	int (*ble_gap_event)(gl_ble_gap_evrnt_t event, gl_ble_gap_data_t *data);
	// int (*ble_gatt_event)(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);
} gl_ble_cbs;




int gl_ble_subscribe(gl_ble_cbs* callback);
int gl_ble_unsubscribe(void);


/* BLE System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(gl_ble_get_mac_rsp_t *rsp);

/*Enable or disable the BLE module*/
int gl_ble_enable(int enable);

/*Set the global power level*/
int gl_ble_set_power(gl_ble_set_power_rsp_t * rsp, int power);


/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
int gl_ble_discovery(int phys,int interval,int window,int type,int mode);

/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(void);

/*Act as master, Start connect to a remote BLE device*/
int gl_ble_connect(gl_ble_connect_rsp_t* rsp,char* address,int address_type,int phy);

/*Act as master, disconnect with remote device*/
int gl_ble_disconnect(int connection);

/*Act as master, Get rssi of connection with remote device*/
int gl_ble_get_rssi(gl_ble_get_rssi_rsp_t* rsp,int connection);

/*Act as master, Get service list of a remote GATT server*/
int gl_ble_get_service(gl_ble_get_service_rsp_t *rsp, int connection);

/*Act as master, Get characteristic list of a remote GATT server*/
int gl_ble_get_char(gl_ble_get_char_rsp_t *rsp, int connection, int service_handle);

/*Act as master, Read value of specified characteristic in a remote gatt server*/
int gl_ble_read_char(gl_ble_char_read_rsp_t *rsp, int connection, int char_handle);

/*Act as master, Write value to specified characteristic in a remote gatt server*/
int gl_ble_write_char(gl_ble_write_char_rsp_t *rsp, int connection, int char_handle,char* value,int res);

/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
int gl_ble_set_notify(int connection, int char_handle,int flag);


/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
int gl_ble_adv(int phys, int interval_min,int interval_max,int discover,int connect);

/*Act as BLE slave, Set customized advertising data*/
int gl_ble_adv_data(int flag, char* data);

/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(void);

/*Act as BLE slave, Send Notification*/
int gl_ble_send_notify(gl_ble_send_notify_rsp_t *rsp,int connection,int char_handle, char* value);

/*DTM test, tx*/
int gl_ble_dtm_tx(gl_ble_dtm_test_rsp_t *rsp, int packet_type,int length, int channel, int phy);

/*DTM test, rx*/
int gl_ble_dtm_rx(gl_ble_dtm_test_rsp_t *rsp, int channel, int phy);

/*DTM test, end*/
int gl_ble_dtm_end(gl_ble_dtm_test_rsp_t *rsp);

#endif