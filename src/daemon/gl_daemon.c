/*****************************************************************************
 * @file  daemon.c
 * @brief Daemon program manage BLE module and provide BLE operation interfaces
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
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "bg_types.h"
#include "gl_uart.h"
#include "gl_hal.h"
#include "gl_log.h"
#include "gl_methods.h"
#include "gl_dev_mgr.h"
#include "gl_common.h"
#include "gl_errno.h"
 
static struct ubus_context * ctx = NULL;
static const char* sock_path = NULL;
static struct blob_buf b;
static struct uloop_fd serial_fd;

/* BLE System functions */

/*Enable or disable the BLE module*/
enum
{
	ENABLE_OR_DISABLE,
	ENABLE_POLICY_MAX,
};
static const struct blobmsg_policy enable_policy[ENABLE_POLICY_MAX] = {
	[ENABLE_OR_DISABLE] = {.name = "enable", .type = BLOBMSG_TYPE_INT32},
};

/* A callback function for ubus methods handling */
static int enable(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	/* delete a descriptor from the event processing loop */
    uloop_fd_delete(&serial_fd);

	/* for parsed attr */
	struct blob_attr *tb[ENABLE_POLICY_MAX];
	
	/* parse blob_msg from the caller to request policy */
	blobmsg_parse(enable_policy, ENABLE_POLICY_MAX, tb, blob_data(msg), blob_len(msg));
	int enable = blobmsg_get_u32(tb[ENABLE_OR_DISABLE]);
	json_object* output = ble_enable(enable);

	/* send a reply msg to the caller for information */
	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	/* register a new descriptor into the event processing loop */
	uloop_fd_add(&serial_fd, ULOOP_READ);
	
	return GL_SUCCESS;
}

/*Get local bluetooth MAC*/
int local_mac(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);
    
    json_object* output = ble_local_mac();

    blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);
    
	uloop_fd_add(&serial_fd, ULOOP_READ);
    return GL_SUCCESS;
}
/*Set the global power level*/
enum
{
	SYSTEM_POWER_LEVEL,
	SYSTEM_POWER_MAX,
};
static const struct blobmsg_policy set_power_policy[SYSTEM_POWER_MAX] = {
	[SYSTEM_POWER_LEVEL] = {.name = "system_power_level", .type = BLOBMSG_TYPE_INT32},
};
static int set_power(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[SYSTEM_POWER_MAX];
	blobmsg_parse(set_power_policy, SYSTEM_POWER_MAX, tb, blob_data(msg), blob_len(msg));
	int power = blobmsg_get_u32(tb[SYSTEM_POWER_LEVEL]);
	json_object* output = ble_set_power(power);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
enum
{
	PHYS,
	INTERVAL,
	WINDOW,
	TYPE,
	MODE,
	DISCOVERY_POLICY_MAX,
};
static const struct blobmsg_policy discovery_policy[DISCOVERY_POLICY_MAX] = {
	[PHYS] = {.name = "phys", .type = BLOBMSG_TYPE_INT32},
	[INTERVAL] = {.name = "interval", .type = BLOBMSG_TYPE_INT32},
	[WINDOW] = {.name = "window", .type = BLOBMSG_TYPE_INT32},
	[TYPE] = {.name = "type", .type = BLOBMSG_TYPE_INT32},
	[MODE] = {.name = "mode", .type = BLOBMSG_TYPE_INT32},
};
static int discovery(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[DISCOVERY_POLICY_MAX];
	blobmsg_parse(discovery_policy, DISCOVERY_POLICY_MAX, tb, blob_data(msg), blob_len(msg));
	int phys = blobmsg_get_u32(tb[PHYS]);
	int interval = blobmsg_get_u32(tb[INTERVAL]);
	int window = blobmsg_get_u32(tb[WINDOW]);
	int type = blobmsg_get_u32(tb[TYPE]);
	int mode = blobmsg_get_u32(tb[MODE]);

	json_object* output = ble_discovery(phys,interval,window,type,mode);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/*Act as master, End the current GAP discovery procedure*/
int stop(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);
    
    json_object* output = ble_stop();

    blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);
    
	uloop_fd_add(&serial_fd, ULOOP_READ);
    return GL_SUCCESS;
}
/*Act as master, Start connect to a remote BLE device*/
enum
{
	CONN_ADDRESS,
	CONN_ADDRESS_TYPE,
	CONN_PHY,
	CONN_MAX,
};
static const struct blobmsg_policy conn_policy[CONN_MAX] = {
	[CONN_ADDRESS] = {.name = "conn_address", .type = BLOBMSG_TYPE_STRING},
	[CONN_ADDRESS_TYPE] = {.name = "conn_address_type", .type = BLOBMSG_TYPE_INT32},
	[CONN_PHY] = {.name = "conn_phy", .type = BLOBMSG_TYPE_INT32},
};
static int connect(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	log_debug("leave fd listen");
    uloop_fd_delete(&serial_fd);
	struct blob_attr *tb[CONN_MAX];
	blobmsg_parse(conn_policy, CONN_MAX, tb, blob_data(msg), blob_len(msg));
	char* address = blobmsg_get_string(tb[CONN_ADDRESS]);
	int address_type = blobmsg_get_u32(tb[CONN_ADDRESS_TYPE]);
	int conn_phy = blobmsg_get_u32(tb[CONN_PHY]);
	json_object* output = ble_connect(address, address_type, conn_phy);

	char *str = json_object_to_json_string(output);
	
	int ret = -1;

	json_object *val_obj = NULL;
	if ( json_object_object_get_ex(output, "code",  &val_obj) ) {
		ret = json_object_get_int(val_obj);
	}

	if ( !ret )
		add_device_to_list(output);
	else 
		log_err("Connect output is null\n");

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);

	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	log_debug("start fd listen");
	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as master, disconnect with remote device*/
enum
{
	DISCONN_ADDRESS,
	DISCONNECT_MAX,
};
static const struct blobmsg_policy disconnect_policy[DISCONNECT_MAX] = {
	[DISCONN_ADDRESS] = {.name = "disconn_address", .type = BLOBMSG_TYPE_STRING},
};
static int disconnect(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[DISCONNECT_MAX];
	blobmsg_parse(disconnect_policy, DISCONNECT_MAX, tb, blob_data(msg), blob_len(msg));

	char* address = blobmsg_get_string(tb[DISCONN_ADDRESS]);
	int connection = ble_dev_mgr_get_connection(address);
	json_object* output = ble_disconnect(connection);
	char *str = json_object_to_json_string(output);
	
	char *addr = ble_dev_mgr_get_address(connection);

	json_object_object_add(output, "address",json_object_new_string(addr));

	char *str1 = json_object_to_json_string(output);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as master, Get rssi of connection with remote device*/
enum
{
	RSSI_ADDRESS,
	RSSI_MAX,
};
static const struct blobmsg_policy get_rssi_policy[RSSI_MAX] = {
	[RSSI_ADDRESS] = {.name = "rssi_address", .type = BLOBMSG_TYPE_STRING},
};
static int get_rssi(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[RSSI_MAX];
	blobmsg_parse(get_rssi_policy, RSSI_MAX, tb, blob_data(msg), blob_len(msg));
	// int connection = blobmsg_get_u32(tb[RSSI_CONNECTION]);

	char* address = blobmsg_get_string(tb[RSSI_ADDRESS]);
	int connection = ble_dev_mgr_get_connection(address);
	json_object* output = ble_get_rssi(connection);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);

	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as master, Get service list of a remote GATT server*/
enum
{
	SERVICE_ADDRESS,
	SERVICE_MAX,
};
static const struct blobmsg_policy get_service_policy[SERVICE_MAX] = {
	[SERVICE_ADDRESS] = {.name = "get_service_address", .type = BLOBMSG_TYPE_STRING},
};
static int get_service(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[SERVICE_MAX];
	blobmsg_parse(get_service_policy, SERVICE_MAX, tb, blob_data(msg), blob_len(msg));

	char *address = blobmsg_get_string(tb[SERVICE_ADDRESS]);
	printf("address = %s\n", address);
	int connection = ble_dev_mgr_get_connection(address);
	printf("connection = %d\n", connection);
	json_object* output = ble_get_service(connection);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as master, Get characteristic list of a remote GATT server*/
enum
{
	CHAR_CONN_ADDRESS,
	CHAR_SERVICE_HANDLE,
	CHAR_MAX,
};
static const struct blobmsg_policy get_char_policy[CHAR_MAX] = {
	[CHAR_CONN_ADDRESS] = {.name = "char_conn_address", .type = BLOBMSG_TYPE_STRING},
	[CHAR_SERVICE_HANDLE] = {.name = "char_service_handle", .type = BLOBMSG_TYPE_INT32},
};
static int get_char(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[CHAR_MAX];
	blobmsg_parse(get_char_policy, CHAR_MAX, tb, blob_data(msg), blob_len(msg));
	
	int connection = 0;

	char *address = blobmsg_get_string(tb[CHAR_CONN_ADDRESS]);
	connection = ble_dev_mgr_get_connection(address);
	
	int service_handle = blobmsg_get_u32(tb[CHAR_SERVICE_HANDLE]);
	json_object* output = ble_get_char(connection, service_handle);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/*Act as master, Read value of specified characteristic in a remote gatt server*/
enum
{
	GATT_READ_CHAR_CONN_ADDR,
	GATT_READ_CHAR_CHAR_HANDLE,
	GATT_READ_CHAR_MAX,
};

static const struct blobmsg_policy read_char_policy[GATT_READ_CHAR_MAX] = {
	[GATT_READ_CHAR_CONN_ADDR] = {.name = "char_conn_addr", .type = BLOBMSG_TYPE_STRING},
	[GATT_READ_CHAR_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
};

static int read_char(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[GATT_READ_CHAR_MAX];
	blobmsg_parse(read_char_policy, GATT_READ_CHAR_MAX, tb, blob_data(msg), blob_len(msg));
	
	char *address = blobmsg_get_string(tb[GATT_READ_CHAR_CONN_ADDR]);
	int connection = ble_dev_mgr_get_connection(address);

	int char_handle = blobmsg_get_u32(tb[GATT_READ_CHAR_CHAR_HANDLE]);
	json_object* output = ble_read_char(connection,char_handle);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/*Act as master, Write value to specified characteristic in a remote gatt server*/
enum
{
	GATT_WRITE_CHAR_CONN_ADDR,
	GATT_WRITE_CHAR_CHAR_HANDLE,
	GATT_WRITE_CHAR_VALUE,
	GATT_WRITE_CHAR_RES,
	GATT_WRITE_CHAR_MAX,
};
static const struct blobmsg_policy write_char_policy[GATT_WRITE_CHAR_MAX] = {
	[GATT_WRITE_CHAR_CONN_ADDR] = {.name = "char_conn_addrsss", .type = BLOBMSG_TYPE_STRING},
	[GATT_WRITE_CHAR_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
	[GATT_WRITE_CHAR_VALUE] = {.name = "char_value", .type = BLOBMSG_TYPE_STRING},
	[GATT_WRITE_CHAR_RES] = {.name = "write_res", .type = BLOBMSG_TYPE_INT32},
};
static int write_char(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[GATT_WRITE_CHAR_MAX];
	blobmsg_parse(write_char_policy, GATT_WRITE_CHAR_MAX, tb, blob_data(msg), blob_len(msg));
	
	char *address = blobmsg_get_string(tb[GATT_WRITE_CHAR_CONN_ADDR]);
	int connection = ble_dev_mgr_get_connection(address);
	int char_handle = blobmsg_get_u32(tb[GATT_WRITE_CHAR_CHAR_HANDLE]);
	char* value = blobmsg_get_string(tb[GATT_WRITE_CHAR_VALUE]);
	int write_res = blobmsg_get_u32(tb[GATT_WRITE_CHAR_RES]);
	
	json_object* output = ble_write_char(connection, char_handle, value, write_res);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);
	free(address);
	uloop_fd_add(&serial_fd, ULOOP_READ);

	return GL_SUCCESS;
}
/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
enum
{
	GATT_SET_NOTIFY_CONN_ADDR,
	GATT_SET_NOTIFY_CHAR_HANDLE,
	GATT_SET_NOTIFY_FLAG,
	GATT_SET_NOTIFY_MAX,
};
static const struct blobmsg_policy set_notify_policy[GATT_SET_NOTIFY_MAX] = {
	[GATT_SET_NOTIFY_CONN_ADDR] = {.name = "conn_addrsss", .type = BLOBMSG_TYPE_STRING},
	[GATT_SET_NOTIFY_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
	[GATT_SET_NOTIFY_FLAG] = {.name = "notify_flag", .type = BLOBMSG_TYPE_INT32},
};
static int set_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);
	struct blob_attr *tb[GATT_SET_NOTIFY_MAX];
	blobmsg_parse(set_notify_policy, GATT_SET_NOTIFY_MAX, tb, blob_data(msg), blob_len(msg));
	
	char *address = blobmsg_get_string(tb[GATT_SET_NOTIFY_CONN_ADDR]);
	int connection = ble_dev_mgr_get_connection(address);
	int char_handle = blobmsg_get_u32(tb[GATT_SET_NOTIFY_CHAR_HANDLE]);
	int flag = blobmsg_get_u32(tb[GATT_SET_NOTIFY_FLAG]);

	json_object* output = ble_set_notify(connection, char_handle, flag);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
enum
{
	ADV_PHYS,
	ADV_INTERVAL_MIN,
	ADV_INTERVAL_MAX,
	ADV_DISCOVER,
	ADV_CONN,
	ADV_MAX,
};
static const struct blobmsg_policy adv_policy[ADV_MAX] = {
	[ADV_PHYS] = {.name = "adv_phys", .type = BLOBMSG_TYPE_INT32},
	[ADV_INTERVAL_MIN] = {.name = "adv_interval_min", .type = BLOBMSG_TYPE_INT32},
	[ADV_INTERVAL_MAX] = {.name = "adv_interval_max", .type = BLOBMSG_TYPE_INT32},
	[ADV_DISCOVER] = {.name = "adv_discover", .type = BLOBMSG_TYPE_INT32},
	[ADV_CONN] = {.name = "adv_conn", .type = BLOBMSG_TYPE_INT32},
};
static int adv(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[ADV_MAX];
	blobmsg_parse(adv_policy, ADV_MAX, tb, blob_data(msg), blob_len(msg));
	int adv_phys = blobmsg_get_u32(tb[ADV_PHYS]);
	int adv_interval_min = blobmsg_get_u32(tb[ADV_INTERVAL_MIN]);
	int adv_interval_max = blobmsg_get_u32(tb[ADV_INTERVAL_MAX]);
	int adv_discover = blobmsg_get_u32(tb[ADV_DISCOVER]);
	int adv_conn = blobmsg_get_u32(tb[ADV_CONN]);
	json_object* output = ble_adv(adv_phys, adv_interval_min, adv_interval_max, adv_discover, adv_conn);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as BLE slave, Set customized advertising data*/
enum
{
	ADV_DATA_FLAG,
	ADV_DATA,
	ADV_DATA_MAX,
};
static const struct blobmsg_policy adv_data_policy[ADV_DATA_MAX] = {
	[ADV_DATA_FLAG] = {.name = "adv_data_flag", .type = BLOBMSG_TYPE_INT32},
	[ADV_DATA] = {.name = "adv_data", .type = BLOBMSG_TYPE_STRING},
};
static int adv_data(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[ADV_DATA_MAX];
	blobmsg_parse(adv_data_policy, ADV_DATA_MAX, tb, blob_data(msg), blob_len(msg));
	int adv_data_flag = blobmsg_get_u32(tb[ADV_DATA_FLAG]);
	char* adv_data = blobmsg_get_string(tb[ADV_DATA]);
	json_object* output = ble_adv_data(adv_data_flag,adv_data);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/*Act as BLE slave, Stop advertising*/
int stop_adv(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);
    
    json_object* output = ble_stop_adv();

    blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);
    
	uloop_fd_add(&serial_fd, ULOOP_READ);
    return GL_SUCCESS;
}
/*Act as BLE slave, Send Notification*/
enum
{
	SEND_NOTI_CONN_ADDR,
	SEND_NOTI_CHAR,
	SEND_NOTI_VALUE,
	SEND_NOTI_MAX,
};
static const struct blobmsg_policy send_noti_policy[SEND_NOTI_MAX] = {
	[SEND_NOTI_CONN_ADDR] = {.name = "send_noti_conn_addr", .type = BLOBMSG_TYPE_STRING},
	[SEND_NOTI_CHAR] = {.name = "send_noti_char", .type = BLOBMSG_TYPE_INT32},
	[SEND_NOTI_VALUE] = {.name = "send_noti_value", .type = BLOBMSG_TYPE_STRING},
};
static int send_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[SEND_NOTI_MAX];
	blobmsg_parse(send_noti_policy, SEND_NOTI_MAX, tb, blob_data(msg), blob_len(msg));
	
	char *address = blobmsg_get_string(tb[SEND_NOTI_CONN_ADDR]);
	int connection = ble_dev_mgr_get_connection(address);

	int send_noti_char = blobmsg_get_u32(tb[SEND_NOTI_CHAR]);
	char* send_noti_value = blobmsg_get_string(tb[SEND_NOTI_VALUE]);
	json_object* output = ble_send_notify(connection,send_noti_char,send_noti_value);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);
	free(address);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/* DTM test functions, TX*/
enum
{
	DTM_TX_TYPE,
	DTM_TX_LENGTH,
	DTM_TX_CHANNEL,
	DTM_TX_PHY,
	DTM_TX_MAX
};
static const struct blobmsg_policy dtm_tx_policy[DTM_TX_MAX] = {
	[DTM_TX_TYPE] = {.name = "dtm_tx_type", .type = BLOBMSG_TYPE_INT32},
	[DTM_TX_LENGTH] = {.name = "dtm_tx_length", .type = BLOBMSG_TYPE_INT32},
	[DTM_TX_CHANNEL] = {.name = "dtm_tx_channel", .type = BLOBMSG_TYPE_INT32},
	[DTM_TX_PHY] = {.name = "dtm_tx_phy", .type = BLOBMSG_TYPE_INT32}
};
static int dtm_tx(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[DTM_TX_MAX];
	blobmsg_parse(dtm_tx_policy, DTM_TX_MAX, tb, blob_data(msg), blob_len(msg));
	int dtm_tx_type = blobmsg_get_u32(tb[DTM_TX_TYPE]);
	int dtm_tx_length = blobmsg_get_u32(tb[DTM_TX_LENGTH]);
	int dtm_tx_channel = blobmsg_get_u32(tb[DTM_TX_CHANNEL]);
	int dtm_tx_phy = blobmsg_get_u32(tb[DTM_TX_PHY]);
	json_object* output = ble_dtm_tx(dtm_tx_type,dtm_tx_length,dtm_tx_channel,dtm_tx_phy);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/* DTM test functions, RX */
enum
{
	DTM_RX_CHANNEL,
	DTM_RX_PHY,
	DTM_RX_MAX
};
static const struct blobmsg_policy dtm_rx_policy[DTM_RX_MAX] = {
	[DTM_RX_CHANNEL] = {.name = "dtm_rx_channel", .type = BLOBMSG_TYPE_INT32},
	[DTM_RX_PHY] = {.name = "dtm_rx_phy", .type = BLOBMSG_TYPE_INT32}
};
static int dtm_rx(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	struct blob_attr *tb[DTM_RX_MAX];
	blobmsg_parse(dtm_rx_policy, DTM_RX_MAX, tb, blob_data(msg), blob_len(msg));
	int dtm_rx_channel = blobmsg_get_u32(tb[DTM_RX_CHANNEL]);
	int dtm_rx_phy = blobmsg_get_u32(tb[DTM_RX_PHY]);
	json_object* output = ble_dtm_rx(dtm_rx_channel,dtm_rx_phy);

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}
/* DTM test functions, end */

static int dtm_end(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    uloop_fd_delete(&serial_fd);

	json_object* output = ble_dtm_end();

	blob_buf_init(&b, 0);
	blobmsg_add_object(&b, output);
	ubus_send_reply(ctx, req, b.head);
	json_object_put(output);

	uloop_fd_add(&serial_fd, ULOOP_READ);
	return GL_SUCCESS;
}

/* ubus methods */
static struct ubus_method ble_methods[] = 
{
	/* System */
	UBUS_METHOD("enable", enable, enable_policy),
	UBUS_METHOD_NOARG("local_mac", local_mac),
	UBUS_METHOD("set_power", set_power, set_power_policy),
	/*Master*/
	UBUS_METHOD("discovery", discovery, discovery_policy),
	UBUS_METHOD_NOARG("stop", stop),
	UBUS_METHOD("connect", connect, conn_policy),
	UBUS_METHOD("disconnect", disconnect, disconnect_policy),
	UBUS_METHOD("get_rssi", get_rssi, get_rssi_policy),
	UBUS_METHOD("get_service", get_service, get_service_policy),
	UBUS_METHOD("get_char", get_char, get_char_policy),
	UBUS_METHOD("read_char", read_char, read_char_policy),
	UBUS_METHOD("write_char", write_char, write_char_policy),
	UBUS_METHOD("set_notify", set_notify, set_notify_policy),
	/*Slave*/
	UBUS_METHOD("adv", adv, adv_policy),
	UBUS_METHOD("adv_data", adv_data, adv_data_policy),
	UBUS_METHOD_NOARG("stop_adv", stop_adv),
	UBUS_METHOD("send_notify", send_notify, send_noti_policy),

	/*Test*/
	UBUS_METHOD("dtm_tx", dtm_tx, dtm_tx_policy),
	UBUS_METHOD("dtm_rx", dtm_rx, dtm_rx_policy),
	UBUS_METHOD_NOARG("dtm_end", dtm_end),
};

/* ubus object type */
static struct ubus_object_type ble_obj_type = UBUS_OBJECT_TYPE("ble", ble_methods);

/* ubus object assignment */
static struct ubus_object ble_obj = 
{
	.name = "ble",
	.type = &ble_obj_type,
	.methods = ble_methods,
	.n_methods = ARRAY_SIZE(ble_methods),
};

static void ubus_reconn_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout reconn_timer = {
		.cb = ubus_reconn_timer,
	};
	if(ubus_reconnect(ctx,sock_path) != 0){
		uloop_timeout_set(&reconn_timer,1000);
	}
	else{
		ubus_add_uloop(ctx);
	}
}

static void ubus_connection_lost(struct ubus_context *ctx)
{
	ubus_reconn_timer(NULL);
}

static void manage_device(json_object* o)
{
	json_object *val_obj = NULL;
	uint16_t connection;

	char *type = NULL, *addr = NULL;
	if ( json_object_object_get_ex(o, "type",  &val_obj) ) {
		type = json_object_get_string(val_obj);
	}

	log_info("notification type: %s", type);

	if ( !strcmp(type, CONN_OPEN)) {
		add_device_to_list(o);
	}
	else if ( !strcmp(type, CONN_CLOSE)) {
		if ( json_object_object_get_ex(o, "connection", &val_obj)) {
			connection = json_object_get_int(val_obj);
		}

		addr = ble_dev_mgr_get_address(connection);

		json_object_object_del(o, "connection");
		json_object_object_add(o, "address", json_object_new_string(addr));
		delete_device_from_list(o);
	}	
	else if ( !strcmp(type, CONN_UPDATE)) {
		if ( json_object_object_get_ex(o, "connection", &val_obj)) {
			connection = json_object_get_int(val_obj);
		}

		addr = ble_dev_mgr_get_address(connection);

		json_object_object_del(o, "connection");
		json_object_object_add(o, "address", json_object_new_string(addr));		
	}
	else if ( !strcmp(type, REMOTE_NOTIFY))	{
		if ( json_object_object_get_ex(o, "connection", &val_obj)) {
			connection = json_object_get_int(val_obj);
		}		
		
		addr = ble_dev_mgr_get_address(connection);
		
		json_object_object_del(o, "connection");
		json_object_object_add(o, "address", json_object_new_string(addr));
		
	}
	else if ( !strcmp(type, REMOTE_WRITE))	{
		if ( json_object_object_get_ex(o, "connection", &val_obj)) {
			connection = json_object_get_int(val_obj);
		}		
		
		addr = ble_dev_mgr_get_address(connection);
		
		json_object_object_del(o, "connection");
		json_object_object_add(o, "address", json_object_new_string(addr));		
		
	}
	else if ( !strcmp(type, REMOTE_SET)) {
		if ( json_object_object_get_ex(o, "connection", &val_obj)) {
			connection = json_object_get_int(val_obj);
		}		
		
		addr = ble_dev_mgr_get_address(connection);
		
		json_object_object_del(o, "connection");
		json_object_object_add(o, "address", json_object_new_string(addr));		
	}

    return;
}

void serial_msg_handle_cb(struct uloop_fd *u, unsigned int events)
{
    json_object* output = serial_msg_callback();

	if(output) {
		manage_device(output);
		blob_buf_init(&b, 0);
		blobmsg_add_object(&b, output);

		/* broadcast notification message */
		ubus_notify(ctx,  &ble_obj, "Notify", b.head, -1);
		json_object_put(output);
	}
}

int main(int argc, char * argv[])
{	
	/* Enable ble module */
	ble_enable(1);

	/* Init device manage */
	ble_dev_mgr_init();

	/* Create an epoll instance descriptor poll_fd */
	uloop_init();

    int serialFd = hal_init();
    serial_fd.cb = serial_msg_handle_cb;
    serial_fd.fd = serialFd;

	/* Register a new descriptor into the event processing loop */
    uloop_fd_add(&serial_fd, ULOOP_READ);
    
	/* Connect to ubusd and get ctx */
	ctx = ubus_connect(sock_path);
    if (!ctx) {
		fprintf(stderr,"Ubus connect failed\n");
		return -1;
	}
	ctx->connection_lost = ubus_connection_lost;

	/* Register epoll events to uloop, start sock listing */
    ubus_add_uloop(ctx);

	/* Register a ubus_object to ubusd */
	if (ubus_add_object(ctx, &ble_obj) != 0)
	{
		fprintf(stderr,"ubus add obj failed\n");
		ubus_free(ctx);
		return -1;
	}

	/* uloop routine: events monitoring and callback provoking */
	uloop_run();
 
	ubus_free(ctx);

	/* Destruct event loop */
	uloop_done();

	return GL_SUCCESS;
}