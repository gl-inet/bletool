/*****************************************************************************
 * @file  libglbleapi.c
 * @brief Shared library for API interface
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

#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <gl/debug.h>

#include "libglbleapi.h"
#include "ble_dev_mgr.h"
#include "infra_log.h"

static struct ubus_subscriber subscriber;
static struct uloop_timeout listen_timeout;
static unsigned char listen;

static gl_ble_cbs ble_msg_cb;

/* GAP call back functions.*/
static void call_adv_packet_cb(json_object *msg);
static void call_conn_update_cb(json_object *msg);
static void call_conn_open_cb(json_object *msg);
static void call_conn_close_cb(json_object *msg);

/* Module call back functions.*/
static void call_system_boot_cb(json_object *msg);

/* GATT call back functions.*/
static void call_remote_notify_cb(json_object *msg);
static void call_remote_write_cb(json_object *msg);
static void call_remote_set_cb(json_object *msg);

static void sub_remove_callback(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
	fprintf(stderr, "Removed by server\n");
}

static int sub_handler(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	if (!msg)
	{
		return -1;
	}

	char *str = blobmsg_format_json(msg, true);
	json_object *o = json_tokener_parse(str);
	if (!o)
	{
		printf("json parse null\n");
		free(str);
		return -1;
	}

	json_object *tmp_type = json_object_object_get(o, "type");
	char *type = json_object_get_string(tmp_type);
	if (0 == strcmp(type, "unknow_msg"))
	{
		LOG(LOG_DEBUG, "ble ubus unknow_msg\n");
	}
	else if (0 == strcmp(type, "system_boot"))
	{
		LOG(LOG_DEBUG, "ble ubus system boot\n");
		call_system_boot_cb(o);
	}
	else if (0 == strcmp(type, "conn_close"))
	{
		LOG(LOG_DEBUG, "ble ubus connect close\n");
		call_conn_close_cb(o);
	}
	else if (0 == strcmp(type, "conn_open"))
	{
		LOG(LOG_DEBUG, "ble ubus connect open\n");
		call_conn_open_cb(o);
	}
	else if (0 == strcmp(type, "remote_notify"))
	{
		LOG(LOG_DEBUG, "ble ubus remote notify\n");
		call_remote_notify_cb(o);
	}
	else if (0 == strcmp(type, "remote_write"))
	{
		LOG(LOG_DEBUG, "ble ubus remote write\n");
		call_remote_write_cb(o);
	}
	else if (0 == strcmp(type, "remote_set"))
	{
		LOG(LOG_DEBUG, "ble ubus remote set\n");
		call_remote_set_cb(o);
	}
	else if (0 == strcmp(type, "adv_packet"))
	{
		LOG(LOG_DEBUG, "ble ubus adv_packet\n");
		call_adv_packet_cb(o);
	}
	else if (0 == strcmp(type, "conn_update"))
	{
		LOG(LOG_DEBUG, "ble ubus connect update\n");
		call_conn_update_cb(o);
	}

	json_object_put(o);
	free(str);
	return 0;
}

static void listen_timeout_cb(struct uloop_timeout *timeout)
{
	if (!listen)
	{
		uloop_end();
	}
	else
	{
		uloop_timeout_set(timeout, 1 * 1000);
	}
}

static void ble_register_cb(gl_ble_cbs *cb)
{
	if(NULL != cb->ble_module_event)
	{
		ble_msg_cb.ble_module_event = cb->ble_module_event;
	}

	if (NULL != cb->ble_gap_event)
	{
		ble_msg_cb.ble_gap_event = cb->ble_gap_event;
	}

	if(NULL != cb->ble_gatt_event)
	{
		ble_msg_cb.ble_gatt_event = cb->ble_gatt_event;
	}
}

int gl_ble_subscribe(gl_ble_cbs *callback)
{
	int ret;
	unsigned int id = 0;

	ble_register_cb(callback);

	subscriber.cb = sub_handler;
	subscriber.remove_cb = sub_remove_callback;

	struct ubus_context *CTX = ubus_connect(NULL);
	if (!CTX)
	{
		fprintf(stderr, "ubus_connect failed.\n");
		return -1;
	}
	ret = ubus_register_subscriber(CTX, &subscriber);
	if (ret)
	{
		fprintf(stderr, "Failed to register subscriber: %d\n", ret);
	}

	if (ubus_lookup_id(CTX, "ble", &id))
	{
		fprintf(stderr, "ubus_lookup_id failed.\n");
		if (CTX)
		{
			ubus_free(CTX);
		}
		return -1;
	}
	ret = ubus_subscribe(CTX, &subscriber, id);
	if (ret)
	{
		fprintf(stderr, "Failed to subscribe: %d\n", ret);
	}

	listen = 1;
	listen_timeout.cb = listen_timeout_cb;

	uloop_init();
	ubus_add_uloop(CTX);
	uloop_timeout_set(&listen_timeout, 1 * 1000);

	uloop_run();
	uloop_done();
	return 0;
}
int gl_ble_unsubscribe(void)
{
	listen = 0;
	return 0;
}

static void ubus_invoke_complete_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char **str = (char **)req->priv;

	if (msg && str)
		*str = blobmsg_format_json_indent(msg, true, 0);
}
int json_parameter_check(json_object *obj, char **parameters, int para_num)
{
	json_object *o = NULL;
	int i;
	if (!obj)
		return -1;
	o = json_object_object_get(obj, "code");
	if (!o)
	{
		return -1;
	}
	int code = json_object_get_int(o);
	if (code)
	{
		return code;
	}
	for (i = 0; i < para_num; i++)
	{
		if (!json_object_object_get_ex(obj, parameters[i], &o))
			return -1;
	}
	return 0;
}

/* C/C++ program interface */
int gl_ble_call(const char *path, const char *method, struct blob_buf *b, int timeout, char **str)
{
	unsigned int id = 0;
	struct ubus_context *ctx = NULL;

	ctx = ubus_connect(NULL);
	if (!ctx)
	{
		fprintf(stderr, "ubus_connect failed.\n");
		return -1;
	}

	if (ubus_lookup_id(ctx, path, &id))
	{
		fprintf(stderr, "ubus_lookup_id failed.\n");
		if (ctx)
		{
			ubus_free(ctx);
		}
		return -1;
	}

	ubus_invoke(ctx, id, method, b->head, ubus_invoke_complete_cb, (void *)str, timeout * 1000);

	if (ctx)
		ubus_free(ctx);

	return 0;
}

/* System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(gl_ble_get_mac_rsp_t *rsp)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "local_mac", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"mac"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}
	char *address = json_object_get_string(json_object_object_get(o, "mac"));
	int mac[6];
	sscanf(address, "%02x:%02x:%02x:%02x:%02x:%02x",
		   &mac[5], &mac[4], &mac[3], &mac[2], &mac[1], &mac[0]);
	int i = 0;
	while (i < 6)
	{
		rsp->addr[i] = mac[i];
		i++;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Enable or disable the BLE module*/
int gl_ble_enable(int enable)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "enable", enable);

	gl_ble_call("ble", "enable", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Set system tx power*/
int gl_ble_set_power(gl_ble_set_power_rsp_t *rsp, int power)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "system_power_level", power);

	gl_ble_call("ble", "set_power", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"power"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->current_power = json_object_get_int(json_object_object_get(o, "power"));

	free(str);
	json_object_put(o);
	return 0;
}

/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
int gl_ble_discovery(int phys, int interval, int window, int type, int mode)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "phys", phys);
	blobmsg_add_u32(&b, "interval", interval);
	blobmsg_add_u32(&b, "window", window);
	blobmsg_add_u32(&b, "type", type);
	blobmsg_add_u32(&b, "mode", mode);

	gl_ble_call("ble", "discovery", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(void)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "stop", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Start connect to a remote BLE device*/
int gl_ble_connect(gl_ble_connect_rsp_t *rsp, char *address, int address_type, int phy)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_address", address);
	blobmsg_add_u32(&b, "conn_address_type", address_type);
	blobmsg_add_u32(&b, "conn_phy", phy);

	gl_ble_call("ble", "connect", &b, 5, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"connection", "address", "address_type", "master", "bonding", "advertiser"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o, "connection"));
	rsp->address_type = json_object_get_int(json_object_object_get(o, "address_type"));
	rsp->master = json_object_get_int(json_object_object_get(o, "master"));
	rsp->bonding = json_object_get_int(json_object_object_get(o, "bonding"));
	rsp->advertiser = json_object_get_int(json_object_object_get(o, "advertiser"));
	//char* address = json_object_get_string(json_object_object_get(o,"address"));
	int mac[6];
	sscanf(address, "%02x:%02x:%02x:%02x:%02x:%02x",
		   &mac[5], &mac[4], &mac[3], &mac[2], &mac[1], &mac[0]);
	int i = 0;
	while (i < 6)
	{
		rsp->addr[i] = mac[i];
		i++;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, disconnect with remote device*/
int gl_ble_disconnect(int connection)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "disconn_connection", connection);

	gl_ble_call("ble", "disconnect", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Get rssi of connection with remote device*/
int gl_ble_get_rssi(gl_ble_get_rssi_rsp_t *rsp, int connection)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "rssi_connection", connection);

	gl_ble_call("ble", "get_rssi", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"connection", "rssi"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o, "connection"));
	rsp->rssi = json_object_get_int(json_object_object_get(o, "rssi"));

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Get service list of a remote GATT server*/
int gl_ble_get_service(gl_ble_get_service_rsp_t *rsp, int connection)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);

	gl_ble_call("ble", "get_service", &b, 2, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"connection", "service_list"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o, "connection"));

	json_object *list = json_object_object_get(o, "service_list");
	int len = json_object_array_length(list);
	rsp->list_len = len;
	json_object *obj;

	int i = 0;
	while (i < len)
	{
		obj = json_object_array_get_idx(list, i);
		rsp->list[i].handle = json_object_get_int(json_object_object_get(obj, "service_handle"));
		strcpy(rsp->list[i].uuid, json_object_get_string(json_object_object_get(obj, "service_uuid")));
		i++;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Get characteristic list of a remote GATT server*/
int gl_ble_get_char(gl_ble_get_char_rsp_t *rsp, int connection, int service_handle)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);
	blobmsg_add_u32(&b, "char_service_handle", service_handle);

	gl_ble_call("ble", "get_char", &b, 2, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"connection", "characteristic_list"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o, "connection"));

	json_object *list = json_object_object_get(o, "characteristic_list");
	int len = json_object_array_length(list);
	rsp->list_len = len;
	json_object *obj;

	int i = 0;
	while (i < len)
	{
		obj = json_object_array_get_idx(list, i);
		rsp->list[i].handle = json_object_get_int(json_object_object_get(obj, "characteristic_handle"));
		rsp->list[i].properties = json_object_get_int(json_object_object_get(obj, "properties"));
		strcpy(rsp->list[i].uuid, json_object_get_string(json_object_object_get(obj, "characteristic_uuid")));
		i++;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Read value of specified characteristic in a remote gatt server*/
int gl_ble_read_char(gl_ble_char_read_rsp_t *rsp, int connection, int char_handle)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);

	gl_ble_call("ble", "read_char", &b, 2, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"connection", "characteristic_handle", "att_opcode", "offset", "value"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o, "connection"));
	rsp->handle = json_object_get_int(json_object_object_get(o, "characteristic_handle"));
	rsp->att_opcode = json_object_get_int(json_object_object_get(o, "att_opcode"));
	rsp->offset = json_object_get_int(json_object_object_get(o, "offset"));
	strcpy(rsp->value, json_object_get_string(json_object_object_get(o, "offset")));

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Write value to specified characteristic in a remote gatt server*/
int gl_ble_write_char(gl_ble_write_char_rsp_t *rsp, int connection, int char_handle, char *value, int res)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_string(&b, "char_value", value);
	blobmsg_add_u32(&b, "write_res", res);

	gl_ble_call("ble", "write_char", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	json_object *obj = json_object_object_get(o, "sent_len");
	if (obj)
	{
		rsp->sent_len = json_object_get_int(obj);
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
int gl_ble_set_notify(int connection, int char_handle, int flag)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_u32(&b, "notify_flag", flag);

	gl_ble_call("ble", "set_notify", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}

/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
int gl_ble_adv(int phys, int interval_min, int interval_max, int discover, int connect)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_phys", phys);
	blobmsg_add_u32(&b, "adv_interval_min", interval_min);
	blobmsg_add_u32(&b, "adv_interval_max", interval_max);
	blobmsg_add_u32(&b, "adv_discover", discover);
	blobmsg_add_u32(&b, "adv_conn", connect);

	gl_ble_call("ble", "adv", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as BLE slave, Set customized advertising data*/
int gl_ble_adv_data(int flag, char *data)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_data_flag", flag);
	blobmsg_add_string(&b, "adv_data", data);

	gl_ble_call("ble", "adv_data", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(void)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "stop_adv", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
	return 0;
}
/*Act as BLE slave, Send Notification*/
int gl_ble_send_notify(gl_ble_send_notify_rsp_t *rsp, int connection, int char_handle, char *value)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "send_noti_conn", connection);
	blobmsg_add_u32(&b, "send_noti_char", char_handle);
	blobmsg_add_string(&b, "send_noti_value", value);

	gl_ble_call("ble", "send_notify", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"sent_len"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}
	rsp->sent_len = json_object_get_int(json_object_object_get(o, "sent_len"));

	free(str);
	json_object_put(o);
	return 0;
}
/*DTM test, tx*/
int gl_ble_dtm_tx(gl_ble_dtm_test_rsp_t *rsp, int packet_type, int length, int channel, int phy)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_tx_type", packet_type);
	blobmsg_add_u32(&b, "dtm_tx_length", length);
	blobmsg_add_u32(&b, "dtm_tx_channel", channel);
	blobmsg_add_u32(&b, "dtm_tx_phy", phy);

	gl_ble_call("ble", "dtm_tx", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o, "number_of_packets"));

	free(str);
	json_object_put(o);
	return 0;
}
/*DTM test, rx*/
int gl_ble_dtm_rx(gl_ble_dtm_test_rsp_t *rsp, int channel, int phy)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_rx_channel", channel);
	blobmsg_add_u32(&b, "dtm_rx_phy", phy);

	gl_ble_call("ble", "dtm_rx", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o, "number_of_packets"));

	free(str);
	json_object_put(o);
	return 0;
}
/*DTM test, end*/
int gl_ble_dtm_end(gl_ble_dtm_test_rsp_t *rsp)
{
	if (!rsp)
	{
		return -2;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "dtm_end", &b, 1, &str);
	if (NULL == str)
	{
		return -1;
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o, "number_of_packets"));

	free(str);
	json_object_put(o);
	return 0;
}

static void call_adv_packet_cb(json_object *msg)
{
	gl_ble_gap_data_t data;
	memset(&data, 0, sizeof(gl_ble_gap_data_t));

	//get rssi
	json_object *json_rssi = json_object_object_get(msg, "rssi");
	data.scan_rst.rssi = json_object_get_int(json_rssi);

	//get packet_type
	json_object *json_packet_type = json_object_object_get(msg, "packet_type");
	data.scan_rst.packet_type = json_object_get_int(json_packet_type);

	//get packet_type
	json_object *json_address = json_object_object_get(msg, "address");
	strcpy(data.scan_rst.addr, json_object_get_string(json_address));

	//get address_type
	json_object *json_address_type = json_object_object_get(msg, "address_type");
	data.scan_rst.ble_addr_type = json_object_get_int(json_address_type);

	//get address_type
	json_object *json_bonding = json_object_object_get(msg, "bonding");
	data.scan_rst.bonding = json_object_get_int(json_bonding);

	//get address_type
	json_object *json_data = json_object_object_get(msg, "data");
	strcpy(data.scan_rst.ble_adv, json_object_get_string(json_data));

	ble_msg_cb.ble_gap_event(GAP_BLE_SCAN_RESULT_EVT, &data);

	return;
}

static void call_conn_update_cb(json_object *msg)
{
	gl_ble_gap_data_t data;
	memset(&data, 0, sizeof(gl_ble_gap_data_t));

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.update_conn_data.connection = json_object_get_int(json_connection);

	//interval
	json_object *json_interval = json_object_object_get(msg, "interval");
	data.update_conn_data.interval = json_object_get_int(json_interval);

	//latency
	json_object *json_latency = json_object_object_get(msg, "latency");
	data.update_conn_data.latency = json_object_get_int(json_latency);

	// timeout
	json_object *json_timeout = json_object_object_get(msg, "timeout");
	data.update_conn_data.timeout = json_object_get_int(json_timeout);

	//security_mode
	json_object *json_security_mode = json_object_object_get(msg, "security_mode");
	data.update_conn_data.security_mode = json_object_get_int(json_security_mode);

	//txsize
	json_object *json_txsize = json_object_object_get(msg, "txsize");
	data.update_conn_data.txsize = json_object_get_int(json_txsize);

	ble_msg_cb.ble_gap_event(GAP_BLE_UPDATE_CONN_EVT, &data);

	return;
}

static void call_conn_open_cb(json_object *msg)
{
	gl_ble_gap_data_t data;
	memset(&data, 0, sizeof(gl_ble_gap_data_t));

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	strcpy(data.connect_open_data.addr, json_object_get_string(json_address));

	//address_type
	json_object *json_address_type = json_object_object_get(msg, "address_type");
	data.connect_open_data.ble_addr_type = json_object_get_int(json_address_type);

	//conn_role
	json_object *json_conn_role = json_object_object_get(msg, "conn_role");
	data.connect_open_data.conn_role = json_object_get_int(json_conn_role);

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.connect_open_data.connection = json_object_get_int(json_connection);

	//bonding
	json_object *json_bonding = json_object_object_get(msg, "bonding");
	data.connect_open_data.bonding = json_object_get_int(json_bonding);

	//advertiser
	json_object *json_advertiser = json_object_object_get(msg, "advertiser");
	data.connect_open_data.advertiser = json_object_get_int(json_advertiser);

	ble_msg_cb.ble_gap_event(GAP_BLE_CONNECT_EVT, &data);

	return;
}

static void call_conn_close_cb(json_object *msg)
{
	gl_ble_gap_data_t data;
	memset(&data, 0, sizeof(gl_ble_gap_data_t));

	//reason
	json_object *json_reason = json_object_object_get(msg, "reason");
	data.disconnect_data.reason = json_object_get_int(json_reason);

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.disconnect_data.connection = json_object_get_int(json_connection);

	ble_msg_cb.ble_gap_event(GAP_BLE_DISCONNECT_EVT, &data);

	return;
}

static void call_remote_notify_cb(json_object *msg)
{
	gl_ble_gatt_data_t data;
	memset(&data, 0, sizeof(gl_ble_gatt_data_t));

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.remote_notify.connection = json_object_get_int(json_connection);

	//characteristic
	json_object *json_characteristic = json_object_object_get(msg, "characteristic");
	data.remote_notify.characteristic = json_object_get_int(json_characteristic);

	//att_opcode
	json_object *json_att_opcode = json_object_object_get(msg, "att_opcode");
	data.remote_notify.att_opcode = json_object_get_int(json_att_opcode);

	//offset
	json_object *json_offset = json_object_object_get(msg, "offset");
	data.remote_notify.offset = json_object_get_int(json_offset);

	//value
	json_object *json_value = json_object_object_get(msg, "value");
	strcpy(data.remote_notify.value, json_object_get_string(json_value));

	ble_msg_cb.ble_gatt_event(GATT_BLE_REMOTE_NOTIFY_EVT, &data);

	return;
}

static void call_remote_write_cb(json_object *msg)
{
	gl_ble_gatt_data_t data;
	memset(&data, 0, sizeof(gl_ble_gatt_data_t));

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.remote_write.connection = json_object_get_int(json_connection);

	//attribute
	json_object *json_attribute = json_object_object_get(msg, "attribute");
	data.remote_write.attribute = json_object_get_int(json_attribute);

	//att_opcode
	json_object *json_att_opcode = json_object_object_get(msg, "att_opcode");
	data.remote_write.att_opcode = json_object_get_int(json_att_opcode);

	//value
	json_object *json_value = json_object_object_get(msg, "value");
	strcpy(data.remote_write.value, json_object_get_string(json_value));

	ble_msg_cb.ble_gatt_event(GATT_BLE_REMOTE_WRITE_EVT, &data);

	return;
}

static void call_remote_set_cb(json_object *msg)
{
	gl_ble_gatt_data_t data;
	memset(&data, 0, sizeof(gl_ble_gatt_data_t));

	//connection
	json_object *json_connection = json_object_object_get(msg, "connection");
	data.remote_set.connection = json_object_get_int(json_connection);

	//characteristic
	json_object *json_characteristic = json_object_object_get(msg, "characteristic");
	data.remote_set.characteristic = json_object_get_int(json_characteristic);

	//status_flags
	json_object *json_status_flags = json_object_object_get(msg, "status_flags");
	data.remote_set.status_flags = json_object_get_int(json_status_flags);

	//client_config_flags
	json_object *json_client_config_flags = json_object_object_get(msg, "client_config_flags");
	data.remote_set.client_config_flags = json_object_get_int(json_client_config_flags);

	ble_msg_cb.ble_gatt_event(GATT_BLE_REMOTE_SET_EVT, &data);

	return;
}

static void call_system_boot_cb(json_object *msg)
{
	gl_ble_module_data_t data;
	memset(&data, 0, sizeof(gl_ble_module_data_t));

	//major
	json_object *json_major = json_object_object_get(msg, "major");
	data.system_boot_data.major = json_object_get_int(json_major);

	//minor
	json_object *json_minor = json_object_object_get(msg, "minor");
	data.system_boot_data.minor = json_object_get_int(json_minor);

	//patch
	json_object *json_patch = json_object_object_get(msg, "patch");
	data.system_boot_data.patch = json_object_get_int(json_patch);

	//build
	json_object *json_build = json_object_object_get(msg, "build");
	data.system_boot_data.build = json_object_get_int(json_build);

	//bootloader
	json_object *json_bootloader = json_object_object_get(msg, "bootloader");
	data.system_boot_data.bootloader = json_object_get_int(json_bootloader);

	//hw
	json_object *json_hw = json_object_object_get(msg, "hw");
	data.system_boot_data.hw = json_object_get_int(json_hw);

	//ble_hash
	json_object *json_hash = json_object_object_get(msg, "hash");
	strcpy(data.system_boot_data.ble_hash, json_object_get_string(json_hash));
	
	ble_msg_cb.ble_module_event(MODULE_BLE_SYSTEM_BOOT_EVT, &data);

	return;
}
