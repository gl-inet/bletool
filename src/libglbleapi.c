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
#include "libglbleapi.h"

static struct ubus_context * ctx = NULL;
static struct ubus_subscriber msg_subscriber;
static struct blob_buf b;
static const char* path = NULL;
static unsigned int id;
method_handler_t method_handler;
method_handler_t sub_handler;


static void default_handler(json_object* obj)
{
	/*Do nothing*/
}

static void sub_remove_callback(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
	fprintf(stderr,"Removed by server\n");
}
static int sub_callback(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	if(!msg)
	{
		return ;
	}
	char* str = blobmsg_format_json(msg, true);
	json_object* o = json_tokener_parse(str);
	sub_handler(o);
	free(str);
}
static void method_callback(struct ubus_request *req, int type, struct blob_attr *msg)
{
	if(!msg)
	{
		return ;
	}
	char* str = blobmsg_format_json(msg, true);
	json_object* obj = json_tokener_parse(str);
	method_handler(obj);
	free(str);
}

/* C/C++ program interface */
int gl_ble_init(struct ubus_context *CTX)
{
	if(!CTX)
	{
		ctx = ubus_connect(path);
		if (!ctx)
		{
			fprintf(stderr,"Ubus connect failed\n");
			return -1;
		}
	}
	else
	{
		ctx = CTX;
	}
	ubus_add_uloop(ctx);
	
	int ret = ubus_lookup_id(ctx, "ble", &id);
	if(ret)
	{
		fprintf(stderr,"lookup ble instance failed\n");
		return ret;	
	}
	method_handler = default_handler;
	return 0;
}

int gl_ble_free(void)
{
	ubus_free(ctx);
	uloop_done();
	return 0;
}
int gl_ble_subscribe(method_handler_t cb)
{
	int ret;
	msg_subscriber.cb = sub_callback;
	msg_subscriber.remove_cb = sub_remove_callback;
	if(cb){
		sub_handler = cb;
	}
	else{
		sub_handler = default_handler;
	}
	ret = ubus_register_subscriber(ctx, &msg_subscriber);
	if(ret)
	{
		fprintf(stderr, "Failed to register subscriber: %d\n",ret);
	}

	ret = ubus_subscribe(ctx, &msg_subscriber, id);
	if(ret)
	{
		fprintf(stderr, "Failed to subscribe: %d\n",ret);
	}

	return 0;
}
int gl_ble_unsubscribe(void)
{
	int ret;
	ret = ubus_unsubscribe(ctx, &msg_subscriber, id);
	if(ret)
	{
		fprintf(stderr, "Failed to unsubscribe: %d\n",ret);
	}
	return 0;
}



/* System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(method_handler_t cb)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);

	return ubus_invoke(ctx, id, "local_mac", b.head, method_callback, NULL, 1000);
}
/*Enable or disable the BLE module*/
enum
{
	ENABLE_OR_DISABLE,
	ENALBE_POLICY_MAX,
};
static const struct blobmsg_policy enable_policy[ENALBE_POLICY_MAX] = {
	[ENABLE_OR_DISABLE] = {.name = "enable", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_enable(method_handler_t cb,int enable)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, enable_policy[ENABLE_OR_DISABLE].name, enable);

	return ubus_invoke(ctx, id, "enable", b.head, method_callback, NULL, 1000);
}
/*Enable or disable the BLE module*/
enum
{
	SYSTEM_POWER_LEVEL,
	SYSTEM_POWER_MAX,
};
static const struct blobmsg_policy set_power_policy[SYSTEM_POWER_MAX] = {
	[SYSTEM_POWER_LEVEL] = {.name = "system_power_level", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_set_power(method_handler_t cb,int power)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, set_power_policy[SYSTEM_POWER_LEVEL].name, power);

	return ubus_invoke(ctx, id, "set_power", b.head, method_callback, NULL, 1000);
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
int gl_ble_discovery(method_handler_t cb,int phys,int interval,int window,int type,int mode)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, discovery_policy[PHYS].name, phys);
	blobmsg_add_u32(&b, discovery_policy[INTERVAL].name, interval);
	blobmsg_add_u32(&b, discovery_policy[WINDOW].name, window);
	blobmsg_add_u32(&b, discovery_policy[TYPE].name, type);
	blobmsg_add_u32(&b, discovery_policy[MODE].name, mode);

	return ubus_invoke(ctx, id, "discovery", b.head, method_callback, NULL, 1000);
}
/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(method_handler_t cb)
{
	if(cb)
	{
		method_handler = cb;
	}
	return ubus_invoke(ctx, id, "stop", b.head, method_callback, NULL, 1000);
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
int gl_ble_connect(method_handler_t cb,char* address,int address_type,int phy)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, conn_policy[CONN_ADDRESS].name, address);
	blobmsg_add_u32(&b, conn_policy[CONN_ADDRESS_TYPE].name, address_type);
	blobmsg_add_u32(&b, conn_policy[CONN_PHY].name, phy);

	return ubus_invoke(ctx, id, "connect", b.head, method_callback, NULL, 1000);
}
/*Act as master, disconnect with remote device*/
enum
{
	DISCONN_CONNECTION,
	DISCONNECT_MAX,
};
static const struct blobmsg_policy disconnect_policy[DISCONNECT_MAX] = {
	[DISCONN_CONNECTION] = {.name = "disconn_connection", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_disconnect(method_handler_t cb,int connection)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, disconnect_policy[DISCONN_CONNECTION].name, connection);

	return ubus_invoke(ctx, id, "disconnect", b.head, method_callback, NULL, 1000);
}
/*Act as master, Get rssi of connection with remote device*/
enum
{
	RSSI_CONNECTION,
	RSSI_MAX,
};
static const struct blobmsg_policy get_rssi_policy[RSSI_MAX] = {
	[RSSI_CONNECTION] = {.name = "rssi_connection", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_get_rssi(method_handler_t cb,int connection)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, get_rssi_policy[RSSI_CONNECTION].name, connection);

	return ubus_invoke(ctx, id, "get_rssi", b.head, method_callback, NULL, 1000);
}
/*Act as master, Get service list of a remote GATT server*/
enum
{
	SERVICE_CONNECTION,
	SERVICE_MAX,
};
static const struct blobmsg_policy get_service_policy[SERVICE_MAX] = {
	[SERVICE_CONNECTION] = {.name = "get_service_connection", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_get_service(method_handler_t cb, int connection)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, get_service_policy[SERVICE_CONNECTION].name, connection);

	return ubus_invoke(ctx, id, "get_service", b.head, method_callback, NULL, 1000);
}
/*Act as master, Get characteristic list of a remote GATT server*/
enum
{
	CHAR_CONNECTION,
	CHAR_SERVICE_HANDLE,
	CHAR_MAX,
};
static const struct blobmsg_policy get_char_policy[CHAR_MAX] = {
	[CHAR_CONNECTION] = {.name = "get_service_connection", .type = BLOBMSG_TYPE_INT32},
	[CHAR_SERVICE_HANDLE] = {.name = "char_service_handle", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_get_char(method_handler_t cb, int connection, int service_handle)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, get_char_policy[CHAR_CONNECTION].name, connection);
	blobmsg_add_u32(&b, get_char_policy[CHAR_SERVICE_HANDLE].name, service_handle);

	return ubus_invoke(ctx, id, "get_char", b.head, method_callback, NULL, 1000);
}
/*Act as master, Read value of specified characteristic in a remote gatt server*/
enum
{
	GATT_READ_CHAR_CONNECTION,
	GATT_READ_CHAR_CHAR_HANDLE,
	GATT_READ_CHAR_MAX,
};
static const struct blobmsg_policy read_char_policy[GATT_READ_CHAR_MAX] = {
	[GATT_READ_CHAR_CONNECTION] = {.name = "char_connection", .type = BLOBMSG_TYPE_INT32},
	[GATT_READ_CHAR_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_read_char(method_handler_t cb, int connection, int char_handle)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, read_char_policy[GATT_READ_CHAR_CONNECTION].name, connection);
	blobmsg_add_u32(&b, read_char_policy[GATT_READ_CHAR_CHAR_HANDLE].name, char_handle);

	return ubus_invoke(ctx, id, "read_char", b.head, method_callback, NULL, 1000);
}
/*Act as master, Write value to specified characteristic in a remote gatt server*/
enum
{
	GATT_WRITE_CHAR_CONNECTION,
	GATT_WRITE_CHAR_CHAR_HANDLE,
	GATT_WRITE_CHAR_VALUE,
	GATT_WRITE_CHAR_RES,
	GATT_WRITE_CHAR_MAX,
};
static const struct blobmsg_policy write_char_policy[GATT_WRITE_CHAR_MAX] = {
	[GATT_WRITE_CHAR_CONNECTION] = {.name = "char_connection", .type = BLOBMSG_TYPE_INT32},
	[GATT_WRITE_CHAR_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
	[GATT_WRITE_CHAR_VALUE] = {.name = "char_value", .type = BLOBMSG_TYPE_STRING},
	[GATT_WRITE_CHAR_RES] = {.name = "write_res", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_write_char(method_handler_t cb, int connection, int char_handle,char* value,int res)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, write_char_policy[GATT_WRITE_CHAR_CONNECTION].name, connection);
	blobmsg_add_u32(&b, write_char_policy[GATT_WRITE_CHAR_CHAR_HANDLE].name, char_handle);
	blobmsg_add_string(&b, write_char_policy[GATT_WRITE_CHAR_VALUE].name, value);
	blobmsg_add_u32(&b, write_char_policy[GATT_WRITE_CHAR_RES].name, res);

	return ubus_invoke(ctx, id, "write_char", b.head, method_callback, NULL, 1000);
}
/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
enum
{
	GATT_SET_NOTIFY_CONNECTION,
	GATT_SET_NOTIFY_CHAR_HANDLE,
	GATT_SET_NOTIFY_FLAG,
	GATT_SET_NOTIFY_MAX,
};
static const struct blobmsg_policy set_notify_policy[GATT_SET_NOTIFY_MAX] = {
	[GATT_SET_NOTIFY_CONNECTION] = {.name = "connection", .type = BLOBMSG_TYPE_INT32},
	[GATT_SET_NOTIFY_CHAR_HANDLE] = {.name = "char_handle", .type = BLOBMSG_TYPE_INT32},
	[GATT_SET_NOTIFY_FLAG] = {.name = "notify_flag", .type = BLOBMSG_TYPE_INT32},
};
int gl_ble_set_notify(method_handler_t cb, int connection, int char_handle,int flag)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, set_notify_policy[GATT_SET_NOTIFY_CONNECTION].name, connection);
	blobmsg_add_u32(&b, set_notify_policy[GATT_SET_NOTIFY_CHAR_HANDLE].name, char_handle);
	blobmsg_add_u32(&b, set_notify_policy[GATT_SET_NOTIFY_FLAG].name, flag);

	return ubus_invoke(ctx, id, "set_notify", b.head, method_callback, NULL, 1000);
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
int gl_ble_adv(method_handler_t cb, int phys, int interval_min,int interval_max,int discover,int connect)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, adv_policy[ADV_PHYS].name, phys);
	blobmsg_add_u32(&b, adv_policy[ADV_INTERVAL_MIN].name, interval_min);
	blobmsg_add_u32(&b, adv_policy[ADV_INTERVAL_MAX].name, interval_max);
	blobmsg_add_u32(&b, adv_policy[ADV_DISCOVER].name, discover);
	blobmsg_add_u32(&b, adv_policy[ADV_CONN].name, connect);

	return ubus_invoke(ctx, id, "adv", b.head, method_callback, NULL, 1000);
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
int gl_ble_adv_data(method_handler_t cb, int flag, char* data)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, adv_data_policy[ADV_DATA_FLAG].name, flag);
	blobmsg_add_string(&b, adv_data_policy[ADV_DATA].name, data);

	return ubus_invoke(ctx, id, "adv_data", b.head, method_callback, NULL, 1000);
}
/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(method_handler_t cb)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);

	return ubus_invoke(ctx, id, "stop_adv", b.head, method_callback, NULL, 1000);
}
/*Act as BLE slave, Send Notification*/
enum
{
	SEND_NOTI_CONN,
	SEND_NOTI_CHAR,
	SEND_NOTI_VALUE,
	SEND_NOTI_MAX,
};
static const struct blobmsg_policy send_noti_policy[SEND_NOTI_MAX] = {
	[SEND_NOTI_CONN] = {.name = "send_noti_conn", .type = BLOBMSG_TYPE_INT32},
	[SEND_NOTI_CHAR] = {.name = "send_noti_char", .type = BLOBMSG_TYPE_INT32},
	[SEND_NOTI_VALUE] = {.name = "send_noti_value", .type = BLOBMSG_TYPE_STRING},
};
int gl_ble_send_notify(method_handler_t cb,int connection,int char_handle, char* value)
{
	if(cb)
	{
		method_handler = cb;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, send_noti_policy[SEND_NOTI_CONN].name, connection);
	blobmsg_add_u32(&b, send_noti_policy[SEND_NOTI_CHAR].name, char_handle);
	blobmsg_add_string(&b, send_noti_policy[SEND_NOTI_VALUE].name, value);

	return ubus_invoke(ctx, id, "send_notify", b.head, method_callback, NULL, 1000);
}