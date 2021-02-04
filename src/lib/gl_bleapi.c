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

#include "gl_bleapi.h"
#include "gl_dev_mgr.h"
#include "gl_log.h"
#include "gl_common.h"

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

static void sub_remove_callback(struct ubus_context *ctx, struct ubus_subscriber *obj, int32_t id)
{
	fprintf(stderr, "Removed by server\n");
}

static int32_t sub_handler(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, 
						const char *method, struct blob_attr *msg)
{
	if (!msg) { 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	char *str = blobmsg_format_json(msg, true);
	json_object *o = json_tokener_parse(str);
	if (!o) {
		log_err("Json parse null!\n"); 
		free(str);
		return GL_ERR_RESP_MISSING;
	}

	json_object *val_obj = NULL;
	char *type = NULL;

	if ( json_object_object_get_ex(o, "type",  &val_obj) ) {
		type = json_object_get_string(val_obj);
	}

	if (0 == strcmp(type, "unknow_msg"))
	{
		log_debug("ble ubus unknow_msg");
	}
	else if (0 == strcmp(type, "system_boot"))
	{
		log_debug("ble ubus unknow_msg");
		call_system_boot_cb(o);
	}
	else if (0 == strcmp(type, "conn_close"))
	{
		log_debug("ble ubus connect close");
		call_conn_close_cb(o);
	}
	else if (0 == strcmp(type, "conn_open"))
	{
		log_debug("ble ubus connect open");
		call_conn_open_cb(o);
	}
	else if (0 == strcmp(type, "remote_notify"))
	{
		log_debug("ble ubus remote notify");
		call_remote_notify_cb(o);
	}
	else if (0 == strcmp(type, "remote_write"))
	{
		log_debug("ble ubus remote write");
		call_remote_write_cb(o);
	}
	else if (0 == strcmp(type, "remote_set"))
	{
		log_debug("ble ubus remote set");
		call_remote_set_cb(o);
	}
	else if (0 == strcmp(type, "adv_packet"))
	{
		log_debug("ble ubus adv_packet");
		call_adv_packet_cb(o);
	}
	else if (0 == strcmp(type, "conn_update"))
	{
		log_debug("ble ubus connect update");
		call_conn_update_cb(o);
	}

	json_object_put(o);
	free(str);

	return GL_SUCCESS;
}

static void listen_timeout_cb(struct uloop_timeout *timeout)
{
	if (!listen) {
		uloop_end();
	}
	else {
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

GL_RET gl_ble_subscribe(gl_ble_cbs *callback)
{
	GL_RET ret;
	int32_t id = 0;

	ble_register_cb(callback);

	/* The handler for notification arrival */
	subscriber.cb = sub_handler;

	/* When the server exits */
	subscriber.remove_cb = sub_remove_callback;

	/* Connect to ubusd and get ctx */
	struct ubus_context *CTX = ubus_connect(NULL);
	if (!CTX) {
		fprintf(stderr,"Ubus connect failed\n");
		return GL_ERR_UBUS_CONNECT;
	}

	ret = ubus_register_subscriber(CTX, &subscriber);
	if (ret) {
		fprintf(stderr, "Failed to register subscriber: %d\n", ret);
	}

	/* Get the id of the object to subscribe to */
	if (ubus_lookup_id(CTX, "ble", &id)) {
		fprintf(stderr,"Ubus lookup id failed.\n");
		if (CTX) {
			ubus_free(CTX);
		}
		return GL_ERR_UBUS_LOOKUP;
	}

	/* Subscribe object */
	ret = ubus_subscribe(CTX, &subscriber, id);
	if (ret) { 
		log_err("Failed to subscribe: %d\n", ret); 
	}

	listen = 1;
	listen_timeout.cb = listen_timeout_cb;

	uloop_init();
	ubus_add_uloop(CTX);
	uloop_timeout_set(&listen_timeout, 1 * 1000);
	uloop_run();
	uloop_done();

	log_debug("ULOOP TIMEOUT!\n");
	
	ret = gl_ble_unsubscribe();
	if ( ret ) {
		log_err("ubus_unsubscribe failed. error code: %d", ret);
		if (CTX)
			ubus_free(CTX);
		return GL_ERR_UBUS_UNSUBSCRIBE;
	}
	ubus_free(CTX);
	
	return GL_SUCCESS;
}

GL_RET gl_ble_unsubscribe(void) {
	listen = 0;
	return GL_SUCCESS;
}

static void ubus_invoke_complete_cb(struct ubus_request *req, int32_t type, struct blob_attr *msg)
{
	char **str = (char **)req->priv;

	if (msg && str)
		*str = blobmsg_format_json_indent(msg, true, 0);
}

GL_RET json_parameter_check(json_object *obj, char **parameters, int32_t para_num)
{
	json_object *o = NULL;
	int32_t i;
	
	if (!obj) { 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	o = json_object_object_get(obj, "code");
	if (!o) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	int32_t code = json_object_get_int(o);
	if (code) {
		return code;
	}
	for (i = 0; i < para_num; i++) {
		if (!json_object_object_get_ex(obj, parameters[i], &o)) {
			log_err("Response missing!\n");
			return GL_ERR_RESP_MISSING;
		}
	}
	return GL_SUCCESS;
}

GL_RET gl_ble_call(const char *path, const char *method, struct blob_buf *b, int32_t timeout, char **str)
{
	int32_t id = 0;
	struct ubus_context *ctx = NULL;

	/* Connect to ubusd and get ctx */
	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr,"Ubus connect failed\n");
		return GL_ERR_UBUS_CONNECT;
	}

	/* Search a registered object with a given name */
	if (ubus_lookup_id(ctx, path, &id)) {
		fprintf(stderr,"Ubus lookup id failed.\n");
		if (ctx) {
			ubus_free(ctx);
		}
		return GL_ERR_UBUS_LOOKUP;
	}

	/* Call the ubus host object */
	ubus_invoke(ctx, id, method, b->head, ubus_invoke_complete_cb, (void *)str, timeout * 1000);

	if (ctx)
		ubus_free(ctx);

	return GL_SUCCESS;
}

GL_RET gl_ble_enable(int32_t enable)
{
	char *str = NULL;
	static struct blob_buf b;

	/* Prepare request method policy and data */
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "enable", enable);

	gl_ble_call("ble", "enable", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}
	
	/* Construct a json formatted string as a json object */
	json_object *o = json_tokener_parse(str);
	
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) {
		/* Release the generated object and resource */
		free(str);
		json_object_put(o);		
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_get_mac(BLE_MAC mac)
{
	char *str = NULL;
	json_object *val_obj = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "local_mac", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"mac"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);
		return ret; 
	}

	char *address = NULL;
	if ( json_object_object_get_ex(o, "mac",  &val_obj) ) {
		address = json_object_get_string(val_obj);
	}
	// printf("address: %s\n", address);

	str2addr(address, mac);

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_set_power(int power, int *current_power)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "system_power_level", power);

	gl_ble_call("ble", "set_power", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"power"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	json_object *val_obj = NULL;

	if ( json_object_object_get_ex(o, "power",  &val_obj) ) {
		*current_power = json_object_get_int(val_obj);
	}

	free(str);
	json_object_put(o);
	
	return GL_SUCCESS;
}

GL_RET gl_ble_discovery(int32_t phys, int32_t interval, int32_t window, int32_t type, int32_t mode)
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
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_stop_discovery(void)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "stop_discovery", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_connect(BLE_MAC address, int32_t address_type, int32_t phy)
{
	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_address", address_str);
	blobmsg_add_u32(&b, "conn_address_type", address_type);
	blobmsg_add_u32(&b, "conn_phy", phy);

	gl_ble_call("ble", "connect", &b, 4, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	// json_object *val_obj = NULL;

	// char *opened_address = NULL;
	// if ( json_object_object_get_ex(o, "address",  &val_obj) ) {
	// 	opened_address = json_object_get_string(val_obj);
	// }
	// free(str);
	// json_object_put(o);

	// if(0 != strncmp(address_str, opened_address, DEVICE_MAC_LEN))
	// {
	// 	return GL_UNKNOW_ERR;
	// }

	return GL_SUCCESS;
}

GL_RET gl_ble_disconnect(BLE_MAC address)
{
	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);	
	blobmsg_add_string(&b, "disconn_address", address_str);

	gl_ble_call("ble", "disconnect", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_get_rssi(BLE_MAC address, int32_t *rssi)
{
	char *str = NULL;
	int32_t connection = 0;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);
	
	blob_buf_init(&b, 0);	
	blobmsg_add_string(&b, "rssi_address", address_str);

	gl_ble_call("ble", "get_rssi", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"rssi"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	json_object *val_obj = NULL;

	if ( json_object_object_get_ex(o, "rssi",  &val_obj) ) {
		*rssi = json_object_get_int(val_obj);
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_get_service(gl_ble_service_list_t *service_list, BLE_MAC address)
{
	if ((!service_list) || (!address))
	{ 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "get_service_address", address_str);

	gl_ble_call("ble", "get_service", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"service_list"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	json_object *list = json_object_object_get(o, "service_list");
	int32_t len = json_object_array_length(list);
	service_list->list_len = len;
	json_object *obj;

	int i = 0;
	while (i < len)
	{
		obj = json_object_array_get_idx(list, i);
		service_list->list[i].handle = json_object_get_int(json_object_object_get(obj, "service_handle"));
		strcpy(service_list->list[i].uuid, json_object_get_string(json_object_object_get(obj, "service_uuid")));
		i++;
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_get_char(gl_ble_char_list_t *char_list, BLE_MAC address, int service_handle)
{
	if ((!char_list) || (!address))
	{ 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "char_conn_address", address_str);
	blobmsg_add_u32(&b, "char_service_handle", service_handle);

	gl_ble_call("ble", "get_char", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"characteristic_list"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	json_object *list = json_object_object_get(o, "characteristic_list");
	int32_t len = json_object_array_length(list);
	char_list->list_len = len;
	json_object *obj;

	int32_t i = 0;
	while (i < len)
	{
		obj = json_object_array_get_idx(list, i);
		char_list->list[i].handle = json_object_get_int(json_object_object_get(obj, "characteristic_handle"));
		char_list->list[i].properties = json_object_get_int(json_object_object_get(obj, "properties"));
		strcpy(char_list->list[i].uuid, json_object_get_string(json_object_object_get(obj, "characteristic_uuid")));
		i++;
	}
	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_read_char(BLE_MAC address, int char_handle, char *value)
{
	if (!value) { 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "char_conn_addr", address_str);
	blobmsg_add_u32(&b, "char_handle", char_handle);

	gl_ble_call("ble", "read_char", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"characteristic_handle", "att_opcode", "offset", "value"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	json_object *val_obj = NULL;

	int rsp_handle = -1;
	if ( json_object_object_get_ex(o, "characteristic_handle",  &val_obj) ) {
		rsp_handle = json_object_get_int(val_obj);
	}

	if(char_handle != rsp_handle) {
		free(str);
		json_object_put(o);
		return GL_UNKNOW_ERR;
	}

	if ( json_object_object_get_ex(o, "value",  &val_obj) ) {
		strcpy(value, json_object_get_string(val_obj));
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_write_char(uint8_t *address, int32_t char_handle, char *value, int32_t res)
{
	if ((!value) || (strlen(value) % 2)) { 
		log_err("Parameter error!\n"); 
		return GL_ERR_PARAM; 
	}

	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "char_conn_addrsss", address_str);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_string(&b, "char_value", value);
	blobmsg_add_u32(&b, "write_res", res);

	gl_ble_call("ble", "write_char", &b, 2, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};

	GL_RET ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		goto end;
	}

end:
	free(str);
	json_object_put(o);
	return ret;
}

GL_RET gl_ble_set_notify(BLE_MAC address, int32_t char_handle, int32_t flag)
{
	char *str = NULL;
	static struct blob_buf b;
	
	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_addrsss", address_str);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_u32(&b, "notify_flag", flag);

	gl_ble_call("ble", "set_notify", &b, 1, &str);

	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);	
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_adv(int32_t phys, int32_t interval_min, int32_t interval_max, int32_t discover, int32_t adv_conn)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_phys", phys);
	blobmsg_add_u32(&b, "adv_interval_min", interval_min);
	blobmsg_add_u32(&b, "adv_interval_max", interval_max);
	blobmsg_add_u32(&b, "adv_discover", discover);
	blobmsg_add_u32(&b, "adv_conn", adv_conn);

	gl_ble_call("ble", "adv", &b, 1, &str);

	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));

	if (ret) { 
		free(str);
		json_object_put(o);
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_adv_data(int32_t flag, char *data)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_data_flag", flag);
	blobmsg_add_string(&b, "adv_data", data);

	gl_ble_call("ble", "adv_data", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_stop_adv(void)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble", "stop_adv", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);
		return ret; 
	}

	free(str);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET gl_ble_send_notify(BLE_MAC address, int32_t char_handle, char *value)
{
	char *str = NULL;
	static struct blob_buf b;

	char address_str[BLE_MAC_LEN] = {0};
	addr2str(address, address_str);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "send_noti_conn_addr", address_str);
	blobmsg_add_u32(&b, "send_noti_char", char_handle);
	blobmsg_add_string(&b, "send_noti_value", value);

	gl_ble_call("ble", "send_notify", &b, 1, &str);
	if (NULL == str) { 
		log_err("Response missing!\n"); 
		return GL_ERR_RESP_MISSING; 
	}

	json_object *o = json_tokener_parse(str);
	char *parameters[] = {"sent_len"};
	int32_t ret = json_parameter_check(o, parameters, sizeof(parameters) / sizeof(parameters[0]));
	if (ret) { 
		free(str);
		json_object_put(o);
		return ret; 
	}

	return GL_SUCCESS;
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
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.scan_rst.address);

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

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.update_conn_data.address);

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
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.connect_open_data.address);

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

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.disconnect_data.address);

	ble_msg_cb.ble_gap_event(GAP_BLE_DISCONNECT_EVT, &data);

	return;
}

static void call_remote_notify_cb(json_object *msg)
{
	gl_ble_gatt_data_t data;
	memset(&data, 0, sizeof(gl_ble_gatt_data_t));

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.remote_notify.address);

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

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.remote_write.address);

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

	//address
	json_object *json_address = json_object_object_get(msg, "address");
	char *address = json_object_get_string(json_address);
	str2addr(address, &data.remote_set.address);

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
	json_object *val_obj = NULL;

	gl_ble_module_data_t data;
	memset(&data, 0, sizeof(gl_ble_module_data_t));

	//major
	if ( json_object_object_get_ex(msg, "major",  &val_obj) ) {
		data.system_boot_data.major = json_object_get_int(val_obj);
	}
	
	//minor
	if ( json_object_object_get_ex(msg, "minor",  &val_obj) ) {
		data.system_boot_data.minor = json_object_get_int(val_obj);
	}

	//patch
	if ( json_object_object_get_ex(msg, "patch",  &val_obj) ) {
		data.system_boot_data.patch = json_object_get_int(val_obj);
	}

	//build
	if ( json_object_object_get_ex(msg, "build",  &val_obj) ) {
		data.system_boot_data.build = json_object_get_int(val_obj);
	}
	
	//bootloader
	if ( json_object_object_get_ex(msg, "bootloader",  &val_obj) )  {
		data.system_boot_data.bootloader = json_object_get_int(val_obj);
	}
	
	//hw
	if ( json_object_object_get_ex(msg, "hw", &val_obj) )  {
		data.system_boot_data.hw = json_object_get_int(val_obj);
	}

	//ble_hash
	if ( json_object_object_get_ex(msg, "hash", &val_obj) )  {
		strcpy(data.system_boot_data.ble_hash, json_object_get_string(val_obj));
	}
	
	ble_msg_cb.ble_module_event(MODULE_BLE_SYSTEM_BOOT_EVT, &data);

	return;
}

