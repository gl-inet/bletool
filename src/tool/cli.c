/*****************************************************************************
 * @file  cli.c
 * @brief CLI interface of BLE functions
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
#include <getopt.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <json-c/json.h>

#include "libglbleapi.h"
#include "ble_dev_mgr.h"
#include "infra_log.h"

#define PARA_MISSING "parameter missing\n"

static int ble_module_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data);
static int ble_gap_cb(gl_ble_gap_evrnt_t event, gl_ble_gap_data_t *data);
static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);

static int sub_cb(struct ubus_context *ctx, struct ubus_object *obj,
				  struct ubus_request_data *req,
				  const char *method, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	printf("%s\n", str);
	free(str);

	return 0;
}
static void sub_remove_cb(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
	fprintf(stderr, "Removed by server\n");
}

static void ubus_invoke_complete(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char **str = (char **)req->priv;

	if (msg && str)
		*str = blobmsg_format_json(msg, true);
}
int ble_ubus_call(char *path, const char *method, struct blob_buf *b, int timeout, char **str)
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

	ubus_invoke(ctx, id, method, b->head, ubus_invoke_complete, (void *)str, timeout * 1000);

	if (ctx)
		ubus_free(ctx);

	return 0;
}
/* System functions */
int cmd_enable(int argc, char **argv)
{
	int enable = 0;
	if (argc < 3)
	{
		enable = 1;
	}
	else
	{
		enable = atoi(argv[2]);
	}
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "enable", enable);

	ble_ubus_call("ble", "enable", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_set_power(int argc, char **argv)
{
	int power;
	if (argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}
	else
	{
		power = atoi(argv[2]);
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "system_power_level", power);

	ble_ubus_call("ble", "set_power", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_local_address(int argc, char **argv)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble", "local_mac", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}

int cmd_listen(int argc, char **argv)
{
	gl_ble_cbs ble_cb;
	memset(&ble_cb, 0, sizeof(gl_ble_cbs));

	ble_cb.ble_gap_event = ble_gap_cb;
	ble_cb.ble_gatt_event = ble_gatt_cb;
	ble_cb.ble_module_event = ble_module_cb;

	gl_ble_subscribe(&ble_cb);
}
/*BLE slave functions */
int cmd_adv_data(int argc, char **argv)
{
	int ch, flag = -1;
	char *value = NULL;

	struct option long_options[] = {
		{"flag", required_argument, NULL, 'f'},
		{"value", required_argument, NULL, 'v'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "f:v:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'f':
			flag = atoi(optarg);
			break;
		case 'v':
			value = optarg;
			break;
		}
	}

	if (flag < 0 || !value)
	{
		printf(PARA_MISSING);
		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_data_flag", flag);
	blobmsg_add_string(&b, "adv_data", value);

	ble_ubus_call("ble", "adv_data", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_adv(int argc, char **argv)
{
	int ch, phys = 1, interval_min = 160, interval_max = 160, discover = 2, connect = 2;

	struct option long_options[] = {
		{"phys", required_argument, NULL, 'p'},
		{"interval_min", required_argument, NULL, 'n'},
		{"interval_max", required_argument, NULL, 'x'},
		{"discover", required_argument, NULL, 'd'},
		{"connect", required_argument, NULL, 'c'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "p:n:x:d:c:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'p':
			phys = atoi(optarg);
			break;
		case 'n':
			interval_min = atoi(optarg);
			break;
		case 'x':
			interval_max = atoi(optarg);
			break;
		case 'd':
			discover = atoi(optarg);
			break;
		case 'c':
			connect = atoi(optarg);
			break;
		}
	}

	if (interval_max < interval_min)
	{
		interval_max = interval_min;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_phys", phys);
	blobmsg_add_u32(&b, "adv_interval_min", interval_min);
	blobmsg_add_u32(&b, "adv_interval_max", interval_max);
	blobmsg_add_u32(&b, "adv_discover", discover);
	blobmsg_add_u32(&b, "adv_conn", connect);

	ble_ubus_call("ble", "adv", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_adv_stop(int argc, char **argv)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble", "stop_adv", &b, 1, &str);
	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}

int cmd_send_notify(int argc, char **argv)
{

	int ch, connection = -1, char_handle = -1;
	char *value = NULL;

	struct option long_options[] = {
		{"connection", required_argument, NULL, 'c'},
		{"char_handle", required_argument, NULL, 'h'},
		{"value", required_argument, NULL, 'v'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:h:v:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			connection = atoi(optarg);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		case 'v':
			value = optarg;
			break;
		}
	}

	if (connection < 0 || char_handle < 0 || !value)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "send_noti_conn", connection);
	blobmsg_add_u32(&b, "send_noti_char", char_handle);
	blobmsg_add_string(&b, "send_noti_value", value);

	ble_ubus_call("ble", "send_notify", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}

int cmd_discovery(int argc, char **argv)
{
	int ch, phys = 1, interval = 16, window = 16, type = 0, mode = 1;

	struct option long_options[] = {
		{"phys", required_argument, NULL, 'p'},
		{"interval", required_argument, NULL, 'i'},
		{"window", required_argument, NULL, 'w'},
		{"type", required_argument, NULL, 't'},
		{"mode", required_argument, NULL, 'm'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "p:i:w:t:m:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'p':
			phys = atoi(optarg);
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'w':
			window = atoi(optarg);
			break;
		case 't':
			type = atoi(optarg);
			break;
		case 'm':
			mode = atoi(optarg);
			break;
		}
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "phys", phys);
	blobmsg_add_u32(&b, "interval", interval);
	blobmsg_add_u32(&b, "window", window);
	blobmsg_add_u32(&b, "type", type);
	blobmsg_add_u32(&b, "mode", mode);

	ble_ubus_call("ble", "discovery", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}

int cmd_stop(int argc, char **argv)
{
	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble", "stop", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_connect(int argc, char **argv)
{
	int ch, phy = 1, address_type = -1;
	char *address = NULL;

	struct option long_options[] = {
		{"phys", required_argument, NULL, 'p'},
		{"address_type", required_argument, NULL, 't'},
		{"address", required_argument, NULL, 'a'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "p:t:a:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'p':
			phy = atoi(optarg);
			break;
		case 't':
			address_type = atoi(optarg);
			break;
		case 'a':
			address = optarg;
			break;
		}
	}

	if (address_type < 0 || !address)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_address", address);
	blobmsg_add_u32(&b, "conn_address_type", address_type);
	blobmsg_add_u32(&b, "conn_phy", phy);

	ble_ubus_call("ble", "connect", &b, 5, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_disconnect(int argc, char **argv)
{
	int connection = -1;

	if (argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}
	else
	{
		connection = atoi(argv[2]);
	}

	if (connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "disconn_connection", connection);

	ble_ubus_call("ble", "disconnect", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_get_rssi(int argc, char **argv)
{
	int connection = -1;

	if (argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}
	else
	{
		connection = atoi(argv[2]);
	}

	if (connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "rssi_connection", connection);

	ble_ubus_call("ble", "get_rssi", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_get_service(int argc, char **argv)
{
	int connection = -1;

	if (argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}
	else
	{
		connection = atoi(argv[2]);
	}

	if (connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);

	ble_ubus_call("ble", "get_service", &b, 2, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_get_char(int argc, char **argv)
{
	int ch, connection = -1, service_handle = -1;

	struct option long_options[] = {
		{"connection", required_argument, NULL, 'c'},
		{"service_handle", required_argument, NULL, 'h'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:h:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			connection = atoi(optarg);
			break;
		case 'h':
			service_handle = atoi(optarg);
			break;
		}
	}

	if (connection < 0 || service_handle < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);
	blobmsg_add_u32(&b, "char_service_handle", service_handle);

	ble_ubus_call("ble", "get_char", &b, 2, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_set_notify(int argc, char **argv)
{
	int ch, connection = -1, char_handle = -1, flag = -1;

	struct option long_options[] = {
		{"connection", required_argument, NULL, 'c'},
		{"char_handle", required_argument, NULL, 'h'},
		{"flag", required_argument, NULL, 'f'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:h:f:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			connection = atoi(optarg);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		case 'f':
			flag = atoi(optarg);
			break;
		}
	}

	if (connection < 0 || char_handle < 0 || flag < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_u32(&b, "notify_flag", flag);

	ble_ubus_call("ble", "set_notify", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_read_value(int argc, char **argv)
{
	int ch, connection = -1, char_handle = -1;

	struct option long_options[] = {
		{"connection", required_argument, NULL, 'c'},
		{"char_handle", required_argument, NULL, 'h'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:h:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			connection = atoi(optarg);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		}
	}

	if (connection < 0 || char_handle < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);

	ble_ubus_call("ble", "read_char", &b, 2, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_write_value(int argc, char **argv)
{
	int ch, connection = -1, char_handle = -1, res = 0;
	char *value = NULL;

	struct option long_options[] = {
		{"connection", required_argument, NULL, 'c'},
		{"char_handle", required_argument, NULL, 'h'},
		{"res", required_argument, NULL, 'r'},
		{"value", required_argument, NULL, 'v'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:h:r:v:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			connection = atoi(optarg);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		case 'r':
			res = atoi(optarg);
			break;
		case 'v':
			value = optarg;
			break;
		}
	}

	if (connection < 0 || char_handle < 0 || !value)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_string(&b, "char_value", value);
	blobmsg_add_u32(&b, "write_res", res);

	ble_ubus_call("ble", "write_char", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_dtm_tx(int argc, char **argv)
{
	/* Default setting, PRBS9 packet payload, length 20, channel 0, phy 1M PHY*/
	int ch, packet_type = 0, length = 20, channel = 0, phy = 1;

	struct option long_options[] = {
		{"packet_type", required_argument, NULL, 't'},
		{"length", required_argument, NULL, 'l'},
		{"channel", required_argument, NULL, 'c'},
		{"phy", required_argument, NULL, 'p'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "t:l:c:p:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 't':
			packet_type = atoi(optarg);
			break;
		case 'l':
			length = atoi(optarg);
			break;
		case 'c':
			channel = atoi(optarg);
			break;
		case 'p':
			phy = atoi(optarg);
			break;
		}
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_tx_type", packet_type);
	blobmsg_add_u32(&b, "dtm_tx_length", length);
	blobmsg_add_u32(&b, "dtm_tx_channel", channel);
	blobmsg_add_u32(&b, "dtm_tx_phy", phy);

	ble_ubus_call("ble", "dtm_tx", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_dtm_rx(int argc, char **argv)
{
	/* Default setting, channel 0, phy 1M PHY*/
	int ch, channel = 0, phy = 1;

	struct option long_options[] = {
		{"channel", required_argument, NULL, 'c'},
		{"phy", required_argument, NULL, 'p'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "c:p:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'c':
			channel = atoi(optarg);
			break;
		case 'p':
			phy = atoi(optarg);
			break;
		}
	}

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_rx_channel", channel);
	blobmsg_add_u32(&b, "dtm_rx_phy", phy);

	ble_ubus_call("ble", "dtm_rx", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}
int cmd_dtm_end(int argc, char **argv)
{

	char *str = NULL;
	static struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble", "dtm_end", &b, 1, &str);

	if (NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n", str);

	free(str);

	return 0;
}

static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data)
{
	switch (event)
	{
	case GATT_BLE_REMOTE_NOTIFY_EVT:
	{
		gl_ble_gatt_data_t *remote_notify = (gl_ble_gatt_data_t *)data;
		printf("***************** ble remote notify *********************\n");
		printf("{\n");
		printf("  connection: %d\n", data->remote_notify.connection);
		printf("  characteristic: %d\n", data->remote_notify.characteristic);
		printf("  att_opcode: %d\n", data->remote_notify.att_opcode);
		printf("  offset: %d\n", data->remote_notify.offset);
		printf("  value: %s\n", data->remote_notify.value);
		printf("}\n");
		printf("\n");

		break;
	}
	case GATT_BLE_REMOTE_WRITE_EVT:
	{
		gl_ble_gatt_data_t *remote_write = (gl_ble_gatt_data_t *)data;
		printf("***************** ble remote write *********************\n");
		printf("{\n");
		printf("  connection: %d\n", data->remote_write.connection);
		printf("  attribute: %d\n", data->remote_write.attribute);
		printf("  att_opcode: %d\n", data->remote_write.att_opcode);
		printf("  offset: %d\n", data->remote_write.offset);
		printf("  value: %s\n", data->remote_write.value);
		printf("}\n");
		printf("\n");

		break;
	}
	case GATT_BLE_REMOTE_SET_EVT:
	{
		gl_ble_gatt_data_t *remote_set = (gl_ble_gatt_data_t *)data;
		printf("***************** ble remote set *********************\n");
		printf("{\n");
		printf("  connection: %d\n", data->remote_set.connection);
		printf("  characteristic: %d\n", data->remote_set.characteristic);
		printf("  status_flags: %d\n", data->remote_set.status_flags);
		printf("  client_config_flags: %d\n", data->remote_set.client_config_flags);
		printf("}\n");
		printf("\n");

		break;
	}

	default:
		break;
	}
}

static int ble_module_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data)
{
	switch (event)
	{
	case MODULE_BLE_SYSTEM_BOOT_EVT:
	{
		gl_ble_module_data_t *system_boot = (gl_ble_module_data_t *)data;
		printf("***************** ble system boot *********************\n");
		printf("{\n");
		printf("  major: %d\n", data->system_boot_data.major);
		printf("  minor: %d\n", data->system_boot_data.minor);
		printf("  patch: %d\n", data->system_boot_data.patch);
		printf("  build: %d\n", data->system_boot_data.build);
		printf("  bootloader: %d\n", data->system_boot_data.bootloader);
		printf("  hw: %d\n", data->system_boot_data.hw);
		printf("  ble_hash: %s\n", data->system_boot_data.ble_hash);
		printf("}\n");
		printf("\n");
		break;
	}

	default:
		break;
	}
}

static int ble_gap_cb(gl_ble_gap_evrnt_t event, gl_ble_gap_data_t *data)
{
	switch (event)
	{
	case GAP_BLE_SCAN_RESULT_EVT:
	{
		gl_ble_gap_data_t *scan_result = (gl_ble_gap_data_t *)data;
		printf("***************** ble adv data *********************\n");
		printf("{\n");
		printf("  address: %s\n", data->scan_rst.addr);
		printf("  address type: %d\n", data->scan_rst.ble_addr_type);
		printf("  rssi: %d\n", data->scan_rst.rssi);
		printf("  packet type: %d\n", data->scan_rst.packet_type);
		printf("  bonding: %d\n", data->scan_rst.bonding);
		printf("  data: %s\n", data->scan_rst.ble_adv);
		printf("}\n");
		printf("\n");
		break;
	}

	case GAP_BLE_UPDATE_CONN_EVT:
	{
		gl_ble_gap_data_t *update_conn = (gl_ble_gap_data_t *)data;
		printf("***************** ble update connect *********************\n");
		printf("{\n");
		printf("  connection: %d\n", data->update_conn_data.connection);
		printf("  interval: %d\n", data->update_conn_data.interval);
		printf("  latency: %d\n", data->update_conn_data.latency);
		printf("  timeout: %d\n", data->update_conn_data.timeout);
		printf("  security_mode: %d\n", data->update_conn_data.security_mode);
		printf("  txsize: %d\n", data->update_conn_data.txsize);
		printf("}\n");
		printf("\n");
		break;
	}

	case GAP_BLE_CONNECT_EVT:
	{
		gl_ble_gap_data_t *connect = (gl_ble_gap_data_t *)data;
		printf("***************** ble connect *********************\n");
		printf("{\n");
		printf("  address: %s\n", data->connect_open_data.addr);
		printf("  address type: %d\n", data->connect_open_data.ble_addr_type);
		printf("  connect role: %d\n", data->connect_open_data.conn_role);
		printf("  bonding: %d\n", data->connect_open_data.bonding);
		printf("  advertiser: %d\n", data->connect_open_data.advertiser);
		printf("}\n");
		printf("\n");
		break;
	}

	case GAP_BLE_DISCONNECT_EVT:
	{
		gl_ble_gap_data_t *disconnect = (gl_ble_gap_data_t *)data;
		printf("***************** ble disconnect *********************\n");
		printf("{\n");
		printf("  connection: %d\n", data->disconnect_data.connection);
		printf("  reason: %d\n", data->disconnect_data.reason);
		printf("}\n");
		printf("\n");
		break;
	}

	default:
		break;
	}
}

static struct
{
	const char *name;
	int (*cb)(int argc, char **argv);
	char *doc;
} commands[] = {
	/* System functions */
	{"enable", cmd_enable, "Enable or disable the module"},
	{"set_power", cmd_set_power, "Set the tx power level"},
	{"local_address", cmd_local_address, "Get local Bluetooth module public address"},
	{"listen", cmd_listen, "Listen BLE event"},
	/*BLE slave functions */
	{"adv_data", cmd_adv_data, "Set adv data"},
	{"adv", cmd_adv, "Set and Start advertising"},
	{"adv_stop", cmd_adv_stop, "Stop advertising"},
	{"send_notify", cmd_send_notify, "Send notification to remote device"},
	/*BLE master functions */
	{"discovery", cmd_discovery, "Start discovery"},
	{"stop", cmd_stop, "End current GAP procedure"},
	{"connect", cmd_connect, "Open connection"},
	{"disconnect", cmd_disconnect, "Close connection"},
	{"get_rssi", cmd_get_rssi, "Get rssi of an established connection"},
	{"get_service", cmd_get_service, "Get supported services list"},
	{"get_char", cmd_get_char, "Get supported characteristics in specified service"},
	{"set_notify", cmd_set_notify, "Enable or disable the notifications and indications"},
	{"read_value", cmd_read_value, "Read specified characteristic value"},
	{"write_value", cmd_write_value, "Write characteristic value"},
	/*DTM test functions */
	{"dtm_tx", cmd_dtm_tx, "Start transmitter for dtm test"},
	{"dtm_rx", cmd_dtm_rx, "Start receiver for dtm test"},
	{"dtm_end", cmd_dtm_end, "End a dtm test"},
	{NULL, NULL, 0}};
static int usage(void)
{
	int i = 0;
	while (1)
	{
		if (commands[i].name)
		{
			printf("%-25s      %s\n", commands[i].name, commands[i].doc);
		}
		else
		{
			break;
		}
		i++;
	}
	return 0;
}
int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		usage();
		return -1;
	}

	int i = 0;
	while (commands[i].name)
	{
		if (strlen(commands[i].name) == strlen(argv[1]) && 0 == strcmp(commands[i].name, argv[1]))
		{
			return commands[i].cb(argc, argv);
		}
		i++;
	}
	usage();

	return 0;
}
