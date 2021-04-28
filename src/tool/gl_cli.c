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
#include <json-c/json.h>

#include <unistd.h>
#include <signal.h>

#include "gl_bleapi.h"
#include "gl_dev_mgr.h"
#include "gl_log.h"
#include "gl_errno.h"
#include "gl_type.h"
#include "gl_common.h"

#define PARA_MISSING 	"Parameter missing\n"
#define PARA_ERROR 		"Parameter error\n"

static int ble_module_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data);
static int ble_gap_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data);
static int ble_gap_test_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data);
static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);

/* System functions */
GL_RET cmd_enable(int argc, char **argv)
{
	int enable = 0;
	if (argc < 3) {
		enable = 1;
	}
	else {
		enable = atoi(argv[2]);
	}

	GL_RET ret  = gl_ble_enable(enable);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o,"code",json_object_new_int(ret));
	char *temp=json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);
	
	return GL_SUCCESS;
}

GL_RET cmd_local_address(int argc, char **argv)
{
	BLE_MAC address;
	char str_addr[20] = {0};
	GL_RET ret = gl_ble_get_mac(address);

	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o,"code",json_object_new_int(ret));
	if(ret == GL_SUCCESS)
	{
		addr2str(address, str_addr);
		json_object_object_add(o, "mac", json_object_new_string(str_addr));
	}
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_set_power(int argc, char **argv)
{
	int power = 0;
	int current_p = 0;
	if (argc < 3) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}
	else {
		power = atoi(argv[2]);
	}

	GL_RET ret = gl_ble_set_power(power, &current_p);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	if(ret == GL_SUCCESS)
	{
		json_object_object_add(o, "current_power", json_object_new_int(current_p));
	}
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);
	
	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}


GL_RET cmd_listen(int argc, char **argv)
{
	gl_ble_cbs ble_cb;
	memset(&ble_cb, 0, sizeof(gl_ble_cbs));

	ble_cb.ble_gap_event = ble_gap_cb;
	ble_cb.ble_gatt_event = ble_gatt_cb;
	ble_cb.ble_module_event = ble_module_cb;

	gl_ble_subscribe(&ble_cb);
}

/*BLE slave functions */
GL_RET cmd_adv(int argc, char **argv)
{
	int ch, phys = 1, interval_min = 160, interval_max = 160, discover = 2, adv_conn = 2;

	struct option long_options[] = {
		{"phys", required_argument, NULL, 'p'},
		{"interval_min", required_argument, NULL, 'n'},
		{"interval_max", required_argument, NULL, 'x'},
		{"discover", required_argument, NULL, 'd'},
		{"adv_conn", required_argument, NULL, 'c'},
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
			adv_conn = atoi(optarg);
			break;
		}
	}

	if (interval_max < interval_min)
	{
		interval_max = interval_min;
	}

	GL_RET ret = gl_ble_adv(phys, interval_min, interval_max, discover, adv_conn);

	// json format	
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_adv_data(int argc, char **argv)
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

	if (flag < 0 || !value) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	GL_RET ret = gl_ble_adv_data(flag, value);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);	
	
	//free(temp);
	json_object_put(o);
	return GL_SUCCESS;
}

GL_RET cmd_adv_stop(int argc, char **argv)
{
	GL_RET ret = gl_ble_stop_adv();

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_send_notify(int argc, char **argv)
{
	int ch = 0, char_handle = -1;
	char *value = NULL, *str = NULL;
	char *address = NULL;	

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"char_handle", required_argument, NULL, 'h'},
		{"value", required_argument, NULL, 'v'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "a:h:v:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
			case 'h':
				char_handle = atoi(optarg);
				break;
			case 'v':
				value = optarg;
				break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0 || !value)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret = gl_ble_send_notify(address_u8, char_handle, value);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp=json_object_to_json_string(o);
	printf("%s\n",temp);	

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_discovery(int argc, char **argv)
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

	GL_RET ret = gl_ble_discovery(phys, interval, window, type, mode);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_stop(int argc, char **argv)
{
	GL_RET ret = gl_ble_stop_discovery();

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_connect(int argc, char **argv)
{
	int ch, phy = 1, address_type = -1, option_index;
	char *address = NULL;

	struct option long_options[] = {
		{"phys", required_argument, NULL, 'p'},
		{"address_type", required_argument, NULL, 't'},
		{"address", required_argument, NULL, 'a'},
		{0, 0, 0, 0}
	};

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

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	if (address_type < 0 || !address) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret =  gl_ble_connect(address_u8, address_type, phy);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o,"code",json_object_new_int(ret));
	char *temp=json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_disconnect(int argc, char **argv)
{
	char *address = NULL;
	int ch, option_index;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{0, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv, "a:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'a':
			address = optarg;
			break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret = gl_ble_disconnect(address_u8);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_get_rssi(int argc, char **argv)
{
	int ch, option_index;
	char *address = NULL;

	struct option long_options[] = {
	{"address", required_argument, NULL, 'a'},
	{0}};
	
	if (argc < 4)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	while ((ch = getopt_long(argc, argv, "a:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	uint8_t addr_len = strlen(address);
	if (addr_len != BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}
	
	BLE_MAC address_u8;
	str2addr(address, address_u8);
	int rssi = 0;

	GL_RET ret = gl_ble_get_rssi(address_u8, &rssi);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o,"code",json_object_new_int(ret));

	if ( ret == GL_SUCCESS ) {
		json_object_object_add(o, "rssi", json_object_new_int(rssi));
	}
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_get_service(int argc, char **argv)
{
	int ch, option_index;
	char *address = NULL;

	struct option long_options[] = {
	{"address", required_argument, NULL, 'a'},
	{0}};
	
	if (argc < 4)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	while ((ch = getopt_long(argc, argv, "a:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	gl_ble_service_list_t service_list;
	memset(&service_list, 0, sizeof(gl_ble_service_list_t));

	int ret = gl_ble_get_service(&service_list, address_u8);

	// json format
	json_object *o = NULL, *l = NULL, *obj = NULL, *array = NULL;
	
	array = json_object_new_array();
	obj = json_object_new_object(); 
	json_object_object_add(obj, "code", json_object_new_int(ret));
    json_object_object_add(obj, "service_list", array);
	int len = service_list.list_len;
	int i = 0;

	if ( !ret ) {
		while ( i < len ) {	
			o = json_object_new_object();
            l = json_object_object_get(obj, "service_list");
			json_object_object_add(o, "service_handle", json_object_new_int(service_list.list[i].handle));
			json_object_object_add(o, "service_uuid", json_object_new_string(service_list.list[i].uuid));
            json_object_array_add(l,o);
			i++;
		}
	}
	char *temp = json_object_to_json_string(obj);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(obj);

	return GL_SUCCESS;
}

GL_RET cmd_get_char(int argc, char **argv)
{
	int ch, service_handle = -1;
	int option_index;
	char *str = NULL;
	char *address = NULL;	
	uint8_t addr_len;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"service_handle", required_argument, NULL, 'h'},
		{0, 0, 0, 0}};
	
	while ((ch = getopt_long(argc, argv, "a:h:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
			case 'h':
				service_handle = atoi(optarg);
				break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1 || service_handle < 0)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	gl_ble_char_list_t char_list;
	memset(&char_list, 0, sizeof(gl_ble_char_list_t));

	GL_RET ret = gl_ble_get_char(&char_list, address_u8, service_handle);

	// json format
	json_object *o = NULL, *l = NULL, *obj = NULL, *array = NULL;
	
	array = json_object_new_array();
	obj = json_object_new_object(); 
	json_object_object_add(obj, "code", json_object_new_int(ret));
    json_object_object_add(obj, "characteristic_list", array);
	int len = char_list.list_len;
	int i = 0;

	if ( ret == GL_SUCCESS ) {
		while ( i < len ) {	
			o = json_object_new_object();
            l = json_object_object_get(obj, "characteristic_list");
			json_object_object_add(o, "characteristic_handle", json_object_new_int(char_list.list[i].handle));
			json_object_object_add(o, "properties", json_object_new_int(char_list.list[i].properties));
			json_object_object_add(o, "characteristic_uuid", json_object_new_string(char_list.list[i].uuid));
            json_object_array_add(l,o);
			i++;
		}
	}
	char *temp = json_object_to_json_string(obj);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(obj);

	return GL_SUCCESS;
}
GL_RET cmd_set_notify(int argc, char **argv)
{
	int ch, char_handle = -1, flag = -1;
	char *str = NULL;
	char *address = NULL;	
	uint8_t addr_len;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"char_handle", required_argument, NULL, 'h'},
		{"flag", required_argument, NULL, 'f'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "a:h:f:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
			case 'h':
				char_handle = atoi(optarg);
				break;
			case 'f':
				flag = atoi(optarg);
				break;
		}
	}

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0 || flag < 0)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret = gl_ble_set_notify(address_u8, char_handle, flag);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_read_value(int argc, char **argv)
{
	int ch, char_handle = -1;
	char *str = NULL, *address = NULL;
	uint8_t addr_len;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"char_handle", required_argument, NULL, 'h'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "a:h:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
				break;
			case 'h':
				char_handle = atoi(optarg);
				break;
		}
	}
	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	addr_len = strlen(address);

	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0) {
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret = gl_ble_read_char(address_u8, char_handle);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o,"code",json_object_new_int(ret));

	char *temp = json_object_to_json_string(o);
	printf("%s\n",temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

GL_RET cmd_write_value(int argc, char **argv)
{
	int ch, char_handle = -1, res = 0;
	char *value = NULL, *str = NULL;
	char *address = NULL;	
	uint8_t addr_len;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"char_handle", required_argument, NULL, 'h'},
		{"res", required_argument, NULL, 'r'},
		{"value", required_argument, NULL, 'v'},
		{0, 0, 0, 0}};
	int option_index;

	while ((ch = getopt_long(argc, argv, "a:h:r:v:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'a':
				address = optarg;
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

	if(address == NULL)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM;
	}

	addr_len = strlen(address);

	if (addr_len < BLE_MAC_LEN - 1  || char_handle < 0 || !value) {
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	BLE_MAC address_u8;
	str2addr(address, address_u8);

	GL_RET ret = gl_ble_write_char(address_u8, char_handle, value, res);

	// json format
	json_object* o = NULL;
	o = json_object_new_object();
	json_object_object_add(o, "code", json_object_new_int(ret));
	char *temp = json_object_to_json_string(o);
	printf("%s\n", temp);

	//free(temp);
	json_object_put(o);

	return GL_SUCCESS;
}

static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data)
{
	char address[BLE_MAC_LEN] = {0};
	switch (event)
	{
	case GATT_BLE_REMOTE_NOTIFY_EVT:
	{
		gl_ble_gatt_data_t *remote_notify = (gl_ble_gatt_data_t *)data;
		addr2str(data->remote_notify.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("remote_notify"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "characteristic", json_object_new_int(data->remote_notify.characteristic));
		json_object_object_add(o, "att_opcode", json_object_new_int(data->remote_notify.att_opcode));
		json_object_object_add(o, "offset", json_object_new_int(data->remote_notify.offset));
		json_object_object_add(o, "value", json_object_new_string(data->remote_notify.value));
		char *temp=json_object_to_json_string(o);
		printf("%s\n",temp);

		json_object_put(o);
		break;
	}
	case GATT_BLE_REMOTE_WRITE_EVT:
	{
		gl_ble_gatt_data_t *remote_write = (gl_ble_gatt_data_t *)data;
		addr2str(data->remote_write.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("remote_write"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "attribute", json_object_new_int(data->remote_write.attribute));
		json_object_object_add(o, "att_opcode", json_object_new_int(data->remote_write.att_opcode));
		json_object_object_add(o, "offset", json_object_new_int(data->remote_write.offset));
		json_object_object_add(o, "value", json_object_new_string(data->remote_write.value));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
		break;
	}
	case GATT_BLE_REMOTE_SET_EVT:
	{
		gl_ble_gatt_data_t *remote_set = (gl_ble_gatt_data_t *)data;		
		addr2str(data->remote_set.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("remote_set"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "characteristic", json_object_new_int(data->remote_set.characteristic));
		json_object_object_add(o, "status_flags", json_object_new_int(data->remote_set.status_flags));
		json_object_object_add(o, "client_config_flags", json_object_new_int(data->remote_set.client_config_flags));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
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

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("module_start"));
		json_object_object_add(o, "major", json_object_new_int(data->system_boot_data.major));
		json_object_object_add(o, "minor", json_object_new_int(data->system_boot_data.minor));
		json_object_object_add(o, "patch", json_object_new_int(data->system_boot_data.patch));
		json_object_object_add(o, "build", json_object_new_int(data->system_boot_data.build));
		json_object_object_add(o, "bootloader", json_object_new_int(data->system_boot_data.bootloader));
		json_object_object_add(o, "hw", json_object_new_int(data->system_boot_data.hw));
		json_object_object_add(o, "ble_hash", json_object_new_string(data->system_boot_data.ble_hash));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
		break;
	}
	default:
		break;
	}
}

static int ble_gap_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data)
{
	char address[BLE_MAC_LEN] = {0};
	switch (event)
	{
	case GAP_BLE_SCAN_RESULT_EVT:
	{
		gl_ble_gap_data_t *scan_result = (gl_ble_gap_data_t *)data;
		addr2str(data->scan_rst.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("scan_result"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "address_type", json_object_new_int(data->scan_rst.ble_addr_type));
		json_object_object_add(o, "rssi", json_object_new_int(data->scan_rst.rssi));
		json_object_object_add(o, "packet_type", json_object_new_int(data->scan_rst.packet_type));
		json_object_object_add(o, "bonding", json_object_new_int(data->scan_rst.bonding));
		json_object_object_add(o, "data", json_object_new_string(data->scan_rst.ble_adv));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);

		json_object_put(o);
		break;
	}

	case GAP_BLE_UPDATE_CONN_EVT:
	{
		gl_ble_gap_data_t *update_conn = (gl_ble_gap_data_t *)data;
		addr2str(data->update_conn_data.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("connect_update"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "interval", json_object_new_int(data->update_conn_data.interval));
		json_object_object_add(o, "latency", json_object_new_int(data->update_conn_data.latency));
		json_object_object_add(o, "timeout", json_object_new_int(data->update_conn_data.timeout));
		json_object_object_add(o, "security_mode", json_object_new_int(data->update_conn_data.security_mode));
		json_object_object_add(o, "txsize", json_object_new_int(data->update_conn_data.txsize));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
		break;
	}

	case GAP_BLE_CONNECT_EVT:
	{
		gl_ble_gap_data_t *connect = (gl_ble_gap_data_t *)data;
		addr2str(data->connect_open_data.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("connect_open"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "address_type", json_object_new_int(data->connect_open_data.ble_addr_type));
		json_object_object_add(o, "connect_role", json_object_new_int(data->connect_open_data.conn_role));
		json_object_object_add(o, "bonding", json_object_new_int(data->connect_open_data.bonding));
		json_object_object_add(o, "advertiser", json_object_new_int(data->connect_open_data.advertiser));
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
		break;
	}

	case GAP_BLE_DISCONNECT_EVT:
	{
		gl_ble_gap_data_t *disconnect = (gl_ble_gap_data_t *)data;
		addr2str(data->disconnect_data.address, address);

		// json format
		json_object* o = NULL;
		o = json_object_new_object();
		json_object_object_add(o, "type", json_object_new_string("connect_close"));
		json_object_object_add(o, "mac", json_object_new_string(address));
		json_object_object_add(o, "reason", json_object_new_int(data->disconnect_data.reason));	
		char *temp = json_object_to_json_string(o);
		printf("%s\n",temp);
		
		json_object_put(o);
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
	// {"print_format", cmd_print_format, "Specify log print information: JSON format(default) or debug format"},
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
	{"stop_discovery", cmd_stop, "End current GAP procedure"},
	{"connect", cmd_connect, "Open connection"},
	{"disconnect", cmd_disconnect, "Close connection"},
	{"get_rssi", cmd_get_rssi, "Get rssi of an established connection"},
	{"get_service", cmd_get_service, "Get supported services list"},
	{"get_char", cmd_get_char, "Get supported characteristics in specified service"},
	{"set_notify", cmd_set_notify, "Enable or disable the notifications and indications"},
	{"read_value", cmd_read_value, "Read specified characteristic value"},
	{"write_value", cmd_write_value, "Write characteristic value"},
	{NULL, NULL, 0}};

static int usage(void)
{
	int i = 0;
	while (1) {
		if (commands[i].name) {
			printf("%-25s      %s\n", commands[i].name, commands[i].doc);
		}
		else {
			break;
		}
		i++;
	}
	return GL_SUCCESS;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return GL_ERR_PARAM_MISSING;
	}

	int i = 0;
	while (commands[i].name) {
		if (strlen(commands[i].name) == strlen(argv[1]) && 0 == strcmp(commands[i].name, argv[1]))
		{
			return commands[i].cb(argc, argv);
		}
		i++;
	}
	usage();

	return GL_SUCCESS;
}
