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
	
	printf("{ \"code\": %d ", ret);
	printf("} \n");	

	return GL_SUCCESS;
}

GL_RET cmd_local_address(int argc, char **argv)
{
	char addr[BLE_MAC_LEN] = {0};
	gl_ble_get_mac_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_get_mac_rsp_t));
	GL_RET ret = gl_ble_get_mac(&rsp);
	
	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		addr2str(rsp.address, addr);
		printf(", \"address\": \"%s\" ", addr);
	}
	printf("}\n");	

	return GL_SUCCESS;
}

GL_RET cmd_set_power(int argc, char **argv)
{
	int power = 0;
	if (argc < 3) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}
	else {
		power = atoi(argv[2]);
	}

	gl_ble_set_power_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_set_power_rsp_t));
	GL_RET ret = gl_ble_set_power(&rsp, power);
	
	// printf("{ \"code\": %d ", ret);
	// printf("} \n");	
	if ( !ret ) {
		printf("\"current_power\": %d dBm ", rsp.current_power);
		printf("} \n");	
	}
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
	
	printf("{ \"code\": %d ", ret);
	printf("}\n");	

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

	printf("{ \"code\": %d ", ret);
	printf("}\n");	

	return GL_SUCCESS;
}

GL_RET cmd_adv_stop(int argc, char **argv)
{
	GL_RET ret = gl_ble_stop_adv();

	printf("{ \"code\": %d ", ret);
	printf("}\n");

	return GL_SUCCESS;
}

GL_RET cmd_send_notify(int argc, char **argv)
{
	int ch = 0, char_handle = -1;
	char *value = NULL, *str = NULL;
	char address[BLE_MAC_LEN] = {0};	
	uint8_t addr_len;

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
			strcpy(address, argv[2]);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		case 'v':
			value = optarg;
			break;
		}
	}

	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0 || !value)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	gl_ble_send_notify_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_send_notify_rsp_t));
	GL_RET ret = gl_ble_send_notify(&rsp, address_u8, char_handle, value);

	printf("{ \"code\": %d ", ret);
	if ( !ret ) {
		printf(", \"sent_len\": %d", rsp.sent_len);
	}
	printf(" }\n");	

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

	printf("{ \"code\": %d ", ret);
	printf("}\n");	

	return GL_SUCCESS;
}

GL_RET cmd_stop(int argc, char **argv)
{
	GL_RET ret = gl_ble_stop();

	printf("{ \"code\": %d ", ret);
	printf("}\n");

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

	if (address_type < 0 || !address) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	gl_ble_connect_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_connect_rsp_t));

	GL_RET ret =  gl_ble_connect(&rsp, address_u8, address_type, phy);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"address\": %s, ", address);
		printf("\"address_type\": %d, ", rsp.address_type);
		printf("\"master\": %d, ", rsp.master);
		printf("\"bonding\": %d, ", rsp.bonding);
		printf("\"advertiser\": %d ", rsp.advertiser);
	}
	printf(" }\n");	

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

	if (!address) {
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	GL_RET ret = gl_ble_disconnect(address_u8);

	printf("{ \"code\": %d", ret);
	printf(" }\n");

	return GL_SUCCESS;
}

GL_RET cmd_get_rssi(int argc, char **argv)
{
	char address[BLE_MAC_LEN] = {0};

	struct option long_options[] = {
	{"address", required_argument, NULL, 'a'},
	{0}};
	
	if (argc < 4)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}
	else
	{
		strcpy(address, argv[3]);
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}
	
	gl_ble_get_rssi_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_get_rssi_rsp_t));

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	GL_RET ret = gl_ble_get_rssi(&rsp, address_u8);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"address\": \"%s\"", address);
		printf(", \"rssi\": %d", rsp.rssi);
	}
	printf(" }\n");	

	return GL_SUCCESS;
}

GL_RET cmd_get_service(int argc, char **argv)
{
	char address[BLE_MAC_LEN] = {0};

	struct option long_options[] = {
	{"address", required_argument, NULL, 'a'},
	{0}};
	
	if (argc < 4)
	{
		printf(PARA_MISSING);
		return GL_ERR_PARAM_MISSING;
	}
	else
	{
		strcpy(address, argv[3]);
	}

	uint8_t addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	gl_ble_get_service_rsp_t rsp;

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	int ret = gl_ble_get_service(&rsp, address_u8);

	printf("{ \"code\": %d", ret);
	int len = rsp.list_len;
	int i = 0;
	while ( i < len ) {
		printf(", \"service_handle\": %d", rsp.list[i].handle);
		printf(", \"service_uuid\": \"%s\" ", rsp.list[i].uuid);
		i++;
	}
	printf("}\n");

	return GL_SUCCESS;
}

GL_RET cmd_get_char(int argc, char **argv)
{
	int ch, service_handle = -1;
	int option_index;
	char *str = NULL;
	char address[BLE_MAC_LEN] = {0};	
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
			strcpy(address, argv[3]);
			break;
		case 'h':
			service_handle = atoi(optarg);
			break;
		}
	}

	addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1 || service_handle < 0)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	gl_ble_get_char_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_get_char_rsp_t));
	GL_RET ret = gl_ble_get_char(&rsp, address_u8, service_handle);

	printf("{ \"code\": %d, ", ret);
	int len = rsp.list_len;
	int i = 0;
	while ( i < len ) {
		printf("\"characteristic_handle\": %d, ", rsp.list[i].handle);
		printf("\"properties\": \"%d\", ", rsp.list[i].properties);
		printf("\"characteristic_uuid\": \"%s\", ", rsp.list[i].uuid);
		i++;
	}
	printf("} \n");	

	return GL_SUCCESS;
}
GL_RET cmd_set_notify(int argc, char **argv)
{
	int ch, char_handle = -1, flag = -1;
	char *str = NULL;
	char address[BLE_MAC_LEN] = {0};	
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
			strcpy(address, argv[3]);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		case 'f':
			flag = atoi(optarg);
			break;
		}
	}

	addr_len = strlen(address);
	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0 || flag < 0)
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	GL_RET ret = gl_ble_set_notify(address_u8, char_handle, flag);
	
	printf("{ \"code\": %d ", ret);
	printf("} \n");	

	return GL_SUCCESS;
}

GL_RET cmd_read_value(int argc, char **argv)
{
	int ch, char_handle = -1;
	char *str = NULL;
	char address[BLE_MAC_LEN] = {0};	
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
			strcpy(address, argv[3]);
			break;
		case 'h':
			char_handle = atoi(optarg);
			break;
		}
	}
	addr_len = strlen(address);

	if (addr_len < BLE_MAC_LEN - 1 || char_handle < 0) {
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	gl_ble_char_read_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_char_read_rsp_t));

	GL_RET ret = gl_ble_read_char(&rsp, address_u8, char_handle);

	printf("{ \"code\": %d, ", ret);
	if ( !ret ) {
		printf("\"characteristic_handle\": %d, ", rsp.handle);
		printf("\"att_opcode\": %d, ", rsp.att_opcode);
		printf("\"offset\": %d, ", rsp.offset);
		printf("\"value\": \"%s\" ", rsp.value);
	}
	printf("} \n");	

	return GL_SUCCESS;
}

GL_RET cmd_write_value(int argc, char **argv)
{
	int ch, char_handle = -1, res = 0;
	char *value = NULL, *str = NULL;
	char address[BLE_MAC_LEN] = {0};	
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
			strcpy(address, argv[3]);
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

	if (addr_len < BLE_MAC_LEN - 1  || char_handle < 0 || !value) {
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	uint8_t address_u8[DEVICE_MAC_LEN] = {0};
	str2addr(address, &address_u8);

	gl_ble_write_char_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_write_char_rsp_t));
	GL_RET ret = gl_ble_write_char(&rsp, address_u8, char_handle, value, res);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"sent_len\": %d", rsp.sent_len);
		printf(" } \n");	
	}

	return GL_SUCCESS;
}

GL_RET cmd_dtm_tx(int argc, char **argv)
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

	gl_ble_dtm_test_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_dtm_test_rsp_t));
	GL_RET ret = gl_ble_dtm_tx(&rsp, packet_type, length, channel, phy);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"number_of_packets\": %d ", rsp.number_of_packets);
	}
	printf("}\n");

	return GL_SUCCESS;
}

GL_RET cmd_dtm_rx(int argc, char **argv)
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

	gl_ble_dtm_test_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_dtm_test_rsp_t));
	GL_RET ret = gl_ble_dtm_rx(&rsp, channel, phy);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"number_of_packets\": %d ", rsp.number_of_packets);
	}
	printf("}\n");

	return GL_SUCCESS;
}

GL_RET cmd_dtm_end(int argc, char **argv)
{
	gl_ble_dtm_test_rsp_t rsp;
	memset(&rsp, 0, sizeof(gl_ble_dtm_test_rsp_t));
	GL_RET ret = gl_ble_dtm_end(&rsp);

	printf("{ \"code\": %d", ret);
	if ( !ret ) {
		printf(", \"number_of_packets\": %d ", rsp.number_of_packets);
	}
	printf("}\n");

	return GL_SUCCESS;
}

char *address_test = NULL;
int rssi_sum = 0;
int adv_cnt = 0;
int timeout = 0;
int real_time = 0;

static void signal_handler()
{
	printf("\n");
	printf("Number of broadcast packets	:	%d\n", adv_cnt);
	printf("Packages loss probability	: 	%.2f\n", 1-(float)adv_cnt / 100.0);
	printf("The total number of RSSI	:	%d\n", rssi_sum);
	printf("The average of RSSI		:	%.1f\n\n", (float)rssi_sum/adv_cnt);
	
	adv_cnt = 0;
	rssi_sum = 0;
	alarm(0);
	GL_RET ret = gl_ble_stop();
	exit(0);	
}

GL_RET cmd_adv_pack_test(int argc, char **argv) 
{
	int ch = 0;
	char  *str = NULL;

	uint8_t addr_len;

	struct option long_options[] = {
		{"address", required_argument, NULL, 'a'},
		{"timeout", required_argument, NULL, 't'},
		{0, 0, 0, 0}};
	
	int option_index;

	while ((ch = getopt_long(argc, argv, "a:t:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'a':
			address_test = optarg;
			printf("\nThe remote address is %s\n", address_test);
			break;
		case 't':
			timeout = atoi(optarg);
			printf("The timeout is %d seconds.\n\n", timeout);
			break;
		}
	}

	addr_len = strlen(address_test);
	if (addr_len < BLE_MAC_LEN - 1 || timeout <= 0 )
	{
		printf(PARA_ERROR);
		return GL_ERR_PARAM;
	}

	int phys = 1, interval = 16, window = 16, type = 0, mode = 1;
	GL_RET ret = gl_ble_discovery(phys, interval, window, type, mode);

	// printf("{ \"code\": %d ", ret);
	// printf("}\n");	

	signal(SIGALRM, signal_handler);
	alarm(timeout);

	gl_ble_cbs ble_cb;
	memset(&ble_cb, 0, sizeof(gl_ble_cbs));
	ble_cb.ble_gap_event = ble_gap_test_cb;
	ble_cb.ble_gatt_event = NULL;
	ble_cb.ble_module_event = NULL;
	gl_ble_subscribe(&ble_cb);

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
		addr2str(&data->remote_notify.address, address);
		
		printf("\nBle remote notify event: \n");
		printf("{");		
		printf(" \"address\": \"%s\", ", address);
		printf("\"characteristic\": %d, ",data->remote_notify.characteristic);
		printf("\"att_opcode\": %d, ",data->remote_notify.att_opcode);
		printf("\"offset\": %d, ", data->remote_notify.offset);
		printf("\"value\": \"%s\" ", data->remote_notify.value);
		printf("}\n");
		break;
	}
	case GATT_BLE_REMOTE_WRITE_EVT:
	{
		gl_ble_gatt_data_t *remote_write = (gl_ble_gatt_data_t *)data;
		addr2str(&data->remote_write.address, address);
		
		printf("\nBle remote write event: \n");
		printf("{");
		printf(" \"address\": \"%s\", ", address);
		printf("\"attribute\": %d, ", data->remote_write.attribute);
		printf("\"att_opcode\": %d, ", data->remote_write.att_opcode);
		printf("\"offset\": %d, ", data->remote_write.offset);
		printf("\"value\": \"%s\" ", data->remote_write.value);
		printf("}\n");
		break;
	}
	case GATT_BLE_REMOTE_SET_EVT:
	{
		gl_ble_gatt_data_t *remote_set = (gl_ble_gatt_data_t *)data;		
		addr2str(&data->remote_set.address, address);
		
		printf("\nBle remote set event: \n");
		printf("{");
		printf(" \"address\": \"%s\", ", address);
		printf("\"characteristic\": %d, ", data->remote_set.characteristic);
		printf("\"status_flags\": %d, ", data->remote_set.status_flags);
		printf("\"client_config_flags\": %d ", data->remote_set.client_config_flags);
		printf("}\n");
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
		
		printf("\nBle system boot event: \n");
		printf("{");
		printf(" \"major\": \"%d\", ", data->system_boot_data.major);
		printf("\"minor\": %d, ",data->system_boot_data.minor);
		printf("\"patch\": %d, ",data->system_boot_data.patch);
		printf("\"build\": %d, ", data->system_boot_data.build);
		printf("\"bootloader\": %d, ", data->system_boot_data.bootloader);
		printf("\"hw\": %d, ", data->system_boot_data.hw);
		printf("\"ble_hash\": \"%s\" ", data->system_boot_data.ble_hash);
		printf("}\n");
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
		addr2str(&data->update_conn_data.address, address);

		printf("{");
		printf(" \"address\": \"%s\", ", address);
		printf("\"address type\": %d, ", data->scan_rst.ble_addr_type);
		printf("\"rssi\": %d, ", data->scan_rst.rssi);
		printf("\"packet type\": %d, ", data->scan_rst.packet_type);
		printf("\"bonding\": %d, ", data->scan_rst.bonding);
		printf("\"data\": \"%s\" ", data->scan_rst.ble_adv);
		printf("}\n");
		break;
	}

	case GAP_BLE_UPDATE_CONN_EVT:
	{
		gl_ble_gap_data_t *update_conn = (gl_ble_gap_data_t *)data;
		addr2str(&data->update_conn_data.address, address);
		
		printf("\nBle update connect event: \n");		
		printf("{");
		printf(" \"address\": \"%s\", ", address);
		printf("\"interval\": %d, ", data->update_conn_data.interval);
		printf("\"latency\": %d, ", data->update_conn_data.latency);
		printf("\"timeout\": %d, ", data->update_conn_data.timeout);
		printf("\"security_mode\": %d, ",  data->update_conn_data.security_mode);
		printf("\"txsize\": %d ", data->update_conn_data.txsize);
		printf("}\n");
		break;
	}

	case GAP_BLE_CONNECT_EVT:
	{
		gl_ble_gap_data_t *connect = (gl_ble_gap_data_t *)data;
		addr2str(&data->disconnect_data.address, address);
		
		printf("\nBle connect event: \n");
		printf("{");
		printf(" \"address\": \"%s\", ", address);
		printf("\"address type\": %d, ", data->connect_open_data.ble_addr_type);
		printf("\"connect role\": %d, ", data->connect_open_data.conn_role);
		printf("\"bonding\": %d, ", data->connect_open_data.bonding);
		printf("\"advertiser\": %d ", data->connect_open_data.advertiser);
		printf("}\n");
		break;
	}

	case GAP_BLE_DISCONNECT_EVT:
	{
		gl_ble_gap_data_t *disconnect = (gl_ble_gap_data_t *)data;
		addr2str(&data->disconnect_data.address, address);

		printf("\nBle disconnect event: \n");
		printf("{ ");
		printf(" \"address\": \"%s\", ", address);
		printf("\"reason\": %d ", data->disconnect_data.reason);
		printf("}\n");
		break;
	}
	default:
		break;
	}
}

static int ble_gap_test_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data)
{
	char address[BLE_MAC_LEN] = {0};
	
	switch (event)
	{
	case GAP_BLE_SCAN_RESULT_EVT:
	{
		gl_ble_gap_data_t *scan_result = (gl_ble_gap_data_t *)data;
		addr2str(&data->update_conn_data.address, address);
		if(!strcmp(address, address_test)) {
			adv_cnt ++;
			rssi_sum += data->scan_rst.rssi;
		}
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
	/* Adv test */
	{"adv_pack_test", cmd_adv_pack_test, "Start ble adv packet test"},	
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
