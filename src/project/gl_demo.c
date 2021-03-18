/*****************************************************************************
 * @file  test.c
 * @brief Start the BLE discovery and subscribe the BLE event
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
#include <stdint.h>

#include "gl_errno.h"
#include "gl_type.h"
#include "gl_bleapi.h"
#include "gl_thread.h"
#include "gl_errno.h"
#include "gl_common.h"

#define TARGET_BLE_ADV_DATA     "0909626c652d74657374"
#define DEFAULT_PHY             1
#define CONNECT_WAIT_TIME       5
#define CONNECT_MAX             2

typedef struct 
{
	BLE_MAC mac;
	int addr_type;
}target_dev_t;

static int _g_target_dev_num = 0;
target_dev_t target_dev[CONNECT_MAX];    // The MAC of target devices

static int _g_connected_dev_num = 0;
BLE_MAC connected_dev[CONNECT_MAX]; // The MAC of connected devices

static bool _g_connecting;

static int _g_work_mode;
#define FINDING_TARGET_DEV			0
#define WAITTING_FIND_TARGET_DEV	1
#define START_CONNECT_TARGET_DEV	2
#define FIND_R_W_CHAR_HANDLE		3
#define SEND_DATA_TO_TARGET_DEV		4
#define RECV_DATA_FORM_TARGET_DEV	5

static void create_recv_thread(void);
static void ble_run(void);

int main()
{
	BLE_MAC address;
	GL_RET ret = gl_ble_get_mac(address);
	if(ret != GL_SUCCESS)
	{
		return -1;
	}
	
	printf("local ble mac: %02x:%02x:%02x:%02x:%02x:%02x\n", \
			address[5],address[4],address[3],	\
			address[2],address[1],address[0]);

	create_recv_thread();

	while(1)
	{
		switch (_g_work_mode)
		{
			case FINDING_TARGET_DEV:
			{
				gl_ble_discovery(DEFAULT_PHY, 16, 16, 1, 1);
				_g_work_mode = WAITTING_FIND_TARGET_DEV;

				break;
			}
			case WAITTING_FIND_TARGET_DEV:
			{
				if(_g_target_dev_num == CONNECT_MAX)
				{
					printf("Find all target device! Stop discovery ... \n");
					if(GL_SUCCESS != gl_ble_stop_discovery())
					{
						printf("Stop discovery failed!!!\n");
						break;
					}
				}
				_g_work_mode = START_CONNECT_TARGET_DEV;

				break;
			}
			case START_CONNECT_TARGET_DEV:
			{
				int wait_time = 0;
				char address[BLE_MAC_LEN] = {0};
				
				while(_g_connected_dev_num != _g_target_dev_num)
				{
					addr2str(target_dev[_g_connected_dev_num].mac, address);
					printf("Try to connect to target device %s ... \n", address);

					_g_connecting = true;
					gl_ble_connect(target_dev[_g_connected_dev_num].mac, target_dev[_g_connected_dev_num].addr_type, DEFAULT_PHY);
					while(wait_time < CONNECT_WAIT_TIME)
					{
						if(!_g_connecting)
						{
							break;
						}
						wait_time++;
						sleep(1);
					}

					if(!_g_connecting)
					{
						printf("Connect success!\n");
					}else{
						gl_ble_disconnect(target_dev[_g_connected_dev_num].mac);
						printf("Connect to target device failed!");
					}
				}

				_g_work_mode = FIND_R_W_CHAR_HANDLE;
				break;
			}
			case FIND_R_W_CHAR_HANDLE:
			{

			}
			case SEND_DATA_TO_TARGET_DEV:
			{

				sleep(1);
				_g_work_mode = RECV_DATA_FORM_TARGET_DEV;
				break;
			}
			case RECV_DATA_FORM_TARGET_DEV:
			{

				sleep(30);
				_g_work_mode = SEND_DATA_TO_TARGET_DEV;
				break;
			}
			default:
				break;
		}
		usleep(1000000);
	}

	return 0;
}

static void create_recv_thread(void)
{
	thread_ctx_t* ctx = _thread_get_ctx();

    ctx->mutex = HAL_MutexCreate();
    if (ctx->mutex == NULL) {
        printf("Not Enough Memory");
        return ;
    }

    int ret;
    ret = HAL_ThreadCreate(&ctx->g_dispatch_thread, ble_run, NULL, NULL, NULL);
    if (ret != 0) {
        printf("pthread_create failed!\n");
        return ;
    }
}

static int ble_gap_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data);
static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data);
static int ble_module_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data);

static void ble_run(void)
{
	gl_ble_cbs ble_cb;
	memset(&ble_cb, 0, sizeof(gl_ble_cbs));

	ble_cb.ble_gap_event = ble_gap_cb;
	ble_cb.ble_gatt_event = ble_gatt_cb;
	ble_cb.ble_module_event = ble_module_cb;


	gl_ble_subscribe(&ble_cb);

	// printf("");
	return ;
}


static int ble_gap_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data)
{
	char address[BLE_MAC_LEN] = {0};

	switch (event)
	{
		case GAP_BLE_SCAN_RESULT_EVT:
		{
			gl_ble_gap_data_t *scan_result = (gl_ble_gap_data_t *)data;
			// addr2str(data->scan_rst.address, address);
			// printf("recv adv date from: %s\n", address);
			
			if(strcmp(data->scan_rst.ble_adv, TARGET_BLE_ADV_DATA) == 0)
			{
				memcpy(&target_dev[_g_target_dev_num].mac, data->scan_rst.address, sizeof(BLE_MAC));
				target_dev[_g_target_dev_num].addr_type = data->scan_rst.ble_addr_type;
				_g_target_dev_num++;
			}

			if(_g_target_dev_num == CONNECT_MAX)
			{
				printf("Find all target device! Stop discovery ... \n");
				if(GL_SUCCESS != gl_ble_stop_discovery())
				{
					printf("Stop discovery failed!!!\n");
					break;
				}
			}

			break;
		}
		case GAP_BLE_UPDATE_CONN_EVT:
		{
			gl_ble_gap_data_t *update_conn = (gl_ble_gap_data_t *)data;
			addr2str(data->update_conn_data.address, address);

			
			break;
		}

		case GAP_BLE_CONNECT_EVT:
		{
			gl_ble_gap_data_t *connect = (gl_ble_gap_data_t *)data;
			addr2str(data->connect_open_data.address, address);
			
			if(memcmp(data->connect_open_data.address, target_dev[_g_connected_dev_num].mac, sizeof(BLE_MAC)) == 0)
			{
				printf("Connect open!!! Target device: %s\n", address);
				_g_connecting = false;
				_g_connected_dev_num++;
			}
			break;
		}

		case GAP_BLE_DISCONNECT_EVT:
		{
			gl_ble_gap_data_t *disconnect = (gl_ble_gap_data_t *)data;
			addr2str(data->disconnect_data.address, address);

			
			break;
		}
		default:
			break;
	}
}

static int ble_gatt_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data)
{

}

static int ble_module_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data)
{
	switch (event)
	{
		case MODULE_BLE_SYSTEM_BOOT_EVT:
		{
			gl_ble_module_data_t *system_boot = (gl_ble_module_data_t *)data;
			printf("BLE module restart!!!\n");
			break;
		}
		default:
			break;
	}
}

