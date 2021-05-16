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
#include "gl_bleapi.h"
#include "gl_dev_mgr.h"
#include "gl_log.h"
#include "gl_common.h"
#include "gl_hal.h"
#include "gl_methods.h"

gl_ble_cbs ble_msg_cb;

static void create_module_thread(void);

/************************************************************************************************************************************/

static void create_module_thread(void)
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

GL_RET gl_ble_init(void)
{
	/* Init device manage */
	ble_dev_mgr_init();
	
	// init hal
	hal_init();

	// create a thread to recv module message
	create_module_thread();

	return GL_SUCCESS;
}

GL_RET gl_ble_subscribe(gl_ble_cbs *callback)
{
	if(NULL != callback->ble_module_event)
	{
		ble_msg_cb.ble_module_event = callback->ble_module_event;
	}

	if (NULL != callback->ble_gap_event)
	{
		ble_msg_cb.ble_gap_event = callback->ble_gap_event;
	}

	if(NULL != callback->ble_gatt_event)
	{
		ble_msg_cb.ble_gatt_event = callback->ble_gatt_event;
	}

	return GL_SUCCESS;

}

int32_t ble_gap_evt_default_cb(gl_ble_gap_event_t event, gl_ble_gap_data_t *data)
{
	/*          do nothing            */
	log_debug("ble_gap_evt_default_cb\n");
	return 0;
}

int32_t ble_gatt_evt_default_cb(gl_ble_gatt_event_t event, gl_ble_gatt_data_t *data)
{
	/*          do nothing            */
	log_debug("ble_gatt_evt_default_cb\n");
	return 0;
}

int32_t ble_module_evt_default_cb(gl_ble_module_event_t event, gl_ble_module_data_t *data)
{
	/*          do nothing            */
	log_debug("ble_module_evt_default_cb\n");
	return 0;
}

GL_RET gl_ble_unsubscribe(void)
{
	ble_msg_cb.ble_gap_event = ble_gap_evt_default_cb;
	ble_msg_cb.ble_gatt_event = ble_gatt_evt_default_cb;
	ble_msg_cb.ble_module_event = ble_module_evt_default_cb;

	return GL_SUCCESS;
}

GL_RET gl_ble_enable(int32_t enable)
{
	return ble_enable(enable);
}

GL_RET gl_ble_get_mac(BLE_MAC mac)
{
	return ble_local_mac(mac);
}

GL_RET gl_ble_set_power(int power, int *current_power)
{
	return ble_set_power(power, current_power);
}

GL_RET gl_ble_adv_data(int flag, char *data)
{
	return ble_adv_data(flag, data);
}

GL_RET gl_ble_adv(int phys, int interval_min, int interval_max, int discover, int adv_conn)
{
	return ble_adv(phys, interval_min, interval_max, discover, adv_conn);
}

GL_RET gl_ble_stop_adv(void)
{
	return ble_stop_adv();
}

GL_RET gl_ble_send_notify(BLE_MAC address, int char_handle, char *value)
{
	return ble_send_notify(address, char_handle, value);
}

GL_RET gl_ble_discovery(int phys, int interval, int window, int type, int mode)
{
	return ble_discovery(phys, interval, window, type, mode);
}

GL_RET gl_ble_stop_discovery(void)
{
	return ble_stop_discovery();
}

GL_RET gl_ble_connect(BLE_MAC address, int address_type, int phy)
{
	return ble_connect(address, address_type, phy);
}

GL_RET gl_ble_disconnect(BLE_MAC address)
{
	return ble_disconnect(address);
}

GL_RET gl_ble_get_rssi(BLE_MAC address, int32_t *rssi)
{
	return ble_get_rssi(address, rssi);
}

GL_RET gl_ble_get_service(gl_ble_service_list_t *service_list, BLE_MAC address)
{
	return ble_get_service(service_list, address);
}

GL_RET gl_ble_get_char(gl_ble_char_list_t *char_list, BLE_MAC address, int service_handle)
{
	return ble_get_char(char_list, address, service_handle);
}

GL_RET gl_ble_read_char(BLE_MAC address, int char_handle)
{
	return ble_read_char(address, char_handle);
}

GL_RET gl_ble_write_char(BLE_MAC address, int char_handle, char *value, int res)
{
	return ble_write_char(address, char_handle, value, res);
}

GL_RET gl_ble_set_notify(BLE_MAC address, int char_handle, int flag)
{
	return ble_set_notify(address, char_handle, flag);
}

