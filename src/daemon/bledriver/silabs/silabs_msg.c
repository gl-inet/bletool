#include <stdio.h>
#include <string.h>
#include <libubox/uloop.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "silabs_msg.h"
#include "gl_common.h"
#include "bg_types.h"
#include "host_gecko.h"
#include "gl_uart.h"
#include "gl_thread.h"
#include "timestamp.h"
#include "gl_log.h"
#include "gl_dev_mgr.h"
#include "silabs_bleapi.h"


BGLIB_DEFINE();


struct gecko_cmd_packet* evt = NULL;

// save resp data evt
struct gecko_cmd_packet special_evt[SPE_EVT_MAX];
int special_evt_num = 0;


struct gecko_cmd_packet* gecko_get_event(int block);
struct gecko_cmd_packet* gecko_wait_event(void);
struct gecko_cmd_packet* gecko_wait_message(void); //wait for event from system

// bool appBooted = false; // App booted flag

// ubus value
extern struct ubus_object ble_obj;
extern struct ubus_context * ctx;


void silabs_event_handler(struct gecko_cmd_packet *p);
static void reverse_rev_payload(struct gecko_cmd_packet* pck);



void* silabs_run(void* arg)
{
    int fd = (int*)arg;

    while (1) {
        // Check for stack event.
		// if(0 == _thread_ctx_mutex_try_lock()) {
		evt = gecko_wait_event();
		// 	_thread_ctx_mutex_unlock();
		// }

        // Run application and event handler.
        silabs_event_handler(evt);

		usleep(100);
    }

}

/*
* wait for module events
*/
struct gecko_cmd_packet* gecko_wait_event(void)
{
	// block mode
    return gecko_get_event(1);
}

/*
* 
*/
struct gecko_cmd_packet* gecko_get_event(int block)
{
    struct gecko_cmd_packet* p;

    while (1) {
        if (gecko_queue_w != gecko_queue_r) {
            p = &gecko_queue[gecko_queue_r];
            gecko_queue_r = (gecko_queue_r + 1) % BGLIB_QUEUE_LEN;
            return p;
        }
        //if not blocking and nothing in uart -> out
        // if (!block) {
        //     return NULL;
        // }

        //read more messages from device
        if ((p = gecko_wait_message())) {
            return p;
        }
    }
}

struct gecko_cmd_packet* gecko_wait_message(void) //wait for event from system
{
    uint32_t msg_length;
    uint32_t header;
    uint8_t* payload;
    struct gecko_cmd_packet *pck, *retVal = NULL;
    int ret;
    //sync to header byte

	/* fix bug(2021.2.18): big endian recv bug*/
    // ret = uartRx(1, (uint8_t*)&header);
    // if (ret < 0 || (header & 0x78) != gecko_dev_type_gecko) {
    //     return 0;
    // }
    // ret = uartRx(BGLIB_MSG_HEADER_LEN - 1, &((uint8_t*)&header)[1]);
    // if (ret < 0) {
    //     return 0;
    // }

    ret = uartRx(BGLIB_MSG_HEADER_LEN, (uint8_t*)&header);
    if(ENDIAN){
        reverse_endian((uint8_t*)&header,BGLIB_MSG_HEADER_LEN);
    } 

	if (ret < 0 || (header & 0x78) != gecko_dev_type_gecko){
        return 0;
    }

    msg_length = BGLIB_MSG_LEN(header);

    if (msg_length > BGLIB_MSG_MAX_PAYLOAD) {
        return 0;
    }

    if ((header & 0xf8) == (gecko_dev_type_gecko | gecko_msg_type_evt)) {
        //received event
        if ((gecko_queue_w + 1) % BGLIB_QUEUE_LEN == gecko_queue_r) {
            //drop packet
            if (msg_length) {
                uint8 tmp_payload[BGLIB_MSG_MAX_PAYLOAD];
                uartRx(msg_length, tmp_payload);
            }
            return 0; //NO ROOM IN QUEUE
        }
        pck = &gecko_queue[gecko_queue_w];
        gecko_queue_w = (gecko_queue_w + 1) % BGLIB_QUEUE_LEN;
    } else if ((header & 0xf8) == gecko_dev_type_gecko ) { //response
        retVal = pck = gecko_rsp_msg;
    } else {
        //fail
        return 0;
    }
    pck->header = header;
    payload = (uint8_t*)&pck->data.payload;
    /**
   * Read the payload data if required and store it after the header.
   */
    if (msg_length) {
        ret = uartRx(msg_length, payload);
        if (ret < 0) {
			log_err("recv fail\n");
            return 0;
        }
    }

	if(ENDIAN)  
	{
		reverse_rev_payload(pck);
	}

    // Using retVal avoid double handling of event msg types in outer function
    return retVal;
}



int rx_peek_timeout(int ms)
{
    int timeout = ms;
    while (timeout) {
        timeout--;
        if (uartRxPeek() > 0) {
            return 0;
        }
        usleep(1000);
    }

    return -1;
}
void gecko_handle_command(uint32_t hdr, void* data)
{
	uint32_t send_msg_length = BGLIB_MSG_HEADER_LEN + BGLIB_MSG_LEN(gecko_cmd_msg->header);
	if(ENDIAN) 
	{
		reverse_endian((uint8_t*)&gecko_cmd_msg->header,BGLIB_MSG_HEADER_LEN);
	}

	// _thread_ctx_mutex_lock(); // get lock
	uartTx(send_msg_length, (uint8_t*)gecko_cmd_msg); // send cmd msg
	// _thread_ctx_mutex_unlock(); // release lock

	rx_peek_timeout(200); // wait for response
}















static struct blob_buf evt_b;
char* target_dev_address = NULL;
/*
 *	module events report 
 */
void silabs_event_handler(struct gecko_cmd_packet *p)
{
    json_object* o = NULL;
    char value[256] = {0};
    char addr[18] = {0};
	char* change_mac_addr = NULL;

	log_debug("Event handler: 0x%04x\n", BGLIB_MSG_ID(evt->header));

    // Do not handle any events until system is booted up properly.
    // if ((BGLIB_MSG_ID(evt->header) != gecko_evt_system_boot_id)
    //     && !appBooted) {
        // #if defined(DEBUG)
        // #endif
    //     usleep(50000);
    //     return;
    // }

    switch(BGLIB_MSG_ID(p->header)){
		case gecko_rsp_le_gap_connect_id:
		{
			// as master start to connect slave device
			if(target_dev_address == NULL)
			{
				log_err("As master start to connect device, but target device mac lost!");
				return ;
			}
			ble_dev_mgr_add(target_dev_address, p->data.rsp_le_gap_connect.connection);
			break;
		}
        case gecko_evt_system_boot_id:
		{
			// appBooted = true;
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(SYSTEM_BOOT));
			json_object_object_add(o,"major",json_object_new_int(p->data.evt_system_boot.major));
			json_object_object_add(o,"minor",json_object_new_int(p->data.evt_system_boot.minor));
			json_object_object_add(o,"patch",json_object_new_int(p->data.evt_system_boot.patch));
			json_object_object_add(o,"build",json_object_new_int(p->data.evt_system_boot.build));
			json_object_object_add(o,"bootloader",json_object_new_int(p->data.evt_system_boot.bootloader));
			json_object_object_add(o,"hw",json_object_new_int(p->data.evt_system_boot.hw));
			hex2str((uint8*)&p->data.evt_system_boot.hash,sizeof(uint32),value);
			json_object_object_add(o,"hash",json_object_new_string(value));
			break;
		}
        case gecko_evt_le_connection_closed_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(CONN_CLOSE));
			json_object_object_add(o,"reason",json_object_new_int(p->data.evt_le_connection_closed.reason));

			// get target device mac
			uint16_t ret = ble_dev_mgr_get_address(p->data.evt_le_connection_closed.connection, &change_mac_addr);
			if(ret != 0)
			{
				log_err("get dev mac from dev-list failed!\n");
				json_object_object_add(o,"code",json_object_new_int(ret));
				return -1;
			}
			json_object_object_add(o, "address", json_object_new_string(change_mac_addr));

			// delete from dev-list
			ble_dev_mgr_del(p->data.evt_le_connection_closed.connection);
			break;
		}
        case gecko_evt_gatt_characteristic_value_id:
		{
			if(p->data.evt_gatt_characteristic_value.att_opcode == gatt_handle_value_notification){
				o = json_object_new_object();
				json_object_object_add(o,"type",json_object_new_string(REMOTE_NOTIFY));
				json_object_object_add(o,"characteristic",json_object_new_int(p->data.evt_gatt_characteristic_value.characteristic));
				json_object_object_add(o,"att_opcode",json_object_new_int(p->data.evt_gatt_characteristic_value.att_opcode));
				json_object_object_add(o,"offset",json_object_new_int(p->data.evt_gatt_characteristic_value.offset));
				hex2str(p->data.evt_gatt_characteristic_value.value.data,p->data.evt_gatt_characteristic_value.value.len,value);
				json_object_object_add(o,"value",json_object_new_string(value));

				// get target device mac
				uint16_t ret = ble_dev_mgr_get_address(p->data.evt_gatt_characteristic_value.connection, &change_mac_addr);
				if(ret != 0)
				{
					log_err("get dev mac from dev-list failed!\n");
					json_object_object_add(o,"code",json_object_new_int(ret));
					return -1;
				}
				json_object_object_add(o, "address", json_object_new_string(change_mac_addr));
			}
			break;
		}
        case gecko_evt_gatt_server_attribute_value_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(REMOTE_WRITE));
			json_object_object_add(o,"attribute",json_object_new_int(p->data.evt_gatt_server_attribute_value.attribute));
			json_object_object_add(o,"att_opcode",json_object_new_int(p->data.evt_gatt_server_attribute_value.att_opcode));
			json_object_object_add(o,"offset",json_object_new_int(p->data.evt_gatt_server_attribute_value.offset));
			hex2str(p->data.evt_gatt_server_attribute_value.value.data,p->data.evt_gatt_server_attribute_value.value.len,value);
			json_object_object_add(o,"value",json_object_new_string(value));

			// get target device mac
			uint16_t ret = ble_dev_mgr_get_address(p->data.evt_gatt_server_attribute_value.connection, &change_mac_addr);
			if(ret != 0)
			{
				log_err("get dev mac from dev-list failed!\n");
				json_object_object_add(o,"code",json_object_new_int(ret));
				return -1;
			}
			json_object_object_add(o, "address", json_object_new_string(change_mac_addr));
			break;
		}
        case gecko_evt_gatt_server_characteristic_status_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(REMOTE_SET));
			json_object_object_add(o,"characteristic",json_object_new_int(p->data.evt_gatt_server_characteristic_status.characteristic));
			json_object_object_add(o,"status_flags",json_object_new_int(p->data.evt_gatt_server_characteristic_status.status_flags));
			json_object_object_add(o,"client_config_flags",json_object_new_int(p->data.evt_gatt_server_characteristic_status.client_config_flags));
			
			// get target device mac
			uint16_t ret = ble_dev_mgr_get_address(p->data.evt_gatt_server_characteristic_status.connection, &change_mac_addr);
			if(ret != 0)
			{
				log_err("get dev mac from dev-list failed!\n");
				json_object_object_add(o,"code",json_object_new_int(ret));
				return -1;
			}
			json_object_object_add(o, "address", json_object_new_string(change_mac_addr));
			break;
		}
        case gecko_evt_le_gap_scan_response_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(ADV_PKG));
			json_object_object_add(o,"rssi",json_object_new_int(p->data.evt_le_gap_scan_response.rssi));
			json_object_object_add(o,"packet_type",json_object_new_int(p->data.evt_le_gap_scan_response.packet_type));
			addr2str(p->data.evt_le_gap_scan_response.address.addr,addr);
			json_object_object_add(o,"address",json_object_new_string(addr));
			json_object_object_add(o,"address_type",json_object_new_int(p->data.evt_le_gap_scan_response.address_type));
			json_object_object_add(o,"bonding",json_object_new_int(p->data.evt_le_gap_scan_response.bonding));
			hex2str(p->data.evt_le_gap_scan_response.data.data, p->data.evt_le_gap_scan_response.data.len,value);
			json_object_object_add(o,"data",json_object_new_string(value));
			break;
		}
        case gecko_evt_le_connection_parameters_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(CONN_UPDATE));
			json_object_object_add(o,"interval",json_object_new_int(p->data.evt_le_connection_parameters.interval));
			json_object_object_add(o,"latency",json_object_new_int(p->data.evt_le_connection_parameters.latency));
			json_object_object_add(o,"timeout",json_object_new_int(p->data.evt_le_connection_parameters.timeout));
			json_object_object_add(o,"security_mode",json_object_new_int(p->data.evt_le_connection_parameters.security_mode));
			json_object_object_add(o,"txsize",json_object_new_int(p->data.evt_le_connection_parameters.txsize));

			// get target device mac
			uint16_t ret = ble_dev_mgr_get_address(p->data.evt_le_connection_parameters.connection, &change_mac_addr);
			if(ret != 0)
			{
				log_err("get dev mac from dev-list failed!\n");
				json_object_object_add(o,"code",json_object_new_int(ret));
				return -1;
			}
			json_object_object_add(o, "address", json_object_new_string(change_mac_addr));
			break;
		}
        case gecko_evt_le_connection_opened_id:
		{
			o = json_object_new_object();
			json_object_object_add(o,"type",json_object_new_string(CONN_OPEN));
			addr2str(p->data.evt_le_connection_opened.address.addr,addr);
			json_object_object_add(o,"address",json_object_new_string(addr));
			json_object_object_add(o,"address_type",json_object_new_int(p->data.evt_le_connection_opened.address_type));
			json_object_object_add(o,"master",json_object_new_int(p->data.evt_le_connection_opened.master));
			json_object_object_add(o,"bonding",json_object_new_int(p->data.evt_le_connection_opened.bonding));
			json_object_object_add(o,"advertiser",json_object_new_int(p->data.evt_le_connection_opened.advertiser));

			ble_dev_mgr_add(addr, p->data.evt_le_connection_opened.connection);
			break;
		}
		case gecko_evt_gatt_service_id:
		case gecko_evt_gatt_characteristic_id:
		{
			special_evt[special_evt_num].header = p->header;
			memcpy(&special_evt[special_evt_num].data.payload, p->data.payload, BGLIB_MSG_MAX_PAYLOAD);
			special_evt_num++;
			break;
		}
        default:
            break;
    }

	if(!o)
	{
		return ;
	}
	// else{
	// 	printf("object %s\n",json_object_to_json_string(o));
	// }

	blob_buf_init(&evt_b, 0);
	blobmsg_add_object(&evt_b, o);
	ubus_notify(ctx, &ble_obj, "Notify", evt_b.head, -1);

	json_object_put(o);
    return ;
}

int wait_rsp_evt(uint32_t evt_id, uint32_t timeout)
{
    uint32_t current_time_us = 0, start_time_us = 0;
    uint32_t spend = 0;

	uint32_t timeout_us = timeout * 1000;

    start_time_us = utils_get_timestamp();

    while (timeout_us > spend) {
		if (evt_id == BGLIB_MSG_ID(evt->header)) {
			return 0;
		}
		
        current_time_us = utils_get_timestamp();
        spend = current_time_us - start_time_us;
    }

    return -1;
}




















static void reverse_rev_payload(struct gecko_cmd_packet* pck)
{
  uint32 p = BGLIB_MSG_ID(pck->header);
//   log_debug("p: %04x %04x\n", p, BGLIB_MSG_ID(pck->header));

  switch (p){
      case gecko_rsp_dfu_flash_set_address_id:
          reverse_endian((uint8*)&(pck->data.rsp_dfu_flash_set_address.result),2);
          break;
      case gecko_rsp_dfu_flash_upload_id:
          reverse_endian((uint8*)&(pck->data.rsp_dfu_flash_upload.result),2);
          break;
      case gecko_rsp_dfu_flash_upload_finish_id:
          reverse_endian((uint8*)&(pck->data.rsp_dfu_flash_upload_finish.result),2);
          break;
      case gecko_rsp_system_hello_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_hello.result),2);
          break;
      case gecko_rsp_system_set_bt_address_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_set_bt_address.result),2);
          break;
      case gecko_rsp_system_get_random_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_get_random_data.result),2);
          break;
      case gecko_rsp_system_halt_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_halt.result),2);
          break;
      case gecko_rsp_system_set_device_name_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_set_device_name.result),2);
          break;
      case gecko_rsp_system_linklayer_configure_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_linklayer_configure.result),2);
          break;
      case gecko_rsp_system_get_counters_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_get_counters.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_system_get_counters.tx_packets),2);
          reverse_endian((uint8*)&(pck->data.rsp_system_get_counters.rx_packets),2);
          reverse_endian((uint8*)&(pck->data.rsp_system_get_counters.crc_errors),2);
          reverse_endian((uint8*)&(pck->data.rsp_system_get_counters.failures),2);
          break;
      case gecko_rsp_le_gap_open_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_open.result),2);
          break;
      case gecko_rsp_le_gap_set_mode_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_mode.result),2);
          break;
      case gecko_rsp_le_gap_discover_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_discover.result),2);
          break;
      case gecko_rsp_le_gap_end_procedure_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_end_procedure.result),2);
          break;
      case gecko_rsp_le_gap_set_adv_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_adv_parameters.result),2);
          break;
      case gecko_rsp_le_gap_set_conn_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_conn_parameters.result),2);
          break;
      case gecko_rsp_le_gap_set_scan_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_scan_parameters.result),2);
          break;
      case gecko_rsp_le_gap_set_adv_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_adv_data.result),2);
          break;
      case gecko_rsp_le_gap_set_adv_timeout_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_adv_timeout.result),2);
          break;
      case gecko_rsp_le_gap_bt5_set_mode_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_bt5_set_mode.result),2);
          break;
      case gecko_rsp_le_gap_bt5_set_adv_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_bt5_set_adv_parameters.result),2);
          break;
      case gecko_rsp_le_gap_bt5_set_adv_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_bt5_set_adv_data.result),2);
          break;
      case gecko_rsp_le_gap_set_privacy_mode_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_privacy_mode.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_timing_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_timing.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_channel_map_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_channel_map.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_report_scan_request_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_report_scan_request.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_phy_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_phy.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_configuration_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_configuration.result),2);
          break;
      case gecko_rsp_le_gap_clear_advertise_configuration_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_clear_advertise_configuration.result),2);
          break;
      case gecko_rsp_le_gap_start_advertising_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_start_advertising.result),2);
          break;
      case gecko_rsp_le_gap_stop_advertising_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_stop_advertising.result),2);
          break;
      case gecko_rsp_le_gap_set_discovery_timing_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_discovery_timing.result),2);
          break;
      case gecko_rsp_le_gap_set_discovery_type_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_discovery_type.result),2);
          break;
      case gecko_rsp_le_gap_start_discovery_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_start_discovery.result),2);
          break;
      case gecko_rsp_le_gap_set_data_channel_classification_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_data_channel_classification.result),2);
          break;
      case gecko_rsp_le_gap_connect_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_connect.result),2);
          break;
      case gecko_rsp_le_gap_set_advertise_tx_power_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_tx_power.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_advertise_tx_power.set_power),2);
          break;
      case gecko_rsp_le_gap_set_discovery_extended_scan_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_set_discovery_extended_scan_response.result),2);
          break;
      case gecko_rsp_le_gap_start_periodic_advertising_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_start_periodic_advertising.result),2);
          break;
      case gecko_rsp_le_gap_stop_periodic_advertising_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_stop_periodic_advertising.result),2);
          break;
      case gecko_rsp_le_gap_enable_whitelisting_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_gap_enable_whitelisting.result),2);
          break;
      case gecko_rsp_sync_open_id:
          reverse_endian((uint8*)&(pck->data.rsp_sync_open.result),2);
          break;
      case gecko_rsp_sync_close_id:
          reverse_endian((uint8*)&(pck->data.rsp_sync_close.result),2);
          break;
      case gecko_rsp_le_connection_set_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_connection_set_parameters.result),2);
          break;
      case gecko_rsp_le_connection_get_rssi_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_connection_get_rssi.result),2);
          break;
      case gecko_rsp_le_connection_disable_slave_latency_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_connection_disable_slave_latency.result),2);
          break;
      case gecko_rsp_le_connection_set_phy_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_connection_set_phy.result),2);
          break;
      case gecko_rsp_le_connection_close_id:
          reverse_endian((uint8*)&(pck->data.rsp_le_connection_close.result),2);
          break;
      case gecko_rsp_gatt_set_max_mtu_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_set_max_mtu.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_set_max_mtu.max_mtu),2);
          break;
      case gecko_rsp_gatt_discover_primary_services_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_discover_primary_services.result),2);
          break;
      case gecko_rsp_gatt_discover_characteristics_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_discover_characteristics.result),2);
          break;
      case gecko_rsp_gatt_set_characteristic_notification_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_set_characteristic_notification.result),2);
          break;
      case gecko_rsp_gatt_discover_descriptors_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_discover_descriptors.result),2);
          break;
      case gecko_rsp_gatt_discover_primary_services_by_uuid_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_discover_primary_services_by_uuid.result),2);
          break; 
      case gecko_rsp_gatt_read_characteristic_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_read_characteristic_value.result),2);
          break;
      case gecko_rsp_gatt_write_characteristic_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_write_characteristic_value.result),2);
          break;
      case gecko_rsp_gatt_write_characteristic_value_without_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_write_characteristic_value_without_response.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_write_characteristic_value_without_response.sent_len),2);
          break;
      case gecko_rsp_gatt_prepare_characteristic_value_write_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_prepare_characteristic_value_write.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_prepare_characteristic_value_write.sent_len),2);
          break;
      case gecko_rsp_gatt_execute_characteristic_value_write_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_execute_characteristic_value_write.result),2);
          break;
      case gecko_rsp_gatt_send_characteristic_confirmation_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_send_characteristic_confirmation.result),2);
          break;
      case gecko_rsp_gatt_read_descriptor_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_read_descriptor_value.result),2);
          break;
      case gecko_rsp_gatt_write_descriptor_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_write_descriptor_value.result),2);
          break;
      case gecko_rsp_gatt_find_included_services_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_find_included_services.result),2);
          break;
      case gecko_rsp_gatt_read_multiple_characteristic_values_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_read_multiple_characteristic_values.result),2);
          break;
      case gecko_rsp_gatt_read_characteristic_value_from_offset_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_read_characteristic_value_from_offset.result),2);
          break;
      case gecko_rsp_gatt_prepare_characteristic_value_reliable_write_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_prepare_characteristic_value_reliable_write.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_prepare_characteristic_value_reliable_write.sent_len),2);
          break;
      case gecko_rsp_gatt_server_read_attribute_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_read_attribute_value.result),2);
          break;
      case gecko_rsp_gatt_server_read_attribute_type_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_read_attribute_type.result),2);
          break;
      case gecko_rsp_gatt_server_write_attribute_value_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_write_attribute_value.result),2);
          break;
      case gecko_rsp_gatt_server_send_user_read_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_send_user_read_response.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_send_user_read_response.sent_len),2);
          break;
      case gecko_rsp_gatt_server_send_user_write_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_send_user_write_response.result),2);
          break;
      case gecko_rsp_gatt_server_send_characteristic_notification_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_send_characteristic_notification.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_send_characteristic_notification.sent_len),2);
          break;
      case gecko_rsp_gatt_server_find_attribute_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_find_attribute.result),2);
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_find_attribute.attribute),2);
          break;
      case gecko_rsp_gatt_server_set_capabilities_id:
          reverse_endian((uint8*)&(pck->data.rsp_gatt_server_set_capabilities.result),2);
          break;
      case gecko_rsp_hardware_set_soft_timer_id:
          reverse_endian((uint8*)&(pck->data.rsp_hardware_set_soft_timer.result),2);
          break;
      case gecko_rsp_hardware_get_time_id:
          reverse_endian((uint8*)&(pck->data.rsp_hardware_get_time.seconds),4);
          reverse_endian((uint8*)&(pck->data.rsp_hardware_get_time.ticks),2);
          break;
      case gecko_rsp_hardware_set_lazy_soft_timer_id:
          reverse_endian((uint8*)&(pck->data.rsp_hardware_set_lazy_soft_timer.result),2);
          break;
      case gecko_rsp_flash_ps_erase_all_id:
          reverse_endian((uint8*)&(pck->data.rsp_flash_ps_erase_all.result),2);
          break;
      case gecko_rsp_flash_ps_save_id:
          reverse_endian((uint8*)&(pck->data.rsp_flash_ps_save.result),2);
          break;
      case gecko_rsp_flash_ps_load_id:
          reverse_endian((uint8*)&(pck->data.rsp_flash_ps_load.result),2);
          break;
      case gecko_rsp_flash_ps_erase_id:
          reverse_endian((uint8*)&(pck->data.rsp_flash_ps_erase.result),2);
          break;
      case gecko_rsp_test_dtm_tx_id:
          reverse_endian((uint8*)&(pck->data.rsp_test_dtm_tx.result),2);
          break;
      case gecko_rsp_test_dtm_rx_id:
          reverse_endian((uint8*)&(pck->data.rsp_test_dtm_rx.result),2);
          break;
      case gecko_rsp_test_dtm_end_id:
          reverse_endian((uint8*)&(pck->data.rsp_test_dtm_end.result),2);
          break;
      case gecko_rsp_sm_set_bondable_mode_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_set_bondable_mode.result),2);
          break;
      case gecko_rsp_sm_configure_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_configure.result),2);
          break;
      case gecko_rsp_sm_store_bonding_configuration_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_store_bonding_configuration.result),2);
          break;
      case gecko_rsp_sm_increase_security_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_increase_security.result),2);
          break;
      case gecko_rsp_sm_delete_bonding_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_delete_bonding.result),2);
          break;
      case gecko_rsp_sm_delete_bondings_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_delete_bondings.result),2);
          break;
      case gecko_rsp_sm_enter_passkey_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_enter_passkey.result),2);
          break;
      case gecko_rsp_sm_passkey_confirm_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_passkey_confirm.result),2);
          break;
      case gecko_rsp_sm_set_oob_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_set_oob_data.result),2);
          break;
      case gecko_rsp_sm_list_all_bondings_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_list_all_bondings.result),2);
          break;
      case gecko_rsp_sm_bonding_confirm_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_bonding_confirm.result),2);
          break;
      case gecko_rsp_sm_set_debug_mode_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_set_debug_mode.result),2);
          break;
      case gecko_rsp_sm_set_passkey_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_set_passkey.result),2);
          break;
      case gecko_rsp_sm_use_sc_oob_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_use_sc_oob.result),2);
          break;
      case gecko_rsp_sm_set_sc_remote_oob_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_set_sc_remote_oob_data.result),2);
          break;
      case gecko_rsp_sm_add_to_whitelist_id:
          reverse_endian((uint8*)&(pck->data.rsp_sm_add_to_whitelist.result),2);
          break;
      case gecko_rsp_homekit_configure_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_configure.result),2);
          break;
      case gecko_rsp_homekit_advertise_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_advertise.result),2);
          break;
      case gecko_rsp_homekit_delete_pairings_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_delete_pairings.result),2);
          break;
      case gecko_rsp_homekit_check_authcp_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_check_authcp.result),2);
          break;
      case gecko_rsp_homekit_send_write_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_send_write_response.result),2);
          break;
      case gecko_rsp_homekit_send_read_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_send_read_response.result),2);
          break;
      case gecko_rsp_homekit_gsn_action_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_gsn_action.result),2);
          break;
      case gecko_rsp_homekit_event_notification_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_event_notification.result),2);
          break;
      case gecko_rsp_homekit_broadcast_action_id:
          reverse_endian((uint8*)&(pck->data.rsp_homekit_broadcast_action.result),2);
          break;
      case gecko_rsp_coex_set_options_id:
          reverse_endian((uint8*)&(pck->data.rsp_coex_set_options.result),2);
          break;
      case gecko_rsp_coex_get_counters_id:
          reverse_endian((uint8*)&(pck->data.rsp_coex_get_counters.result),2);
          break;
      case gecko_rsp_l2cap_coc_send_connection_request_id:
          reverse_endian((uint8*)&(pck->data.rsp_l2cap_coc_send_connection_request.result),2);
          break;
      case gecko_rsp_l2cap_coc_send_connection_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_l2cap_coc_send_connection_response.result),2);
          break;
      case gecko_rsp_l2cap_coc_send_le_flow_control_credit_id:
          reverse_endian((uint8*)&(pck->data.rsp_l2cap_coc_send_le_flow_control_credit.result),2);
          break;
      case gecko_rsp_l2cap_coc_send_disconnection_request_id:
          reverse_endian((uint8*)&(pck->data.rsp_l2cap_coc_send_disconnection_request.result),2);
          break;
      case gecko_rsp_l2cap_coc_send_data_id:
          reverse_endian((uint8*)&(pck->data.rsp_l2cap_coc_send_data.result),2);
          break;
      case gecko_rsp_cte_transmitter_enable_cte_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_enable_cte_response.result),2);
          break;
      case gecko_rsp_cte_transmitter_disable_cte_response_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_disable_cte_response.result),2);
          break;
      case gecko_rsp_cte_transmitter_start_connectionless_cte_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_start_connectionless_cte.result),2);
          break;
      case gecko_rsp_cte_transmitter_stop_connectionless_cte_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_stop_connectionless_cte.result),2);
          break;
      case gecko_rsp_cte_transmitter_set_dtm_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_set_dtm_parameters.result),2);
          break;
      case gecko_rsp_cte_transmitter_clear_dtm_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_transmitter_clear_dtm_parameters.result),2);
          break;
      case gecko_rsp_cte_receiver_configure_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_configure.result),2);
          break;
      case gecko_rsp_cte_receiver_start_iq_sampling_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_start_iq_sampling.result),2);
          break;
      case gecko_rsp_cte_receiver_stop_iq_sampling_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_stop_iq_sampling.result),2);
          break;
      case gecko_rsp_cte_receiver_start_connectionless_iq_sampling_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_start_connectionless_iq_sampling.result),2);
          break;
      case gecko_rsp_cte_receiver_stop_connectionless_iq_sampling_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_stop_connectionless_iq_sampling.result),2);
          break;
      case gecko_rsp_cte_receiver_set_dtm_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_set_dtm_parameters.result),2);
          break;
      case gecko_rsp_cte_receiver_clear_dtm_parameters_id:
          reverse_endian((uint8*)&(pck->data.rsp_cte_receiver_clear_dtm_parameters.result),2);
          break;
      case gecko_rsp_user_message_to_target_id:
          reverse_endian((uint8*)&(pck->data.rsp_user_message_to_target.result),2);
          break;
      case gecko_rsp_system_set_tx_power_id:
          reverse_endian((uint8*)&(pck->data.rsp_system_set_tx_power.set_power),2);
          break;
      case gecko_evt_dfu_boot_id:
          reverse_endian((uint8*)&(pck->data.evt_dfu_boot.version),4);
          break;
      case gecko_evt_dfu_boot_failure_id:
          reverse_endian((uint8*)&(pck->data.evt_dfu_boot_failure.reason),2);
          break;
      case gecko_evt_system_boot_id:
          reverse_endian((uint8*)&(pck->data.evt_system_boot.major),2);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.minor),2);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.patch),2);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.build),2);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.bootloader),4);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.hw),2);
          reverse_endian((uint8*)&(pck->data.evt_system_boot.hash),4);
          break;
      case gecko_evt_system_external_signal_id:
          reverse_endian((uint8*)&(pck->data.evt_system_external_signal.extsignals),4);
          break;
      case gecko_evt_system_hardware_error_id:
          reverse_endian((uint8*)&(pck->data.evt_system_hardware_error.status),2);
          break;
      case gecko_evt_system_error_id:
          reverse_endian((uint8*)&(pck->data.evt_system_error.reason),2);
          break;
      case gecko_evt_le_gap_extended_scan_response_id:
          reverse_endian((uint8*)&(pck->data.evt_le_gap_extended_scan_response.periodic_interval),2);
          break;
      case gecko_evt_sync_opened_id:
          reverse_endian((uint8*)&(pck->data.evt_sync_opened.adv_interval),2);
          reverse_endian((uint8*)&(pck->data.evt_sync_opened.clock_accuracy),2);
          break;
      case gecko_evt_sync_closed_id:
          reverse_endian((uint8*)&(pck->data.evt_sync_closed.reason),2);
          break;
      case gecko_evt_le_connection_closed_id:
          reverse_endian((uint8*)&(pck->data.evt_le_connection_closed.reason),2);
          break;
      case gecko_evt_le_connection_parameters_id:
          reverse_endian((uint8*)&(pck->data.evt_le_connection_parameters.interval),2);
          reverse_endian((uint8*)&(pck->data.evt_le_connection_parameters.latency),2);
          reverse_endian((uint8*)&(pck->data.evt_le_connection_parameters.timeout),2);
          reverse_endian((uint8*)&(pck->data.evt_le_connection_parameters.txsize),2);
          break;
      case gecko_evt_gatt_mtu_exchanged_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_mtu_exchanged.mtu),2);
          break;
      case gecko_evt_gatt_service_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_service.service),4);
          break;
      case gecko_evt_gatt_characteristic_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_characteristic.characteristic),2);
          break;
      case gecko_evt_gatt_descriptor_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_descriptor.descriptor),2);
          break;
      case gecko_evt_gatt_characteristic_value_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_characteristic_value.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_characteristic_value.offset),2);
          break;
      case gecko_evt_gatt_descriptor_value_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_descriptor_value.descriptor),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_descriptor_value.offset),2);
          break;
      case gecko_evt_gatt_procedure_completed_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_procedure_completed.result),2);
          break;
      case gecko_evt_gatt_server_attribute_value_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_attribute_value.attribute),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_attribute_value.offset),2);
          break;
      case gecko_evt_gatt_server_user_read_request_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_user_read_request.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_user_read_request.offset),2);
          break;
      case gecko_evt_gatt_server_user_write_request_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_user_write_request.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_user_write_request.offset),2);
          break;
      case gecko_evt_gatt_server_characteristic_status_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_characteristic_status.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_characteristic_status.client_config_flags),2);
          break;
      case gecko_evt_gatt_server_execute_write_completed_id:
          reverse_endian((uint8*)&(pck->data.evt_gatt_server_execute_write_completed.result),2);
          break;
      case gecko_evt_test_dtm_completed_id:
          reverse_endian((uint8*)&(pck->data.evt_test_dtm_completed.result),2);
          reverse_endian((uint8*)&(pck->data.evt_test_dtm_completed.number_of_packets),2);
          break;
      case gecko_evt_sm_passkey_display_id:
          reverse_endian((uint8*)&(pck->data.evt_sm_passkey_display.passkey),4);
          break;
      case gecko_evt_sm_confirm_passkey_id:
          reverse_endian((uint8*)&(pck->data.evt_sm_confirm_passkey.passkey),4);
          break;
      case gecko_evt_sm_bonding_failed_id:
          reverse_endian((uint8*)&(pck->data.evt_sm_bonding_failed.reason),2);
          break;
      case gecko_evt_homekit_paired_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_paired.reason),2);
          break;
      case gecko_evt_homekit_pair_verified_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_pair_verified.reason),2);
          break;
      case gecko_evt_homekit_connection_closed_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_connection_closed.reason),2);
          break;
      case gecko_evt_homekit_write_request_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_write_request.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_homekit_write_request.chr_value_size),2);
          reverse_endian((uint8*)&(pck->data.evt_homekit_write_request.authorization_size),2);
          reverse_endian((uint8*)&(pck->data.evt_homekit_write_request.value_offset),2);
          break;
      case gecko_evt_homekit_read_request_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_read_request.characteristic),2);
          reverse_endian((uint8*)&(pck->data.evt_homekit_read_request.offset),2);
          break;
      case gecko_evt_homekit_disconnection_required_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_disconnection_required.reason),2);
          break;
      case gecko_evt_homekit_pairing_removed_id:
          reverse_endian((uint8*)&(pck->data.evt_homekit_pairing_removed.remaining_pairings),2);
          break;
      case gecko_evt_l2cap_coc_connection_request_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_request.le_psm),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_request.source_cid),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_request.mtu),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_request.mps),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_request.initial_credit),2);
          break;
      case gecko_evt_l2cap_coc_connection_response_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_response.destination_cid),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_response.mtu),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_response.mps),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_response.initial_credit),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_connection_response.result),2);
          break;
      case gecko_evt_l2cap_coc_le_flow_control_credit_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_le_flow_control_credit.cid),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_le_flow_control_credit.credits),2);
          break;
      case gecko_evt_l2cap_coc_channel_disconnected_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_channel_disconnected.cid),2);
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_channel_disconnected.reason),2);
          break;
      case gecko_evt_l2cap_coc_data_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_coc_data.cid),2);
          break;
      case gecko_evt_l2cap_command_rejected_id:
          reverse_endian((uint8*)&(pck->data.evt_l2cap_command_rejected.reason),2);
          break;
      case gecko_evt_cte_receiver_iq_report_id:
          reverse_endian((uint8*)&(pck->data.evt_cte_receiver_iq_report.status),2);
          reverse_endian((uint8*)&(pck->data.evt_cte_receiver_iq_report.rssi),2);
          break;
  }
}

