/*****************************************************************************
 * @file 
 * @brief Bluetooth driver for silabs EFR32
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
#include <string.h>
#include "silabs_bleapi.h"
#include "host_gecko.h"
#include "gl_uart.h"
#include "gl_hal.h"
#include "bg_types.h"
#include "gl_errno.h"
#include "gl_common.h"
#include "silabs_msg.h"
#include "gl_dev_mgr.h"

extern struct gecko_cmd_packet* evt;


json_object* silabs_ble_enable(int enable)
{
    json_object* obj = json_object_new_object();
    if(enable)
    {
        system(rston);
    }
    else{
        system(rstoff);
    }
    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}

json_object* silabs_ble_local_mac(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_system_get_bt_address();
	p = gecko_rsp_msg;

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }

    char addr[18];
    addr2str(p->data.rsp_system_get_bt_address.address.addr,addr);
    json_object_object_add(obj,"mac",json_object_new_string(addr)); 
    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}

json_object* silabs_ble_discovery(int phys,int interval,int window,int type,int mode)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_set_discovery_timing(phys,interval,window);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
    }
    if(p->data.rsp_le_gap_set_discovery_timing.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_discovery_timing.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    gecko_cmd_le_gap_set_discovery_type(phys,type);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
    }
    if(p->data.rsp_le_gap_set_discovery_type.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_discovery_type.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    gecko_cmd_le_gap_start_discovery(phys,mode);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
    }
    if(p->data.rsp_le_gap_start_discovery.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_start_discovery.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}

json_object* silabs_ble_stop_discovery(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_end_procedure();
    p = gecko_rsp_msg;

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
	
	if(p->data.rsp_le_gap_end_procedure.result != 0)
	{
    	json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_end_procedure.result + MANUFACTURER_ERR_BASE));
	}else{
    	json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
	}

    return obj;
}
json_object* silabs_ble_adv(int adv_phys,int adv_interval_min,int adv_interval_max,int adv_discover,int adv_conn)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_set_advertise_phy(0, adv_phys, adv_phys);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_set_advertise_phy.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_advertise_phy.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }


    gecko_cmd_le_gap_set_advertise_timing(0, adv_interval_min, adv_interval_max, 0, 0);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_set_advertise_timing.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_advertise_timing.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    gecko_cmd_le_gap_start_advertising(0, adv_discover, adv_conn);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_start_advertising.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_start_advertising.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));

    return obj;

}

json_object* silabs_ble_adv_data(int adv_data_flag,char* adv_data)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    if(!adv_data)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_PARAM));
        return obj;
    }
    int len = strlen(adv_data)/2;
    uint8* data = (uint8*)calloc(len,sizeof(uint8));
    str2array(data,adv_data,len);

    gecko_cmd_le_gap_bt5_set_adv_data(0, adv_data_flag, len, data);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_bt5_set_adv_data.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_bt5_set_adv_data.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}

json_object* silabs_ble_stop_adv(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_stop_advertising(0);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_stop_advertising.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_stop_advertising.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}

json_object* silabs_ble_send_notify(int send_noti_conn,int send_noti_char,char* send_noti_value)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();
    
    if(!send_noti_value)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_PARAM));
        return obj;
    }

    int len = strlen(send_noti_value)/2;
    uint8* value = (uint8*)calloc(len,sizeof(uint8));
    str2array(value,send_noti_value,len);

    gecko_cmd_gatt_server_send_characteristic_notification(send_noti_conn, send_noti_char, len, value);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_server_send_characteristic_notification.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_server_send_characteristic_notification.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"sent_len",json_object_new_int(p->data.rsp_gatt_server_send_characteristic_notification.sent_len));
    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    return obj;
}


json_object* silabs_ble_connect(char* address,int address_type,int conn_phy)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    if(!address)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_PARAM));
        return obj;
    }

    bd_addr addr;
    str2addr(address,addr.addr);
    gecko_cmd_le_gap_connect(addr, address_type, conn_phy);
    p = gecko_rsp_msg;

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;       
    }   
    if(p->data.rsp_le_gap_connect.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_connect.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }
    int connection = p->data.rsp_le_gap_connect.connection;
	// printf("connection : %d\n", connection);
	
	uint32_t evt_id = gecko_evt_le_connection_opened_id;
	if(wait_rsp_evt(evt_id, 4000) == 0) {
		if(evt->data.evt_le_connection_opened.connection == connection && evt->data.evt_le_connection_opened.master == 1)
		{
			// printf("~~~~~~~~~~~~~\n");
    		json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
			char str[18] = {0};
			addr2str(evt->data.evt_le_connection_opened.address.addr,str);
			// printf("str: %s\n", str);
			json_object_object_add(obj,"address",json_object_new_string(str));
    		json_object_object_add(obj,"connection",json_object_new_int(connection));

			// add_device_to_list(obj);
			return obj;
		}
	}

	// connect timeout , disconnect 
	gecko_cmd_le_connection_close(connection);
	json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
    return obj;
}

json_object* silabs_ble_disconnect(int connection)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_le_connection_close(connection);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }

	if(p->data.rsp_le_connection_close.result != 0)
	{
    	json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_connection_close.result + MANUFACTURER_ERR_BASE));
	}else{
        json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
	}

    return obj;
}

json_object* silabs_ble_get_rssi(int connection)
{
    struct gecko_cmd_packet* p = NULL;
	int result = -1;
    json_object* obj = json_object_new_object(); 
 
    gecko_cmd_le_connection_get_rssi(connection);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_le_connection_get_rssi.result)
    {
		result = p->data.rsp_le_connection_get_rssi.result;
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_connection_get_rssi.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

	uint32_t evt_id = gecko_evt_le_connection_rssi_id;
	if(wait_rsp_evt(evt_id, 300) == 0) {
        json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
		json_object_object_add(obj,"rssi",json_object_new_int(evt->data.evt_le_connection_rssi.rssi));
	}else{
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
	}

    return obj;
}

json_object* silabs_ble_get_service(int connection)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    int wait_time = 200; // >10
    gecko_cmd_gatt_discover_primary_services(connection);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_discover_primary_services.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_discover_primary_services.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    json_object_object_add(obj,"connection",json_object_new_int(connection));
    char value[256] = {0};
    json_object* array = json_object_new_array();
    json_object_object_add(obj,"service_list",array);
    json_object *l, *o;

	int i = 0;

	uint32_t evt_id = gecko_evt_gatt_procedure_completed_id;
	if(wait_rsp_evt(evt_id, 300) == 0)
	{
		while(i < special_evt_num)
		{
			struct gecko_cmd_packet* e = &special_evt[i];
			if(BGLIB_MSG_ID(e->header) == gecko_evt_gatt_service_id && e->data.evt_gatt_service.connection == connection)
			{
				o = json_object_new_object();
				l = json_object_object_get(obj,"service_list");
				json_object_object_add(o,"service_handle",json_object_new_int(e->data.evt_gatt_service.service));
				memset(value,0,256);
				reverse_endian(e->data.evt_gatt_service.uuid.data, e->data.evt_gatt_service.uuid.len);
				hex2str(e->data.evt_gatt_service.uuid.data, e->data.evt_gatt_service.uuid.len,value);
				json_object_object_add(o,"service_uuid",json_object_new_string(value));
				json_object_array_add(l,o);
			}

			i++;
		}
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
		return obj;
	}

	if(BGLIB_MSG_ID(evt->header) == gecko_evt_gatt_procedure_completed_id)
	{
		special_evt_num = 0;
		return obj;
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
		return obj;
	}

}


json_object* silabs_ble_get_char(int connection,int service_handle)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    char value[256] = {0};
    json_object* array = json_object_new_array();
    json_object_object_add(obj,"characteristic_list",array);
    json_object *l, *o;

    gecko_cmd_gatt_discover_characteristics(connection, service_handle);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_discover_characteristics.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_discover_characteristics.result + MANUFACTURER_ERR_BASE));
        return obj;       
    }

	int i = 0;

	uint32_t evt_id = gecko_evt_gatt_procedure_completed_id;
	if(wait_rsp_evt(evt_id, 300) == 0)
	{
		while(i < special_evt_num)
		{
			struct gecko_cmd_packet* e = &special_evt[i];
			if(BGLIB_MSG_ID(e->header) == gecko_evt_gatt_characteristic_id && e->data.evt_gatt_characteristic.connection == connection)
			{
				o = json_object_new_object();
				l = json_object_object_get(obj,"characteristic_list");
				json_object_object_add(o,"characteristic_handle",json_object_new_int(e->data.evt_gatt_characteristic.characteristic));
				memset(value,0,256);
				reverse_endian(e->data.evt_gatt_characteristic.uuid.data, e->data.evt_gatt_characteristic.uuid.len);
				hex2str(e->data.evt_gatt_characteristic.uuid.data, e->data.evt_gatt_characteristic.uuid.len,value);
				json_object_object_add(o,"characteristic_uuid",json_object_new_string(value));
				json_object_object_add(o,"properties",json_object_new_int(e->data.evt_gatt_characteristic.properties));
				json_object_array_add(l,o);
			}
			i++;
		}
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
		return obj;
	}

	if(BGLIB_MSG_ID(evt->header) == gecko_evt_gatt_procedure_completed_id)
	{
		special_evt_num = 0;
		json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
		return obj;
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
		return obj;
	}
}

json_object* silabs_ble_set_power(int power)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_system_set_tx_power(power);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
    json_object_object_add(obj,"power",json_object_new_int(p->data.rsp_system_set_tx_power.set_power));
    return obj;
}

json_object* silabs_ble_read_char(int connection,int char_handle)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_gatt_read_characteristic_value(connection, char_handle);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_read_characteristic_value.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_read_characteristic_value.result + MANUFACTURER_ERR_BASE));
        return obj;   
    }

    json_object_object_add(obj,"connection",json_object_new_int(connection));

	uint32_t evt_id = gecko_evt_gatt_characteristic_value_id;
    if(wait_rsp_evt(evt_id, 300) == 0)
	{
		if(evt->data.evt_gatt_characteristic_value.connection == connection && evt->data.evt_gatt_characteristic_value.att_opcode == gatt_read_response)
		{
			char value[256] = {0};
			json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
			json_object_object_add(obj,"characteristic_handle",json_object_new_int(evt->data.evt_gatt_characteristic_value.characteristic));
			json_object_object_add(obj,"att_opcode",json_object_new_int(evt->data.evt_gatt_characteristic_value.att_opcode));
			json_object_object_add(obj,"offset",json_object_new_int(evt->data.evt_gatt_characteristic_value.offset));
			hex2str(evt->data.evt_gatt_characteristic_value.value.data, evt->data.evt_gatt_characteristic_value.value.len,value);
			json_object_object_add(obj,"value",json_object_new_string(value));
		}
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_ERR_EVENT_MISSING));
	}

    return obj;
}

json_object* silabs_ble_write_char(int connection,int char_handle,char* value,int write_res)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    int len = strlen(value)/2;
    unsigned char data[256];
    str2array(data,value,len);

    if(write_res)
    {
        gecko_cmd_gatt_write_characteristic_value(connection, char_handle, len, data);
        p = gecko_rsp_msg;
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
            return obj;
        }
		if(p->data.rsp_gatt_write_characteristic_value.result != 0)
		{
        	json_object_object_add(obj,"code", \
				json_object_new_int(p->data.rsp_gatt_write_characteristic_value.result + MANUFACTURER_ERR_BASE));
		}else{
			json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
		}
    }else{
        gecko_cmd_gatt_write_characteristic_value_without_response(connection, char_handle, len, data);
        p = gecko_rsp_msg;
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
            return obj;
        }
		if(p->data.rsp_gatt_write_characteristic_value_without_response.result != 0)
		{
        	json_object_object_add(obj,"code", \
				json_object_new_int(p->data.rsp_gatt_write_characteristic_value_without_response.result + MANUFACTURER_ERR_BASE));
		}else{
			json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
        	json_object_object_add(obj,"sent_len",json_object_new_int(p->data.rsp_gatt_write_characteristic_value_without_response.sent_len));
		}
    }

    return obj;
}

json_object* silabs_ble_set_notify(int connection,int char_handle,int flag)
{        
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_gatt_set_characteristic_notification(connection, char_handle, flag);
    p = gecko_rsp_msg;
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(GL_ERR_RESP_MISSING));
        return obj;
    }

	if(p->data.rsp_gatt_set_characteristic_notification.result != 0)
	{
	    json_object_object_add(obj,"code", \
			json_object_new_int(p->data.rsp_gatt_set_characteristic_notification.result + MANUFACTURER_ERR_BASE));
	}else{
		json_object_object_add(obj,"code",json_object_new_int(GL_SUCCESS));
	}

    return obj;
}