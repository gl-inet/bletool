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
#include "uart.h"



#define UNKNOW_MSG              "unknow_msg"
#define SYSTEM_BOOT             "system_boot"
#define CONN_CLOSE              "conn_close"
#define CONN_OPEN               "conn_open"
#define REMOTE_MOTIFY           "remote_notify"
#define REMOTE_WRITE            "remote_write"
#define REMOTE_SET              "remote_set"
#define ADV_PKG                 "adv_packet"
#define CONN_UPDATE             "conn_update"


#define SUCCESS                  0   
#define RESPONSE_MISSING        -1
#define EVENT_MISSING           -2
#define MSG_ERROR               -3
#define PARAMETER_ERROR         -4

char rston[64] = {0};
char rstoff[64] = {0};
struct gecko_cmd_packet pck;

static void reverse_rev_payload(struct gecko_cmd_packet* pck);

int str2array(uint8* dst, char* src, int len)
{
    int i = 0;
    int tmp;
    while(i < len)
    {
        sscanf(src+i*2,"%02x",&tmp);
        dst[i] = tmp;
        i++;
    }
    return 0;
}
static int hex2str(uint8* head, int len, char* value)
{
    int i = 0;

    if(len >= 256/2)
    {
        len = 128;
    }
    while(i < len)
    {
        sprintf(value+i*2,"%02x",head[i]);
        i++;
    }
    return 0;
}
int addr2str(bd_addr *adr, char* str)
{
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
    adr->addr[5],adr->addr[4],adr->addr[3],adr->addr[2],adr->addr[1],adr->addr[0]);
    return 0;
}
int str2addr(char* str,bd_addr *address)
{
    int mac[6];
    sscanf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
            &mac[5],&mac[4],&mac[3],&mac[2],&mac[1],&mac[0]);
    int i = 0;
    while(i < 6)
    {
        address->addr[i] = mac[i];
        i++;
    }
    return 0;
}
void reverse_endian(uint8_t* header,uint8_t length)
{
  uint8_t* tmp = (uint8_t*)malloc(length);
  memcpy(tmp,header,length);
  int i = length-1;
  int j = 0;
  for(;i>=0;i--,j++)
  {
    *(header+j) = *(tmp+i);
  }
  free(tmp);
  return;
}
struct gecko_cmd_packet* silabs_read_pkt(void)
{
    uint32_t msg_length;
    uint32_t header;
    int      ret;

    memset(&pck,0,sizeof(struct gecko_cmd_packet));

    ret = uartRx(BGLIB_MSG_HEADER_LEN, (uint8_t*)&header);
    if(ENDIAN){
        reverse_endian((uint8_t*)&header,BGLIB_MSG_HEADER_LEN);
    } 

    if (ret < 0 || (header & 0x78) != gecko_dev_type_gecko){
        return NULL;
    }

    msg_length = BGLIB_MSG_LEN(header);
    if (msg_length > BGLIB_MSG_MAX_PAYLOAD || msg_length <= 0){
        return NULL;
    }

    pck.header = header;
    ret = uartRx(msg_length, (uint8_t*)&pck.data.payload);
    if (ret < 0) {
        return NULL;
    }

    if(ENDIAN)  reverse_rev_payload(&pck);
    return &pck;
}
struct gecko_cmd_packet* silabs_wait_pkt(uint32_t* id_list, int msecond)
{
    struct gecko_cmd_packet* p;
    int timeout = msecond/10;  //detect per 10 mseconds

    while(timeout)
    {
        timeout -- ;
        if(uartRxPeek() > 0)
        {
            p = silabs_read_pkt();
            if(p)
            {
                int i = 1;
                while(i <= id_list[0])
                {
                    if(id_list[i] == BGLIB_MSG_ID(p->header))
                    {
                        return p;
                    }
                    i++;
                }
            }
        }
        usleep(10000);
    }
    return NULL;
}

json_object* silabs_get_notify(void)
{
    struct gecko_cmd_packet* p = NULL;
    p = silabs_read_pkt();

    if(!p)
    {
        return NULL;
    }

    json_object* o = NULL;
    char value[256] = {0};
    char addr[18] = {0};

    switch(BGLIB_MSG_ID(p->header)){
        case gecko_evt_system_boot_id:
            {
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
            }
            break;
        case gecko_evt_le_connection_closed_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(CONN_CLOSE));
                json_object_object_add(o,"reason",json_object_new_int(p->data.evt_le_connection_closed.reason));
                json_object_object_add(o,"connection",json_object_new_int(p->data.evt_le_connection_closed.connection));
            }
            break;
        case gecko_evt_gatt_characteristic_value_id:
            {
                if(pck.data.evt_gatt_characteristic_value.att_opcode == gatt_handle_value_notification){
                    o = json_object_new_object();
                    json_object_object_add(o,"type",json_object_new_string(REMOTE_MOTIFY));
                    json_object_object_add(o,"connection",json_object_new_int(p->data.evt_gatt_characteristic_value.connection));
                    json_object_object_add(o,"characteristic",json_object_new_int(p->data.evt_gatt_characteristic_value.characteristic));
                    json_object_object_add(o,"att_opcode",json_object_new_int(p->data.evt_gatt_characteristic_value.att_opcode));
                    json_object_object_add(o,"offset",json_object_new_int(p->data.evt_gatt_characteristic_value.offset));
                    hex2str(p->data.evt_gatt_characteristic_value.value.data,p->data.evt_gatt_characteristic_value.value.len,value);
                    json_object_object_add(o,"value",json_object_new_string(value));
                }
            }
            break;
        case gecko_evt_gatt_server_attribute_value_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(REMOTE_WRITE));
                json_object_object_add(o,"connection",json_object_new_int(p->data.evt_gatt_server_attribute_value.connection));
                json_object_object_add(o,"attribute",json_object_new_int(p->data.evt_gatt_server_attribute_value.attribute));
                json_object_object_add(o,"att_opcode",json_object_new_int(p->data.evt_gatt_server_attribute_value.att_opcode));
                json_object_object_add(o,"offset",json_object_new_int(p->data.evt_gatt_server_attribute_value.offset));
                hex2str(p->data.evt_gatt_server_attribute_value.value.data,p->data.evt_gatt_server_attribute_value.value.len,value);
                json_object_object_add(o,"value",json_object_new_string(value));
            }
            break;
        case gecko_evt_gatt_server_characteristic_status_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(REMOTE_SET));
                json_object_object_add(o,"connection",json_object_new_int(p->data.evt_gatt_server_characteristic_status.connection));
                json_object_object_add(o,"characteristic",json_object_new_int(p->data.evt_gatt_server_characteristic_status.characteristic));
                json_object_object_add(o,"status_flags",json_object_new_int(p->data.evt_gatt_server_characteristic_status.status_flags));
                json_object_object_add(o,"client_config_flags",json_object_new_int(p->data.evt_gatt_server_characteristic_status.client_config_flags));
            }
            break;
        case gecko_evt_le_gap_scan_response_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(ADV_PKG));
                json_object_object_add(o,"rssi",json_object_new_int(p->data.evt_le_gap_scan_response.rssi));
                json_object_object_add(o,"packet_type",json_object_new_int(p->data.evt_le_gap_scan_response.packet_type));
                addr2str(&p->data.evt_le_gap_scan_response.address,addr);
                json_object_object_add(o,"address",json_object_new_string(addr));
                json_object_object_add(o,"address_type",json_object_new_int(p->data.evt_le_gap_scan_response.address_type));
                json_object_object_add(o,"bonding",json_object_new_int(p->data.evt_le_gap_scan_response.bonding));
                hex2str(p->data.evt_le_gap_scan_response.data.data, p->data.evt_le_gap_scan_response.data.len,value);
                json_object_object_add(o,"data",json_object_new_string(value));
            }
            break;
        case gecko_evt_le_connection_parameters_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(CONN_UPDATE));
                json_object_object_add(o,"connection",json_object_new_int(p->data.evt_le_connection_parameters.connection));
                json_object_object_add(o,"interval",json_object_new_int(p->data.evt_le_connection_parameters.interval));
                json_object_object_add(o,"latency",json_object_new_int(p->data.evt_le_connection_parameters.latency));
                json_object_object_add(o,"timeout",json_object_new_int(p->data.evt_le_connection_parameters.timeout));
                json_object_object_add(o,"security_mode",json_object_new_int(p->data.evt_le_connection_parameters.security_mode));
                json_object_object_add(o,"txsize",json_object_new_int(p->data.evt_le_connection_parameters.txsize));
            }
            break;
        case gecko_evt_le_connection_opened_id:
            {
                o = json_object_new_object();
                json_object_object_add(o,"type",json_object_new_string(CONN_OPEN));
                addr2str(&p->data.evt_le_connection_opened.address,addr);
                json_object_object_add(o,"address",json_object_new_string(addr));
                json_object_object_add(o,"address_type",json_object_new_int(p->data.evt_le_connection_opened.address_type));
                json_object_object_add(o,"master",json_object_new_int(p->data.evt_le_connection_opened.master));
                json_object_object_add(o,"connection",json_object_new_int(p->data.evt_le_connection_opened.connection));
                json_object_object_add(o,"bonding",json_object_new_int(p->data.evt_le_connection_opened.bonding));
                json_object_object_add(o,"advertiser",json_object_new_int(p->data.evt_le_connection_opened.advertiser));
            }
            break;
        default:
            break;
    }
    return o;
}

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
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}

json_object* silabs_ble_local_mac(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_system_get_bt_address();
    uint32_t id_list[2] = {1,gecko_rsp_system_get_bt_address_id};
    p = silabs_wait_pkt(id_list,200);

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }

    char addr[18];
    addr2str(&p->data.rsp_system_get_bt_address.address,addr);
    json_object_object_add(obj,"mac",json_object_new_string(addr)); 
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}
json_object* silabs_ble_discovery(int phys,int interval,int window,int type,int mode)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_set_discovery_timing(phys,interval,window);

    uint32_t id_list[2] = {1,gecko_rsp_le_gap_set_discovery_timing_id};
    p = silabs_wait_pkt(id_list,200);

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
    }
    if(p->data.rsp_le_gap_set_discovery_timing.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_discovery_timing.result));
        return obj;       
    }

    gecko_cmd_le_gap_set_discovery_type(phys,type);
    id_list[1] = gecko_rsp_le_gap_set_discovery_type_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
    }
    if(p->data.rsp_le_gap_set_discovery_type.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(pck.data.rsp_le_gap_set_discovery_type.result));
        return obj;       
    }

    gecko_cmd_le_gap_start_discovery(phys,mode);
    id_list[1] = gecko_rsp_le_gap_start_discovery_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
    }
    if(p->data.rsp_le_gap_start_discovery.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_start_discovery.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}
json_object* silabs_ble_stop(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_end_procedure();
    uint32_t id_list[2] = {1,gecko_rsp_le_gap_end_procedure_id};
    p = silabs_wait_pkt(id_list,200);

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }

    json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_end_procedure.result));
    return obj;
}
json_object* silabs_ble_adv(int adv_phys,int adv_interval_min,int adv_interval_max,int adv_discover,int adv_conn)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_set_advertise_phy(0, adv_phys, adv_phys);
    uint32_t id_list[2] = {1,gecko_rsp_le_gap_set_advertise_phy_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_set_advertise_phy.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_advertise_phy.result));
        return obj;       
    }


    gecko_cmd_le_gap_set_advertise_timing(0, adv_interval_min, adv_interval_max, 0, 0);
    id_list[1] = gecko_rsp_le_gap_set_advertise_timing_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_set_advertise_timing.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_set_advertise_timing.result));
        return obj;       
    }

    gecko_cmd_le_gap_start_advertising(0, adv_discover, adv_conn);
    id_list[1] = gecko_rsp_le_gap_start_advertising_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_start_advertising.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_start_advertising.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));

    return obj;

}

json_object* silabs_ble_adv_data(int adv_data_flag,char* adv_data)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    if(!adv_data)
    {
        json_object_object_add(obj,"code",json_object_new_int(PARAMETER_ERROR));
        return obj;
    }
    int len = strlen(adv_data)/2;
    uint8* data = (uint8*)calloc(len,sizeof(uint8));
    str2array(data,adv_data,len);

    gecko_cmd_le_gap_bt5_set_adv_data(0, adv_data_flag, len, data);
    uint32_t id_list[2] = {1,gecko_rsp_le_gap_bt5_set_adv_data_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_bt5_set_adv_data.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_bt5_set_adv_data.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}

json_object* silabs_ble_stop_adv(void)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    gecko_cmd_le_gap_stop_advertising(0);
    uint32_t id_list[2] = {1,gecko_rsp_le_gap_stop_advertising_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_gap_stop_advertising.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_stop_advertising.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}

json_object* silabs_ble_send_notify(int send_noti_conn,int send_noti_char,char* send_noti_value)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();
    
    if(!send_noti_value)
    {
        json_object_object_add(obj,"code",json_object_new_int(PARAMETER_ERROR));
        return obj;
    }

    int len = strlen(send_noti_value)/2;
    uint8* value = (uint8*)calloc(len,sizeof(uint8));
    str2array(value,send_noti_value,len);

    gecko_cmd_gatt_server_send_characteristic_notification(send_noti_conn, send_noti_char, len, value);
    uint32_t id_list[2] = {1,gecko_rsp_gatt_server_send_characteristic_notification_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_server_send_characteristic_notification.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_server_send_characteristic_notification.result));
        return obj;       
    }

    json_object_object_add(obj,"sent_len",json_object_new_int(p->data.rsp_gatt_server_send_characteristic_notification.sent_len));
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    return obj;
}

json_object* silabs_ble_connect(char* address,int address_type,int conn_phy)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object();

    if(!address)
    {
        json_object_object_add(obj,"code",json_object_new_int(PARAMETER_ERROR));
        return obj;
    }

    bd_addr addr;
    str2addr(address,&addr);
    gecko_cmd_le_gap_connect(addr, address_type, conn_phy);

    uint32_t id_list[2] = {1,gecko_rsp_le_gap_connect_id};
    p = silabs_wait_pkt(id_list,200);

    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;       
    }
    if(p->data.rsp_le_gap_connect.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_gap_connect.result));
        return obj;       
    }
    int connection = p->data.rsp_le_gap_connect.connection;


    id_list[1] = gecko_evt_le_connection_opened_id;
    p = silabs_wait_pkt(id_list,4000);
    if(!p)
    {
        gecko_cmd_le_connection_close(connection);
        json_object_object_add(obj,"code",json_object_new_int(EVENT_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    json_object_object_add(obj,"connection",json_object_new_int(p->data.evt_le_connection_opened.connection));
    char str[18] = {0};
    addr2str(&pck.data.evt_le_connection_opened.address,str);
    json_object_object_add(obj,"address",json_object_new_string(str));
    json_object_object_add(obj,"address_type",json_object_new_int(p->data.evt_le_connection_opened.address_type));
    json_object_object_add(obj,"master",json_object_new_int(p->data.evt_le_connection_opened.master));
    json_object_object_add(obj,"bonding",json_object_new_int(p->data.evt_le_connection_opened.bonding));
    json_object_object_add(obj,"advertiser",json_object_new_int(p->data.evt_le_connection_opened.advertiser));

    return obj;
}

json_object* silabs_ble_disconnect(int connection)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_le_connection_close(connection);
    uint32_t id_list[2] = {1,gecko_rsp_le_connection_close_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_connection_close.result));
    return obj;
}

json_object* silabs_ble_get_rssi(int connection)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 
 
    gecko_cmd_le_connection_get_rssi(connection);
    uint32_t id_list[2] = {1,gecko_rsp_le_connection_get_rssi_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_le_connection_get_rssi.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_le_connection_get_rssi.result));
        return obj;       
    }

    id_list[1] = gecko_evt_le_connection_rssi_id;
    p = silabs_wait_pkt(id_list,300);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(EVENT_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    json_object_object_add(obj,"connection",json_object_new_int(p->data.evt_le_connection_rssi.connection));
    json_object_object_add(obj,"status",json_object_new_int(p->data.evt_le_connection_rssi.status));
    json_object_object_add(obj,"rssi",json_object_new_int(p->data.evt_le_connection_rssi.rssi));
    return obj;
}

json_object* silabs_ble_get_service(int connection)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    int wait_time = 200; // >10
    gecko_cmd_gatt_discover_primary_services(connection);
    uint32_t id_list[2] = {1,gecko_rsp_gatt_discover_primary_services_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_discover_primary_services.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_discover_primary_services.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    json_object_object_add(obj,"connection",json_object_new_int(connection));
    char value[256] = {0};
    json_object* array = json_object_new_array();
    json_object_object_add(obj,"service_list",array);
    json_object *l, *o;
    uint32_t id_list_service[3] = {2,gecko_evt_gatt_service_id,gecko_evt_gatt_procedure_completed_id};
    while(1)
    {
        p = silabs_wait_pkt(id_list_service,500);
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(EVENT_MISSING));
            return obj;
        }
        if(BGLIB_MSG_ID(p->header) == gecko_evt_gatt_service_id && p->data.evt_gatt_service.connection == connection)
        {
            o = json_object_new_object();
            l = json_object_object_get(obj,"service_list");
            json_object_object_add(o,"service_handle",json_object_new_int(p->data.evt_gatt_service.service));
            memset(value,0,256);
            reverse_endian(p->data.evt_gatt_service.uuid.data,pck.data.evt_gatt_service.uuid.len);
            hex2str(p->data.evt_gatt_service.uuid.data,pck.data.evt_gatt_service.uuid.len,value);
            json_object_object_add(o,"service_uuid",json_object_new_string(value));
            json_object_array_add(l,o);
        }
        if(BGLIB_MSG_ID(p->header) == gecko_evt_gatt_procedure_completed_id)
        {
            return obj;
        }
    }
}

json_object* silabs_ble_get_char(int connection,int service_handle)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_gatt_discover_characteristics(connection, service_handle);
    uint32_t id_list[2] = {1,gecko_rsp_gatt_discover_characteristics_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_discover_characteristics.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_discover_characteristics.result));
        return obj;       
    }

    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    char value[256] = {0};
    json_object* array = json_object_new_array();
    json_object_object_add(obj,"characteristic_list",array);
    json_object *l, *o;
    uint32_t id_list_char[3] = {2,gecko_evt_gatt_characteristic_id,gecko_evt_gatt_procedure_completed_id};
    while(1)
    {
        p = silabs_wait_pkt(id_list_char,500);
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(EVENT_MISSING));
            return obj;
        }
        if(BGLIB_MSG_ID(p->header) == gecko_evt_gatt_characteristic_id && p->data.evt_gatt_characteristic.connection == connection)
        {
            o = json_object_new_object();
            l = json_object_object_get(obj,"characteristic_list");
            json_object_object_add(o,"characteristic_handle",json_object_new_int(p->data.evt_gatt_characteristic.characteristic));
            memset(value,0,256);
            reverse_endian(p->data.evt_gatt_characteristic.uuid.data,pck.data.evt_gatt_characteristic.uuid.len);
            hex2str(p->data.evt_gatt_characteristic.uuid.data,pck.data.evt_gatt_characteristic.uuid.len,value);
            json_object_object_add(o,"characteristic_uuid",json_object_new_string(value));
            json_object_object_add(o,"properties",json_object_new_int(p->data.evt_gatt_characteristic.properties));
            json_object_array_add(l,o);
        }
        if(BGLIB_MSG_ID(p->header) == gecko_evt_gatt_procedure_completed_id)
        {
            return obj;
        }
    }
}

json_object* silabs_ble_set_power(int power)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_system_set_tx_power(power);
    uint32_t id_list[2] = {1,gecko_rsp_system_set_tx_power_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    json_object_object_add(obj,"power",json_object_new_int(p->data.rsp_system_set_tx_power.set_power));
    return obj;
}

json_object* silabs_ble_read_char(int connection,int char_handle)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_gatt_read_characteristic_value(connection, char_handle);
    uint32_t id_list[2] = {1,gecko_rsp_gatt_read_characteristic_value_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_gatt_read_characteristic_value.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_read_characteristic_value.result));
        return obj;   
    }

    json_object_object_add(obj,"connection",json_object_new_int(connection));
    id_list[1] = gecko_evt_gatt_characteristic_value_id;
    p = silabs_wait_pkt(id_list,500);
    if(!p || p->data.evt_gatt_characteristic_value.connection != connection)
    {
        json_object_object_add(obj,"code",json_object_new_int(EVENT_MISSING));
        return obj;       
    }
    char value[256] = {0};
    json_object_object_add(obj,"code",json_object_new_int(SUCCESS));
    json_object_object_add(obj,"characteristic_handle",json_object_new_int(pck.data.evt_gatt_characteristic_value.characteristic));
    json_object_object_add(obj,"att_opcode",json_object_new_int(pck.data.evt_gatt_characteristic_value.att_opcode));
    json_object_object_add(obj,"offset",json_object_new_int(pck.data.evt_gatt_characteristic_value.offset));
    hex2str(pck.data.evt_gatt_characteristic_value.value.data,pck.data.evt_gatt_characteristic_value.value.len,value);
    json_object_object_add(obj,"value",json_object_new_string(value));

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
        uint32_t id_list[2] = {1,gecko_rsp_gatt_write_characteristic_value_id};
        p = silabs_wait_pkt(id_list,200);
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
            return obj;
        }
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_write_characteristic_value.result));
    }else{
        gecko_cmd_gatt_write_characteristic_value_without_response(connection, char_handle, len, data);
        uint32_t id_list[2] = {1,gecko_rsp_gatt_write_characteristic_value_without_response_id};
        p = silabs_wait_pkt(id_list,200);
        if(!p)
        {
            json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
            return obj;
        }
        json_object_object_add(obj,"sent_len",json_object_new_int(p->data.rsp_gatt_write_characteristic_value_without_response.sent_len));
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_write_characteristic_value.result));
    }
    return obj;
}

json_object* silabs_ble_set_notify(int connection,int char_handle,int flag)
{        
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_gatt_set_characteristic_notification(connection, char_handle, flag);
    uint32_t id_list[2] = {1,gecko_rsp_gatt_set_characteristic_notification_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_gatt_set_characteristic_notification.result));
    return obj;
}

json_object* silabs_ble_dtm_tx(int packet_type,int length, int channel, int phy)
{        
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_test_dtm_tx(packet_type, length, channel, phy);
    uint32_t id_list[2] = {1,gecko_rsp_test_dtm_tx_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_test_dtm_tx.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_test_dtm_tx.result));
        return obj;       
    }

    id_list[1] = gecko_evt_test_dtm_completed_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(p->data.evt_test_dtm_completed.result));
    json_object_object_add(obj,"number_of_packets",json_object_new_int(p->data.evt_test_dtm_completed.number_of_packets));
    return obj;
}

json_object* silabs_ble_dtm_rx(int channel, int phy)
{
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_test_dtm_rx(channel, phy);
    uint32_t id_list[2] = {1,gecko_rsp_test_dtm_rx_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_test_dtm_rx.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_test_dtm_rx.result));
        return obj;       
    }

    id_list[1] = gecko_evt_test_dtm_completed_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(p->data.evt_test_dtm_completed.result));
    json_object_object_add(obj,"number_of_packets",json_object_new_int(p->data.evt_test_dtm_completed.number_of_packets));
    return obj;
}

json_object* silabs_ble_dtm_end(void)
{        
    struct gecko_cmd_packet* p = NULL;
    json_object* obj = json_object_new_object(); 

    gecko_cmd_test_dtm_end();
    uint32_t id_list[2] = {1,gecko_rsp_test_dtm_end_id};
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    if(p->data.rsp_test_dtm_end.result)
    {
        json_object_object_add(obj,"code",json_object_new_int(p->data.rsp_test_dtm_end.result));
        return obj;       
    }

    id_list[1] = gecko_evt_test_dtm_completed_id;
    p = silabs_wait_pkt(id_list,200);
    if(!p)
    {
        json_object_object_add(obj,"code",json_object_new_int(RESPONSE_MISSING));
        return obj;
    }
    json_object_object_add(obj,"code",json_object_new_int(p->data.evt_test_dtm_completed.result));
    json_object_object_add(obj,"number_of_packets",json_object_new_int(p->data.evt_test_dtm_completed.number_of_packets));
    return obj;
}


void gecko_handle_command(uint32_t hdr, void* data)
{
    return gecko_handle_command_noresponse(hdr,data);
}

void gecko_handle_command_noresponse(uint32_t hdr, void* data)
{
  uint32_t send_msg_length = BGLIB_MSG_HEADER_LEN + BGLIB_MSG_LEN(gecko_cmd_msg->header);
  if(ENDIAN) reverse_endian((uint8_t*)&gecko_cmd_msg->header,BGLIB_MSG_HEADER_LEN);

  uartTx(send_msg_length, (uint8_t*)gecko_cmd_msg);
}

static void reverse_rev_payload(struct gecko_cmd_packet* pck)
{
  uint32 p = BGLIB_MSG_ID(pck->header);
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