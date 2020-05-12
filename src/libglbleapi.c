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

static struct ubus_subscriber subscriber;
static struct ubus_context* CTX = NULL;
static struct uloop_timeout listen_timeout;
static unsigned char listen;

static void listen_timeout_cb(struct uloop_timeout* timeout)
{
	if(!listen)
	{
		uloop_end();
	}else{
		uloop_timeout_set(timeout, 1 * 1000);
	}
}

int gl_ble_subscribe(ubus_subscriber_cb_t* callback)
{
	int ret;
	unsigned int id = 0;
	subscriber.cb = callback->cb;
	subscriber.remove_cb = callback->remove_cb;

	CTX = ubus_connect(NULL);
    if (!CTX) {
        fprintf(stderr,"ubus_connect failed.\n");
        return -1;
    }
	ret = ubus_register_subscriber(CTX, &subscriber);
	if(ret)
	{
		fprintf(stderr, "Failed to register subscriber: %d\n",ret);
	}

	if (ubus_lookup_id(CTX, "ble", &id)) {
		fprintf(stderr,"ubus_lookup_id failed.\n");
		if (CTX) {
			ubus_free(CTX);
		}
		return -1;
    }
	ret = ubus_subscribe(CTX, &subscriber, id);
	if(ret)
	{
		fprintf(stderr, "Failed to subscribe: %d\n",ret);
	}

	listen = 1;
	listen_timeout.cb = listen_timeout_cb;

	uloop_init();
    ubus_add_uloop(CTX);
	uloop_timeout_set(&listen_timeout, 1 * 1000);


	uloop_run();
	uloop_done();
	return 0;
}
int gl_ble_unsubscribe(void)
{
	listen = 0;
	return 0;
}


static void ubus_invoke_complete_cb(struct ubus_request* req, int type, struct blob_attr* msg)
{
    char** str = (char**)req->priv;

    if (msg && str)
        *str = blobmsg_format_json_indent(msg, true, 0);
}
int json_parameter_check(json_object* obj, char** parameters, int para_num)
{
    json_object* o = NULL;
    int i;
    if(!obj)
        return -1;
	o = json_object_object_get(obj,"code");
	if(!o)
	{
		return -1;
	}
	int code = json_object_get_int(o);
	if(code)
	{
		return code;
	}
    for(i = 0; i<para_num;i++)
    {
        if(!json_object_object_get_ex(obj,parameters[i],&o))
            return -1;
    }
    return 0;
}

/* C/C++ program interface */
int gl_ble_call(const char* path, const char* method, struct blob_buf* b, int timeout, char** str)
{
    unsigned int id = 0;
    struct ubus_context* ctx = NULL;

    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr,"ubus_connect failed.\n");
        return -1;
    }

    if (ubus_lookup_id(ctx, path, &id)) {
        fprintf(stderr,"ubus_lookup_id failed.\n");
        if (ctx) {
            ubus_free(ctx);
        }
        return -1;
    }

    ubus_invoke(ctx, id, method, b->head, ubus_invoke_complete_cb, (void*)str, timeout * 1000);

    if (ctx)
        ubus_free(ctx);

    return 0;
}

/* System functions */

/*Get local bluetooth MAC*/
int gl_ble_get_mac(gl_ble_get_mac_rsp_t *rsp)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble","local_mac",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"mac"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}
	char* address = json_object_get_string(json_object_object_get(o,"mac"));
	int mac[6];
    sscanf(address,"%02x:%02x:%02x:%02x:%02x:%02x",
            &mac[5],&mac[4],&mac[3],&mac[2],&mac[1],&mac[0]);
    int i = 0;
    while(i < 6)
    {
        rsp->addr[i] = mac[i];
        i++;
    }

	free(str);
	json_object_put(o);
    return 0;
}
/*Enable or disable the BLE module*/
int gl_ble_enable(int enable)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "enable", enable);

	gl_ble_call("ble","enable",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Set system tx power*/
int gl_ble_set_power(gl_ble_set_power_rsp_t * rsp, int power)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "system_power_level", power);

	gl_ble_call("ble","set_power",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"power"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->current_power = json_object_get_int(json_object_object_get(o,"power"));

	free(str);
	json_object_put(o);
    return 0;
}

/* BLE master functions */

/*Act as master, Set and start the BLE discovery*/
int gl_ble_discovery(int phys,int interval,int window,int type,int mode)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "phys", phys);
	blobmsg_add_u32(&b, "interval", interval);
	blobmsg_add_u32(&b, "window", window);
	blobmsg_add_u32(&b, "type", type);
	blobmsg_add_u32(&b, "mode", mode);

	gl_ble_call("ble","discovery",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, End the current GAP discovery procedure*/
int gl_ble_stop(void)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble","stop",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Start connect to a remote BLE device*/
int gl_ble_connect(gl_ble_connect_rsp_t* rsp,char* address,int address_type,int phy)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_address", address);
	blobmsg_add_u32(&b, "conn_address_type", address_type);
	blobmsg_add_u32(&b, "conn_phy", phy);

	gl_ble_call("ble","connect",&b,2,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"connection","address","address_type","master","bonding","advertiser"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o,"connection"));
	rsp->address_type = json_object_get_int(json_object_object_get(o,"address_type"));
	rsp->master = json_object_get_int(json_object_object_get(o,"master"));
	rsp->bonding = json_object_get_int(json_object_object_get(o,"bonding"));
	rsp->advertiser = json_object_get_int(json_object_object_get(o,"advertiser"));
	char* address = json_object_get_string(json_object_object_get(o,"address"));
	int mac[6];
    sscanf(address,"%02x:%02x:%02x:%02x:%02x:%02x",
            &mac[5],&mac[4],&mac[3],&mac[2],&mac[1],&mac[0]);
    int i = 0;
    while(i < 6)
    {
        rsp->addr[i] = mac[i];
        i++;
    }

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, disconnect with remote device*/
int gl_ble_disconnect(int connection)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "disconn_connection", connection);

	gl_ble_call("ble","disconnect",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Get rssi of connection with remote device*/
int gl_ble_get_rssi(gl_ble_get_rssi_rsp_t* rsp,int connection)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "rssi_connection", connection);

	gl_ble_call("ble","get_rssi",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"connection","rssi"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o,"connection"));
	rsp->rssi = json_object_get_int(json_object_object_get(o,"rssi"));

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Get service list of a remote GATT server*/
int gl_ble_get_service(gl_ble_get_service_rsp_t *rsp, int connection)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);

	gl_ble_call("ble","get_service",&b,2,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"connection","service_list"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o,"connection"));

	json_object* list = json_object_object_get(o,"service_list");
	int len = json_object_array_length(list);
	rsp->list_len = len;
	json_object* obj;

	int i = 0;
	while(i < len)
	{
		obj = json_object_array_get_idx(list,i);
		rsp->list[i].handle = json_object_get_int(json_object_object_get(obj,"service_handle"));
		strcpy(rsp->list[i].uuid,json_object_get_string(json_object_object_get(obj,"service_uuid")));
		i++;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Get characteristic list of a remote GATT server*/
int gl_ble_get_char(gl_ble_get_char_rsp_t *rsp, int connection, int service_handle)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);
	blobmsg_add_u32(&b, "char_service_handle", service_handle);

	gl_ble_call("ble","get_char",&b,2,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"connection","characteristic_list"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o,"connection"));

	json_object* list = json_object_object_get(o,"characteristic_list");
	int len = json_object_array_length(list);
	rsp->list_len = len;
	json_object* obj;

	int i = 0;
	while(i < len)
	{
		obj = json_object_array_get_idx(list,i);
		rsp->list[i].handle = json_object_get_int(json_object_object_get(obj,"characteristic_handle"));
		rsp->list[i].properties = json_object_get_int(json_object_object_get(obj,"properties"));
		strcpy(rsp->list[i].uuid,json_object_get_string(json_object_object_get(obj,"characteristic_uuid")));
		i++;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Read value of specified characteristic in a remote gatt server*/
int gl_ble_read_char(gl_ble_char_read_rsp_t *rsp, int connection, int char_handle)
{	
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);

	gl_ble_call("ble","read_char",&b,2,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"connection","characteristic_handle","att_opcode","offset","value"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	rsp->connection = json_object_get_int(json_object_object_get(o,"connection"));
	rsp->handle = json_object_get_int(json_object_object_get(o,"characteristic_handle"));
	rsp->att_opcode = json_object_get_int(json_object_object_get(o,"att_opcode"));
	rsp->offset = json_object_get_int(json_object_object_get(o,"offset"));
	strcpy(rsp->value,json_object_get_string(json_object_object_get(o,"offset")));

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Write value to specified characteristic in a remote gatt server*/
int gl_ble_write_char(gl_ble_write_char_rsp_t *rsp, int connection, int char_handle,char* value,int res)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_string(&b, "char_value", value);
	blobmsg_add_u32(&b, "write_res", res);

	gl_ble_call("ble","write_char",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	json_object* obj = json_object_object_get(o,"sent_len");
	if(obj)
	{
		rsp->sent_len = json_object_get_int(obj);
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as master, Enable or disable the notification or indication of a remote gatt server*/
int gl_ble_set_notify(int connection, int char_handle,int flag)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_u32(&b, "notify_flag", flag);

	gl_ble_call("ble","set_notify",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}

/* BLE slave functions */

/*Act as BLE slave, Set and Start Avertising*/
int gl_ble_adv(int phys, int interval_min,int interval_max,int discover,int connect)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_phys", phys);
	blobmsg_add_u32(&b, "adv_interval_min", interval_min);
	blobmsg_add_u32(&b, "adv_interval_max", interval_max);
	blobmsg_add_u32(&b, "adv_discover", discover);
	blobmsg_add_u32(&b, "adv_conn", connect);

	gl_ble_call("ble","adv",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as BLE slave, Set customized advertising data*/
int gl_ble_adv_data(int flag, char* data)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_data_flag", flag);
	blobmsg_add_string(&b,"adv_data", data);

	gl_ble_call("ble","adv_data",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as BLE slave, Stop advertising*/
int gl_ble_stop_adv(void)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble","stop_adv",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}

	free(str);
	json_object_put(o);
    return 0;
}
/*Act as BLE slave, Send Notification*/
int gl_ble_send_notify(gl_ble_send_notify_rsp_t *rsp,int connection,int char_handle, char* value)
{
	if(!rsp)
	{
		return -2;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "send_noti_conn", connection);
	blobmsg_add_u32(&b, "send_noti_char", char_handle);
	blobmsg_add_string(&b, "send_noti_value", value);

	gl_ble_call("ble","send_notify",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"sent_len"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}
	rsp->sent_len = json_object_get_int(json_object_object_get(o,"sent_len"));

	free(str);
	json_object_put(o);
    return 0;
}
/*DTM test, tx*/
int gl_ble_dtm_tx(gl_ble_dtm_test_rsp_t *rsp, int packet_type,int length, int channel, int phy)
{
	if(!rsp)
	{
		return -2;
	}
	
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_tx_type", packet_type);
	blobmsg_add_u32(&b, "dtm_tx_length", length);
	blobmsg_add_u32(&b, "dtm_tx_channel", channel);
	blobmsg_add_u32(&b, "dtm_tx_phy", phy);

	gl_ble_call("ble","dtm_tx",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o,"number_of_packets"));

	free(str);
	json_object_put(o);
    return 0;
}
/*DTM test, rx*/
int gl_ble_dtm_rx(gl_ble_dtm_test_rsp_t *rsp, int channel, int phy)
{
	if(!rsp)
	{
		return -2;
	}
	
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_rx_channel", channel);
	blobmsg_add_u32(&b, "dtm_rx_phy", phy);

	gl_ble_call("ble","dtm_rx",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o,"number_of_packets"));

	free(str);
	json_object_put(o);
    return 0;
}
/*DTM test, end*/
int gl_ble_dtm_end(gl_ble_dtm_test_rsp_t *rsp)
{
	if(!rsp)
	{
		return -2;
	}
	
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	gl_ble_call("ble","dtm_end",&b,1,&str);
	if(NULL == str)
	{
		return -1;
	}

	json_object* o = json_tokener_parse(str);
	char* parameters[] = {"number_of_packets"};
	int ret = json_parameter_check(o,parameters,sizeof(parameters)/sizeof(parameters[0]));
	if(ret)
	{
		return ret;
	}
	rsp->number_of_packets = json_object_get_int(json_object_object_get(o,"number_of_packets"));

	free(str);
	json_object_put(o);
    return 0;
}