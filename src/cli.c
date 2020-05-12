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

#define PARA_MISSING	"parameter missing\n"

static int sub_cb(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req,
			    const char *method, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	printf("%s\n",str);
	free(str);

	return 0;
}
static void sub_remove_cb(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id)
{
	fprintf(stderr,"Removed by server\n");
}


static void ubus_invoke_complete(struct ubus_request* req, int type, struct blob_attr* msg)
{
    char** str = (char**)req->priv;

    if (msg && str)
        *str = blobmsg_format_json_indent(msg, true, 0);
}
int ble_ubus_call(char* path, const char* method, struct blob_buf* b, int timeout, char** str)
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

    ubus_invoke(ctx, id, method, b->head, ubus_invoke_complete, (void*)str, timeout * 1000);

    if (ctx)
        ubus_free(ctx);

    return 0;
}
/* System functions */
int cmd_enable(int argc, char** argv)
{
	int enable = 0;
	if(argc < 3)
	{
		enable = 1;
	}else{
		enable = atoi(argv[2]);
	}
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "enable", enable);

	ble_ubus_call("ble","enable",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);
	
	return 0;
}
int cmd_set_power(int argc, char** argv)
{
	int power;
	if(argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}else{
		power = atoi(argv[2]);
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "system_power_level", power);

	ble_ubus_call("ble","set_power",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);
	
	return 0;
}
int cmd_local_address(int argc, char** argv)
{
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble","local_mac",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_listen(int argc, char** argv)
{
	ubus_subscriber_cb_t callback;
	callback.cb = sub_cb;
	callback.remove_cb = sub_remove_cb;

	gl_ble_subscribe(&callback);
	
	return 0;
}

/*BLE slave functions */
int cmd_adv_data(int argc, char** argv)
{
	int ch,flag = -1;
	char* value = NULL;

	struct option long_options[] ={
		{"flag",	required_argument,	NULL,	'f'},
		{"value",	required_argument,	NULL,	'v'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"f:v:",long_options,&option_index)) != -1)
	{
		switch(ch)
		{
			case 'f':
				flag = atoi(optarg);
				break;
			case 'v':
				value = optarg;
				break;
		}
	}

	if(flag < 0 || !value)
	{
		printf(PARA_MISSING);
		return -1;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_data_flag", flag);
	blobmsg_add_string(&b,"adv_data", value);

	ble_ubus_call("ble","adv_data",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_adv(int argc, char** argv)
{
	int ch,phys = 1,interval_min = 160, interval_max = 160,discover = 2, connect = 2;

	struct option long_options[] ={
		{"phys",			required_argument,	NULL,	'p'},
		{"interval_min",	required_argument,	NULL,	'n'},
		{"interval_max",	required_argument,	NULL,	'x'},
		{"discover",		required_argument,	NULL,	'd'},
		{"connect",			required_argument,	NULL,	'c'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"p:n:x:d:c:",long_options,&option_index)) != -1)
	{
		switch(ch)
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

	if(interval_max < interval_min)
	{
		interval_max = interval_min;
	}

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "adv_phys", phys);
	blobmsg_add_u32(&b, "adv_interval_min", interval_min);
	blobmsg_add_u32(&b, "adv_interval_max", interval_max);
	blobmsg_add_u32(&b, "adv_discover", discover);
	blobmsg_add_u32(&b, "adv_conn", connect);

	ble_ubus_call("ble","adv",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_adv_stop(int argc, char** argv)
{	
	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);

	ble_ubus_call("ble","stop_adv",&b,1,&str);
	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_discovery(int argc, char** argv)
{
	int ch,phys = 1,interval = 16, window = 16,type = 0, mode = 1;

	struct option long_options[] ={
		{"phys",			required_argument,	NULL,	'p'},
		{"interval",		required_argument,	NULL,	'i'},
		{"window",			required_argument,	NULL,	'w'},
		{"type",			required_argument,	NULL,	't'},
		{"mode",			required_argument,	NULL,	'm'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"p:i:w:t:m:",long_options,&option_index)) != -1)
	{
		switch(ch)
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

	char* str = NULL;
	struct blob_buf b;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "phys", phys);
	blobmsg_add_u32(&b, "interval", interval);
	blobmsg_add_u32(&b, "window", window);
	blobmsg_add_u32(&b, "type", type);
	blobmsg_add_u32(&b, "mode", mode);

	ble_ubus_call("ble","discovery",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_stop(int argc, char** argv)
{
	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);

	ble_ubus_call("ble","stop",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_connect(int argc, char** argv)
{
	int ch,phy = 1,address_type = -1;
	char* address = NULL;

	struct option long_options[] ={
		{"phys",			required_argument,	NULL,	'p'},
		{"address_type",	required_argument,	NULL,	't'},
		{"address",			required_argument,	NULL,	'a'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"p:t:a:",long_options,&option_index)) != -1)
	{
		switch(ch)
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

	if(address_type < 0 || !address)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "conn_address", address);
	blobmsg_add_u32(&b, "conn_address_type", address_type);
	blobmsg_add_u32(&b, "conn_phy", phy);

	ble_ubus_call("ble","connect",&b,2,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;	
}
int cmd_disconnect(int argc, char** argv)
{
	int connection = -1;

	if(argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}else{
		connection = atoi(argv[2]);
	}

	if(connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "disconn_connection", connection);

	ble_ubus_call("ble","disconnect",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;		
}
int cmd_get_rssi(int argc, char** argv)
{
	int connection = -1;
	
	if(argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}else{
		connection = atoi(argv[2]);
	}

	if(connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "rssi_connection", connection);

	ble_ubus_call("ble","get_rssi",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_get_service(int argc, char** argv)
{
	int connection = -1;
	
	if(argc < 3)
	{
		printf(PARA_MISSING);
		return -1;
	}else{
		connection = atoi(argv[2]);
	}

	if(connection < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);

	ble_ubus_call("ble","get_service",&b,2,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_get_char(int argc, char** argv)
{
	int ch,connection = -1,service_handle = -1;

	struct option long_options[] ={
		{"connection",			required_argument,	NULL,	'c'},
		{"service_handle",		required_argument,	NULL,	'h'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"c:h:",long_options,&option_index)) != -1)
	{
		switch(ch)
		{
			case 'c':
				connection = atoi(optarg);
				break;
			case 'h':
				service_handle = atoi(optarg);
				break;
		}
	}

	if(connection < 0 || service_handle < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "get_service_connection", connection);
	blobmsg_add_u32(&b, "char_service_handle", service_handle);

	ble_ubus_call("ble","get_char",&b,2,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_set_notify(int argc, char** argv)
{
	int ch,connection = -1,char_handle = -1,flag = -1;

	struct option long_options[] ={
		{"connection",			required_argument,	NULL,	'c'},
		{"char_handle",			required_argument,	NULL,	'h'},
		{"flag",				required_argument,	NULL,	'f'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"c:h:f:",long_options,&option_index)) != -1)
	{
		switch(ch)
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

	if(connection < 0 || char_handle < 0 || flag < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}	

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_u32(&b, "notify_flag", flag);

	ble_ubus_call("ble","set_notify",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);
	
	return 0;
}
int cmd_read_value(int argc, char** argv)
{
	int ch,connection = -1,char_handle = -1;

	struct option long_options[] ={
		{"connection",			required_argument,	NULL,	'c'},
		{"char_handle",			required_argument,	NULL,	'h'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"c:h:",long_options,&option_index)) != -1)
	{
		switch(ch)
		{
			case 'c':
				connection = atoi(optarg);
				break;
			case 'h':
				char_handle = atoi(optarg);
				break;
		}
	}

	if(connection < 0 || char_handle < 0)
	{
		printf(PARA_MISSING);

		return -1;
	}	

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);

	ble_ubus_call("ble","read_char",&b,2,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);
	
	return 0;
}
int cmd_write_value(int argc, char** argv)
{
	int ch,connection = -1,char_handle = -1,res = 0;
	char* value = NULL;

	struct option long_options[] ={
		{"connection",			required_argument,	NULL,	'c'},
		{"char_handle",			required_argument,	NULL,	'h'},
		{"res",					required_argument,	NULL,	'r'},
		{"value",				required_argument,	NULL,	'v'},
		{0,	0, 0, 0}
	};
	int option_index;

	while((ch = getopt_long(argc,argv,"c:h:r:v:",long_options,&option_index)) != -1)
	{
		switch(ch)
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

	if(connection < 0 || char_handle < 0 || !value)
	{
		printf(PARA_MISSING);

		return -1;
	}	

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "char_connection", connection);
	blobmsg_add_u32(&b, "char_handle", char_handle);
	blobmsg_add_string(&b, "char_value", value);
	blobmsg_add_u32(&b, "write_res", res);

	ble_ubus_call("ble","write_char",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);
	
	return 0;	
}
int cmd_dtm_tx(int argc, char** argv)
{
	/* Default setting, PRBS9 packet payload, length 20, channel 0, phy 1M PHY*/
	int ch, packet_type = 0, length = 20, channel = 0, phy =  1;
	
	struct option long_options[] ={
			{"packet_type",			required_argument,	NULL,	't'},
			{"length",				required_argument,	NULL,	'l'},
			{"channel",				required_argument,	NULL,	'c'},
			{"phy",					required_argument,	NULL,	'p'},
			{0,	0, 0, 0}
		};
	int option_index;

	while((ch = getopt_long(argc,argv,"t:l:c:p:",long_options,&option_index)) != -1)
	{
		switch(ch)
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


	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_tx_type", packet_type);
	blobmsg_add_u32(&b, "dtm_tx_length", length);
	blobmsg_add_u32(&b, "dtm_tx_channel", channel);
	blobmsg_add_u32(&b, "dtm_tx_phy", phy);

	ble_ubus_call("ble","dtm_tx",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_dtm_rx(int argc, char** argv)
{
	/* Default setting, channel 0, phy 1M PHY*/
	int ch, channel = 0, phy =  1;
	
	struct option long_options[] ={
			{"channel",				required_argument,	NULL,	'c'},
			{"phy",					required_argument,	NULL,	'p'},
			{0,	0, 0, 0}
		};
	int option_index;

	while((ch = getopt_long(argc,argv,"c:p:",long_options,&option_index)) != -1)
	{
		switch(ch)
		{
			case 'c':
				channel = atoi(optarg);
				break;
			case 'p':
				phy = atoi(optarg);
				break;
		}
	}


	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "dtm_rx_channel", channel);
	blobmsg_add_u32(&b, "dtm_rx_phy", phy);

	ble_ubus_call("ble","dtm_rx",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
int cmd_dtm_end(int argc, char** argv)
{

	char* str = NULL;
	struct blob_buf b;
	
	blob_buf_init(&b, 0);

	ble_ubus_call("ble","dtm_end",&b,1,&str);

	if(NULL == str)
	{
		printf("Invoke Error\n");
		return -1;
	}
	printf("%s\n",str);

	free(str);

	return 0;
}
static struct {
	const char *name;
	int (*cb)(int argc, char **argv);
	char* doc;
} commands[] = {
	/* System functions */
	{"enable",                            cmd_enable,                             "Enable or disable the module"                },
	{"set_power",                         cmd_set_power,                          "Set the tx power level"                      },
  	{"local_address",                     cmd_local_address,                      "Get local Bluetooth module public address"   },
	{"listen",                     		  cmd_listen,                        	  "Listen BLE event"   							},
	/*BLE slave functions */
	{"adv_data",                          cmd_adv_data,                           "Set adv data"                                },
	{"adv",                         	  cmd_adv,                          	  "Set and Start advertising"                   },
	{"adv_stop",                          cmd_adv_stop,                           "Stop advertising"                            },
	/*BLE master functions */
	{"discovery",                         cmd_discovery,                          "Start discovery"                             },
	{"stop",                              cmd_stop,                               "End current GAP procedure"                   },
	{"connect",                           cmd_connect,                            "Open connection"                             },
	{"disconnect",                        cmd_disconnect,                         "Close connection"                            },
	{"get_rssi",                          cmd_get_rssi,                           "Get rssi of an established connection"       },
	{"get_service",                       cmd_get_service,                        "Get supported services list"                 },
	{"get_char",                          cmd_get_char,                           "Get supported characteristics in specified service"},
	{"set_notify",                        cmd_set_notify,                         "Enable or disable the notifications and indications"},
	{"read_value",                        cmd_read_value,                         "Read specified characteristic value"         },
	{"write_value",                       cmd_write_value,                        "Write characteristic value"                  },
	/*DTM test functions */
	{"dtm_tx",                       	  cmd_dtm_tx,                        	  "Start transmitter for dtm test"              },
	{"dtm_rx",                       	  cmd_dtm_rx,                        	  "Start receiver for dtm test"                 },
	{"dtm_end",                       	  cmd_dtm_end,                            "End a dtm test"                              },
	{ NULL, NULL, 0 }
};
static int usage(void)
{
	int i = 0;
	while(1)
	{
		if(commands[i].name)
		{
			printf("%-25s      %s\n",commands[i].name,commands[i].doc);
		}
		else{
			break;
		}
		i++;
	}
	return 0;
}
int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		usage();
		return -1;
	}

	int i = 0;
	while(commands[i].name)
	{
		if(strlen(commands[i].name) == strlen(argv[1]) && 0 == strcmp(commands[i].name,argv[1]))
		{
			return commands[i].cb(argc,argv);
		}
		i++;
	}
	usage();

	return 0;
}
