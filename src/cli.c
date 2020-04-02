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

#include "libglbleapi.h"

#define PARA_MISSING	"parameter missing\n"


void print(json_object* obj)
{
	char* str;
	if(obj)
	{
		str = json_object_to_json_string(obj);
	}
	printf("%s\n",str);
	json_object_put(obj);
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
	gl_ble_enable(print,enable);
	
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
	gl_ble_set_power(print,power);

	return 0;
}
int cmd_local_address(int argc, char** argv)
{
	gl_ble_get_mac(print);
	return 0;
}
int cmd_listen(int argc, char** argv)
{
	gl_ble_subscribe(print);

	uloop_run();
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
	gl_ble_adv_data(print,flag,value);

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

	gl_ble_adv(print,phys,interval_min,interval_max,discover,connect);

	return 0;
}
int cmd_adv_stop(int argc, char** argv)
{	
	gl_ble_stop_adv(print);

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

	gl_ble_discovery(print,phys,interval,window,type,mode);

	return 0;
}
int cmd_stop(int argc, char** argv)
{
	gl_ble_stop(print);

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
	gl_ble_connect(print,address,address_type,phy);

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

	gl_ble_disconnect(print,connection);

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

	gl_ble_get_rssi(print,connection);

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

	gl_ble_get_service(print,connection);

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
	gl_ble_get_char(print,connection,service_handle);

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

	gl_ble_set_notify(print,connection,char_handle,flag);
	
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

	gl_ble_read_char(print,connection,char_handle);
	
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

	gl_ble_write_char(print,connection,char_handle,value,res);
	
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
  	{"local_address",                     cmd_local_address,                        "Get local Bluetooth module public address"   },
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
	uloop_init();
	gl_ble_init(NULL);

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
