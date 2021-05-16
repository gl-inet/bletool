/*****************************************************************************
 * @file  hal.c
 * @brief Hardware interface adaptation
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

#include "gl_uart.h"
#include <uci.h>
#include "gl_log.h"
#include "gl_hal.h"

unsigned char ENDIAN;

char rston[64] = {0};
char rstoff[64] = {0};

struct uci_context* guci2_init();
int guci2_free(struct uci_context* ctx);
int guci2_get(struct uci_context* ctx, const char* section_or_key, char value[]);


static int check_endian(void)
{
  int x = 1;
  if(*((char *)&x) == 1) 
  {
	ENDIAN = 0;   //little endian
	log_debug("little endian\n");
  }else{
	ENDIAN = 1;   //big endian
	log_debug("big endian\n");
  }

  return 0;
}
static int serial_init(void)
{
    char uart_port[64] = {0};
    uint32_t baud_rate;
    uint32_t flowcontrol;

    struct uci_context* ctx = guci2_init();
    char value[64] = {0};

    /*Init port*/
    if(guci2_get(ctx,"ble.@bleserial[0].port",value) < 0)
    {
        fprintf(stderr,"BLE: serial config missing.\n");
        return -1;
    }
    strcpy(uart_port,value);
    memset(value,0,64);

    /*Init baudrate*/
    if(guci2_get(ctx,"ble.@bleserial[0].baudrate",value) < 0)
    {
        fprintf(stderr,"BLE: serial config missing.\n");
        return -1;
    }
    baud_rate = atoi(value);
    memset(value,0,64);

    /*Init flowcontrol*/
    if(guci2_get(ctx,"ble.@bleserial[0].flowcontrol",value) < 0)
    {
        fprintf(stderr,"BLE: serial config missing.\n");
        return -1;
    }
    flowcontrol = atoi(value);
    memset(value,0,64);

    /*Init rston*/
    if(guci2_get(ctx,"ble.@bleserial[0].rston",value) < 0)
    {
        fprintf(stderr,"BLE: serial config missing.\n");
        return -1;
    }
    strcpy(rston,value);
    memset(value,0,64);

    /*Init rstoff*/
    if(guci2_get(ctx,"ble.@bleserial[0].rstoff",value) < 0)
    {
        fprintf(stderr,"BLE: serial config missing.\n");
        return -1;
    }
    strcpy(rstoff,value);

    guci2_free(ctx);

    return uartOpen((int8_t*)uart_port, baud_rate, flowcontrol, 100);
}

int hal_init(void)
{
    check_endian();

    int serialFd = serial_init();
    if( serialFd < 0 )
    {
        fprintf(stderr,"Hal initilized failed.\n");
        exit(1);
    }

	// reset module
	system(rstoff); 
	usleep(500000);
	system(rston); 

    return serialFd;
}

struct uci_context* guci2_init()
{
	
	struct uci_context* ctx = uci_alloc_context();
		
	return ctx;
}

int guci2_free(struct uci_context* ctx)
{
	uci_free_context(ctx);
	return 0;
}

static const char *delimiter = " ";

static void uci_show_value(struct uci_option *o, char value[]){
	struct uci_element *e;
	bool sep = false;
//	char *space;

	switch(o->type) {
	case UCI_TYPE_STRING:
		sprintf(value,"%s", o->v.string);
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			sprintf(value,"%s", (sep ? delimiter : ""));
			//space = strpbrk(e->name, " \t\r\n");
			//if (!space )
				sprintf(value,"%s", e->name);
			//sep = true;
		}
		break;
	default:
		strcpy(value,"");
		break;
	}
}

int guci2_get(struct uci_context* ctx, const char* section_or_key, char value[])
{
	struct uci_ptr ptr;
	struct uci_element *e;
	int ret = UCI_OK;
	char *str=(char*)malloc(strlen(section_or_key)+1); //must not use a const value
	strcpy(str,section_or_key);
	if (uci_lookup_ptr(ctx, &ptr, str, true) != UCI_OK) {
		ret=-1;
		strcpy(value,"");
		goto out;
	}
	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		ctx->err = UCI_ERR_NOTFOUND;
		ret=-1;
		strcpy(value,"");
		goto out;
	}
	e = ptr.last;
	switch(e->type) {
	case UCI_TYPE_SECTION:
		sprintf(value,"%s", ptr.s->type);
		break;
	case UCI_TYPE_OPTION:
		uci_show_value(ptr.o, value);
		break;
	default:
		strcpy(value,"");
		ret=-1;
		goto out;
		break;
	}
out:
	free(str);
	return ret;
}