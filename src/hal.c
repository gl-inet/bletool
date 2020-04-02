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

#include "uart.h"
#include <gl/debug.h>
#include "hal.h"

unsigned char ENDIAN;
extern char rston[];
extern char rstoff[];


static int check_endian(void)
{
  int x = 1;
  if(*((char *)&x) == 1) ENDIAN = 0;   //little endian
  else ENDIAN = 1;   //big endian
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
    return serialFd;
}
