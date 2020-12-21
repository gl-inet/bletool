/*****************************************************************************
 * @file 
 * @brief 
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
#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>

#define MAC_LEN 18

typedef struct {
    uint8_t addr[MAC_LEN];
} ble_addr;

int addr2str(ble_addr *adr, char* str);
int str2addr(char* str, ble_addr *address);
int str2array(uint8_t* dst, char* src, int len);
int hex2str(uint8_t* head, int len, char* value);
void reverse_endian(uint8_t* header, uint8_t length);

#endif