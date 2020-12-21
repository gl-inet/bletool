#include <stdint.h>
#include <stdio.h>
#include "common.h"

int addr2str(ble_addr* adr, char* str) {
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", adr->addr[5], adr->addr[4],
            adr->addr[3], adr->addr[2], adr->addr[1], adr->addr[0]);
    return 0;
}

int str2addr(char* str, ble_addr* address) {
    int mac[6];
    sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[5], &mac[4], &mac[3],
           &mac[2], &mac[1], &mac[0]);
    int i = 0;
    while (i < 6) {
        address->addr[i] = mac[i];
        i++;
    }
    return 0;
}

int str2array(uint8_t* dst, char* src, int len) {
    int i = 0;
    int tmp;
    while (i < len) {
        sscanf(src + i * 2, "%02x", &tmp);
        dst[i] = tmp;
        i++;
    }
    return 0;
}
int hex2str(uint8_t* head, int len, char* value) {
    int i = 0;
    while (i < len) {
        sprintf(value + i * 2, "%02x", head[i]);
        i++;
    }
    return 0;
}

void reverse_endian(uint8_t* header, uint8_t length) {
    uint8_t* tmp = (uint8_t*)malloc(length);
    memcpy(tmp, header, length);
    int i = length - 1;
    int j = 0;
    for (; i >= 0; i--, j++) {
        *(header + j) = *(tmp + i);
    }
    free(tmp);
    return;
}
