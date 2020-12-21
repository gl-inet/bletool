/*****************************************************************************
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
#include <sys/time.h>
#include <time.h>
#include <json-c/json.h>
#include "ble_dev_mgr.h"
#include "infra_log.h"

ble_dev_mgr_ctx_t g_ble_dev_mgr = {0};

uint32_t HAL_TimeStamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

 ble_dev_mgr_ctx_t *_ble_dev_mgr_get_ctx(void)
{
    return &g_ble_dev_mgr;
}

void ble_dev_mgr_print(void)
{
    ble_dev_mgr_ctx_t* mgr_ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t* node = NULL, *next_node = NULL;

    printf("\nConnected devices: \n");

    list_for_each_entry_safe( node, next_node, &mgr_ctx->dev_list, linked_list )
    {
        if ( node != NULL ) 
        {
            
            printf("dev_addr = %s, connection = %d \n", node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection );
        }
        else
            printf("No device connection\n");
    }
}

static int search_ble_dev_by_addr(char *dev_addr, ble_dev_mgr_node_t **node)
{
    ble_dev_mgr_ctx_t *ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list)
    {
        if (!strcmp(search_node->ble_dev_desc.dev_addr, dev_addr))
        {
            if (node)
            {
                *node = search_node;
            }
            return 0;
        }
    }
    return -1;
}

int ble_dev_mgr_init(void)
{
    ble_dev_mgr_ctx_t * mgr_ctx = _ble_dev_mgr_get_ctx();
    memset(mgr_ctx, 0, sizeof(ble_dev_mgr_ctx_t));

    /* Init Device List */
    INIT_LIST_HEAD(&mgr_ctx->dev_list);

    return 0;
}

int ble_dev_mgr_add(char *dev_addr, uint16_t connection)
{
    ble_dev_mgr_ctx_t *mgr_ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL;

    node = malloc(sizeof(ble_dev_mgr_node_t));
    memset(node, 0, sizeof(ble_dev_mgr_node_t));

    memcpy(node->ble_dev_desc.dev_addr, dev_addr, DEVICE_MAC_LEN);
    node->ble_dev_desc.connection = connection;

    INIT_LIST_HEAD(&node->linked_list);

    int ret_dev_list = list_empty(&mgr_ctx->dev_list);
    
    list_add_tail(&node->linked_list, &mgr_ctx->dev_list);
    printf("Device Join: dev_addr=%s, connection=%d.\n", node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
        
    return 0;
}

int search_ble_dev_by_connection( uint16_t connection, ble_dev_mgr_node_t** node)
{
    ble_dev_mgr_ctx_t* ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t* search_node = NULL;
    // printf("45\n");
    list_for_each_entry(search_node, &ctx->dev_list, linked_list)
    {
        if (search_node->ble_dev_desc.connection == connection)
        {
            if (node)
                *node = search_node;
            return 0;
        }
    }
    return -1;
}

int ble_dev_mgr_del(uint16_t connection)
{
    ble_dev_mgr_node_t *node = NULL;

    if (connection == 0)
    {
        return -1;
    }
    if (search_ble_dev_by_connection(connection, &node) != 0)
    {
        return -1;
    }

    list_del(&node->linked_list);

    printf("Device Leave: dev_addr=%s, connection=%d\n",node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);

    // ble_dev_mgr_print();

    free(node);

    return 0;
}

char *ble_dev_mgr_get_address(uint16_t connection)
{
    ble_dev_mgr_node_t* node = NULL;

    if (connection == 0)
    {
        return NULL;
    }
    // printf("1454\n");
    if ( search_ble_dev_by_connection(connection, &node) != 0)
    {
        return NULL;
    }
    return node->ble_dev_desc.dev_addr;
}

uint16_t ble_dev_mgr_get_connection(char *dev_addr)
{
    printf("get connection!!!\n");
    ble_dev_mgr_node_t* node = NULL;

    if (dev_addr == NULL)
    {
        printf("address is null\n");
        return -1;
    }

    printf("dev_addr: %s\n", dev_addr);

    if(search_ble_dev_by_addr(dev_addr, &node) != 0)
    {
        printf("55\n");
        return -1;
    }
    printf("connection is %d\n", node->ble_dev_desc.connection);

    return node->ble_dev_desc.connection;
}

int ble_dev_mgr_get_list_size(void) 
{
    int index = 0;
    ble_dev_mgr_ctx_t *ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL;

    list_for_each_entry(node, &ctx->dev_list, linked_list)
    {
        index++;
    }

    return index;
}

int ble_dev_mgr_update(uint16_t connection)
{
    ble_dev_mgr_node_t* node = NULL;

    if (search_ble_dev_by_connection(connection, &node) != 0) {
        return -1;
    }
    node->ble_dev_desc.connection = connection;

    return 0;
}

/* Device Management.*/
void add_device_to_list(json_object *o)
{
    // printf("add_device_to_list\n");
	/* get mac */
	char *str_mac = NULL;
	json_object *json_mac = json_object_object_get(o, "address");
	if (json_mac)
	{
		str_mac = json_object_get_string(json_mac);
	}
	else
	{
		strcpy(str_mac, "mac is missing");
	}

	/* get connection */
	uint16_t connection;
	json_object *json_connection = json_object_object_get(o, "connection");
	if (json_connection)
	{
		connection = json_object_get_int(json_connection);
	}
	else
	{
		connection = 0;
	}

	if (str_mac && (connection != 0))
	{
		ble_dev_mgr_add(str_mac, connection);
	} else {
		printf("Failed to add device\n");
	}

	return;
}

void delete_device_from_list(json_object *o)
{
	uint16_t connection;
	json_object *json_connection = json_object_object_get(o, "connection");

	
	if (json_connection)
	{
		connection = json_object_get_int(json_connection);
	}
	else
	{
		return;
	}

	if (connection)
	{
		ble_dev_mgr_del(connection);
	}

	return;
}

void update_device_list(json_object* o)
{
    printf("update_device_list\n");
    uint16_t connection = 0;
    json_object* json_connection = json_object_object_get(o, "connection");
    if (json_connection) {
        connection = (uint16_t)json_object_get_int(json_connection);
    } else {
        json_object_put(o);
        o = NULL;
        return;
    }
    
    if (connection == 0)  {
        json_object_put(o);
        o = NULL;
        return;
    }

    ble_dev_mgr_update(connection);
    log_debug("device list update!!!!\n");
}