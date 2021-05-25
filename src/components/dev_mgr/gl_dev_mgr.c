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

#include "gl_dev_mgr.h"

#include <json-c/json.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "gl_errno.h"
#include "gl_log.h"

ble_dev_mgr_ctx_t g_ble_dev_mgr = {0};

uint32_t HAL_TimeStamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

ble_dev_mgr_ctx_t *_ble_dev_mgr_get_ctx(void) { return &g_ble_dev_mgr; }

void ble_dev_mgr_print(void) {
    ble_dev_mgr_ctx_t *mgr_ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL, *next_node = NULL;

    log_info("\nConnected devices: \n");

    list_for_each_entry_safe(node, next_node, &mgr_ctx->dev_list, linked_list) {
        if (node != NULL) {
            log_info("dev_addr = %s, connection = %d \n",
                   node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
        } else
            log_err("No device connection\n");
    }
}

static int search_ble_dev_by_addr(char *dev_addr, ble_dev_mgr_node_t **node) {
    ble_dev_mgr_ctx_t *ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list) {
        if (!strcmp(search_node->ble_dev_desc.dev_addr, dev_addr)) {
            if (node) {
                *node = search_node;
            }
            return GL_SUCCESS;
        }
    }
    log_err("The device is not in the list");
    return GL_ERR_MSG;
}

static int search_ble_dev_by_connection(uint16_t connection,
                                 ble_dev_mgr_node_t **node) {
    ble_dev_mgr_ctx_t *ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list) {
        if (search_node->ble_dev_desc.connection == connection) {
            if (node) *node = search_node;
            return GL_SUCCESS;
        }
    }
    log_err("The device is not in the list");
    return GL_ERR_MSG;
}

int ble_dev_mgr_init(void) {
    ble_dev_mgr_ctx_t *mgr_ctx = _ble_dev_mgr_get_ctx();
    memset(mgr_ctx, 0, sizeof(ble_dev_mgr_ctx_t));

    /* Init Device List */
    INIT_LIST_HEAD(&mgr_ctx->dev_list);

    return GL_SUCCESS;
}

int ble_dev_mgr_add(char *dev_addr, uint16_t connection) 
{
    ble_dev_mgr_ctx_t *mgr_ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL;
	ble_dev_mgr_node_t *search_node = NULL;

    list_for_each_entry(search_node, &mgr_ctx->dev_list, linked_list) {
        if (!strcmp(search_node->ble_dev_desc.dev_addr, dev_addr)) {
			node = search_node;
            break;
        }
    }

	if(node == NULL)
	{
		node = malloc(sizeof(ble_dev_mgr_node_t));
		memset(node, 0, sizeof(ble_dev_mgr_node_t));

		memcpy(node->ble_dev_desc.dev_addr, dev_addr, MAC_STR_LEN);
		node->ble_dev_desc.connection = connection;

		INIT_LIST_HEAD(&node->linked_list);

		// int ret_dev_list = list_empty(&mgr_ctx->dev_list);

		list_add_tail(&node->linked_list, &mgr_ctx->dev_list);
		log_info("Device Join: dev_addr=%s, connection=%d.\n",
			node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
	}else{
		node->ble_dev_desc.connection = connection;
		log_info("Device update: dev_addr=%s, connection=%d.\n",
			node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
	}

    return GL_SUCCESS;
}

int ble_dev_mgr_del(uint16_t connection) {
    ble_dev_mgr_node_t *node = NULL;

    if (connection == 0) {
        log_err("Connection is null");
        return GL_ERR_PARAM;
    }
    if (search_ble_dev_by_connection(connection, &node) != 0) {
        log_err("The device is not in the list");
        return GL_ERR_MSG;
    }

    list_del(&node->linked_list);

    log_info("Device Leave: dev_addr=%s, connection=%d\n",
             node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
    free(node);

    return GL_SUCCESS;
}

uint16_t ble_dev_mgr_get_address(uint16_t connection, char **mac) {
    ble_dev_mgr_node_t *node = NULL;

    if (connection == 0) {
        log_err("Connection is null");
        return GL_ERR_PARAM;
    }
    if (search_ble_dev_by_connection(connection, &node) != 0) {
        log_err("The device is not in the list");
        return GL_ERR_MSG;
    }

	*mac = node->ble_dev_desc.dev_addr;
    return GL_SUCCESS;
}

uint16_t ble_dev_mgr_get_connection(char *dev_addr, int* connection) {
    ble_dev_mgr_node_t *node = NULL;

    if (dev_addr == NULL) {
        log_err("Address is null");
        return GL_ERR_PARAM;
    }

    if (search_ble_dev_by_addr(dev_addr, &node) != 0) {
        log_err("The device is not in the list");
        return GL_ERR_MSG;
    }

	*connection = node->ble_dev_desc.connection;
    return GL_SUCCESS;
}

int ble_dev_mgr_get_list_size(void) {
    int index = 0;
    ble_dev_mgr_ctx_t *ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL;

    list_for_each_entry(node, &ctx->dev_list, linked_list) { index++; }

    return index;
}

int ble_dev_mgr_update(uint16_t connection) {
    ble_dev_mgr_node_t *node = NULL;

    if (search_ble_dev_by_connection(connection, &node) != 0) {
        return -1;
    }
    node->ble_dev_desc.connection = connection;

    return GL_SUCCESS;
}

int ble_dev_mgr_del_all(void)
{
    log_err("ble_dev_mgr_del_all\n");
    ble_dev_mgr_ctx_t *mgr_ctx = _ble_dev_mgr_get_ctx();
    ble_dev_mgr_node_t *node = NULL;

    list_for_each_entry_safe(node, next_node, &mgr_ctx->dev_list, linked_list) {
        log_err("Del node: %s, connection=%d\n", node->ble_dev_desc.dev_addr, node->ble_dev_desc.connection);
        list_del(&node->linked_list);
        free(node);
    }

    return GL_SUCCESS;
}