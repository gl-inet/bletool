#include "host_gecko.h"

#ifndef BGLIB_QUEUE_LEN
#define BGLIB_QUEUE_LEN 30
#endif

#define BGLIB_DEFINE()                                      \
  struct gecko_cmd_packet _gecko_cmd_msg;                   \
  struct gecko_cmd_packet _gecko_rsp_msg;                   \
  struct gecko_cmd_packet *gecko_cmd_msg = &_gecko_cmd_msg; \
  struct gecko_cmd_packet *gecko_rsp_msg = &_gecko_rsp_msg; \
  int32_t (*bglib_output)(uint32_t len1, uint8_t* data1);      \
  int32_t (*bglib_input)(uint32_t len1, uint8_t* data1);    \
  int32_t (*bglib_peek)(void);                              \
  struct gecko_cmd_packet gecko_queue[BGLIB_QUEUE_LEN];     \
  int    gecko_queue_w = 0;                                 \
  int    gecko_queue_r = 0;

extern struct gecko_cmd_packet gecko_queue[BGLIB_QUEUE_LEN];
extern int    gecko_queue_w;
extern int    gecko_queue_r;

#define BGLIB_INITIALIZE(OFUNC, IFUNC) bglib_output = OFUNC; bglib_input = IFUNC; bglib_peek = NULL;

int wait_rsp_evt(uint32_t *evt_id, uint8_t evt_num, uint32_t timeout);
