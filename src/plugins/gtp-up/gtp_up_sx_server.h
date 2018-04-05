/*
 * Copyright(c) 2017 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _GTP_UP_SX_SERVER_H
#define _GTP_UP_SX_SERVER_H

#include <time.h>
#include "pfcp.h"

typedef struct
{
  u32 fib_index;

  struct {
    ip46_address_t address;
    u16 port;
  } rmt;

  struct {
    ip46_address_t address;
    u16 port;
  } lcl;

  union {
    u8 * data;
    pfcp_header_t * hdr;
  };
} sx_msg_t;

always_inline void sx_msg_free (sx_msg_t * m)
{
  if (m)
    vec_free(m->data);
  clib_mem_free(m);
}

typedef struct
{
  u64 node_index;

  /* Sx Node Id is either IPv4, IPv6 or FQDN */
  u8 * node_id;
} sx_node_t;

typedef struct
{
  u32 node_index;               /**< process node index for evnt scheduling */
  time_t start_time;
  ip46_address_t address;

  vlib_main_t *vlib_main;
} sx_server_main_t;

extern sx_server_main_t sx_server_main;

extern vlib_node_registration_t sx4_input_node;
extern vlib_node_registration_t sx6_input_node;

#define UDP_DST_PORT_SX 8805

void gtp_up_sx_send_data (sx_msg_t * msg);
void gtp_up_sx_server_notify (sx_msg_t * msg);

void gtp_up_sx_handle_input (vlib_main_t * vm, vlib_buffer_t *b, int is_ip4);

clib_error_t * sx_server_main_init (vlib_main_t * vm);

#endif /* _GTP_UP_SX_SERVER_H */
