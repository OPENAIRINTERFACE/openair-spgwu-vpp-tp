/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
    udp gtp_up_sx server
*/

#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include <vppinfra/bihash_vec8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#include "gtp_up_sx_server.h"
#include "gtp_up_sx_api.h"

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

typedef enum
{
  EVENT_RX = 1,
  EVENT_NOTIFY,
} sx_process_event_t;

sx_server_main_t sx_server_main;

#define MAX_HDRS_LEN    100	/* Max number of bytes for headers */

void gtp_up_sx_send_data (sx_msg_t * msg)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_free_list_t *fl;
  vlib_buffer_t *b0 = 0;
  u32 to_node_index;
  vlib_frame_t *f;
  u32 bi0 = ~0;
  u32 *to_next;
  u8 * data0;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      clib_warning ("can't allocate buffer for Sx send event");
      return;
    }

  b0 = vlib_get_buffer (vm, bi0);
  fl =
    vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (b0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  b0->error = 0;
  b0->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b0->current_data = 0;
  b0->total_length_not_including_first_buffer = 0;

  data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);
  clib_memcpy(data0, msg->data, _vec_len(msg->data));
  b0->current_length = _vec_len(msg->data);

  vlib_buffer_push_udp (b0, msg->lcl.port, msg->rmt.port, 1);
  if (ip46_address_is_ip4(&msg->rmt.address))
    {
      vlib_buffer_push_ip4 (vm, b0, &msg->lcl.address.ip4, &msg->rmt.address.ip4,
			    IP_PROTOCOL_UDP, 1);
      to_node_index = ip4_lookup_node.index;
    }
  else
    {
      ip6_header_t *ih;
      ih = vlib_buffer_push_ip6 (vm, b0, &msg->lcl.address.ip6, &msg->rmt.address.ip6,
				 IP_PROTOCOL_UDP);
      vnet_buffer (b0)->l3_hdr_offset = (u8 *) ih - b0->data;
      to_node_index = ip6_lookup_node.index;
    }

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = msg->fib_index;

  f = vlib_get_frame_to_node (vm, to_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, to_node_index, f);
}

static uword
sx_process (vlib_main_t * vm,
	    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  while (1)
    {
      uword event_type, *event_data = 0;

      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case EVENT_RX:
	  {
	    for (int i = 0; i < vec_len (event_data); i++)
	      {
		sx_msg_t * msg = (sx_msg_t *)event_data[i];

		gtp_up_sx_handle_msg(msg);
		sx_msg_free(msg);
	      }
	    break;
	  }

	case EVENT_NOTIFY:
	  {
	    for (int i = 0; i < vec_len (event_data); i++)
	      {
		sx_msg_t * msg = (sx_msg_t *)event_data[i];

		gtp_up_sx_send_data(msg);
		sx_msg_free(msg);
	      }
	    break;
	  }
#if 0
	case 2:         /* Stop and Wait for kickoff again */
	  timeout = 1e9;
	  break;
	case 1:         /* kickoff : Check for unsent buffers */
	  timeout = THREAD_PERIOD;
	  break;
#endif
	case ~0:                /* timeout */
	  gtp_debug ("timeout....");
	  break;
	default:
	  gtp_debug ("event %ld, %p. ", event_type, event_data[0]);
	  break;
	}

      vec_free (event_data);
    }

  return (0);
}

void gtp_up_sx_handle_input (vlib_main_t * vm, vlib_buffer_t *b, int is_ip4)
{
  sx_server_main_t *sx = &sx_server_main;
  udp_header_t *udp;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  sx_msg_t * msg;
  u8 * data;

  /* signal Sx process to handle data */
  msg = clib_mem_alloc_no_fail(sizeof(sx_msg_t));
  memset(msg, 0, sizeof(sx_msg_t));
  msg->fib_index = vnet_buffer (b)->ip.fib_index;

  /* udp_local hands us a pointer to the udp data */
  data = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (data - sizeof (*udp));

  if (is_ip4)
    {
      /* $$$$ fixme: udp_local doesn't do ip options correctly anyhow */
      ip4 = (ip4_header_t *) (((u8 *) udp) - sizeof (*ip4));
      ip_set(&msg->lcl.address, &ip4->dst_address, is_ip4);
      ip_set(&msg->rmt.address, &ip4->src_address, is_ip4);
    }
  else
    {
      ip6 = (ip6_header_t *) (((u8 *) udp) - sizeof (*ip6));
      ip_set(&msg->lcl.address, &ip6->dst_address, is_ip4);
      ip_set(&msg->rmt.address, &ip6->src_address, is_ip4);
    }

  msg->lcl.port = udp->dst_port;
  msg->rmt.port = udp->src_port;

  msg->data = vec_new(u8, vlib_buffer_length_in_chain (vm, b));
  vlib_buffer_contents (vm, vlib_get_buffer_index (vm, b), msg->data);

  gtp_debug ("sending event %p %U:%d - %U:%d, data %p", msg,
		format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
		clib_net_to_host_u16(msg->rmt.port),
		format_ip46_address, &msg->lcl.address, IP46_TYPE_ANY,
		clib_net_to_host_u16(msg->lcl.port),
		msg->data);

  vlib_process_signal_event_mt(vm, sx->node_index, EVENT_RX, (uword)msg);
}

void
gtp_up_sx_server_notify(sx_msg_t * msg)
{
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;

  gtp_debug ("sending NOTIFY event %p", msg);
  vlib_process_signal_event_mt(vm, sx->node_index, EVENT_NOTIFY, (uword)msg);
}

/*********************************************************/

clib_error_t *
sx_server_main_init (vlib_main_t * vm)
{
  sx_server_main_t *sx = &sx_server_main;
  clib_error_t *error;
  vlib_node_t *n;

  if ((error = vlib_call_init_function (vm, vnet_interface_cli_init)))
    return error;

  sx->vlib_main = vm;
  sx->start_time = time(NULL);

  static vlib_node_registration_t r = {
    .name = "sx-api",
    .function = sx_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .process_log2_n_stack_bytes = 16,
    .runtime_data_bytes = sizeof (void *),
  };

  vlib_register_node (vm, &r);
  n = vlib_get_node (vm, r.index);
  sx->node_index = n->index;

  vlib_start_process (vm, n->runtime_index);

  udp_register_dst_port (vm, UDP_DST_PORT_SX,
			 sx4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_SX,
			 sx6_input_node.index, /* is_ip4 */ 0);

  gtp_debug ("PFCP: start_time: %p, %d, %x.", sx, sx->start_time, sx->start_time);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
