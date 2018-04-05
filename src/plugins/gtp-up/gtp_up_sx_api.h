/*
 * Copyright(c) 2018 Travelping GmbH.
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

#ifndef _GTP_UP_SX_ERL_H
#define _GTP_UP_SX_ERL_H

#include <vppinfra/types.h>
#include "gtp_up_sx_server.h"

#define PRIsMAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define ARGsMAC(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

int gtp_up_sx_handle_msg(sx_msg_t * msg);

u8 * format_ipfilter(u8 * s, va_list * args);

#endif /* _GTP_UP_SX_ERL_H */
