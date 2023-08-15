/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 *
 ******************************************************************/

#ifndef IP_H
#define IP_H

#include "oc_endpoint.h"
#include "port/oc_connectivity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

ssize_t oc_ip_send_msg(int sock, struct sockaddr_storage *receiver,
                       const oc_message_t *message);

int oc_ip_recv_msg(int sock, uint8_t *recv_buf, long recv_buf_size,
                   oc_endpoint_t *endpoint, bool multicast);

#ifdef __cplusplus
}
#endif

#endif /* IP_H */
