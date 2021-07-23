/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef TCP_ADAPTER_H
#define TCP_ADAPTER_H

#include "ipcontext.h"
#include "port/oc_connectivity.h"
#include <sys/select.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int oc_tcp_connectivity_init(ip_context_t *dev);

    void oc_tcp_connectivity_shutdown(ip_context_t *dev);

    int oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                           const struct sockaddr_storage *receiver);

    void oc_tcp_add_socks_to_fd_set(ip_context_t *dev);

    void oc_tcp_set_session_fds(fd_set *fds);

    adapter_receive_state_t oc_tcp_receive_message(ip_context_t *dev, fd_set *fds,
                                                   oc_message_t *message);

    void oc_tcp_end_session(ip_context_t *dev, oc_endpoint_t *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* TCP_ADAPTER_H */
