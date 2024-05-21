/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef OC_TCP_INTERNAL_H
#define OC_TCP_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_TCP

#include <stdint.h>
#include "messaging/coap/constants.h"
#include "port/oc_connectivity.h"
#include "oc_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_TCP_DEFAULT_RECEIVE_SIZE                                            \
  (COAP_TCP_DEFAULT_HEADER_LEN + COAP_TCP_MAX_EXTENDED_LENGTH_LEN)

/** @brief Get new tcp session ID */
uint32_t oc_tcp_get_new_session_id(void);

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

typedef struct oc_tcp_on_connect_event_s
{
  struct oc_tcp_on_connect_data_s *next;
  oc_endpoint_t endpoint;
  int state;
  on_tcp_connect_t fn;
  void *fn_data;
} oc_tcp_on_connect_event_t;

/** @brief Create TCP on connect event */
oc_tcp_on_connect_event_t *oc_tcp_on_connect_event_create(
  const oc_endpoint_t *endpoint, int state, on_tcp_connect_t fn, void *fn_data);

/** @brief Free TCP on connect event */
void oc_tcp_on_connect_event_free(oc_tcp_on_connect_event_t *event);

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

/** @brief Check if data is a valid CoAP/TLS header */
bool oc_tcp_is_valid_header(const uint8_t *data, size_t data_size, bool is_tls);

/** @brief Check if the message is a valid for CoAP TCP */
bool oc_tcp_is_valid_message(oc_message_t *message) OC_NONNULL();

/**
 * @brief Read total length from TCP or TLS header
 *
 * @param data the data
 * @param data_size size of the data
 * @param is_tls true if the data is TLS
 * @return long
 */
long oc_tcp_get_total_length_from_header(const uint8_t *data, size_t data_size,
                                         bool is_tls);

/** Convenience wrapper for oc_tcp_get_total_length_from_header */
long oc_tcp_get_total_length_from_message_header(const oc_message_t *message)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_TCP */

#endif /* OC_TCP_INTERNAL_H */
