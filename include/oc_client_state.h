/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_CLIENT_STATE_H
#define OC_CLIENT_STATE_H

#include "messaging/coap/constants.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include <stdbool.h>
#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

typedef enum { HIGH_QOS = 0, LOW_QOS } oc_qos_t;

typedef struct
{
  oc_rep_t *payload;
  oc_status_t code;
  int observe_option;
  void *user_data;
} oc_client_response_t;

typedef enum {
  OC_STOP_DISCOVERY = 0,
  OC_CONTINUE_DISCOVERY
} oc_discovery_flags_t;

typedef oc_discovery_flags_t (*oc_discovery_handler_t)(
  const char *, const char *, oc_string_array_t, oc_interface_mask_t,
  oc_endpoint_t *, oc_resource_properties_t, void *);

typedef void (*oc_response_handler_t)(oc_client_response_t *);

typedef union oc_client_handler_s
{
  oc_response_handler_t response;
  oc_discovery_handler_t discovery;
} oc_client_handler_t;

typedef struct oc_client_cb_s
{
  struct oc_client_cb_s *next;
  oc_string_t uri;
  uint8_t token[COAP_TOKEN_LEN];
  uint8_t token_len;
  uint16_t mid;
  oc_string_t query;
  oc_endpoint_t *endpoint;
  oc_client_handler_t handler;
  void *user_data;
  bool discovery;
  int32_t observe_seq;
  oc_clock_time_t timestamp;
  oc_qos_t qos;
  oc_method_t method;
} oc_client_cb_t;

#ifdef OC_BLOCK_WISE
bool oc_ri_invoke_client_cb(void *response,
                            oc_blockwise_state_t **response_state,
                            oc_client_cb_t *cb, oc_endpoint_t *endpoint);
#else  /* OC_BLOCK_WISE */
bool oc_ri_invoke_client_cb(void *response, oc_client_cb_t *cb,
                            oc_endpoint_t *endpoint);
#endif /* !OC_BLOCK_WISE */

oc_client_cb_t *oc_ri_alloc_client_cb(const char *uri, oc_endpoint_t *endpoint,
                                      oc_method_t method, const char *query,
                                      oc_client_handler_t handler, oc_qos_t qos,
                                      void *user_data);

oc_client_cb_t *oc_ri_get_client_cb(const char *uri, oc_endpoint_t *endpoint,
                                    oc_method_t method);

oc_client_cb_t *oc_ri_find_client_cb_by_token(uint8_t *token,
                                              uint8_t token_len);

oc_client_cb_t *oc_ri_find_client_cb_by_mid(uint16_t mid);

void oc_ri_remove_client_cb_by_mid(uint16_t mid);

oc_discovery_flags_t oc_ri_process_discovery_payload(
  uint8_t *payload, int len, oc_discovery_handler_t handler,
  oc_endpoint_t *endpoint, void *user_data);

#endif /* OC_CLIENT_STATE_H */
