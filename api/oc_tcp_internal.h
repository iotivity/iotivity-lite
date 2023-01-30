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

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

#include "port/oc_connectivity.h"
#include "oc_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#endif /* OC_TCP_INTERNAL_H */
