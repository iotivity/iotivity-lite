/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ***************************************************************************/

#ifndef OC_RI_INTERNAL_H
#define OC_RI_INTERNAL_H

#include "oc_blockwise.h"
#include "oc_endpoint.h"
#include "oc_ri.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_IF_BASELINE_STR "oic.if.baseline"
#define OC_IF_LL_STR "oic.if.ll"
#define OC_IF_B_STR "oic.if.b"
#define OC_IF_R_STR "oic.if.r"
#define OC_IF_RW_STR "oic.if.rw"
#define OC_IF_A_STR "oic.if.a"
#define OC_IF_S_STR "oic.if.s"
#define OC_IF_CREATE_STR "oic.if.create"
#define OC_IF_W_STR "oic.if.w"
#define OC_IF_STARTUP_STR "oic.if.startup"
#define OC_IF_STARTUP_REVERT_STR "oic.if.startup.revert"

// number of resources with a single instance on the whole platform
#define OC_NUM_CORE_PLATFORM_RESOURCES (OCF_CON)

// number of resources with an instance per logical device
#define OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES                                   \
  (OCF_D + 1 - OC_NUM_CORE_PLATFORM_RESOURCES)

#define OC_BASELINE_PROP_NAME "n"
#define OC_BASELINE_PROP_RT "rt"
#define OC_BASELINE_PROP_IF "if"
#define OC_BASELINE_PROP_TAG_LOCN "tag-locn"
#define OC_BASELINE_PROP_TAG_POS_REL "tag-pos-rel"
#define OC_BASELINE_PROP_TAG_POS_DESC "tag-pos-desc"
#define OC_BASELINE_PROP_FUNC_DESC "tag-func-desc"

/** Check if the code is one of the internal terminating code while
 * automatically deallocate the client_cb via the notify_client_cb_with_code
 * mechanism */
bool oc_ri_client_cb_terminated(oc_status_t code);

/**
 * @brief removes the client callback. This is silent remove client without
 * trigger 'cb.handler'.
 *
 * @param cb is oc_client_cb_t* type
 * @return returns OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_ri_remove_client_cb(void *cb);

/**
 * @brief removes the client callback with triggering OC_REQUEST_TIMEOUT to
 * handler.
 *
 * @param cb is oc_client_cb_t* type
 * @return returns OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_ri_remove_client_cb_with_notify_timeout_async(
  void *cb);

#ifdef OC_BLOCK_WISE
extern bool oc_ri_invoke_coap_entity_handler(
  void *request, void *response, oc_blockwise_state_t **request_state,
  oc_blockwise_state_t **response_state, uint16_t block2_size,
  oc_endpoint_t *endpoint);
#else  /* OC_BLOCK_WISE */
extern bool oc_ri_invoke_coap_entity_handler(void *request, void *response,
                                             uint8_t *buffer,
                                             oc_endpoint_t *endpoint);
#endif /* !OC_BLOCK_WISE */

#ifdef OC_TCP
oc_event_callback_retval_t oc_remove_ping_handler_async(void *data);
#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_INTERNAL_H */
