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

#include "messaging/coap/engine.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"

#include <stdbool.h>
#include <stddef.h>
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

/**
 * @brief initialize the resource implementation handler
 */
void oc_ri_init(void);

/**
 * @brief shut down the resource implementation handler
 */
void oc_ri_shutdown(void);

/**
 * @brief free the properties of the resource
 *
 * @param resource the resource (cannot be NULL)
 */
void oc_ri_free_resource_properties(oc_resource_t *resource) OC_NONNULL();

/**
 * @brief Check if given URI is in use by given device
 *
 * @param device index of device
 * @param uri URI to check (cannot be NULL)
 * @param uri_len length of URI
 *
 * @return true if URI is in use
 * @return false otherwise
 */
bool oc_ri_URI_is_in_use(size_t device, const char *uri, size_t uri_len)
  OC_NONNULL();

/** @brief Handle a coap request. */
bool oc_ri_invoke_coap_entity_handler(coap_make_response_ctx_t *ctx,
                                      oc_endpoint_t *endpoint, void *user_data)
  OC_NONNULL(1, 2);

#ifdef OC_TCP
oc_event_callback_retval_t oc_remove_ping_handler_async(void *data);
#endif /* OC_TCP */

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_INTERNAL_H */
