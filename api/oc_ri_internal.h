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

#include "messaging/coap/oc_coap.h"
#include "messaging/coap/engine_internal.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "util/oc_features.h"

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
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
#define PLGD_IF_ETAG_STR "x.plgd.if.etag"
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */

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

typedef struct oc_response_buffer_s
{
  uint8_t *buffer;
  size_t buffer_size;
  size_t response_length;
  coap_status_t code;
  oc_content_format_t content_format;
#ifdef OC_HAS_FEATURE_ETAG
  oc_coap_etag_t etag;
#endif /* OC_HAS_FEATURE_ETAG */
} oc_response_buffer_t;

struct oc_response_s
{
  oc_separate_response_t *separate_response; ///< seperate response
  oc_response_buffer_t *response_buffer;     ///< response buffer
};

/**
 * @brief initialize the resource implementation handler
 */
void oc_ri_init(void);

/**
 * @brief shut down the resource implementation handler
 */
void oc_ri_shutdown(void);

/** @brief Unchecked conversion from a non-error oc_status_t to coap_status_t */
coap_status_t oc_status_code_unsafe(oc_status_t key);

/** @brief Check if given method is supported by the interface */
bool oc_ri_interface_supports_method(oc_interface_mask_t iface,
                                     oc_method_t method);

#ifdef OC_HAS_FEATURE_ETAG

/** @brief Get ETag for given resource */
uint64_t oc_ri_get_etag(const oc_resource_t *resource) OC_NONNULL();

/**
 * @brief Calculate batch ETag for the discovery or a collection resource.
 *
 * The discovery resource and a collection batch ETag are calculated as the
 * maximum of the parent resource ETag and the ETag of all resources contained
 * in the batch response.
 *
 * @param resource parent resource (cannot be NULL)
 * @param endpoint endpoint to verify access to a resource contained by the
 * parent (for SECURE builds, cannot be NULL)
 * @param device device index
 * @return uint64_t ETag value
 */
uint64_t oc_ri_get_batch_etag(const oc_resource_t *resource,
                              const oc_endpoint_t *endpoint, size_t device)
  OC_NONNULL();

#endif /* OC_HAS_FEATURE_ETAG */

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

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_INTERNAL_H */
