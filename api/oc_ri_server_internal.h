/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ***************************************************************************/

#ifndef OC_RI_SERVER_INTERNAL_H
#define OC_RI_SERVER_INTERNAL_H

#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_SERVER

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

/**
 * @brief allocate a resource structure
 *
 * @return oc_resource_t* allocated resource on success
 * @return NULL on allocation failure
 */
oc_resource_t *oc_ri_alloc_resource(void);

/**
 * @brief deallocate a resource structure
 *
 * @param resource the resource to be deallocated
 */
void oc_ri_dealloc_resource(oc_resource_t *resource) OC_NONNULL();

typedef struct oc_ri_on_delete_resource_t
{
  struct oc_ri_on_delete_resource_t *next; ///< next item
  oc_ri_delete_resource_cb_t cb;           ///< callback to be invoked
} oc_ri_on_delete_resource_t;

/**
 * @brief Find callback item in the global list associated with given callback
 *
 * @return NULL if no such item was found
 * @return oc_ri_on_delete_resource_t* found callback item
 */
oc_ri_on_delete_resource_t *oc_ri_on_delete_resource_find_callback(
  oc_ri_delete_resource_cb_t cb) OC_NONNULL();

/**
 * @brief Deallocate all items in the list of callbacks invoked by
 * oc_delayed_delete_resource.
 */
void oc_ri_on_delete_resource_remove_all(void);

/**
 * @brief Invoke all previously added callbacks with the given resource.
 *
 * @param resource resource for the callbacks (cannot be NULL)
 */
void oc_ri_on_delete_resource_invoke(oc_resource_t *resource) OC_NONNULL();

int oc_ri_handle_observation(const coap_packet_t *request,
                             coap_packet_t *response, oc_resource_t *resource,
                             bool resource_is_collection, uint16_t block2_size,
                             const oc_endpoint_t *endpoint,
                             oc_interface_mask_t iface_query) OC_NONNULL();

/** Attempt to notify all observers of the resource */
void oc_ri_notify_resource_observers(oc_resource_t *resource,
                                     oc_interface_mask_t iface_mask)
  OC_NONNULL();

/** Initialize resource interface server variables */
void oc_ri_server_init(void);

/** Reset observations */
void oc_ri_server_reset(void);

/** Deinitialize resource interface server variables */
void oc_ri_server_shutdown(void);

#endif /* OC_SERVER */

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_SERVER_INTERNAL_H */
