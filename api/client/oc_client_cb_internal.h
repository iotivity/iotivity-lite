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

#ifndef OC_CLIENT_CB_INTERNAL_H
#define OC_CLIENT_CB_INTERNAL_H

#include "messaging/coap/coap_internal.h"
#include "oc_client_state.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_CLIENT

/**
 * @brief Client callback filtering function.
 *
 * @param cb callback to check
 * @param user_data user data passed from the caller
 * @return true if the callback matches the filter
 * @return false otherwise
 */
typedef bool (*oc_client_cb_filter_t)(const oc_client_cb_t *cb,
                                      const void *user_data) OC_NONNULL(1);

/**
 * @brief Find a client callback by a filtering function.
 *
 * @param filter filterning function (cannot be NULL)
 * @param user_data custom user data passed to the filtering function
 * @return NULL if not element matches the filter
 * @return oc_client_cb_t * the first element that matches the filter
 */
oc_client_cb_t *oc_client_cb_find_by_filter(oc_client_cb_filter_t filter,
                                            const void *user_data)
  OC_NONNULL(1);

/**
 * @brief Remove callback from global list and deallocate.
 *
 * @param cb callback to deallocate (cannot be NULL)
 */
void oc_client_cb_free(oc_client_cb_t *cb) OC_NONNULL();

#ifdef OC_BLOCK_WISE
/**
 * @brief invoke the Client callback when a response is received
 *
 * @param response the response
 * @param response_state the state of the blockwise transfer
 * @param cb the callback
 * @param endpoint the endpoint
 * @return true
 * @return false
 */
bool oc_client_cb_invoke(const coap_packet_t *response,
                         oc_blockwise_state_t **response_state,
                         oc_client_cb_t *cb, oc_endpoint_t *endpoint)
  OC_NONNULL();
#else  /* !OC_BLOCK_WISE */
/**
 * @brief invoke the Client callback when a response is received
 *
 * @param response the response
 * @param cb the callback
 * @param endpoint the endpoint
 * @return true
 * @return false
 */
bool oc_client_cb_invoke(const coap_packet_t *response, oc_client_cb_t *cb,
                         oc_endpoint_t *endpoint) OC_NONNULL();
#endif /* OC_BLOCK_WISE */

/** @brief Initialize client callbacks. */
void oc_client_cbs_init(void);

/** @brief Deinitialize client callbacks. */
void oc_client_cbs_shutdown(void);

/** @brief Initialize multicast client callbacks. */
void oc_client_cbs_shutdown_multicasts(void);

/**
 * @brief Removes the client callback. This is silent remove client without
 * triggering of 'cb.handler'.
 *
 * @param cb is oc_client_cb_t* type
 * @return OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_client_cb_remove_async(void *cb);

/**
 * @brief removes the client callback with triggering OC_REQUEST_TIMEOUT to
 * handler.
 *
 * @param cb is oc_client_cb_t* type
 * @return OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_client_cb_remove_with_notify_timeout_async(
  void *cb);

#endif /* OC_CLIENT */

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT_CB_INTERNAL_H */
