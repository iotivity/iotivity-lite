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

#include "oc_ri.h"
#include "oc_client_state.h"
#include "util/oc_compiler.h"

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
oc_client_cb_t *client_cb_find_by_filter(oc_client_cb_filter_t filter,
                                         const void *user_data) OC_NONNULL(1);

/**
 * @brief Deallocate client callback.
 *
 * @param cb callback to deallocate (cannot be NULL)
 */
void client_cb_free(oc_client_cb_t *cb) OC_NONNULL();

/** @brief Initialize client callbacks. */
void oc_client_cbs_init(void);

/** @brief Deinitialize client callbacks. */
void oc_client_cbs_shutdown(void);

#endif /* OC_CLIENT */

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT_CB_INTERNAL_H */
