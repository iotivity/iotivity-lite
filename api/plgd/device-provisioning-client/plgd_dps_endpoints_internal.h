/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifndef PLGD_DPS_ENDPOINTS_INTERNAL_H
#define PLGD_DPS_ENDPOINTS_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "util/oc_compiler.h"
#include "util/oc_endpoint_address_internal.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  DPS_ENDPOINT_NOT_CHANGED,
  DPS_ENDPOINT_CHANGED,
};

/**
 * @brief Sets endpoint to DPS.
 *
 * @param ctx dps context (cannot be NULL)
 * @param endpoint endpoint of the provisioning server (cannot be NULL)
 * @param endpoint_len length of \p endpoint
 * @param notify notify observers
 * @return -1 on error
 * @return DPS_ENDPOINT_NOT_CHANGED if endpoint was not changed
 * @return DPS_ENDPOINT_CHANGED if endpoint was changed
 */
int dps_set_endpoint(plgd_dps_context_t *ctx, const char *endpoint,
                     size_t endpoint_len, bool notify) OC_NONNULL();

/** Set DPS endpoint list and select one endpoint to be used by DPS
 *
 * @param ctx DPS context (cannot be NULL)
 * @param selected_endpoint selected endpoint address (cannot be NULL)
 * @param selected_endpoint_name name associated with the selected endpoint
 * @param endpoints list of available endpoints
 * @return true on success
 * @return false on failure
 */
bool dps_set_endpoints(plgd_dps_context_t *ctx,
                       const oc_string_t *selected_endpoint,
                       const oc_string_t *selected_endpoint_name,
                       const oc_rep_t *endpoints) OC_NONNULL(1, 2);

/** Initialize DPS endpoints
 *
 * @param eas endpoint addresses to initialize (cannot be NULL)
 * @param on_selected_change callback invoked when the selected endpoint changes
 * @param on_selected_change_data data passed to the on_selected_change callback
 * @return true on success
 * @return false on failure
 */
bool dps_endpoints_init(
  oc_endpoint_addresses_t *eas,
  on_selected_endpoint_address_change_fn_t on_selected_change,
  void *on_selected_change_data) OC_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_ENDPOINTS_INTERNAL_H */
