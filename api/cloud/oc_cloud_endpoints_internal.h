/******************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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
 ******************************************************************/

#ifndef OC_CLOUD_ENDPOINTS_INTERNAL_H
#define OC_CLOUD_ENDPOINTS_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_uuid.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_CLOUD_MAX_ENDPOINT_ADDRESSES
// max two endpoint addresses per device with static allocation
#define OC_CLOUD_MAX_ENDPOINT_ADDRESSES (2 * OC_MAX_NUM_DEVICES)
#endif /* OC_CLOUD_MAX_ENDPOINT_ADDRESSES */

/** Initialize cloud server endpoint addresses */
bool oc_cloud_endpoint_addresses_init(
  oc_endpoint_addresses_t *ea,
  on_selected_endpoint_address_change_fn_t on_selected_change,
  void *on_selected_change_data, oc_string_view_t default_uri,
  oc_uuid_t default_id) OC_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_ENDPOINTS_INTERNAL_H */
