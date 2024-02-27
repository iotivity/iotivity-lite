
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

#include "util/oc_features.h"

#ifdef OC_CLOUD

#include "api/cloud/oc_cloud_endpoints_internal.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_memb.h"

#include <assert.h>
#include <string.h>

// max two endpoint addresses per device with static allocation
OC_MEMB(g_cloud_endpoint_addresses_s, oc_endpoint_address_t,
        OC_CLOUD_MAX_ENDPOINT_ADDRESSES);

bool
oc_cloud_endpoint_addresses_init(
  oc_endpoint_addresses_t *ea,
  on_selected_endpoint_address_change_fn_t on_selected_change,
  void *on_selected_change_data, oc_string_view_t default_uri,
  oc_uuid_t default_id)
{
  return oc_endpoint_addresses_init(
    ea, &g_cloud_endpoint_addresses_s, on_selected_change,
    on_selected_change_data,
    oc_endpoint_address_make_view_with_uuid(default_uri, default_id));
}

#endif /* OC_CLOUD */
