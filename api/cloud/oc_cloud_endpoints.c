
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
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
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

bool
oc_cloud_endpoint_addresses_set(oc_endpoint_addresses_t *ea,
                                const oc_string_t *selected_uri,
                                oc_uuid_t selected_uuid,
                                oc_endpoint_addresses_rep_t srep)
{
  // cannot call oc_endpoint_addresses_reinit, because the deinit might
  // deallocate oc_string_t values and relocate memory, thus invalidating the
  // oc_string_view created from selected_uri
  oc_endpoint_addresses_deinit(ea);
  oc_string_view_t cis = oc_string_view2(selected_uri);
  // oc_cloud_endpoint_addresses_init only allocates, so the oc_string_view_t
  // will remain valid
  if (!oc_cloud_endpoint_addresses_init(ea, ea->on_selected_change.cb,
                                        ea->on_selected_change.cb_data, cis,
                                        selected_uuid)) {
    OC_CLOUD_WRN("Failed to reinitialize cloud server endpoints");
    return false;
  }

#if OC_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  char selected_id[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&selected_uuid, selected_id, OC_UUID_LEN);
  OC_CLOUD_DBG("reinitialized cloud endpoint addresses, selected cloud (uri: "
               "%s, sid: %s)",
               selected_uri != NULL ? oc_string(*selected_uri) : "NULL",
               selected_id);
  // GCOVR_EXCL_STOP
#endif /* OC_DBG_IS_ENABLED */
  if (srep.servers == NULL) {
    return true;
  }

  assert(srep.servers->type == OC_REP_OBJECT);
  for (const oc_rep_t *server = srep.servers; server != NULL;
       server = server->next) {
    const oc_rep_t *rep =
      oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                 srep.uri_key.data, srep.uri_key.length);
    if (rep == NULL) {
      OC_CLOUD_ERR("cloud server uri missing");
      continue;
    }
    oc_string_view_t uri = oc_string_view2(&rep->value.string);

    rep = oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                     srep.uuid_key.data, srep.uuid_key.length);
    if (rep == NULL) {
      OC_CLOUD_ERR("cloud server id missing");
      continue;
    }
    oc_string_view_t sid = oc_string_view2(&rep->value.string);
    oc_uuid_t uuid;
    if (oc_str_to_uuid_v1(sid.data, sid.length, &uuid) < 0) {
      OC_CLOUD_ERR("invalid cloud sid(%s)", sid.data);
      continue;
    }

    if (oc_endpoint_addresses_contains(ea, uri)) {
      OC_CLOUD_DBG("cloud endpoint address already exists (uri: %s)", uri.data);
      continue;
    }

    if (!oc_endpoint_addresses_add(
          ea, oc_endpoint_address_make_view_with_uuid(uri, uuid))) {
      OC_CLOUD_ERR("failed to add cloud endpoint address (uri: %s, sid: %s)",
                   uri.data, sid.data);
      return false;
    }
    OC_CLOUD_DBG("added cloud endpoint address (uri: %s, sid: %s)", uri.data,
                 sid.data);
  }

  return true;
}

#endif /* OC_CLOUD */
