/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "oc_config.h"

#ifdef OC_CLOUD

#include "api/oc_storage_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_log_internal.h"
#include "oc_cloud_resource_internal.h"
#include "oc_cloud_store_internal.h"
#include "port/oc_connectivity.h"
#include "util/oc_macros_internal.h"

#include <stdint.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_STORAGE
#error Preprocessor macro OC_CLOUD is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_CLOUD is defined.
#endif

#define CLOUD_CI_SERVER "ci_server"
#define CLOUD_SERVERS "x.org.iotivity.servers"
#define CLOUD_SID "sid"
#define CLOUD_AUTH_PROVIDER "auth_provider"
#define CLOUD_UID "uid"
#define CLOUD_ACCESS_TOKEN "access_token"
#define CLOUD_REFRESH_TOKEN "refresh_token"
#define CLOUD_EXPIRES_IN "expires_in"
#define CLOUD_STATUS "status"
#define CLOUD_CPS "cps"
#define CLOUD_ENDPOINT_URI "uri"
#define CLOUD_ENDPOINT_ID "id"

static void
rep_set_text_string(CborEncoder *object_map, oc_string_view_t key,
                    oc_string_view_t value)
{
  g_err |= oc_rep_encode_text_string(object_map, key.data, key.length);
  if (value.data != NULL) {
    g_err |= oc_rep_encode_text_string(object_map, value.data, value.length);
  } else {
    g_err |= oc_rep_encode_text_string(object_map, "", 0);
  }
}

static void
rep_set_int(CborEncoder *object_map, oc_string_view_t key, int64_t value)
{
  g_err |= oc_rep_encode_text_string(object_map, key.data, key.length);
  g_err |= oc_rep_encode_int(object_map, value);
}

void
oc_cloud_store_encode(const oc_cloud_store_t *store)
{
  oc_rep_start_root_object();

  const oc_endpoint_address_t *selected =
    oc_endpoint_addresses_selected(&store->ci_servers);
  if (selected != NULL) {
    assert(selected->metadata.id_type ==
           OC_ENDPOINT_ADDRESS_METADATA_TYPE_UUID);
    g_err |= oc_endpoint_address_encode(
      oc_rep_object(root), OC_STRING_VIEW(CLOUD_CI_SERVER),
      OC_STRING_VIEW(CLOUD_SID), OC_STRING_VIEW_NULL,
      oc_endpoint_address_view(selected));
  }
  g_err |= oc_endpoint_addresses_encode(oc_rep_object(root), &store->ci_servers,
                                        OC_STRING_VIEW(CLOUD_SERVERS), true);
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_AUTH_PROVIDER),
                      oc_string_view2(&store->auth_provider));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_UID),
                      oc_string_view2(&store->uid));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_ACCESS_TOKEN),
                      oc_string_view2(&store->access_token));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_REFRESH_TOKEN),
                      oc_string_view2(&store->refresh_token));
  rep_set_int(oc_rep_object(root), OC_STRING_VIEW(CLOUD_STATUS), store->status);
  rep_set_int(oc_rep_object(root), OC_STRING_VIEW(CLOUD_CPS), store->cps);
  rep_set_int(oc_rep_object(root), OC_STRING_VIEW(CLOUD_EXPIRES_IN),
              store->expires_in);
  oc_rep_end_root_object();
}

static int
store_encode_cloud(size_t device, const void *data)
{
  (void)device;
  const oc_cloud_store_t *store = (const oc_cloud_store_t *)data;
  oc_cloud_store_encode(store);
  return 0;
}

long
oc_cloud_store_dump(const oc_cloud_store_t *store)
{
  long ret = oc_storage_data_save(OC_CLOUD_STORE_NAME, store->device,
                                  store_encode_cloud, store);
  if (ret <= 0) {
    OC_ERR("cannot dump cloud to storage: error(%ld)", ret);
    return false;
  }
  return true;
}

static oc_event_callback_retval_t
cloud_store_dump_handler(void *data)
{
  const oc_cloud_store_t *store = (const oc_cloud_store_t *)data;
  if (oc_cloud_store_dump(store) < 0) {
    OC_CLOUD_ERR("failed to dump store");
  }
  return OC_EVENT_DONE;
}

void
oc_cloud_store_dump_async(const oc_cloud_store_t *store)
{
  oc_remove_delayed_callback(store, cloud_store_dump_handler);
  // ensure that cloud_store_dump_handler uses a const oc_cloud_store_t*
  // so this void* cast which drops const is safe
  oc_set_delayed_callback((void *)store, cloud_store_dump_handler, 0);
  _oc_signal_event_loop();
}

typedef struct
{
  const oc_rep_t *ci_servers;
  const oc_string_t *ci_server;
  const oc_string_t *sid;
  const oc_string_t *auth_provider;
  const oc_string_t *uid;
  const oc_string_t *access_token;
  const oc_string_t *refresh_token;
  uint8_t status;
  uint8_t cps;
  int64_t expires_in;
} cloud_store_data_t;

static bool
cloud_store_parse_string_property(const oc_rep_t *rep, cloud_store_data_t *csd)
{
  assert(rep->type == OC_REP_STRING);

  if (oc_rep_is_property(rep, CLOUD_CI_SERVER,
                         OC_CHAR_ARRAY_LEN(CLOUD_CI_SERVER))) {
    csd->ci_server = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_SID, OC_CHAR_ARRAY_LEN(CLOUD_SID))) {
    csd->sid = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_AUTH_PROVIDER,
                         OC_CHAR_ARRAY_LEN(CLOUD_AUTH_PROVIDER))) {
    csd->auth_provider = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_UID, OC_CHAR_ARRAY_LEN(CLOUD_UID))) {
    csd->uid = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_ACCESS_TOKEN,
                         OC_CHAR_ARRAY_LEN(CLOUD_ACCESS_TOKEN))) {
    csd->access_token = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_REFRESH_TOKEN,
                         OC_CHAR_ARRAY_LEN(CLOUD_REFRESH_TOKEN))) {
    csd->refresh_token = &rep->value.string;
    return true;
  }

  OC_CLOUD_ERR("Unknown string property %s", oc_string(rep->name));
  return false;
}

static bool
cloud_store_parse_int_property(const oc_rep_t *rep, cloud_store_data_t *csd)
{
  assert(rep->type == OC_REP_INT);

  if (oc_rep_is_property(rep, CLOUD_STATUS, OC_CHAR_ARRAY_LEN(CLOUD_STATUS))) {
    assert(rep->value.integer <= UINT8_MAX);
    csd->status = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_CPS, OC_CHAR_ARRAY_LEN(CLOUD_CPS))) {
    assert(rep->value.integer <= UINT8_MAX);
    csd->cps = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_EXPIRES_IN,
                         OC_CHAR_ARRAY_LEN(CLOUD_EXPIRES_IN))) {
    csd->expires_in = rep->value.integer;
    return true;
  }

  OC_CLOUD_ERR("Unknown integer property %s", oc_string(rep->name));
  return false;
}

static bool
cloud_store_parse_object_array_property(const oc_rep_t *rep,
                                        cloud_store_data_t *csd)
{
  assert(rep->type == OC_REP_OBJECT_ARRAY);

  if (oc_rep_is_property(rep, CLOUD_SERVERS,
                         OC_CHAR_ARRAY_LEN(CLOUD_SERVERS))) {
    csd->ci_servers = rep->value.object_array;
    return true;
  }

  OC_CLOUD_ERR("Unknown string array property %s", oc_string(rep->name));
  return false;
}

static bool
cloud_store_set_servers(oc_cloud_store_t *store,
                        const oc_string_t *selected_uri,
                        const oc_string_t *selected_id, const oc_rep_t *servers)
{
  oc_uuid_t uuid = OCF_COAPCLOUDCONF_DEFAULT_SID;
  if (selected_id != NULL) {
    oc_string_view_t selected_idv = oc_string_view2(selected_id);
    if (oc_str_to_uuid_v1(selected_idv.data, selected_idv.length, &uuid) !=
        OC_UUID_ID_SIZE) {
      return false;
    }
  }
  if (!oc_endpoint_addresses_reinit(&store->ci_servers,
                                    oc_endpoint_address_make_view_with_uuid(
                                      oc_string_view2(selected_uri), uuid))) {
    return false;
  }

  if (servers == NULL) {
    return true;
  }

  for (const oc_rep_t *server = servers; server != NULL;
       server = server->next) {
    const oc_rep_t *rep =
      oc_rep_get(server->value.object, OC_REP_STRING, CLOUD_ENDPOINT_URI,
                 OC_CHAR_ARRAY_LEN(CLOUD_ENDPOINT_URI));
    if (rep == NULL) {
      OC_ERR("cloud server uri missing");
      continue;
    }
    oc_string_view_t uri = oc_string_view2(&rep->value.string);

    rep = oc_rep_get(server->value.object, OC_REP_STRING, CLOUD_ENDPOINT_ID,
                     OC_CHAR_ARRAY_LEN(CLOUD_ENDPOINT_ID));
    if (rep == NULL) {
      OC_ERR("cloud server id missing");
      continue;
    }
    oc_string_view_t sid = oc_string_view2(&rep->value.string);
    if (oc_str_to_uuid_v1(sid.data, sid.length, &uuid) < 0) {
      continue;
    }

    if (oc_endpoint_addresses_contains(&store->ci_servers, uri)) {
      continue;
    }

    if (!oc_endpoint_addresses_add(
          &store->ci_servers,
          oc_endpoint_address_make_view_with_uuid(uri, uuid))) {
      return false;
    }
  }

  return true;
}

bool
oc_cloud_store_decode(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  cloud_store_data_t csd;
  memset(&csd, 0, sizeof(cloud_store_data_t));
  // copy data from store so if given properties are not set they will not be
  // changed
  csd.status = store->status;
  csd.cps = (uint8_t)store->cps;
  csd.expires_in = store->expires_in;

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_OBJECT_ARRAY:
      if (!cloud_store_parse_object_array_property(rep, &csd)) {
        return false;
      }
      break;
    case OC_REP_STRING:
      if (!cloud_store_parse_string_property(rep, &csd)) {
        return false;
      }
      break;
    case OC_REP_INT:
      if (!cloud_store_parse_int_property(rep, &csd)) {
        return false;
      }
      break;

    default:
      OC_CLOUD_ERR("Unknown property %s", oc_string(rep->name));
      return false;
    }
    rep = rep->next;
  }

  // copy data to store
  if ((csd.ci_server != NULL || csd.ci_servers != NULL) &&
      !cloud_store_set_servers(store, csd.ci_server, csd.sid, csd.ci_servers)) {
    OC_WRN("failed to set cloud servers from storage");
  }

  if (csd.auth_provider != NULL) {
    oc_copy_string(&store->auth_provider, csd.auth_provider);
  }
  if (csd.uid != NULL) {
    oc_copy_string(&store->uid, csd.uid);
  }
  if (csd.access_token != NULL) {
    oc_copy_string(&store->access_token, csd.access_token);
  }
  if (csd.refresh_token != NULL) {
    oc_copy_string(&store->refresh_token, csd.refresh_token);
  }
  store->status = csd.status;
  store->cps = csd.cps;
  store->expires_in = csd.expires_in;

  return true;
}

static int
store_decode_cloud(const oc_rep_t *rep, size_t device, void *data)
{
  (void)device;
  oc_cloud_store_t *store = (oc_cloud_store_t *)data;
  if (!oc_cloud_store_decode(rep, store)) {
    OC_ERR("cannot load cloud: cannot decode representation");
    return -1;
  }
  return 0;
}

bool
oc_cloud_store_load(oc_cloud_store_t *store)
{
  if (oc_storage_data_load(OC_CLOUD_STORE_NAME, store->device,
                           store_decode_cloud, store) <= 0) {
    OC_DBG("failed to load cloud from storage");
    oc_cloud_store_reinitialize(store);
    return false;
  }
  OC_DBG("cloud loaded from storage");
  return true;
}

void
oc_cloud_store_reinitialize(oc_cloud_store_t *store)
{
  oc_cloud_store_initialize(store, store->ci_servers.on_selected_change,
                            store->ci_servers.on_selected_change_data);
}

void
oc_cloud_store_initialize(
  oc_cloud_store_t *store,
  on_selected_endpoint_address_change_fn_t on_cloud_server_change,
  void *on_cloud_server_change_data)
{
  oc_cloud_store_deinitialize(store);
  oc_cloud_endpoint_addresses_init(
    &store->ci_servers, on_cloud_server_change, on_cloud_server_change_data,
    OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS),
    OCF_COAPCLOUDCONF_DEFAULT_SID);
}

void
oc_cloud_store_deinitialize(oc_cloud_store_t *store)
{
  oc_remove_delayed_callback(store, cloud_store_dump_handler);
  oc_endpoint_addresses_deinit(&store->ci_servers);
  oc_set_string(&store->auth_provider, NULL, 0);
  oc_set_string(&store->uid, NULL, 0);
  oc_set_string(&store->access_token, NULL, 0);
  oc_set_string(&store->refresh_token, NULL, 0);
  store->status = 0;
  store->expires_in = 0;
  store->cps = OC_CPS_UNINITIALIZED;
}

#endif /* OC_CLOUD */
