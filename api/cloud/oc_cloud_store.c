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

#define CLOUD_STORE_NAME "cloud"
#define CLOUD_CI_SERVER "ci_server"
#define CLOUD_SID "sid"
#define CLOUD_AUTH_PROVIDER "auth_provider"
#define CLOUD_UID "uid"
#define CLOUD_ACCESS_TOKEN "access_token"
#define CLOUD_REFRESH_TOKEN "refresh_token"
#define CLOUD_EXPIRES_IN "expires_in"
#define CLOUD_STATUS "status"
#define CLOUD_CPS "cps"

static int
store_decode_cloud(const oc_rep_t *rep, size_t device, void *data)
{
  (void)device;
  oc_cloud_store_t *store = (oc_cloud_store_t *)data;
  if (!cloud_store_decode(rep, store)) {
    OC_ERR("cannot load cloud: cannot decode representation");
    return -1;
  }
  return 0;
}

bool
cloud_store_load(oc_cloud_store_t *store)
{
  if (oc_storage_data_load(CLOUD_STORE_NAME, store->device, store_decode_cloud,
                           store) <= 0) {
    OC_DBG("failed to load cloud from storage");
    cloud_store_initialize(store);
    return false;
  }
  OC_DBG("cloud loaded from storage");
  return true;
}

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
cloud_store_encode(const oc_cloud_store_t *store)
{
  oc_rep_start_root_object();
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_CI_SERVER),
                      oc_string_view2(&store->ci_server));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_AUTH_PROVIDER),
                      oc_string_view2(&store->auth_provider));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_UID),
                      oc_string_view2(&store->uid));
  rep_set_text_string(oc_rep_object(root), OC_STRING_VIEW(CLOUD_SID),
                      oc_string_view2(&store->sid));
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
  cloud_store_encode(store);
  return 0;
}

long
cloud_store_dump(const oc_cloud_store_t *store)
{
  long ret = oc_storage_data_save(CLOUD_STORE_NAME, store->device,
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
  const oc_cloud_store_t *store = (oc_cloud_store_t *)data;
  if (cloud_store_dump(store) < 0) {
    OC_CLOUD_ERR("failed to dump store");
  }
  return OC_EVENT_DONE;
}

void
cloud_store_dump_async(const oc_cloud_store_t *store)
{
  oc_remove_delayed_callback(store, cloud_store_dump_handler);
  // ensure that cloud_store_dump_handler uses a const oc_cloud_store_t*
  // so this void* cast which drops const is safe
  oc_set_delayed_callback((void *)store, cloud_store_dump_handler, 0);
  _oc_signal_event_loop();
}

static bool
cloud_store_parse_string_property(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  assert(rep->type == OC_REP_STRING);
  if (oc_rep_is_property(rep, CLOUD_CI_SERVER,
                         OC_CHAR_ARRAY_LEN(CLOUD_CI_SERVER))) {
    oc_copy_string(&store->ci_server, &rep->value.string);
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_SID, OC_CHAR_ARRAY_LEN(CLOUD_SID))) {
    oc_copy_string(&store->sid, &rep->value.string);
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_AUTH_PROVIDER,
                         OC_CHAR_ARRAY_LEN(CLOUD_AUTH_PROVIDER))) {
    oc_copy_string(&store->auth_provider, &rep->value.string);
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_UID, OC_CHAR_ARRAY_LEN(CLOUD_UID))) {
    oc_copy_string(&store->uid, &rep->value.string);
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_ACCESS_TOKEN,
                         OC_CHAR_ARRAY_LEN(CLOUD_ACCESS_TOKEN))) {
    oc_copy_string(&store->access_token, &rep->value.string);
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_REFRESH_TOKEN,
                         OC_CHAR_ARRAY_LEN(CLOUD_REFRESH_TOKEN))) {
    oc_copy_string(&store->refresh_token, &rep->value.string);
    return true;
  }

  OC_CLOUD_ERR("Unknown string property %s", oc_string(rep->name));
  return false;
}

static bool
cloud_store_parse_int_property(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  assert(rep->type == OC_REP_INT);

  if (oc_rep_is_property(rep, CLOUD_STATUS, OC_CHAR_ARRAY_LEN(CLOUD_STATUS))) {
    assert(rep->value.integer <= UINT8_MAX);
    store->status = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_CPS, OC_CHAR_ARRAY_LEN(CLOUD_CPS))) {
    assert(rep->value.integer <= UINT8_MAX);
    store->cps = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_EXPIRES_IN,
                         OC_CHAR_ARRAY_LEN(CLOUD_EXPIRES_IN))) {
    store->expires_in = rep->value.integer;
    return true;
  }

  OC_CLOUD_ERR("Unknown integer property %s", oc_string(rep->name));
  return false;
}

bool
cloud_store_decode(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (!cloud_store_parse_string_property(rep, store)) {
        return false;
      }
      break;
    case OC_REP_INT:
      if (!cloud_store_parse_int_property(rep, store)) {
        return false;
      }
      break;
    default:
      OC_CLOUD_ERR("Unknown property %s", oc_string(rep->name));
      return false;
    }
    rep = rep->next;
  }
  return true;
}

void
cloud_store_initialize(oc_cloud_store_t *store)
{
  cloud_store_deinitialize(store);
  oc_set_string(&store->ci_server, OCF_COAPCLOUDCONF_DEFAULT_CIS,
                OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_DEFAULT_CIS));
  oc_set_string(&store->sid, OCF_COAPCLOUDCONF_DEFAULT_SID,
                OC_CHAR_ARRAY_LEN(OCF_COAPCLOUDCONF_DEFAULT_SID));
}

void
cloud_store_deinitialize(oc_cloud_store_t *store)
{
  oc_set_string(&store->ci_server, NULL, 0);
  oc_set_string(&store->auth_provider, NULL, 0);
  oc_set_string(&store->uid, NULL, 0);
  oc_set_string(&store->access_token, NULL, 0);
  oc_set_string(&store->refresh_token, NULL, 0);
  oc_set_string(&store->sid, NULL, 0);
  store->status = 0;
  store->expires_in = 0;
  store->cps = OC_CPS_UNINITIALIZED;
}

#endif /* OC_CLOUD */
