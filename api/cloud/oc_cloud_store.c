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

#include "api/oc_rep_internal.h"
#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_log_internal.h"
#include "oc_cloud_store_internal.h"
#include "port/oc_connectivity.h"

#include <stdint.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_STORAGE
#error Preprocessor macro OC_CLOUD is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_CLOUD is defined.
#endif

#define CLOUD_STORE_NAME "cloud"
#define CLOUD_CI_SERVER ci_server
#define CLOUD_SID sid
#define CLOUD_AUTH_PROVIDER auth_provider
#define CLOUD_UID uid
#define CLOUD_ACCESS_TOKEN access_token
#define CLOUD_REFRESH_TOKEN refresh_token
#define CLOUD_EXPIRES_IN expires_in
#define CLOUD_STATUS status
#define CLOUD_CPS cps

#define CLOUD_STR(s) #s
#define CLOUD_XSTR(s) CLOUD_STR(s)
#define CLOUD_XSTRLEN(s) (sizeof(CLOUD_STR(s)) - 1)

#define CLOUD_TAG_MAX (32)

static int cloud_store_load_internal(const char *store_name,
                                     oc_cloud_store_t *store);
static void gen_cloud_tag(const char *name, size_t device, char *cloud_tag);

int
cloud_store_load(oc_cloud_store_t *store)
{
  char cloud_tag[CLOUD_TAG_MAX];
  gen_cloud_tag(CLOUD_STORE_NAME, store->device, cloud_tag);
  return cloud_store_load_internal(cloud_tag, store);
}

static void
rep_set_text_string(CborEncoder *object_map, const char *key, const char *value)
{
  g_err |= oc_rep_encode_text_string(object_map, key, strlen(key));
  if (value != NULL) {
    g_err |= oc_rep_encode_text_string(object_map, value, strlen(value));
  } else {
    g_err |= oc_rep_encode_text_string(object_map, "", 0);
  }
}

static void
rep_set_int(CborEncoder *object_map, const char *key, int64_t value)
{
  g_err |= oc_rep_encode_text_string(object_map, key, strlen(key));
  g_err |= oc_rep_encode_int(object_map, value);
}

static void
gen_cloud_tag(const char *name, size_t device, char *cloud_tag)
{
  int cloud_tag_len =
    snprintf(cloud_tag, CLOUD_TAG_MAX, "%s_%zd", name, device);
  cloud_tag_len =
    (cloud_tag_len < CLOUD_TAG_MAX - 1) ? cloud_tag_len + 1 : CLOUD_TAG_MAX - 1;
  cloud_tag[cloud_tag_len] = '\0';
}

static void
encode_cloud_with_map(CborEncoder *object_map, const oc_cloud_store_t *store)
{
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_CI_SERVER),
                      oc_string(store->ci_server));
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_AUTH_PROVIDER),
                      oc_string(store->auth_provider));
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_UID), oc_string(store->uid));
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_SID), oc_string(store->sid));
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_ACCESS_TOKEN),
                      oc_string(store->access_token));
  rep_set_text_string(object_map, CLOUD_XSTR(CLOUD_REFRESH_TOKEN),
                      oc_string(store->refresh_token));
  rep_set_int(object_map, CLOUD_XSTR(CLOUD_STATUS), store->status);
  rep_set_int(object_map, CLOUD_XSTR(CLOUD_CPS), store->cps);
  rep_set_int(object_map, CLOUD_XSTR(CLOUD_EXPIRES_IN), store->expires_in);
}

static void
cloud_store_encode(const oc_cloud_store_t *store)
{
  oc_rep_start_root_object();
  encode_cloud_with_map(&root_map, store);
  oc_rep_end_root_object();
}

static long
cloud_store_dump_internal(const char *store_name, const oc_cloud_store_t *store)
{
  if (!store_name || !store) {
    return -1;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!buf)
    return -1;
  oc_rep_new_realloc_v1(&buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MIN_APP_DATA_SIZE];
  oc_rep_new_v1(buf, sizeof(buf));
#endif /* !OC_DYNAMIC_ALLOCATION */

  // Dumping cloud and accesspoint information.
  cloud_store_encode(store);
#ifdef OC_DYNAMIC_ALLOCATION
  buf = oc_rep_shrink_encoder_buf(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  long size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    size = oc_storage_write(store_name, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  return size;
}

long
cloud_store_dump(const oc_cloud_store_t *store)
{
  char cloud_tag[CLOUD_TAG_MAX];
  gen_cloud_tag(CLOUD_STORE_NAME, store->device, cloud_tag);
  // Calling dump for cloud and access point info
  return cloud_store_dump_internal(cloud_tag, store);
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
  // ensure that cloud_store_dump_handler uses a const oc_cloud_store_t*
  // so this void* cast which drops const is safe
  oc_remove_delayed_callback((void *)store, cloud_store_dump_handler);
  oc_set_delayed_callback((void *)store, cloud_store_dump_handler, 0);
  _oc_signal_event_loop();
}

static bool
cloud_store_parse_string_property(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  assert(rep->type == OC_REP_STRING);
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_CI_SERVER),
                         CLOUD_XSTRLEN(CLOUD_CI_SERVER))) {
    oc_set_string(&store->ci_server, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_SID),
                         CLOUD_XSTRLEN(CLOUD_SID))) {
    oc_set_string(&store->sid, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_AUTH_PROVIDER),
                         CLOUD_XSTRLEN(CLOUD_AUTH_PROVIDER))) {
    oc_set_string(&store->auth_provider, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_UID),
                         CLOUD_XSTRLEN(CLOUD_UID))) {
    oc_set_string(&store->uid, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_ACCESS_TOKEN),
                         CLOUD_XSTRLEN(CLOUD_ACCESS_TOKEN))) {
    oc_set_string(&store->access_token, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_REFRESH_TOKEN),
                         CLOUD_XSTRLEN(CLOUD_REFRESH_TOKEN))) {
    oc_set_string(&store->refresh_token, oc_string(rep->value.string),
                  oc_string_len(rep->value.string));
    return true;
  }

  OC_CLOUD_ERR("Unknown string property %s", oc_string(rep->name));
  return false;
}

static bool
cloud_store_parse_int_property(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  assert(rep->type == OC_REP_INT);

  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_STATUS),
                         CLOUD_XSTRLEN(CLOUD_STATUS))) {
    assert(rep->value.integer <= UINT8_MAX);
    store->status = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_CPS),
                         CLOUD_XSTRLEN(CLOUD_CPS))) {
    assert(rep->value.integer <= UINT8_MAX);
    store->cps = (uint8_t)rep->value.integer;
    return true;
  }
  if (oc_rep_is_property(rep, CLOUD_XSTR(CLOUD_EXPIRES_IN),
                         CLOUD_XSTRLEN(CLOUD_EXPIRES_IN))) {
    store->expires_in = rep->value.integer;
    return true;
  }

  OC_CLOUD_ERR("Unknown integer property %s", oc_string(rep->name));
  return false;
}

static int
cloud_store_decode(const oc_rep_t *rep, oc_cloud_store_t *store)
{
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (!cloud_store_parse_string_property(rep, store)) {
        return -1;
      }
      break;
    case OC_REP_INT:
      if (!cloud_store_parse_int_property(rep, store)) {
        return -1;
      }
      break;
    default:
      OC_CLOUD_ERR("Unknown property %s", oc_string(rep->name));
      return -1;
    }
    rep = rep->next;
  }
  return 0;
}

static int
cloud_store_load_internal(const char *store_name, oc_cloud_store_t *store)
{
  if (!store_name || !store) {
    return -1;
  }

  int ret = 0;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    OC_CLOUD_ERR("alloc failed!");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = oc_storage_read(store_name, buf, OC_MAX_APP_DATA_SIZE);
  if (size > 0) {
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep;
    if (oc_parse_rep(buf, (int)size, &rep) != 0) {
      OC_CLOUD_ERR("failed to parse cloud store buffer");
    }
    ret = cloud_store_decode(rep, store);
    oc_free_rep(rep);
    oc_rep_set_pool(prev_rep_objects);
  } else {
    cloud_store_initialize(store);
    ret = -2;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

void
cloud_store_initialize(oc_cloud_store_t *store)
{
  cloud_store_deinitialize(store);
#define DEFAULT_CLOUD_CIS "coaps+tcp://127.0.0.1"
  oc_set_string(&store->ci_server, DEFAULT_CLOUD_CIS,
                strlen(DEFAULT_CLOUD_CIS));
#define DEFAULT_CLOUD_SID "00000000-0000-0000-0000-000000000000"
  oc_set_string(&store->sid, DEFAULT_CLOUD_SID, strlen(DEFAULT_CLOUD_SID));
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
