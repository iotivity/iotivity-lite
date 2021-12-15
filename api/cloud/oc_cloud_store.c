/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#ifdef OC_CLOUD

#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_config.h"
#include "oc_rep.h"
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

#define CLOUD_TAG_MAX (32)

static int cloud_store_load_internal(const char *store_name,
                                     oc_cloud_store_t *store);
static void gen_cloud_tag(const char *name, size_t device, char *cloud_tag);

void
cloud_store_load(oc_cloud_store_t *store)
{
  char cloud_tag[CLOUD_TAG_MAX];
  gen_cloud_tag(CLOUD_STORE_NAME, store->device, cloud_tag);
  cloud_store_load_internal(cloud_tag, store);
}

static void
rep_set_text_string(CborEncoder *object_map, const char *key, const char *value)
{
  g_err |= cbor_encode_text_string(object_map, key, strlen(key));
  if ((const char *)value != NULL) {
    g_err |= cbor_encode_text_string(object_map, value, strlen(value));
  } else {
    g_err |= cbor_encode_text_string(object_map, "", 0);
  }
}

static void
rep_set_int(CborEncoder *object_map, const char *key, int64_t value)
{
  g_err |= cbor_encode_text_string(object_map, key, strlen(key));
  g_err |= cbor_encode_int(object_map, value);
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
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return -1;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  // Dumping cloud and accesspoint information.
  cloud_store_encode(store);
  long size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    size = oc_storage_write(store_name, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  return size;
}

void
cloud_store_dump(const oc_cloud_store_t *store)
{
  char cloud_tag[CLOUD_TAG_MAX];
  gen_cloud_tag(CLOUD_STORE_NAME, store->device, cloud_tag);
  // Calling dump for cloud and access point info
  cloud_store_dump_internal(cloud_tag, store);
}

static oc_event_callback_retval_t
cloud_store_dump_handler(void *data)
{
  oc_cloud_store_t *store = (oc_cloud_store_t *)data;
  cloud_store_dump(store);
  return OC_EVENT_DONE;
}

void
cloud_store_dump_async(const oc_cloud_store_t *store)
{
  oc_remove_delayed_callback((void *)store, cloud_store_dump_handler);
  oc_set_delayed_callback((void *)store, cloud_store_dump_handler, 0);
  _oc_signal_event_loop();
}

static int
cloud_store_decode(oc_rep_t *rep, oc_cloud_store_t *store)
{
  oc_rep_t *t = rep;
  size_t len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == strlen(CLOUD_XSTR(CLOUD_CI_SERVER)) &&
          memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_CI_SERVER),
                 strlen(CLOUD_XSTR(CLOUD_CI_SERVER))) == 0) {
        cloud_set_string(&store->ci_server, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else if (len == strlen(CLOUD_XSTR(CLOUD_SID)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_SID),
                        strlen(CLOUD_XSTR(CLOUD_SID))) == 0) {
        cloud_set_string(&store->sid, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else if (len == strlen(CLOUD_XSTR(CLOUD_AUTH_PROVIDER)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_AUTH_PROVIDER),
                        strlen(CLOUD_XSTR(CLOUD_AUTH_PROVIDER))) == 0) {
        cloud_set_string(&store->auth_provider, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else if (len == strlen(CLOUD_XSTR(CLOUD_UID)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_UID),
                        strlen(CLOUD_XSTR(CLOUD_UID))) == 0) {
        cloud_set_string(&store->uid, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else if (len == strlen(CLOUD_XSTR(CLOUD_ACCESS_TOKEN)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_ACCESS_TOKEN),
                        strlen(CLOUD_XSTR(CLOUD_ACCESS_TOKEN))) == 0) {
        cloud_set_string(&store->access_token, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else if (len == strlen(CLOUD_XSTR(CLOUD_REFRESH_TOKEN)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_REFRESH_TOKEN),
                        strlen(CLOUD_XSTR(CLOUD_REFRESH_TOKEN))) == 0) {
        cloud_set_string(&store->refresh_token, oc_string(t->value.string),
                         oc_string_len(t->value.string));
      } else {
        OC_ERR("[CLOUD_STORE] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_INT:
      if (len == strlen(CLOUD_XSTR(CLOUD_STATUS)) &&
          memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_STATUS),
                 strlen(CLOUD_XSTR(CLOUD_STATUS))) == 0) {
        store->status = (uint8_t)t->value.integer;
      } else if (len == strlen(CLOUD_XSTR(CLOUD_CPS)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_CPS),
                        strlen(CLOUD_XSTR(CLOUD_CPS))) == 0) {
        store->cps = (uint8_t)t->value.integer;
      } else if (len == strlen(CLOUD_XSTR(CLOUD_EXPIRES_IN)) &&
                 memcmp(oc_string(t->name), CLOUD_XSTR(CLOUD_EXPIRES_IN),
                        strlen(CLOUD_XSTR(CLOUD_EXPIRES_IN))) == 0) {
        store->expires_in = t->value.integer;
      } else {
        OC_ERR("[CLOUD_STORE] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[CLOUD_STORE] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }
  return 0;
}

void
cloud_store_deinit(oc_cloud_store_t *store)
{
  cloud_set_string(&store->ci_server, NULL, 0);
  cloud_set_string(&store->auth_provider, NULL, 0);
  cloud_set_string(&store->uid, NULL, 0);
  cloud_set_string(&store->access_token, NULL, 0);
  cloud_set_string(&store->refresh_token, NULL, 0);
  cloud_set_string(&store->sid, NULL, 0);
  store->status = 0;
  store->expires_in = 0;
}

static int
cloud_store_load_internal(const char *store_name, oc_cloud_store_t *store)
{
  if (!store_name || !store) {
    return -1;
  }

  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    OC_ERR("[CLOUD_STORE] alloc failed!\n");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
  size = oc_storage_read(store_name, buf, OC_MAX_APP_DATA_SIZE);
  if (size > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
    oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                   rep_objects_alloc, (void *)rep_objects_pool,
                                   0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (int)size, &rep);
    ret = cloud_store_decode(rep, store);
    oc_rep_set_pool(&rep_objects); // Reset representation pool
    oc_free_rep(rep);
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
  cloud_set_string(&store->ci_server, "coaps+tcp://127.0.0.1", 21);
  cloud_set_string(&store->auth_provider, NULL, 0);
  cloud_set_string(&store->uid, NULL, 0);
  cloud_set_string(&store->access_token, NULL, 0);
  cloud_set_string(&store->refresh_token, NULL, 0);
  cloud_set_string(&store->sid, "00000000-0000-0000-0000-000000000000", 36);
  store->status = 0;
  store->expires_in = 0;
}
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
