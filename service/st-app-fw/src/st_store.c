/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "st_store.h"
#include "oc_rep.h"
#include "port/oc_storage.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "util/oc_mem.h"

#define ST_MAX_DATA_SIZE (1024)
#define ST_STORE_NAME "st_info"

#define st_rep_set_string_with_chk(object, key, value)                         \
  if (value)                                                                   \
    oc_rep_set_text_string(object, key, value);

static st_store_t g_store_info;

static int st_decode_store_info(oc_rep_t *rep);
static void st_encode_store_info(void);

int
st_store_load(void)
{
  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf) {
    st_print_log("[ST_STORE] alloc failed!");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
#ifdef OC_SECURITY
  size = oc_storage_read(ST_STORE_NAME, buf, ST_MAX_DATA_SIZE);
#endif
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
    oc_parse_rep(buf, (uint16_t)size, &rep);
    ret = st_decode_store_info(rep);
    oc_free_rep(rep);
  } else {
    st_store_info_initialize();
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  return ret;
}

int
st_store_dump(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return -1;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, ST_MAX_DATA_SIZE);
  st_encode_store_info();
  int size = -1;
#ifdef OC_SECURITY
  size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("[ST_Store] encoded info size %d", size);
    oc_storage_write(ST_STORE_NAME, buf, size);
  }
  OC_LOGbytes(buf, size);
#endif /* OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_reset();

  return size;
}

static oc_event_callback_retval_t
st_store_dump_handler(void *data)
{
  (void)data;
  st_store_dump();
  return OC_EVENT_DONE;
}

void
st_store_dump_async(void)
{
  oc_set_delayed_callback(NULL, st_store_dump_handler, 0);
  _oc_signal_event_loop();
}

void
st_store_info_initialize(void)
{
  g_store_info.status = false;
  if (oc_string(g_store_info.accesspoint.ssid)) {
    oc_free_string(&g_store_info.accesspoint.ssid);
  }
  if (oc_string(g_store_info.accesspoint.pwd)) {
    oc_free_string(&g_store_info.accesspoint.pwd);
  }
  if (oc_string(g_store_info.cloudinfo.ci_server)) {
    oc_free_string(&g_store_info.cloudinfo.ci_server);
  }
  if (oc_string(g_store_info.cloudinfo.auth_provider)) {
    oc_free_string(&g_store_info.cloudinfo.auth_provider);
  }
  if (oc_string(g_store_info.cloudinfo.uid)) {
    oc_free_string(&g_store_info.cloudinfo.uid);
  }
  if (oc_string(g_store_info.cloudinfo.access_token)) {
    oc_free_string(&g_store_info.cloudinfo.access_token);
  }
  if (oc_string(g_store_info.cloudinfo.refresh_token)) {
    oc_free_string(&g_store_info.cloudinfo.refresh_token);
  }
  g_store_info.cloudinfo.status = 0;
}

st_store_t *
st_store_get_info(void)
{
  return &g_store_info;
}

static int
st_decode_ap_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "ssid", 4) == 0) {
        oc_new_string(&g_store_info.accesspoint.ssid,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "pwd", 3) == 0) {
        oc_new_string(&g_store_info.accesspoint.pwd, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static int
st_decode_cloud_manager_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 9 && memcmp(oc_string(t->name), "ci_server", 9) == 0) {
        oc_new_string(&g_store_info.cloudinfo.ci_server,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "auth_provider", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.auth_provider,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "uid", 3) == 0) {
        oc_new_string(&g_store_info.cloudinfo.uid, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 12 &&
                 memcmp(oc_string(t->name), "access_token", 12) == 0) {
        oc_new_string(&g_store_info.cloudinfo.access_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "refresh_token", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.refresh_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_INT:
      if (len == 6 && memcmp(oc_string(t->name), "status", 6) == 0) {
        g_store_info.cloudinfo.status = t->value.integer;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static int
st_decode_store_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_BOOL:
      if (len == 6 && memcmp(oc_string(t->name), "status", 6) == 0) {
        g_store_info.status = t->value.boolean;
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_OBJECT:
      if (len == 11 && memcmp(oc_string(t->name), "accesspoint", 11) == 0) {
        if (st_decode_ap_info(t->value.object) != 0)
          return -1;
      } else if (len == 9 && memcmp(oc_string(t->name), "cloudinfo", 9) == 0) {
        if (st_decode_cloud_manager_info(t->value.object) != 0)
          return -1;
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s, %d", oc_string(t->name), t->type);
      return -1;
    }
    t = t->next;
  }

  return 0;
}

static void
st_encode_store_info(void)
{
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, status, g_store_info.status);
  oc_rep_set_object(root, accesspoint);
  st_rep_set_string_with_chk(accesspoint, ssid,
                             oc_string(g_store_info.accesspoint.ssid));
  st_rep_set_string_with_chk(accesspoint, pwd,
                             oc_string(g_store_info.accesspoint.pwd));
  oc_rep_close_object(root, accesspoint);
  oc_rep_set_object(root, cloudinfo);
  st_rep_set_string_with_chk(cloudinfo, ci_server,
                             oc_string(g_store_info.cloudinfo.ci_server));
  st_rep_set_string_with_chk(cloudinfo, auth_provider,
                             oc_string(g_store_info.cloudinfo.auth_provider));
  st_rep_set_string_with_chk(cloudinfo, uid,
                             oc_string(g_store_info.cloudinfo.uid));
  st_rep_set_string_with_chk(cloudinfo, access_token,
                             oc_string(g_store_info.cloudinfo.access_token));
  st_rep_set_string_with_chk(cloudinfo, refresh_token,
                             oc_string(g_store_info.cloudinfo.refresh_token));
  oc_rep_set_int(cloudinfo, status, g_store_info.cloudinfo.status);
  oc_rep_close_object(root, cloudinfo);
  oc_rep_end_root_object();
}
