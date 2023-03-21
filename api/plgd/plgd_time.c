/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME

#include "plgd_time_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_server_api_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_log.h"
#include "util/oc_compiler.h"
#include "util/oc_macros.h"

#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#include "security/oc_security_internal.h"
#endif /* OC_SECURITY */

#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <time.h>

static plgd_time_t g_oc_plgd_time = { 0 };

plgd_time_t *
plgd_time_get(void)
{
  return &g_oc_plgd_time;
}

static void
dev_set_system_time(void)
{
  oc_clock_time_t pt = plgd_time();
  int ret =
    g_oc_plgd_time.set_system_time(pt, g_oc_plgd_time.set_system_time_data);
  if (ret != 0) {
    OC_ERR("failed to set system time: error(%d)", ret);
    return;
  }
  OC_DBG("system time set to: %ld", (long)pt);
}

void
plgd_time_set(oc_clock_time_t last_synced_time, oc_clock_time_t update_time,
              bool dump, bool notify)
{
  g_oc_plgd_time.store.last_synced_time = last_synced_time;
  g_oc_plgd_time.update_time = update_time;
  g_oc_plgd_time.status = PLGD_TIME_STATUS_IN_SYNC;

  if (g_oc_plgd_time.set_system_time != NULL) {
    dev_set_system_time();
  }

  if (dump) {
    plgd_time_dump();
  }
#ifdef OC_SERVER
  if (notify) {
    // TODO: for platform-wide resources /oic/p and /x.plgd.dev/time
    // all devices should be iterated, not just device 0
    oc_resource_t *r = oc_core_get_resource_by_index(PLGD_TIME, 0);
    if (r != NULL) {
      oc_notify_observers(r);
    }
  }
#else  /* !OC_SERVER */
  (void)notify;
#endif /* OC_SERVER */
}

static int
dev_time_set_time(oc_clock_time_t lst, bool dump, bool notify)
{
  if (lst == 0) {
    OC_DBG("plgd time reset");
    plgd_time_set(0, 0, dump, notify);
    return 0;
  }

  oc_clock_time_t updateTime = oc_clock_time_monotonic();
  if (updateTime == (oc_clock_time_t)-1) {
    OC_ERR("cannot set plgd time: cannot obtain system uptime");
    return -1;
  }

#ifdef OC_DEBUG
  char lst_ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(lst, lst_ts, sizeof(lst_ts));
  uint64_t ut_s = (uint64_t)(updateTime / (double)OC_CLOCK_SECOND);
  OC_DBG("plgd time: %s (update: %" PRIu64 ")", lst_ts, ut_s);
#endif /* OC_DEBUG */

  plgd_time_set(lst, updateTime, dump, notify);
  return 0;
}

int
plgd_time_set_time(oc_clock_time_t time)
{
  return dev_time_set_time(time, true, true);
}

oc_clock_time_t
plgd_time_last_synced_time(void)
{
  return g_oc_plgd_time.store.last_synced_time;
}

static bool
dev_time_is_active(plgd_time_t pt)
{
  return pt.store.last_synced_time > 0;
}

bool
plgd_time_is_active(void)
{
  return dev_time_is_active(g_oc_plgd_time);
}

static oc_clock_time_t
dev_plgd_time(plgd_time_t pt)
{
  if (!dev_time_is_active(pt)) {
    OC_ERR("cannot get plgd time: not active");
    return -1;
  }

  oc_clock_time_t cur = oc_clock_time_monotonic();
  if (cur == (oc_clock_time_t)-1) {
    OC_ERR("cannot get plgd time: cannot obtain system uptime");
    return -1;
  }

  long shift = cur - pt.update_time;
  assert(shift >= 0);
  oc_clock_time_t ptime = (pt.store.last_synced_time + shift);

#ifdef OC_DEBUG
  char pt_ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(pt.store.last_synced_time, pt_ts, sizeof(pt_ts));

  oc_clock_time_t time = oc_clock_time();
  char ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(time, ts, sizeof(ts));
  long diff = (time - ptime) / OC_CLOCK_SECOND;
  OC_DBG("calculated plgd time: %s, system time: %s, diff: %lds", pt_ts, ts,
         diff);
#endif /* OC_DEBUG */
  return ptime;
}

oc_clock_time_t
plgd_time(void)
{
  return dev_plgd_time(g_oc_plgd_time);
}

unsigned long
plgd_time_seconds(void)
{
  return plgd_time() / OC_CLOCK_SECOND;
}

void
plgd_time_set_status(plgd_time_status_t status)
{
#ifdef OC_DEBUG
  const char *status_str = plgd_time_status_to_str(status);
  OC_DBG("plgd time status: %s", status_str != NULL ? status_str : "NULL");
#endif /* OC_DEBUG */
  g_oc_plgd_time.status = status;
}

plgd_time_status_t
plgd_time_status(void)
{
  return g_oc_plgd_time.status;
}

const char *
plgd_time_status_to_str(plgd_time_status_t status)
{
  switch (status) {
  case PLGD_TIME_STATUS_IN_SYNC:
    return PLGD_TIME_STATUS_IN_SYNC_STR;
  case PLGD_TIME_STATUS_SYNCING:
    return PLGD_TIME_STATUS_SYNCING_STR;
  case PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE:
    return PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR;
  }
  return NULL;
}

int
plgd_time_status_from_str(const char *str, size_t str_len)
{
  assert(str != NULL);
  if (str_len == OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_IN_SYNC_STR) &&
      strncmp(str, PLGD_TIME_STATUS_IN_SYNC_STR, str_len) == 0) {
    return PLGD_TIME_STATUS_IN_SYNC;
  }
  if (str_len == OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_SYNCING_STR) &&
      strncmp(str, PLGD_TIME_STATUS_SYNCING_STR, str_len) == 0) {
    return PLGD_TIME_STATUS_SYNCING;
  }
  if (str_len == OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR) &&
      strncmp(str, PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR, str_len) == 0) {
    return PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE;
  }
  return -1;
}

#ifdef OC_SECURITY

static bool
dev_time_property_is_accessible(const char *property_name, int flags)
{
  if ((flags & PLGD_TIME_ENCODE_FLAG_SECURE) != 0) {
    return true;
  }

  size_t len = strlen(property_name);
  // insecure: allow access only to rt, if and time properties
  struct
  {
    const char *name;
    size_t name_len;
  } public[] = {
    { .name = PLGD_TIME_PROP_TIME,
      .name_len = OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_TIME) },
    { .name = OC_BASELINE_PROP_RT,
      .name_len = OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_RT) },
    { .name = OC_BASELINE_PROP_IF,
      .name_len = OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_IF) },
  };

  for (size_t i = 0; i < OC_ARRAY_SIZE(public); ++i) {
    if (len == public[i].name_len &&
        memcmp(property_name, public[i].name, public[i].name_len) == 0) {
      return true;
    }
  }
  return false;
}

#endif /* OC_SECURITY */

static bool
dev_time_property_filter(const char *property_name, void *data)
{
#ifdef OC_SECURITY
  int flags = *(int *)data;
  if ((flags & PLGD_TIME_ENCODE_FLAG_TO_STORAGE) != 0) {
    return true;
  }
  return dev_time_property_is_accessible(property_name, flags);
#else  /* !OC_SECURITY */
  (void)property_name;
  (void)data;
  return true;
#endif /* OC_SECURITY */
}

static int
dev_time_encode_property_time(plgd_time_t pt, int flags)
{
#ifdef OC_SECURITY
  if (!dev_time_property_is_accessible(PLGD_TIME_PROP_TIME, flags)) {
    OC_DBG("cannot access property(%s)", PLGD_TIME_PROP_TIME);
    return 0;
  }
#else  /* !OC_SECURITY */
  (void)flags;
#endif /* OC_SECURITY */
  char time[64] = { 0 };
  if (dev_time_is_active(pt)) {
    oc_clock_time_t ct = dev_plgd_time(pt);
    if (ct == (oc_clock_time_t)-1 ||
        oc_clock_encode_time_rfc3339(ct, time, sizeof(time)) == 0) {
      OC_ERR("cannot encode plgd time: cannot encode time in rfc3339 format");
      return -1;
    }
  }
  oc_rep_set_text_string(root, time, time);
  return 0;
}

static void
dev_time_encode_property_status(plgd_time_t pt, int flags)
{
#ifdef OC_SECURITY
  if (!dev_time_property_is_accessible(PLGD_TIME_PROP_STATUS, flags)) {
    OC_DBG("cannot access property(%s)", PLGD_TIME_PROP_STATUS);
    return;
  }
#else  /* !OC_SECURITY */
  (void)flags;
#endif /* OC_SECURITY */

  const char *status = "";
  if (dev_time_is_active(pt)) {
    status = plgd_time_status_to_str(pt.status);
  }
  oc_rep_set_text_string(root, status, status);
}

static int
dev_time_encode_property_last_synced_time(plgd_time_t pt, int flags)
{
#ifdef OC_SECURITY
  if ((flags & PLGD_TIME_ENCODE_FLAG_TO_STORAGE) == 0 &&
      !dev_time_property_is_accessible(PLGD_TIME_PROP_LAST_SYNCED_TIME,
                                       flags)) {
    OC_DBG("cannot access property(%s)", PLGD_TIME_PROP_LAST_SYNCED_TIME);
    return 0;
  }
#else  /* !OC_SECURITY */
  (void)flags;
#endif /* OC_SECURITY */

  char lst[64] = { 0 };
  if (dev_time_is_active(pt) &&
      (oc_clock_encode_time_rfc3339(pt.store.last_synced_time, lst,
                                    sizeof(lst)) == 0)) {
    OC_ERR("cannot encode plgd time: cannot encode last_synced_time");
    return -1;
  }
  oc_rep_set_text_string(root, lastSyncedTime, lst);
  return 0;
}

int
plgd_time_encode(plgd_time_t pt, oc_interface_mask_t iface_mask, int flags)
{
  if ((iface_mask & PLGD_TIME_IF_MASK) != iface_mask) {
    OC_ERR("cannot encode plgd time: invalid interface(%d)", (int)iface_mask);
    return -1;
  }

  oc_rep_start_root_object();
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    // baseline properties
    const oc_resource_t *r = oc_core_get_resource_by_index(PLGD_TIME, 0);
    if (r != NULL) {
      oc_process_baseline_interface_with_filter(r, dev_time_property_filter,
                                                &flags);
    }
  }

  bool to_storage = (flags & PLGD_TIME_ENCODE_FLAG_TO_STORAGE) != 0;
  if (!to_storage) {
    // time
    if (dev_time_encode_property_time(pt, flags) != 0) {
      return -1;
    }

    // status
    if (pt.status != 0) {
      dev_time_encode_property_status(pt, flags);
    }
  }

  // lastSyncedTime
  if (dev_time_encode_property_last_synced_time(pt, flags) != 0) {
    return -1;
  }
  oc_rep_end_root_object();
  return 0;
}

bool
plgd_time_decode(const oc_rep_t *rep, plgd_time_t *pt)
{
  const oc_string_t *lst_rfc3339 = NULL;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_STRING &&
        oc_rep_is_property(
          rep, PLGD_TIME_PROP_LAST_SYNCED_TIME,
          OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_LAST_SYNCED_TIME))) {
      lst_rfc3339 = &rep->value.string;
      continue;
    }
    OC_WRN("plgd time: unknown property (%s:%d)", oc_string(rep->name),
           (int)rep->type);
  }

  if (lst_rfc3339 == NULL) {
    OC_ERR("cannot decode plgd time: property %s not found",
           PLGD_TIME_PROP_LAST_SYNCED_TIME);
    return false;
  }

  oc_clock_time_t lst = oc_clock_parse_time_rfc3339(
    oc_string(*lst_rfc3339), oc_string_len(*lst_rfc3339));
  if (lst == 0) {
    return false;
  }
  pt->store.last_synced_time = lst;
  return true;
}

static int
store_encode_plgd_time(size_t device, void *data)
{
  (void)device;
  const plgd_time_t *pt = (plgd_time_t *)data;
  return plgd_time_encode(*pt, OC_IF_RW, PLGD_TIME_ENCODE_FLAG_TO_STORAGE);
}

bool
plgd_time_dump(void)
{
  long ret = oc_storage_save_resource(PLGD_TIME_STORE_NAME, /*device*/ 0,
                                      store_encode_plgd_time, &g_oc_plgd_time);
  if (ret <= 0) {
    OC_ERR("cannot dump plgd time to storage: error(%ld)", ret);
    return false;
  }
  return true;
}

static int
store_decode_plgd_time(const oc_rep_t *rep, size_t device, void *data)
{
  (void)device;
  plgd_time_t *pt = (plgd_time_t *)data;
  if (!plgd_time_decode(rep, pt)) {
    OC_ERR("cannot load plgd time: cannot decode representation");
    return -1;
  }
  return 0;
}

bool
plgd_time_load(void)
{
  plgd_time_t pt = { 0 };
  if (oc_storage_load_resource(PLGD_TIME_STORE_NAME, 0, store_decode_plgd_time,
                               &pt) <= 0) {
    OC_ERR("failed to load plgd time from storage");
    return false;
  }

  OC_DBG("plgd time loaded from storage");
  if (dev_time_set_time(pt.store.last_synced_time, false, false) != 0) {
    return false;
  }
  g_oc_plgd_time.status = PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE;
  return true;
}

static void
plgd_time_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)iface_mask;
  (void)data;
  plgd_time_t pt = { 0 };
  if (!plgd_time_decode(request->request_payload, &pt)) {
    OC_ERR("cannot decode data for plgd time resource");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  if (dev_time_set_time(pt.store.last_synced_time, false, false) != 0) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  int flags = PLGD_TIME_ENCODE_FLAG_SECURE; // post is protected by acls, so we
                                            // must have secure access
  if (plgd_time_encode(g_oc_plgd_time, OC_IF_RW, flags) != 0) {
    OC_ERR("cannot encode plgd time resource");
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_send_response(request, OC_STATUS_CHANGED);
  plgd_time_dump();
}

static void
plgd_time_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                       void *data)
{
  (void)data;

  int flags = 0;
#ifdef OC_SECURITY
  if ((request->origin->flags & SECURED) != 0) {
    flags |= PLGD_TIME_ENCODE_FLAG_SECURE;
  }
#endif /* OC_SECURITY */
  if (plgd_time_encode(g_oc_plgd_time, iface_mask, flags) != 0) {
    OC_ERR("cannot encode plgd time resource");
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_send_response(request, OC_STATUS_OK);
}

void
plgd_time_create_resource()
{
  OC_DBG("plgd time: create resource");
  oc_core_populate_resource(PLGD_TIME, /*device*/ 0, PLGD_TIME_URI,
                            PLGD_TIME_IF_MASK, PLGD_TIME_DEFAULT_IF,
                            OC_DISCOVERABLE | OC_OBSERVABLE,
                            plgd_time_resource_get,
                            /*put*/ NULL, plgd_time_resource_post,
                            /*delete*/ NULL, 1, PLGD_TIME_RT);
}

void
plgd_time_configure(bool use_in_mbedtls,
                    plgd_set_system_time_fn_t set_system_time,
                    void *set_system_time_data)
{
  OC_DBG("plgd time: initialize feature");
#ifdef OC_SECURITY
  if (use_in_mbedtls) {
    oc_mbedtls_platform_time_init();
  } else {
    oc_mbedtls_platform_time_deinit();
  }
#else  /* !OC_SECURITY */
  (void)use_in_mbedtls;
#endif /* OC_SECURITY */

  g_oc_plgd_time.set_system_time = set_system_time;
  g_oc_plgd_time.set_system_time_data = set_system_time_data;
}

#endif /* OC_HAS_FEATURE_PLGD_TIME */
