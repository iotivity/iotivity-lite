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
#include "port/oc_log_internal.h"
#include "util/oc_compiler.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <time.h>

#ifdef OC_SECURITY
#include <mbedtls/x509.h>
#endif /* OC_SECURITY */

#ifdef OC_CLIENT

typedef struct time_fetch_param_t
{
  plgd_time_on_fetch_fn_t on_fetch;
  void *on_fetch_data;
#if defined(OC_TCP) || defined(OC_SECURITY)
  bool close_peer_after_fetch;
#endif
} time_fetch_param_t;

OC_MEMB(g_fetch_params_s, time_fetch_param_t, OC_MAX_NUM_DEVICES);

static uint16_t PLGD_TIME_FETCH_TIMEOUT = 4;

#if defined(OC_SECURITY) && defined(OC_PKI)

typedef struct time_verify_certificate_params_t
{
  oc_pki_verify_certificate_cb_t verify_certificate;
  oc_pki_user_data_t peer_data;
} time_verify_certificate_params_t;

OC_MEMB(g_time_verify_certificate_params_s, time_verify_certificate_params_t,
        OC_MAX_NUM_DEVICES);

#endif /* OC_SECURITY && OC_PKI  */

#endif /* OC_CLIENT */

static plgd_time_t g_oc_plgd_time = {
  .store = { 0 },
  .status = 0,
  .update_time = 0,
  .set_system_time = NULL,
  .set_system_time_data = NULL,
};

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
  OC_DBG("plgd-time: system time set to %ld", (long)pt);
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
      oc_notify_resource_changed(r);
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
    OC_DBG("plgd-time reset");
    plgd_time_set(0, 0, dump, notify);
    return 0;
  }

  oc_clock_time_t updateTime = oc_clock_time_monotonic();
  if (updateTime == (oc_clock_time_t)-1) {
    OC_ERR("cannot set plgd-time: cannot obtain system uptime");
    return -1;
  }

#if OC_DBG_IS_ENABLED
  char lst_ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(lst, lst_ts, sizeof(lst_ts));
  uint64_t ut_s = (uint64_t)((double)updateTime / (double)OC_CLOCK_SECOND);
  OC_DBG("plgd-time: %s (update: %" PRIu64 "s)", lst_ts, ut_s);
#endif /* OC_DBG_IS_ENABLED */

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
    OC_ERR("cannot get plgd-time: not active");
    return -1;
  }

  oc_clock_time_t cur = oc_clock_time_monotonic();
  if (cur == (oc_clock_time_t)-1) {
    OC_ERR("cannot get plgd-time: cannot obtain system uptime");
    return -1;
  }

  long elapsed = (long)(cur - pt.update_time);
  assert(elapsed >= 0);
  oc_clock_time_t ptime = (pt.store.last_synced_time + elapsed);

#if OC_DBG_IS_ENABLED
#define RFC3339_BUFFER_SIZE 64
  double to_micros = (10000000 / (double)OC_CLOCK_SECOND);
  char lst_ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(pt.store.last_synced_time, lst_ts,
                               sizeof(lst_ts));
  OC_DBG("calculating plgd-time: last_synced_time=%s, update_time=%ldus, "
         "current_time=%ldus, elapsed_time=%ldus",
         lst_ts, (long)(pt.update_time * to_micros), (long)(cur * to_micros),
         (long)(elapsed * to_micros));

  char pt_ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(ptime, pt_ts, sizeof(pt_ts));

  oc_clock_time_t time = oc_clock_time();
  char ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(time, ts, sizeof(ts));
  long diff = (long)((double)(time - ptime) / (double)OC_CLOCK_SECOND);
  OC_DBG("calculated plgd-time: %s, system time: %s, diff: %lds", pt_ts, ts,
         diff);
#endif /* OC_DBG_IS_ENABLED */
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
#if OC_DBG_IS_ENABLED
  const char *status_str = plgd_time_status_to_str(status);
  OC_DBG("plgd-time status: %s", status_str != NULL ? status_str : "NULL");
#endif /* OC_DBG_IS_ENABLED */
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
    OC_DBG("plgd-time: cannot access property(%s)", PLGD_TIME_PROP_TIME);
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
      OC_ERR("cannot encode plgd-time: cannot encode time in rfc3339 format");
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
    OC_DBG("plgd-time: cannot access property(%s)", PLGD_TIME_PROP_STATUS);
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
    OC_DBG("plgd-time: cannot access property(%s)",
           PLGD_TIME_PROP_LAST_SYNCED_TIME);
    return 0;
  }
#else  /* !OC_SECURITY */
  (void)flags;
#endif /* OC_SECURITY */

  char lst[64] = { 0 };
  if (dev_time_is_active(pt) &&
      (oc_clock_encode_time_rfc3339(pt.store.last_synced_time, lst,
                                    sizeof(lst)) == 0)) {
    OC_ERR("cannot encode plgd-time: cannot encode last_synced_time");
    return -1;
  }
  oc_rep_set_text_string(root, lastSyncedTime, lst);
  return 0;
}

int
plgd_time_encode(plgd_time_t pt, oc_interface_mask_t iface, int flags)
{
  const oc_resource_t *r = oc_core_get_resource_by_index(PLGD_TIME, 0);
  if (r == NULL) {
    OC_ERR("cannot encode plgd-time: resource does not exist");
    return -1;
  }
  if (!oc_resource_supports_interface(r, iface)) {
    OC_ERR("cannot encode plgd-time: invalid interface(%d)", (int)iface);
    return -1;
  }

  oc_rep_start_root_object();
  if (iface == OC_IF_BASELINE) {
    // baseline properties
    oc_process_baseline_interface_with_filter(oc_rep_object(root), r,
                                              dev_time_property_filter, &flags);
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
    OC_WRN("plgd-time: unknown property (%s:%d)", oc_string(rep->name),
           (int)rep->type);
  }

  if (lst_rfc3339 == NULL) {
    OC_ERR("cannot decode plgd-time: property %s not found",
           PLGD_TIME_PROP_LAST_SYNCED_TIME);
    return false;
  }

  oc_clock_time_t lst;
  if (!oc_clock_parse_time_rfc3339_v1(oc_string(*lst_rfc3339),
                                      oc_string_len(*lst_rfc3339), &lst)) {
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
  long ret = oc_storage_data_save(PLGD_TIME_STORE_NAME, /*device*/ 0,
                                  store_encode_plgd_time, &g_oc_plgd_time);
  if (ret <= 0) {
    OC_ERR("cannot dump plgd-time to storage: error(%ld)", ret);
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
    OC_ERR("cannot load plgd-time: cannot decode representation");
    return -1;
  }
  return 0;
}

bool
plgd_time_load(void)
{
  plgd_time_t pt;
  memset(&pt, 0, sizeof(pt));
  if (oc_storage_data_load(PLGD_TIME_STORE_NAME, 0, store_decode_plgd_time,
                           &pt) <= 0) {
    OC_DBG("failed to load plgd-time from storage");
    return false;
  }

  OC_DBG("plgd-time loaded from storage");
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
  plgd_time_t pt;
  memset(&pt, 0, sizeof(pt));
  if (!plgd_time_decode(request->request_payload, &pt)) {
    OC_ERR("cannot decode data for plgd-time resource");
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  if (dev_time_set_time(pt.store.last_synced_time, false, false) != 0) {
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }

  int flags = PLGD_TIME_ENCODE_FLAG_SECURE; // post is protected by acls, so we
                                            // must have secure access
  if (plgd_time_encode(g_oc_plgd_time, OC_IF_RW, flags) != 0) {
    OC_ERR("cannot encode plgd-time resource");
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }

  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
  plgd_time_dump();
}

static void
plgd_time_resource_get(oc_request_t *request, oc_interface_mask_t iface,
                       void *data)
{
  (void)data;

  int flags = 0;
#ifdef OC_SECURITY
  if (request->origin != NULL && (request->origin->flags & SECURED) != 0) {
    flags |= PLGD_TIME_ENCODE_FLAG_SECURE;
  }
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  if (request->origin == NULL && iface == PLGD_IF_ETAG) {
    flags |= PLGD_TIME_ENCODE_FLAG_SECURE;
  }
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
#endif /* OC_SECURITY */
  if (plgd_time_encode(g_oc_plgd_time, iface, flags) != 0) {
    OC_ERR("cannot encode plgd-time resource");
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }

  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

void
plgd_time_create_resource(void)
{
  OC_DBG("plgd-time: create resource");
  int interfaces = (OC_IF_BASELINE | OC_IF_RW);
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  interfaces |= PLGD_IF_ETAG;
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  oc_interface_mask_t default_interface = OC_IF_RW;
  assert((interfaces & default_interface) == default_interface);
  int properties = OC_DISCOVERABLE | OC_OBSERVABLE;

  oc_core_populate_resource(PLGD_TIME, /*device*/ 0, PLGD_TIME_URI,
                            (oc_interface_mask_t)interfaces, default_interface,
                            properties, plgd_time_resource_get,
                            /*put*/ NULL, plgd_time_resource_post,
                            /*delete*/ NULL, 1, PLGD_TIME_RT);
}

void
plgd_time_configure(bool use_in_mbedtls,
                    plgd_set_system_time_fn_t set_system_time,
                    void *set_system_time_data)
{
  OC_DBG("plgd-time: initialize feature");
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

#ifdef OC_CLIENT

plgd_time_fetch_config_t
plgd_time_fetch_config(const oc_endpoint_t *endpoint, const char *uri,
                       plgd_time_on_fetch_fn_t on_fetch, void *on_fetch_data,
                       uint16_t timeout, int selected_identity_credid,
                       bool disable_time_verification)
{
  assert(endpoint != NULL);
  assert(uri != NULL);
  assert(on_fetch != NULL);
  plgd_time_fetch_config_t fetch = {
    .endpoint = endpoint,
    .uri = uri,
    .on_fetch = on_fetch,
    .on_fetch_data = on_fetch_data,
    .timeout = timeout,
  };

#if defined(OC_SECURITY) && defined(OC_PKI)
  fetch.selected_identity_credid = selected_identity_credid;
  fetch.verification.disable_time_verification = disable_time_verification;
#else  /* !OC_SECURITY || !OC_PKI */
  (void)selected_identity_credid;
  (void)disable_time_verification;
#endif /* OC_SECURITY && OC_PKI */

  return fetch;
}

#if defined(OC_SECURITY) && defined(OC_PKI)

plgd_time_fetch_config_t
plgd_time_fetch_config_with_custom_verification(
  const oc_endpoint_t *endpoint, const char *uri,
  plgd_time_on_fetch_fn_t on_fetch, void *on_fetch_data, uint16_t timeout,
  int selected_identity_credid, oc_pki_verify_certificate_cb_t verify,
  oc_pki_user_data_t verify_data)
{
  assert(endpoint != NULL);
  assert(uri != NULL);
  assert(on_fetch != NULL);
  assert(verify != NULL);

  plgd_time_fetch_config_t fetch = {
    .endpoint = endpoint,
    .uri = uri,
    .on_fetch = on_fetch,
    .on_fetch_data = on_fetch_data,
    .timeout = timeout,
  };

#if defined(OC_SECURITY) && defined(OC_PKI)
  fetch.selected_identity_credid = selected_identity_credid;
  fetch.verification.verify = verify;
  fetch.verification.verify_data = verify_data;
#else  /* !OC_SECURITY || !OC_PKI */
  (void)selected_identity_credid;
#endif /* OC_SECURITY && OC_PKI */

  return fetch;
}

#endif /* OC_SECURITY && OC_PKI */

static bool
dev_time_parse_fetch_response(const oc_rep_t *rep, oc_clock_time_t *time)
{
  assert(clock != NULL);

  const char *time_str = NULL;
  size_t time_str_len = 0;
  if (!oc_rep_get_string(rep, "time", (char **)&time_str, &time_str_len)) {
    OC_ERR("fetch plgd-time failed: cannot find time property");
    return false;
  }

  oc_clock_time_t ct;
  if (!oc_clock_parse_time_rfc3339_v1(time_str, time_str_len, &ct)) {
    OC_ERR("fetch plgd-time failed: parse clock time from string(%s)",
           time_str);
    return false;
  }

  *time = ct;
  return true;
}

static void
dev_time_on_fetch(oc_client_response_t *data)
{
  time_fetch_param_t *fp = (time_fetch_param_t *)data->user_data;
  oc_clock_time_t time = 0;
  oc_status_t code = data->code;
  if (code == OC_STATUS_OK &&
      !dev_time_parse_fetch_response(data->payload, &time)) {
    code = OC_STATUS_INTERNAL_SERVER_ERROR;
  }

  OC_DBG("plgd-time: on_fetch time=%d time=%u", (int)code, (unsigned)time);
  fp->on_fetch(code, time, fp->on_fetch_data);
#if defined(OC_TCP) || defined(OC_SECURITY)
  if (fp->close_peer_after_fetch && (code != OC_CONNECTION_CLOSED)) {
    OC_DBG("plgd-time: close fetch time session");
    oc_close_session(data->endpoint);
  }
#endif /* OC_TCP || OC_SECURITY */

  oc_memb_free(&g_fetch_params_s, fp);
}

#if defined(OC_SECURITY) && defined(OC_PKI)

static void
time_verify_certificate_params_free(void *data)
{
  if (data == NULL) {
    return;
  }
  time_verify_certificate_params_t *vcp =
    (time_verify_certificate_params_t *)data;
  if (vcp->peer_data.free != NULL) {
    vcp->peer_data.free(vcp->peer_data.data);
  }
  oc_memb_free(&g_time_verify_certificate_params_s, vcp);
}

static int
dev_time_verify_certificate(oc_tls_peer_t *peer, const mbedtls_x509_crt *crt,
                            int depth, uint32_t *flags)
{
  OC_DBG("plgd-time: verifying certificate at depth %d, flags %u", depth,
         *flags);

  time_verify_certificate_params_t *vcp =
    (time_verify_certificate_params_t *)peer->user_data.data;
  // set expected user data for verify_certificate
  peer->user_data.data = vcp->peer_data.data;
  peer->user_data.free = vcp->peer_data.free;
  int ret = vcp->verify_certificate(peer, crt, depth, flags);
  OC_DBG("plgd-time: default verification done (depth=%d, flags=%u)", depth,
         *flags);
  // restore overriden data for correct deallocation
  peer->user_data.data = vcp;
  peer->user_data.free = time_verify_certificate_params_free;
  *flags &=
    ~((uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE));
  OC_DBG("plgd-time: removed validity errors (flags=%u)", *flags);

  return ret;
}

static bool
dev_time_add_peer(const oc_endpoint_t *endpoint,
                  plgd_time_fetch_verification_config_t verify_config)
{
  // must be only called when there is no peer yet for the endpoint
  assert(oc_tls_get_peer(endpoint) == NULL);
  OC_DBG("plgd-time: add new peer");

  time_verify_certificate_params_t *vcp = NULL;
  if (verify_config.verify == NULL && verify_config.disable_time_verification) {
    vcp = (time_verify_certificate_params_t *)oc_memb_alloc(
      &g_time_verify_certificate_params_s);
    if (vcp == NULL) {
      OC_ERR("plgd-time add peer failed: cannot allocate verify certificate "
             "parameters");
      return false;
    }
  }

  oc_tls_new_peer_params_t peer_params = {
    .endpoint = endpoint,
    .role = MBEDTLS_SSL_IS_CLIENT,
  };
  if (vcp != NULL) {
    oc_tls_pki_verification_params_t pki_params =
      oc_tls_peer_pki_default_verification_params();
    OC_DBG("plgd-time: disable time verification for peer");
    vcp->verify_certificate = pki_params.verify_certificate;
    vcp->peer_data = pki_params.user_data;
    peer_params.user_data.data = vcp;
    peer_params.user_data.free = time_verify_certificate_params_free;
    peer_params.verify_certificate = dev_time_verify_certificate;
  } else if (verify_config.verify != NULL) {
    OC_DBG("plgd-time: custom verification for peer");
    peer_params.user_data = verify_config.verify_data;
    peer_params.verify_certificate = verify_config.verify;
  }
  const oc_tls_peer_t *peer = oc_tls_add_new_peer(peer_params);
  if (peer == NULL) {
    OC_ERR("plgd-time add peer failed: oc_tls_add_peer failed");
    oc_memb_free(&g_time_verify_certificate_params_s, vcp);
    return false;
  }
  return true;
}

#endif /* OC_SECURITY && OC_PKI */

#if defined(OC_TCP) || defined(OC_SECURITY)

static bool
dev_time_has_session(const oc_endpoint_t *endpoint)
{
#ifdef OC_SECURITY
  if ((endpoint->flags & SECURED) != 0) {
    const oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
    OC_DBG("plgd-time: peer state=%d", peer != NULL ? peer->ssl_ctx.state : -1);
    return peer != NULL;
  }
#endif /* OC_SECURITY */

#ifdef OC_TCP
  if ((endpoint->flags & TCP) != 0) {
    int tcp = oc_tcp_connection_state(endpoint);
    OC_DBG("plgd-time: session state=%d", tcp);
    return tcp > 0;
  }
#endif /* OC_TCP */
  return false;
}

#endif /* OC_SECURITY && OC_PKI */

bool
plgd_time_fetch(plgd_time_fetch_config_t fetch, unsigned *flags)
{
#ifndef OC_TCP
  (void)flags;
#endif /* !OC_TCP */
  assert(fetch.endpoint != NULL);
  assert(fetch.uri != NULL);

  if (fetch.timeout == 0) {
    fetch.timeout = PLGD_TIME_FETCH_TIMEOUT;
  }

  time_fetch_param_t *fetch_params =
    (time_fetch_param_t *)oc_memb_alloc(&g_fetch_params_s);
  if (fetch_params == NULL) {
    OC_ERR("cannot allocate fetch plgd-time parameters");
    return false;
  }

#if defined(OC_TCP) || defined(OC_SECURITY)
  bool has_session = dev_time_has_session(fetch.endpoint);
  OC_DBG("plgd-time: has_session=%d", (int)has_session);

  if (!has_session) {
#ifdef OC_TCP
    if ((fetch.endpoint->flags & TCP) != 0 && flags != NULL) {
      OC_DBG("plgd-time: append TCP_SESSION_OPENED to output flags");
      *flags |= PLGD_TIME_FETCH_FLAG_TCP_SESSION_OPENED;
    }
#endif /* OC_TCP */

    // no session was opened -> new one will be opened for fetching of time and
    // closed when it is done
    fetch_params->close_peer_after_fetch = true;
  }
#endif /* OC_TCP || OC_SECURITY */

#if defined(OC_SECURITY) && defined(OC_PKI)
  // dtls or tls -> if we don't have a connected peer already create a new one
  // with disabled time verification on certificates
  bool add_insecure_peer =
    (fetch.endpoint->flags & SECURED) != 0 && !has_session;
  if (add_insecure_peer) {
    oc_tls_select_identity_cert_chain(fetch.selected_identity_credid);

    if (!dev_time_add_peer(fetch.endpoint, fetch.verification)) {
      oc_memb_free(&g_fetch_params_s, fetch_params);
      return false;
    }
  }
#endif /* OC_SECURITY && OC_PKI */

  fetch_params->on_fetch = fetch.on_fetch;
  fetch_params->on_fetch_data = fetch.on_fetch_data;

  if (!oc_do_get_with_timeout(fetch.uri, fetch.endpoint, "", fetch.timeout,
                              dev_time_on_fetch, HIGH_QOS, fetch_params)) {
    OC_ERR("failed to send fetch plgd-time request to endpoint");
#if defined(OC_SECURITY) && defined(OC_PKI)
    if (add_insecure_peer) {
      oc_tls_remove_peer(fetch.endpoint);
    }
#endif /* OC_SECURITY && OC_PKI */
    oc_memb_free(&g_fetch_params_s, fetch_params);
    return false;
  }
  return true;
}

#endif /* OC_CLIENT */

#endif /* OC_HAS_FEATURE_PLGD_TIME */
