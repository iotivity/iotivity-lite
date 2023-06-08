/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#include "oc_config.h"

#ifdef OC_SOFTWARE_UPDATE

#include "oc_swupdate.h"
#include "oc_swupdate_internal.h"

#include "api/oc_core_res_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#endif /* OC_SECURITY  */
#include "util/oc_compiler.h"
#include "util/oc_macros.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#include <assert.h>
#include <limits.h>
#include <stdlib.h>

#ifndef OC_STORAGE
#error Preprocessor macro OC_SOFTWARE_UPDATE is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_SOFTWARE_UPDATE is defined.
#endif

#define OC_SWUPDATE_IDLE_STR "idle"
#define OC_SWUPDATE_ISAC_STR "isac"
#define OC_SWUPDATE_ISVV_STR "isvv"
#define OC_SWUPDATE_UPGRADE_STR "upgrade"

#define OC_SWUPDATE_STATE_IDLE_STR "idle"
#define OC_SWUPDATE_STATE_NSA_STR "nsa"
#define OC_SWUPDATE_STATE_SVV_STR "svv"
#define OC_SWUPDATE_STATE_SVA_STR "sva"
#define OC_SWUPDATE_STATE_UPGRADING_STR "upgrading"

#define OC_SWU_PROP_LASTUPDATE "lastupdate"
#define OC_SWU_PROP_NEWVERSION "nv"
#define OC_SWU_PROP_PACKAGEURL "purl"
#define OC_SWU_PROP_SIGNED "signed"
#define OC_SWU_PROP_UPDATEACTION "swupdateaction"
#define OC_SWU_PROP_UPDATERESULT "swupdateresult"
#define OC_SWU_PROP_UPDATESTATE "swupdatestate"
#define OC_SWU_PROP_UPDATETIME "updatetime"

// Special values for the updatetime property
#define OC_SWU_PROP_UPDATETIME_NONE "none" // skip update action
#define OC_SWU_PROP_UPDATETIME_NOW "now"   // update immediately

typedef enum {
  UPDATE_TIME_NOT_SET,
  UPDATE_TIME_SET,
  UPDATE_TIME_NONE, // keeps property value unchanged
  UPDATE_TIME_NOW,
} update_time_set_t;

typedef struct
{
  const oc_string_t *purl;
  const oc_string_t *nv;
  const oc_string_t *signage;
  oc_swupdate_action_t swupdateaction;
  oc_swupdate_state_t swupdatestate;
  int swupdateresult;
  oc_clock_time_t lastupdate;
  oc_clock_time_t updatetime;

  bool swupdateaction_set;
  bool swupdatestate_set;
  bool swupdateresult_set;
  bool lastupdate_set;
  update_time_set_t updatetime_set;

} oc_swupdate_decode_t;

#ifdef OC_DYNAMIC_ALLOCATION
static oc_swupdate_t *g_sw;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_swupdate_t g_sw[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

static const oc_swupdate_cb_t *g_swupdate_impl;

static oc_event_callback_retval_t swupdate_update_async(void *data);

static void
swupdate_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_sw =
    (oc_swupdate_t *)calloc(oc_core_get_num_devices(), sizeof(oc_swupdate_t));
  if (g_sw == NULL) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_swupdate_free(void)
{
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    oc_ri_remove_timed_event_callback(&g_sw[i], swupdate_update_async);
    oc_free_string(&g_sw[i].purl);
    oc_free_string(&g_sw[i].nv);
    oc_free_string(&g_sw[i].signage);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(g_sw);
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc_swupdate_t *
oc_swupdate_get(size_t device)
{
  return &g_sw[device];
}

void
oc_swupdate_default(size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  assert(g_sw != NULL);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_swupdate_clear(&g_sw[device]);
  // Signage method of the software package, currently the only allowed value
  // is 'vendor'
  oc_new_string(&g_sw[device].signage, "vendor", OC_CHAR_ARRAY_LEN("vendor"));
  oc_swupdate_dump(device);
}

void
oc_swupdate_copy(oc_swupdate_t *dst, const oc_swupdate_t *src)
{
  assert(src != NULL);
  assert(dst != NULL);

  if (dst == src) {
    return;
  }

  oc_copy_string(&dst->purl, &src->purl);
  oc_copy_string(&dst->nv, &src->nv);
  oc_copy_string(&dst->signage, &src->signage);
  dst->swupdateaction = src->swupdateaction;
  dst->swupdatestate = src->swupdatestate;
  dst->swupdateresult = src->swupdateresult;
  dst->lastupdate = src->lastupdate;
  dst->updatetime = src->updatetime;
}

void
oc_swupdate_clear(oc_swupdate_t *swu)
{
  oc_ri_remove_timed_event_callback(swu, swupdate_update_async);
  oc_free_string(&swu->purl);
  oc_free_string(&swu->nv);
  oc_free_string(&swu->signage);
  swu->swupdateaction = OC_SWUPDATE_IDLE;
  swu->swupdatestate = OC_SWUPDATE_STATE_IDLE;
  swu->swupdateresult = 0;
  swu->lastupdate = 0;
  swu->updatetime = 0;
}

static oc_status_t
swupdate_encode_for_device_with_interface(oc_interface_mask_t iface,
                                          size_t device)
{
  switch (iface) {
  case OC_IF_RW:
  case OC_IF_BASELINE:
    if (!oc_swupdate_encode_for_device(
          device, iface == OC_IF_BASELINE
                    ? OC_SWUPDATE_ENCODE_FLAG_INCLUDE_BASELINE
                    : 0)) {

      return OC_STATUS_INTERNAL_SERVER_ERROR;
    }
    return OC_STATUS_OK;
  default:
    break;
  }
  return OC_STATUS_BAD_REQUEST;
}

static void
swupdate_resource_get(oc_request_t *request, oc_interface_mask_t iface,
                      void *data)
{
  (void)data;
  oc_status_t code =
    swupdate_encode_for_device_with_interface(iface, request->resource->device);
  oc_send_response_with_callback(request, code, true);
}

static oc_event_callback_retval_t
swupdate_update_async(void *data)
{
  oc_swupdate_t *s = (oc_swupdate_t *)data;
  size_t device = (size_t)-1;
  for (size_t i = 0; i < oc_core_get_num_devices(); i++) {
    if (s == &g_sw[i]) {
      device = i;
      break;
    }
  }
  if (device == (size_t)-1) {
    OC_ERR("swupdate: cannot schedule update, device data not found");
    return OC_EVENT_DONE;
  }
  oc_swupdate_perform_action(s->swupdateaction, device);
  return OC_EVENT_DONE;
}

void
oc_swupdate_action_schedule(size_t device, oc_clock_time_t schedule_at)
{
  assert(!oc_swupdate_action_is_scheduled(device));

#if OC_DBG_IS_ENABLED
#define RFC3339_BUFFER_SIZE 64
  char scheduled_ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(schedule_at, scheduled_ts, sizeof(scheduled_ts));
  OC_DBG("swupdate: update scheduled at %s", scheduled_ts);
#endif /* OC_DBG_IS_ENABLED */

  oc_clock_time_t now = oc_clock_time();
  if (schedule_at > now) {
    schedule_at -= now;
  } else {
    schedule_at = 0;
  }
  // TODO: update API to schedule callbacks to an absolute time, because of
  // possible time synchronization
  oc_ri_add_timed_event_callback_ticks(&g_sw[device], swupdate_update_async,
                                       schedule_at);
}

bool
oc_swupdate_action_is_scheduled(size_t device)
{
  return oc_ri_has_timed_event_callback(&g_sw[device], swupdate_update_async,
                                        false);
}

static void
swupdate_execute_action(size_t device)
{
  const oc_swupdate_t *s = &g_sw[device];
  oc_ri_remove_timed_event_callback(s, swupdate_update_async);
  if (s->swupdateaction == OC_SWUPDATE_IDLE || s->updatetime == 0) {
    return;
  }
  oc_swupdate_action_schedule(device, s->updatetime);
}

static void
swupdate_resource_post(oc_request_t *request, oc_interface_mask_t iface,
                       void *data)
{
  (void)data;
  size_t device = request->resource->device;
  if (!oc_swupdate_decode_for_device(request->request_payload,
                                     OC_SWUPDATE_DECODE_FLAG_COAP_UPDATE,
                                     device)) {
    oc_send_response_with_callback(request, OC_STATUS_NOT_ACCEPTABLE, true);
    return;
  }

  swupdate_execute_action(device);

  // response
  oc_status_t code = swupdate_encode_for_device_with_interface(iface, device);
  if (code != OC_STATUS_OK) {
    OC_ERR("swupdate: failed to encode POST request response");
  }
  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);

  oc_swupdate_dump(device);
}

static void
swupdate_create_resource(size_t device)
{
  oc_core_populate_resource(
    OCF_SW_UPDATE, device, OCF_SW_UPDATE_URI, OCF_SW_UPDATE_IF_MASK,
    OCF_SW_UPDATE_DEFAULT_IF, OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    swupdate_resource_get, /*put*/ NULL, swupdate_resource_post,
    /*delete*/ NULL, 1, OCF_SW_UPDATE_RT);
}

void
oc_swupdate_create(void)
{
  swupdate_init();
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    swupdate_create_resource(i);
  }
}

const char *
oc_swupdate_action_to_str(oc_swupdate_action_t action)
{
  switch (action) {
  case OC_SWUPDATE_IDLE:
    return OC_SWUPDATE_IDLE_STR;
  case OC_SWUPDATE_ISAC:
    return OC_SWUPDATE_ISAC_STR;
  case OC_SWUPDATE_ISVV:
    return OC_SWUPDATE_ISVV_STR;
  case OC_SWUPDATE_UPGRADE:
    return OC_SWUPDATE_UPGRADE_STR;
  }
  return NULL;
}

int
oc_swupdate_action_from_str(const char *action, size_t action_len)
{
  if (action_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_IDLE_STR) &&
      memcmp(action, OC_SWUPDATE_IDLE_STR, action_len) == 0) {
    return OC_SWUPDATE_IDLE;
  }
  if (action_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_ISAC_STR) &&
      memcmp(action, OC_SWUPDATE_ISAC_STR, action_len) == 0) {
    return OC_SWUPDATE_ISAC;
  }
  if (action_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_ISVV_STR) &&
      memcmp(action, OC_SWUPDATE_ISVV_STR, action_len) == 0) {
    return OC_SWUPDATE_ISVV;
  }
  if (action_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_UPGRADE_STR) &&
      memcmp(action, OC_SWUPDATE_UPGRADE_STR, action_len) == 0) {
    return OC_SWUPDATE_UPGRADE;
  }
  return -1;
}

const char *
oc_swupdate_state_to_str(oc_swupdate_state_t state)
{
  switch (state) {
  case OC_SWUPDATE_STATE_IDLE:
    return OC_SWUPDATE_STATE_IDLE_STR;
  case OC_SWUPDATE_STATE_NSA:
    return OC_SWUPDATE_STATE_NSA_STR;
  case OC_SWUPDATE_STATE_SVV:
    return OC_SWUPDATE_STATE_SVV_STR;
  case OC_SWUPDATE_STATE_SVA:
    return OC_SWUPDATE_STATE_SVA_STR;
  case OC_SWUPDATE_STATE_UPGRADING:
    return OC_SWUPDATE_STATE_UPGRADING_STR;
  }
  return NULL;
}

int
oc_swupdate_state_from_str(const char *state, size_t state_len)
{
  if (state_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_STATE_IDLE_STR) &&
      memcmp(state, OC_SWUPDATE_STATE_IDLE_STR, state_len) == 0) {
    return OC_SWUPDATE_STATE_IDLE;
  }
  if (state_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_STATE_NSA_STR) &&
      memcmp(state, OC_SWUPDATE_STATE_NSA_STR, state_len) == 0) {
    return OC_SWUPDATE_STATE_NSA;
  }
  if (state_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_STATE_SVV_STR) &&
      memcmp(state, OC_SWUPDATE_STATE_SVV_STR, state_len) == 0) {
    return OC_SWUPDATE_STATE_SVV;
  }
  if (state_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_STATE_SVA_STR) &&
      memcmp(state, OC_SWUPDATE_STATE_SVA_STR, state_len) == 0) {
    return OC_SWUPDATE_STATE_SVA;
  }
  if (state_len == OC_CHAR_ARRAY_LEN(OC_SWUPDATE_STATE_UPGRADING_STR) &&
      memcmp(state, OC_SWUPDATE_STATE_UPGRADING_STR, state_len) == 0) {
    return OC_SWUPDATE_STATE_UPGRADING;
  }
  return -1;
}

static void
swupdate_decode_copy(const oc_swupdate_decode_t *src, oc_swupdate_t *dst)
{
  if (src->purl != NULL) {
    oc_copy_string(&dst->purl, src->purl);
  }

  if (src->nv != NULL) {
    oc_copy_string(&dst->nv, src->nv);
  }

  if (src->signage != NULL) {
    oc_copy_string(&dst->signage, src->signage);
  }

  if (src->swupdateaction_set) {
    dst->swupdateaction = src->swupdateaction;
  }

  if (src->swupdatestate_set) {
    dst->swupdatestate = src->swupdatestate;
  }

  if (src->swupdateresult_set) {
    dst->swupdateresult = src->swupdateresult;
  }

  if (src->lastupdate_set) {
    dst->lastupdate = src->lastupdate;
  }

  if (src->updatetime_set != UPDATE_TIME_NOT_SET) {
    if (src->updatetime_set == UPDATE_TIME_SET) {
      dst->updatetime = src->updatetime;
      return;
    }
    if (src->updatetime_set == UPDATE_TIME_NOW) {
      dst->updatetime = oc_clock_time();
      return;
    }
    dst->updatetime = 0;
    return;
  }
}

static bool
swupdate_decode_int_property(const oc_rep_t *rep, int flags,
                             oc_swupdate_decode_t *swudecode)
{
  assert(rep->type == OC_REP_INT);
  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATERESULT,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATERESULT))) {
    if ((flags & OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE) != 0) {
      assert(rep->value.integer <= INT_MAX);
      swudecode->swupdateresult = (int)rep->value.integer;
      swudecode->swupdateresult_set = true;
      return true;
    }
    /* Read-only property */
    return false;
  }
  return false;
}

static oc_clock_time_t
swupdate_decode_timestamp(const oc_string_t *value)
{
  if (oc_string_len(*value) >= 63) {
    return (oc_clock_time_t)-1;
  }
  return oc_clock_parse_time_rfc3339(oc_string(*value), oc_string_len(*value));
}

static bool
swupdate_decode_update_time(const oc_rep_t *rep, int flags,
                            oc_swupdate_decode_t *swudecode)
{
  assert(rep->type == OC_REP_STRING);

  bool from_storage = (flags & OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE) != 0;

  if (!from_storage) {
    // allow special values for UPDATE
    if (oc_string_is_cstr_equal(
          &rep->value.string, OC_SWU_PROP_UPDATETIME_NONE,
          OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATETIME_NONE))) {
      swudecode->updatetime_set = UPDATE_TIME_NONE;
      return true;
    }
    if (oc_string_is_cstr_equal(
          &rep->value.string, OC_SWU_PROP_UPDATETIME_NOW,
          OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATETIME_NOW))) {
      swudecode->updatetime_set = UPDATE_TIME_NOW;
      return true;
    }
  }
  oc_clock_time_t updatetime = swupdate_decode_timestamp(&rep->value.string);
  if (updatetime == (oc_clock_time_t)-1) {
    OC_ERR("swupdate: invalid updatetime property(%s)",
           oc_string(rep->value.string));
    return false;
  }
  swudecode->updatetime = updatetime;
  swudecode->updatetime_set = UPDATE_TIME_SET;
  return true;
}

static bool
swupdate_decode_string_property(const oc_rep_t *rep, int flags,
                                oc_swupdate_decode_t *swudecode)
{
  assert(rep->type == OC_REP_STRING);
  bool from_storage = (flags & OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE) != 0;

  if (oc_rep_is_property(rep, OC_SWU_PROP_NEWVERSION,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_NEWVERSION))) {
    if (!from_storage) {
      /* Read-only property */
      return false;
    }
    swudecode->nv = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_SIGNED,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_SIGNED))) {

    if (!from_storage) {
      return false; // cannot be edited currently, only "vendor" value is
                    // supported
    }
    swudecode->signage = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATEACTION,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATEACTION))) {
    int action = oc_swupdate_action_from_str(oc_string(rep->value.string),
                                             oc_string_len(rep->value.string));
    if (action < 0) {
      return false;
    }
    swudecode->swupdateaction = (oc_swupdate_action_t)action;
    swudecode->swupdateaction_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATESTATE,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATESTATE))) {
    if (!from_storage) {
      /* Read-only property */
      return false;
    }
    int state = oc_swupdate_state_from_str(oc_string(rep->value.string),
                                           oc_string_len(rep->value.string));
    if (state < 0) {
      return false;
    }
    swudecode->swupdatestate = (oc_swupdate_state_t)state;
    swudecode->swupdatestate_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_LASTUPDATE,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_LASTUPDATE))) {
    if (!from_storage) {
      /* Read-only property */
      return false;
    }
    oc_clock_time_t lastupdate = swupdate_decode_timestamp(&rep->value.string);
    if (lastupdate == (oc_clock_time_t)-1) {
      OC_ERR("swupdate: invalid lastupdate property(%s)",
             oc_string(rep->value.string));
      return false;
    }
    swudecode->lastupdate = lastupdate;
    swudecode->lastupdate_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATETIME,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_UPDATETIME))) {
    return swupdate_decode_update_time(rep, flags, swudecode);
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_PACKAGEURL,
                         OC_CHAR_ARRAY_LEN(OC_SWU_PROP_PACKAGEURL))) {
    swudecode->purl = &rep->value.string;
    return true;
  }
  return false;
}

static bool
swupdate_validate_decode(const oc_swupdate_decode_t *swudecode,
                         bool skip_purl_validation)
{
  if (swudecode->updatetime_set == UPDATE_TIME_NOT_SET) {
    OC_ERR("swupdate: updatetime not set");
    return false;
  }
  if (swudecode->updatetime_set == UPDATE_TIME_SET &&
      swudecode->updatetime < oc_clock_time()) {
    OC_ERR("swupdate: updatetime(%ld) is in the past",
           (long)swudecode->updatetime);
    return false;
  }

  if (!skip_purl_validation) {
    const char *purl =
      swudecode->purl == NULL ? NULL : oc_string(*swudecode->purl);
    if (purl == NULL) {
      OC_ERR("swupdate: package URL not set");
      return false;
    }

    if (g_swupdate_impl == NULL || (g_swupdate_impl->validate_purl == NULL)) {
      OC_ERR("swupdate: cannot validate package URL");
      return false;
    }
    if (g_swupdate_impl->validate_purl(purl) < 0) {
      OC_ERR("swupdate: package URL not valid");
      return false;
    }
  }
  return true;
}

bool
oc_swupdate_decode(const oc_rep_t *rep, int flags, oc_swupdate_t *dst)
{
  oc_swupdate_decode_t swudecode = { 0 };
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_STRING &&
        swupdate_decode_string_property(rep, flags, &swudecode)) {
      continue;
    }
    if (rep->type == OC_REP_INT &&
        swupdate_decode_int_property(rep, flags, &swudecode)) {
      continue;
    }

    if ((flags & OC_SWUPDATE_DECODE_FLAG_IGNORE_ERRORS) == 0) {
      OC_ERR("swupdate: cannot decode property (name=%s, type=%d)",
             oc_string(rep->name), (int)rep->type);
      return false;
    }
    OC_DBG("swupdate: cannot decode property (name=%s, type=%d)",
           oc_string(rep->name), (int)rep->type);
  }

  if ((flags & OC_SWUPDATE_DECODE_FLAG_COAP_UPDATE) != 0) {
    // special case for non-idle actions -> if purl is empty we keep the
    // previous purl and skip purl validation
    bool skip_purl_validation = false;
    if (swudecode.swupdateaction_set &&
        swudecode.swupdateaction != OC_SWUPDATE_IDLE &&
        swudecode.purl != NULL && oc_string(*swudecode.purl)[0] == '\0' &&
        oc_string(dst->purl) != NULL) {
      skip_purl_validation = true;
    }

    if (!swupdate_validate_decode(&swudecode, skip_purl_validation)) {
      return false;
    }
  }

  swupdate_decode_copy(&swudecode, dst);
  return true;
}

bool
oc_swupdate_decode_for_device(const oc_rep_t *rep, int flags, size_t device)
{
  return oc_swupdate_decode(rep, flags, &g_sw[device]);
}

static bool
swupdate_encode_package_url(const oc_string_t *purl)
{
  oc_rep_set_text_string(root, purl, oc_string(*purl));
  return g_err == 0;
}

static bool
swupdate_encode_new_version(const oc_string_t *nv)
{
  oc_rep_set_text_string(root, nv, oc_string(*nv));
  return g_err == 0;
}

static bool
swupdate_encode_signed(const oc_string_t *signage)
{
  oc_rep_set_text_string(root, signed, oc_string(*signage));
  return g_err == 0;
}

static bool
swupdate_encode_swupdateaction(oc_swupdate_action_t swupdateaction)
{
  oc_rep_set_text_string(root, swupdateaction,
                         oc_swupdate_action_to_str(swupdateaction));
  return g_err == 0;
}

static bool
swupdate_encode_swupdatestate(oc_swupdate_state_t swupdatestate)
{
  oc_rep_set_text_string(root, swupdatestate,
                         oc_swupdate_state_to_str(swupdatestate));
  return g_err == 0;
}

static bool
swupdate_encode_swupdateresult(int swupdateresult)
{
  oc_rep_set_int(root, swupdateresult, swupdateresult);
  return g_err == 0;
}

bool
oc_swupdate_encode_clocktime_to_string(
  oc_clock_time_t time, oc_swupdate_on_encode_timestamp_to_string_t encode)
{
#define RFC3339_BUFFER_SIZE 64
  char ts[RFC3339_BUFFER_SIZE];
  if (oc_clock_encode_time_rfc3339(time, ts, sizeof(ts)) == 0) {
    return false;
  }
  return encode(ts);
}

static bool
swupdate_on_encode_lastupdate(const char *timestamp)
{
  oc_rep_set_text_string(root, lastupdate, timestamp);
  return g_err == 0;
}

static bool
swupdate_on_encode_updatetime(const char *timestamp)
{
  oc_rep_set_text_string(root, updatetime, timestamp);
  return g_err == 0;
}

int
oc_swupdate_encode_with_resource(const oc_swupdate_t *swu,
                                 const oc_resource_t *swu_res, int flags)
{
  assert(oc_rep_get_cbor_errno() == CborNoError);
  assert(swu != NULL);

  oc_rep_start_root_object();
  if ((flags & OC_SWUPDATE_ENCODE_FLAG_INCLUDE_BASELINE) != 0) {
    assert(swu_res != NULL);
    oc_process_baseline_interface(swu_res);
  }

  bool to_storage = (flags & OC_SWUPDATE_ENCODE_FLAG_TO_STORAGE) != 0;
  if (!swupdate_encode_package_url(&swu->purl)) {
    OC_ERR("swupdate: failed to encode purl property");
    return -1;
  }
  if (!swupdate_encode_new_version(&swu->nv)) {
    OC_ERR("swupdate: failed to encode nv property");
    return -1;
  }
  if (!swupdate_encode_signed(&swu->signage)) {
    OC_ERR("swupdate: failed to encode signed property");
    return -1;
  }
  if (!swupdate_encode_swupdateaction(swu->swupdateaction)) {
    OC_ERR("swupdate: failed to encode swupdateaction property");
    return -1;
  }
  if (!swupdate_encode_swupdatestate(swu->swupdatestate)) {
    OC_ERR("swupdate: failed to encode swupdatestate property");
    return -1;
  }
  if (!swupdate_encode_swupdateresult(swu->swupdateresult)) {
    OC_ERR("swupdate: failed to encode swupdateresult property");
    return -1;
  }
  if (swu->lastupdate > 0 &&
      !oc_swupdate_encode_clocktime_to_string(swu->lastupdate,
                                              swupdate_on_encode_lastupdate)) {
    OC_ERR("swupdate: failed to encode lastupdate property");
    return -1;
  }

  if ((!to_storage || swu->updatetime > 0) &&
      !oc_swupdate_encode_clocktime_to_string(swu->updatetime,
                                              swupdate_on_encode_updatetime)) {
    OC_ERR("swupdate: failed to encode updatetime property");
    return -1;
  }
  oc_rep_end_root_object();
  return g_err;
}

bool
oc_swupdate_encode_for_device(size_t device, int flags)
{
  const oc_swupdate_t *swu = oc_swupdate_get(device);
  const oc_resource_t *swu_res = NULL;
  if ((flags & OC_SWUPDATE_ENCODE_FLAG_INCLUDE_BASELINE) != 0) {
    swu_res = oc_core_get_resource_by_index(OCF_SW_UPDATE, device);
  }
  return oc_swupdate_encode_with_resource(swu, swu_res, flags) == 0;
}

static int
swupdate_store_decode(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  if (!oc_swupdate_decode_for_device(rep, OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE,
                                     device)) {
    OC_ERR("swupdate: cannot decode data for device(%zu)", device);
    return -1;
  }
  return 0;
}

long
oc_swupdate_load(size_t device)
{
  long ret = oc_storage_load_resource(OCF_SW_UPDATE_STORE_NAME, device,
                                      swupdate_store_decode, NULL);
  if (ret <= 0) {
    OC_ERR("swupdate: failed to load swupdate from storage for device(%zu)",
           device);
    oc_swupdate_default(device);
    return ret;
  }
  OC_DBG("swupdate: resource loaded from storage for device(%zu)", device);
  swupdate_execute_action(device);
  return ret;
}

static int
swupdate_store_encode(size_t device, void *data)
{
  (void)data;
  return oc_swupdate_encode_for_device(device,
                                       OC_SWUPDATE_ENCODE_FLAG_TO_STORAGE)
           ? 0
           : -1;
}

long
oc_swupdate_dump(size_t device)
{
  long ret = oc_storage_save_resource(OCF_SW_UPDATE_STORE_NAME, device,
                                      swupdate_store_encode, NULL);
  if (ret <= 0) {
    OC_ERR("swupdate: cannot dump data for device(%zu) to store: error(%ld)",
           device, ret);
  }
  return ret;
}

void
oc_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl)
{
  g_swupdate_impl = swupdate_impl;
}

void
oc_swupdate_notify_new_version_available(size_t device, const char *version,
                                         oc_swupdate_result_t result)
{
  OC_DBG("swupdate: new software version(%s) available for device(%zd) with "
         "result=%d",
         version, device, (int)result);
#ifdef OC_SECURITY
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA);
#endif /* OC_SECURITY */
  oc_swupdate_t *s = &g_sw[device];
  oc_set_string(&s->nv, version, strlen(version));
  s->swupdatestate = OC_SWUPDATE_STATE_NSA;
  s->swupdateresult = result;
  if (result != OC_SWUPDATE_RESULT_SUCCESS) {
    s->swupdateaction = OC_SWUPDATE_IDLE;
  }
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  if (result == OC_SWUPDATE_RESULT_SUCCESS) {
    oc_swupdate_perform_action(OC_SWUPDATE_ISVV, device);
  }
}

void
oc_swupdate_notify_downloaded(size_t device, const char *version,
                              oc_swupdate_result_t result)
{
  (void)version;
  OC_DBG("swupdate: software version %s downloaded and validated for "
         "device(%zd) with result=%d",
         version, device, (int)result);

#ifdef OC_SECURITY
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA | OC_DPM_SVV);
#endif /* OC_SECURITY */
  oc_swupdate_t *s = &g_sw[device];
  s->swupdatestate = OC_SWUPDATE_STATE_SVV;
  s->swupdateresult = result;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  s->swupdatestate = OC_SWUPDATE_STATE_SVA;
  s->swupdateresult = result;
  if (result != OC_SWUPDATE_RESULT_SUCCESS) {
    s->swupdateaction = OC_SWUPDATE_IDLE;
  }
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  if (result == OC_SWUPDATE_RESULT_SUCCESS) {
    oc_swupdate_perform_action(OC_SWUPDATE_UPGRADE, device);
  }
}

void
oc_swupdate_notify_upgrading(size_t device, const char *version,
                             oc_clock_time_t timestamp,
                             oc_swupdate_result_t result)
{
  OC_DBG("swupdate: upgrading to software version %s on device(%zd) with "
         "result=%d",
         version, device, (int)result);
#ifdef OC_SECURITY
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA | OC_DPM_SVV | OC_DPM_SSV);
#endif /* OC_SECURITY */
  oc_swupdate_t *s = &g_sw[device];
  s->swupdatestate = OC_SWUPDATE_STATE_UPGRADING;
  s->swupdateresult = result;
  oc_free_string(&s->nv);
  oc_new_string(&s->nv, version, strlen(version));
  s->lastupdate = timestamp;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
}

void
oc_swupdate_notify_done(size_t device, oc_swupdate_result_t result)
{
  OC_DBG("swupdate: software upgrade done on device(%zd) with result=%d",
         device, (int)result);
#ifdef OC_SECURITY
  oc_sec_pstat_set_current_mode(device, 0);
#endif /* OC_SECURITY */
  oc_swupdate_t *s = &g_sw[device];
  oc_free_string(&s->nv);
  s->swupdateaction = OC_SWUPDATE_IDLE;
  s->swupdatestate = OC_SWUPDATE_STATE_IDLE;
  s->swupdateresult = result;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
}

void
oc_swupdate_perform_action(oc_swupdate_action_t action, size_t device)
{
  OC_DBG("swupdate: perform action(%d) on device(%zd)", (int)action, device);
  oc_swupdate_t *s = &g_sw[device];
  s->swupdateaction = action;
  if (action == OC_SWUPDATE_ISAC) {
    if (g_swupdate_impl && g_swupdate_impl->check_new_version &&
        g_swupdate_impl->check_new_version(device, oc_string(s->purl),
                                           oc_string(s->nv)) < 0) {
      OC_ERR("swupdate: could not check for availability of new version of "
             "software");
    }
    return;
  }
  if (action == OC_SWUPDATE_ISVV) {
    if (g_swupdate_impl && g_swupdate_impl->download_update &&
        g_swupdate_impl->download_update(device, oc_string(s->purl)) < 0) {
      OC_ERR("swupdate: could not download new software update");
    }
    return;
  }
  if (action == OC_SWUPDATE_UPGRADE) {
    if (g_swupdate_impl && g_swupdate_impl->perform_upgrade &&
        g_swupdate_impl->perform_upgrade(device, oc_string(s->purl)) < 0) {
      OC_ERR("swupdate: could not initiate a software update");
    }
    return;
  }
}

#endif /* OC_SOFTWARE_UPDATE */
