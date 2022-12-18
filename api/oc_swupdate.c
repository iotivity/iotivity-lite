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

#include "api/oc_rep_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "oc_swupdate.h"
#include "oc_swupdate_internal.h"
#include "port/oc_clock.h"
#include "security/oc_pstat.h"
#include "util/oc_compiler.h"

#include <assert.h>
#include <limits.h>

#ifndef OC_STORAGE
#error Preprocessor macro OC_SOFTWARE_UPDATE is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_SOFTWARE_UPDATE is defined.
#endif

typedef struct oc_swupdate_t
{
  oc_string_t purl;    ///< package URL, source of the software package
  oc_string_t nv;      ///< new version, new available software version
  oc_string_t signage; ///< signage method of the software package
  oc_swupdate_action_t
    swupdateaction; ///< scheduled action to execute at updatetime
  oc_swupdate_state_t swupdatestate; ///< state of the software update
  int swupdateresult;                ///< result of the software update
  oc_clock_time_t lastupdate;        ///< time of the last software update
  oc_clock_time_t updatetime; ///< scheduled time to execute swupdateaction
} oc_swupdate_t;

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_swupdate_t *g_sw;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_swupdate_t g_sw[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

#define OC_SWU_PROP_LASTUPDATE "lastupdate"
#define OC_SWU_PROP_NEWVERSION "nv"
#define OC_SWU_PROP_PACKAGEURL "purl"
#define OC_SWU_PROP_SIGNED "signed"
#define OC_SWU_PROP_UPDATEACTION "swupdateaction"
#define OC_SWU_PROP_UPDATERESULT "swupdateresult"
#define OC_SWU_PROP_UPDATESTATE "swupdatestate"
#define OC_SWU_PROP_UPDATETIME "updatetime"

static const oc_swupdate_cb_t *g_cb;

static void oc_create_swupdate_resource(size_t device);

oc_swupdate_t *
oc_swupdate_get_context(size_t device)
{
  return &g_sw[device];
}

const char *
oc_swupdate_get_package_url(const oc_swupdate_t *ctx)
{
  return oc_string(ctx->purl);
}

const char *
oc_swupdate_get_new_version(const oc_swupdate_t *ctx)
{
  return oc_string(ctx->nv);
}

oc_swupdate_action_t
oc_swupdate_get_action(const oc_swupdate_t *ctx)
{
  return ctx->swupdateaction;
}

oc_swupdate_state_t
oc_swupdate_get_state(const oc_swupdate_t *ctx)
{
  return ctx->swupdatestate;
}

void
oc_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl)
{
  g_cb = swupdate_impl;
}

static int
oc_swupdate_on_load(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  oc_swupdate_decode(rep, device);
  return 0;
}

const char *
oc_swupdate_action_to_str(oc_swupdate_action_t action)
{
  switch (action) {
  case OC_SWUPDATE_IDLE:
    return "idle";
  case OC_SWUPDATE_ISAC:
    return "isac";
  case OC_SWUPDATE_ISVV:
    return "isvv";
  case OC_SWUPDATE_UPGRADE:
    return "upgrade";
  }
  return NULL;
}

const char *
oc_swupdate_state_to_str(oc_swupdate_state_t state)
{
  switch (state) {
  case OC_SWUPDATE_STATE_IDLE:
    return "idle";
  case OC_SWUPDATE_STATE_NSA:
    return "nsa";
  case OC_SWUPDATE_STATE_SVV:
    return "svv";
  case OC_SWUPDATE_STATE_SVA:
    return "sva";
  case OC_SWUPDATE_STATE_UPGRADING:
    return "upgrading";
  }
  return NULL;
}

static oc_swupdate_state_t
str_to_state(const char *state)
{
  size_t len = strlen(state);
  if (len == 4 && memcmp(state, "idle", 4) == 0) {
    return OC_SWUPDATE_STATE_IDLE;
  }
  if (len == 3 && memcmp(state, "nsa", 3) == 0) {
    return OC_SWUPDATE_STATE_NSA;
  }
  if (len == 3 && memcmp(state, "svv", 3) == 0) {
    return OC_SWUPDATE_STATE_SVV;
  }
  if (len == 3 && memcmp(state, "sva", 3) == 0) {
    return OC_SWUPDATE_STATE_SVA;
  }
  if (len == 9 && memcmp(state, "upgrading", 9) == 0) {
    return OC_SWUPDATE_STATE_UPGRADING;
  }
  return OC_SWUPDATE_STATE_UPGRADING + 1;
}

static oc_swupdate_action_t
str_to_action(const char *action)
{
  size_t len = strlen(action);
  if (len == 4 && memcmp(action, "idle", 4) == 0) {
    return OC_SWUPDATE_IDLE;
  }
  if (len == 4 && memcmp(action, "isac", 4) == 0) {
    return OC_SWUPDATE_ISAC;
  }
  if (len == 4 && memcmp(action, "isvv", 4) == 0) {
    return OC_SWUPDATE_ISVV;
  }
  if (len == 7 && memcmp(action, "upgrade", 7) == 0) {
    return OC_SWUPDATE_UPGRADE;
  }
  return OC_SWUPDATE_UPGRADE + 1;
}

typedef struct
{
  oc_swupdate_t data;
  bool purl_set;
  bool nv_set;
  bool signage_set;
  bool swupdateaction_set;
  bool swupdatestate_set;
  bool swupdateresult_set;
  bool lastupdate_set;
  bool updatetime_set;
} oc_swupdate_decode_t;

static void
oc_swupdate_decode_copy(const oc_swupdate_decode_t *src, oc_swupdate_t *dst)
{
  if (src->purl_set) {
    oc_free_string(&dst->purl);
    if (oc_string_len(src->data.purl) > 0) {
      oc_new_string(&dst->purl, oc_string(src->data.purl),
                    oc_string_len(src->data.purl));
    }
  }

  if (src->nv_set) {
    oc_free_string(&dst->nv);
    if (oc_string_len(src->data.nv) > 0) {
      oc_new_string(&dst->nv, oc_string(src->data.nv),
                    oc_string_len(src->data.nv));
    }
  }

  if (src->signage_set) {
    oc_free_string(&dst->signage);
    if (oc_string_len(src->data.signage) > 0) {
      oc_new_string(&dst->signage, oc_string(src->data.signage),
                    oc_string_len(src->data.signage));
    }
  }

  if (src->swupdateaction_set) {
    dst->swupdateaction = src->data.swupdateaction;
  }

  if (src->swupdatestate_set) {
    dst->swupdatestate = src->data.swupdatestate;
  }

  if (src->swupdateresult_set) {
    dst->swupdateresult = src->data.swupdateresult;
  }

  if (src->updatetime_set) {
    dst->updatetime = src->data.updatetime;
  }

  if (src->lastupdate_set) {
    dst->lastupdate = src->data.lastupdate;
  }
}

static bool
oc_swupdate_decode_int_property(const oc_rep_t *rep, bool from_storage,
                                oc_swupdate_decode_t *swud)
{
  assert(rep->type == OC_REP_INT);
  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATERESULT,
                         sizeof(OC_SWU_PROP_UPDATERESULT) - 1)) {
    if (from_storage) {
      assert(rep->value.integer <= INT_MAX);
      swud->data.swupdateresult = (int)rep->value.integer;
      swud->swupdateresult_set = true;
      return true;
    }
    /* Read-only property */
    return false;
  }
  return false;
}

static bool
oc_swupdate_decode_string_property(const oc_rep_t *rep, bool from_storage,
                                   oc_swupdate_decode_t *swud)
{
  assert(rep->type == OC_REP_STRING);
  if (oc_rep_is_property(rep, OC_SWU_PROP_LASTUPDATE,
                         sizeof(OC_SWU_PROP_LASTUPDATE) - 1)) {
    if (from_storage) {
      swud->data.lastupdate = oc_clock_parse_time_rfc3339(
        oc_string(rep->value.string), oc_string_len(rep->value.string));
      swud->lastupdate_set = true;
      return true;
    }
    /* Read-only property */
    return false;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_NEWVERSION,
                         sizeof(OC_SWU_PROP_NEWVERSION) - 1)) {
    if (from_storage) {
      swud->data.nv = rep->value.string;
      swud->nv_set = true;
      return true;
    }
    /* Read-only property */
    return false;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_PACKAGEURL,
                         sizeof(OC_SWU_PROP_PACKAGEURL) - 1)) {
    swud->data.purl = rep->value.string;
    swud->purl_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_SIGNED,
                         sizeof(OC_SWU_PROP_SIGNED) - 1)) {

    if (from_storage) {
      swud->data.signage = rep->value.string;
      swud->signage_set = true;
      return true;
    }
    return false; // cannot be edited currently, only "vendor" value is
                  // supported
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATEACTION,
                         sizeof(OC_SWU_PROP_UPDATEACTION) - 1)) {
    oc_swupdate_action_t action = str_to_action(oc_string(rep->value.string));
    if (action > OC_SWUPDATE_UPGRADE) {
      return false;
    }
    swud->data.swupdateaction = action;
    swud->swupdateaction_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATESTATE,
                         sizeof(OC_SWU_PROP_UPDATESTATE) - 1)) {
    if (from_storage) {
      swud->data.swupdatestate = str_to_state(oc_string(rep->value.string));
      swud->swupdatestate_set = true;
      return true;
    }
    /* Read-only property */
    return false;
  }

  if (oc_rep_is_property(rep, OC_SWU_PROP_UPDATETIME,
                         sizeof(OC_SWU_PROP_UPDATETIME) - 1)) {
    if (oc_string_len(rep->value.string) >= 63) {
      return false;
    }
    oc_clock_time_t mytime = oc_clock_parse_time_rfc3339(
      oc_string(rep->value.string), oc_string_len(rep->value.string));
    swud->data.updatetime = mytime;
    swud->updatetime_set = true;
    return true;
  }

  return false;
}

static bool
oc_swupdate_decode_property(const oc_rep_t *rep, bool from_storage,
                            oc_swupdate_decode_t *swud)
{
  if (rep->type == OC_REP_STRING) {
    if (!oc_swupdate_decode_string_property(rep, from_storage, swud)) {
      OC_DBG("software update error: cannot decode property(%s)", rep->name);
      return false;
    }
    return true;
  }
  if (rep->type == OC_REP_INT) {
    if (!oc_swupdate_decode_int_property(rep, from_storage, swud)) {
      OC_DBG("software update error: cannot decode property(%s)", rep->name);
      return false;
    }
    return true;
  }
  OC_DBG("software update error: unrecognized property(%s)", rep->name);
  return false;
}

static bool
oc_swupdate_validate_post(size_t device, const oc_swupdate_decode_t *swud)
{
  if (swud->updatetime_set &&
      (swud->data.updatetime == 0 || swud->data.updatetime < oc_clock_time())) {
    return false;
  }

  const char *purl = oc_string(swud->data.purl);
  oc_swupdate_t *s = &g_sw[device];
  if (oc_string(s->purl) == NULL && purl == NULL) {
    return false;
  }

  if (g_cb == NULL || (purl != NULL && (g_cb->validate_purl == NULL ||
                                        g_cb->validate_purl(purl) < 0))) {
    return false;
  }
  return true;
}

static bool
oc_swupdate_decode_and_validate(size_t device, const oc_rep_t *rep,
                                bool from_storage, oc_swupdate_decode_t *swud)
{
  /* loop over all the properties in the input document */
  for (; rep != NULL; rep = rep->next) {
    if (oc_swupdate_decode_property(rep, from_storage, swud)) {
      continue;
    }

    if (from_storage) { // ignore invalid properties when decoding from
                        // storage
      continue;
    }
    return false;
  }
  return from_storage || oc_swupdate_validate_post(device, swud);
}

static oc_event_callback_retval_t
schedule_update(void *data)
{
  oc_swupdate_t *s = (oc_swupdate_t *)data;
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    if (s == &g_sw[i]) {
      break;
    }
  }
  oc_swupdate_perform_action(s->swupdateaction, i);
  return OC_EVENT_DONE;
}

static void
oc_swupdate_execute_action(size_t device)
{
  oc_swupdate_t *s = &g_sw[device];
  if (s->swupdateaction != 0) {
    oc_clock_time_t diff = 0;
    if (s->updatetime != 0) {
      diff = s->updatetime;
      oc_clock_time_t now = oc_clock_time();
      if (diff > now) {
        diff -= now;
      } else {
        diff = 0;
      }
    }
    oc_ri_add_timed_event_callback_ticks(s, schedule_update, diff);
  }
}

long
oc_swupdate_load(size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (buf == NULL) {
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("sw", device, svr_tag);
  long ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret < 0) {
    goto finish;
  }
  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  oc_rep_set_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  if (oc_parse_rep(buf, (int)ret, &rep) == 0) {
    oc_swupdate_decode_t swud;
    memset(&swud, 0, sizeof(swud));
    if (!oc_swupdate_decode_and_validate(device, rep, /*from_storage*/ true,
                                         &swud)) {
      OC_WRN("software update load from store: invalid properties detected");
    }
    oc_swupdate_decode_copy(&swud, &g_sw[device]);
    oc_swupdate_execute_action(device);
  } else {
    ret = -1;
  }
  oc_free_rep(rep);
  oc_rep_set_pool(NULL);

finish:
#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

static void
oc_swupdate_encode(oc_interface_mask_t interfaces, size_t device)
{
  oc_swupdate_t *s = &g_sw[device];
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
    OC_FALLTHROUGH;
  case OC_IF_RW: {
    char ts[64];
    oc_clock_encode_time_rfc3339(s->lastupdate, ts, 64);
    oc_rep_set_text_string(root, lastupdate, ts);

    oc_rep_set_text_string(root, nv, oc_string(s->nv));

    oc_rep_set_text_string(root, purl, oc_string(s->purl));

    oc_rep_set_text_string(root, signed, oc_string(s->signage));

    oc_rep_set_text_string(root, swupdateaction,
                           oc_swupdate_action_to_str(s->swupdateaction));

    oc_rep_set_int(root, swupdateresult, s->swupdateresult);

    oc_rep_set_text_string(root, swupdatestate,
                           oc_swupdate_state_to_str(s->swupdatestate));

    oc_clock_encode_time_rfc3339(s->updatetime, ts, 64);
    oc_rep_set_text_string(root, updatetime, ts);
  } break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

long
oc_swupdate_dump(size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (buf == NULL) {
    return -1;
  }
  oc_rep_new_realloc(&buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MIN_APP_DATA_SIZE];
  oc_rep_new(buf, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_swupdate_encode(OC_IF_RW, device);
#ifdef OC_DYNAMIC_ALLOCATION
  buf = oc_rep_shrink_encoder_buf(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  int size = oc_rep_get_encoded_payload_size();
  long ret = 0;
  if (size > 0) {
    OC_DBG("oc_store: encoded pstat size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("sw", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

void
oc_swupdate_free(void)
{
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    oc_swupdate_t *s = &g_sw[i];
    long ret = oc_swupdate_dump(i);
    if (ret < 0) {
      OC_ERR("failed to save swupdate of device(%zu) to storage, error(%d)", i,
             (int)ret);
    }
    oc_free_string(&s->purl);
    oc_free_string(&s->nv);
    oc_free_string(&s->signage);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_sw != NULL) {
    free(g_sw);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_swupdate_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_sw =
    (oc_swupdate_t *)calloc(oc_core_get_num_devices(), sizeof(oc_swupdate_t));
  if (g_sw == NULL) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    oc_create_swupdate_resource(i);
    g_sw[i].swupdatestate = OC_SWUPDATE_STATE_IDLE;
    g_sw[i].swupdateaction = OC_SWUPDATE_IDLE;
    g_sw[i].updatetime = 0;
    oc_new_string(&g_sw[i].signage, "vendor", sizeof("vendor") - 1);
    long ret = oc_swupdate_load(i);
    if (ret < 0) {
      OC_DBG("failed to load swupdate of device(%zu) from storage, error(%d)",
             i, (int)ret);
    }
  }
}

void
oc_swupdate_notify_new_version_available(size_t device, const char *version,
                                         oc_swupdate_result_t result)
{
  OC_DBG("new software version %s available for device %zd", version, device);
#ifdef OC_SECURITY
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA);
#endif /* OC_SECURITY */
  oc_swupdate_t *s = &g_sw[device];
  oc_free_string(&s->nv);
  oc_new_string(&s->nv, version, strlen(version));
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
  OC_DBG("software version %s downloaded and validated for device %zd", version,
         device);
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
  OC_DBG("upgrading to software version %s on device %zd", version, device);
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
  oc_swupdate_t *s = &g_sw[device];
  s->swupdateaction = action;
  if (action == OC_SWUPDATE_ISAC) {
    if (g_cb && g_cb->check_new_version &&
        g_cb->check_new_version(device, oc_string(s->purl), oc_string(s->nv)) <
          0) {
      OC_ERR("could not check for availability of new version of software");
    }
    return;
  }
  if (action == OC_SWUPDATE_ISVV) {
    if (g_cb && g_cb->download_update &&
        g_cb->download_update(device, oc_string(s->purl)) < 0) {
      OC_ERR("could not download new software update");
    }
    return;
  }
  if (action == OC_SWUPDATE_UPGRADE) {
    if (g_cb && g_cb->perform_upgrade &&
        g_cb->perform_upgrade(device, oc_string(s->purl)) < 0) {
      OC_ERR("could not initiate a software update");
    }
    return;
  }
}

/**
 * post method for "/oc/swu" resource.
 * The function has as input the request body, which are the input values of
 * the POST method. The input values (as a set) are checked if all supplied
 * values are correct. If the input values are correct, they will be assigned
 * to the global property values. Resource Description: Mechanism to schedule
 * a start of the software update.
 *
 * @param requestRep the request representation.
 */
static void
post_swu(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)interfaces;
  (void)user_data;

  oc_swupdate_decode_t swud;
  memset(&swud, 0, sizeof(swud));
  if (!oc_swupdate_decode_and_validate(request->resource->device,
                                       request->request_payload,
                                       /*from_storage*/ false, &swud)) {
    oc_send_response_with_callback(request, OC_STATUS_NOT_ACCEPTABLE, true);
    return;
  }

  oc_swupdate_decode_copy(&swud, &g_sw[request->resource->device]);
  oc_swupdate_execute_action(request->resource->device);

  /* set the response */
  oc_swupdate_encode(OC_IF_RW, request->resource->device);

  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);

  oc_swupdate_dump(request->resource->device);
}

/**
 * get method for "/oc/swu" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values.
 * Resource Description:
 * The Resource performing scheduled software update.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */

static void
get_swu(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;
  oc_swupdate_encode(interfaces, request->resource->device);
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

static void
oc_create_swupdate_resource(size_t device)
{
  oc_core_populate_resource(OCF_SW_UPDATE, device, "oc/swu",
                            OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                            OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
                            get_swu, 0, post_swu, 0, 1, "oic.r.softwareupdate");
}

#endif /* OC_SOFTWARE_UPDATE */
