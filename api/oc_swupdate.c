/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_config.h"
#ifdef OC_SOFTWARE_UPDATE
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_swupdate.h"
#include "oc_swupdate_internal.h"
#include "security/oc_pstat.h"

#ifndef OC_STORAGE
#error Preprocessor macro OC_SOFTWARE_UPDATE is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_SOFTWARE_UPDATE is defined.
#endif

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_swupdate_t *sw;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_swupdate_t sw[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void oc_create_swupdate_resource(size_t device);
void oc_swupdate_encode(oc_interface_mask_t interfaces, size_t device);
void oc_swupdate_decode(oc_rep_t *rep, size_t device);

static const oc_swupdate_cb_t *cb;

void
oc_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl)
{
  cb = swupdate_impl;
}

#define SVR_TAG_MAX (32)
static void
gen_svr_tag(const char *name, size_t device_index, char *svr_tag)
{
  int svr_tag_len =
    snprintf(svr_tag, SVR_TAG_MAX, "%s_%zd", name, device_index);
  svr_tag_len =
    (svr_tag_len < SVR_TAG_MAX - 1) ? svr_tag_len + 1 : SVR_TAG_MAX - 1;
  svr_tag[svr_tag_len] = '\0';
}

static void
oc_load_sw(size_t device)
{
  long ret = 0;
  oc_rep_t *rep = 0;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("sw", device, svr_tag);
  ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
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
    oc_parse_rep(buf, (uint16_t)ret, &rep);
    oc_swupdate_decode(rep, device);
    oc_free_rep(rep);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

static void
oc_dump_sw(size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_swupdate_encode(OC_IF_RW, device);
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded pstat size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("sw", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_swupdate_free(void)
{
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    oc_swupdate_t *s = &sw[i];
    oc_dump_sw(i);
    if (oc_string_len(s->purl) > 0) {
      oc_free_string(&s->purl);
    }
    if (oc_string_len(s->nv) > 0) {
      oc_free_string(&s->nv);
    }
    if (oc_string_len(s->signage) > 0) {
      oc_free_string(&s->signage);
    }
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (sw) {
    free(sw);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_swupdate_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  sw =
    (oc_swupdate_t *)calloc(oc_core_get_num_devices(), sizeof(oc_swupdate_t));
  if (!sw) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    oc_create_swupdate_resource(i);
    sw[i].swupdatestate = OC_SWUPDATE_STATE_IDLE;
    sw[i].swupdateaction = OC_SWUPDATE_IDLE;
    sw[i].updatetime = 0;
    oc_new_string(&sw[i].signage, "vendor", 6);
    oc_load_sw(i);
  }
}

void
oc_swupdate_notify_new_version_available(size_t device, const char *version,
                                         oc_swupdate_result_t result)
{
  (void)version;
  OC_DBG("new software version %s available for device %zd", version, device);
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA);
  oc_swupdate_t *s = &sw[device];
  s->swupdatestate = OC_SWUPDATE_STATE_NSA;
  s->swupdateresult = result;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  oc_swupdate_perform_action(OC_SWUPDATE_ISVV, device);
}

void
oc_swupdate_notify_downloaded(size_t device, const char *version,
                              oc_swupdate_result_t result)
{
  (void)version;
  OC_DBG("software version %s downloaded and validated for device %zd", version,
         device);
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA | OC_DPM_SVV);
  oc_swupdate_t *s = &sw[device];
  s->swupdatestate = OC_SWUPDATE_STATE_SVV;
  s->swupdateresult = result;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  s->swupdatestate = OC_SWUPDATE_STATE_SVA;
  s->swupdateresult = result;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
  oc_swupdate_perform_action(OC_SWUPDATE_UPGRADE, device);
}

void
oc_swupdate_notify_upgrading(size_t device, const char *version,
                             oc_clock_time_t timestamp,
                             oc_swupdate_result_t result)
{
  OC_DBG("upgrading to software version %s on device %zd", version, device);
  oc_sec_pstat_set_current_mode(device, OC_DPM_NSA | OC_DPM_SVV | OC_DPM_SSV);
  oc_swupdate_t *s = &sw[device];
  s->swupdatestate = OC_SWUPDATE_STATE_UPGRADING;
  s->swupdateresult = result;
  if (oc_string_len(s->nv) > 0) {
    oc_free_string(&s->nv);
    oc_new_string(&s->nv, version, strlen(version));
  }
  s->lastupdate = timestamp;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
#endif /* OC_SERVER */
}

void
oc_swupdate_notify_done(size_t device, oc_swupdate_result_t result)
{
  oc_sec_pstat_set_current_mode(device, 0);
  oc_swupdate_t *s = &sw[device];
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
  oc_swupdate_t *s = &sw[device];
  s->swupdateaction = action;
  if (action == OC_SWUPDATE_ISAC) {
    if (cb && cb->check_new_version &&
        cb->check_new_version(device, oc_string(s->purl), oc_string(s->nv)) <
          0) {
      OC_ERR("could not check for availability of new version of software");
    }
  } else if (action == OC_SWUPDATE_ISVV) {
    if (cb && cb->download_update &&
        cb->download_update(device, oc_string(s->purl)) < 0) {
      OC_ERR("could not download new software update");
    }
  } else if (action == OC_SWUPDATE_UPGRADE) {
    if (cb && cb->perform_upgrade &&
        cb->perform_upgrade(device, oc_string(s->purl)) < 0) {
      OC_ERR("could not initiate a software update");
    }
  }
}

static const char *
action_to_str(oc_swupdate_action_t action)
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

static const char *
state_to_str(oc_swupdate_state_t state)
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

void
oc_swupdate_encode(oc_interface_mask_t interfaces, size_t device)
{
  oc_swupdate_t *s = &sw[device];
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SW_UPDATE, device));
  /* fall through */
  case OC_IF_RW: {
    char ts[64];
    oc_clock_encode_time_rfc3339(s->lastupdate, ts, 64);
    oc_rep_set_text_string(root, lastupdate, ts);

    oc_rep_set_text_string(root, nv, oc_string(s->nv));

    oc_rep_set_text_string(root, purl, oc_string(s->purl));

    oc_rep_set_text_string(root, signed, oc_string(s->signage));

    oc_rep_set_text_string(root, swupdateaction,
                           action_to_str(s->swupdateaction));

    oc_rep_set_int(root, swupdateresult, s->swupdateresult);

    oc_rep_set_text_string(root, swupdatestate, state_to_str(s->swupdatestate));

    oc_clock_encode_time_rfc3339(s->updatetime, ts, 64);
    oc_rep_set_text_string(root, updatetime, ts);
  } break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static oc_event_callback_retval_t
schedule_update(void *data)
{
  oc_swupdate_t *s = (oc_swupdate_t *)data;
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    if (s == &sw[i]) {
      break;
    }
  }
  oc_swupdate_perform_action(s->swupdateaction, i);
  return OC_EVENT_DONE;
}

void
oc_swupdate_decode(oc_rep_t *rep, size_t device)
{
  oc_swupdate_t *s = &sw[device];
  /* loop over all the properties in the input document */
  while (rep != NULL) {
    if (oc_string_len(rep->name) == 10 &&
        memcmp(oc_string(rep->name), "lastupdate", 10) == 0) {
      s->lastupdate = oc_clock_parse_time_rfc3339(
        oc_string(rep->value.string), oc_string_len(rep->value.string));
    }
    if (oc_string_len(rep->name) == 2 &&
        memcmp(oc_string(rep->name), "nv", 2) == 0) {
      if (oc_string_len(s->nv) > 0) {
        oc_free_string(&s->nv);
      }
      if (oc_string_len(rep->value.string) > 0) {
        oc_new_string(&s->nv, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      }
    }
    if (oc_string_len(rep->name) == 4 &&
        memcmp(oc_string(rep->name), "purl", 4) == 0) {
      if (oc_string_len(s->purl) > 0) {
        oc_free_string(&s->purl);
      }
      if (oc_string_len(rep->value.string) > 0) {
        oc_new_string(&s->purl, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      }
    }
    if (oc_string_len(rep->name) == 6 &&
        memcmp(oc_string(rep->name), "signed", 6) == 0) {
      if (oc_string_len(s->signage) > 0) {
        oc_free_string(&s->signage);
      }
      if (oc_string_len(rep->value.string) > 0) {
        oc_new_string(&s->signage, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      }
    }
    if (oc_string_len(rep->name) == 14 &&
        memcmp(oc_string(rep->name), "swupdateaction", 14) == 0) {
      s->swupdateaction = str_to_action(oc_string(rep->value.string));
    }
    if (oc_string_len(rep->name) == 14 &&
        memcmp(oc_string(rep->name), "swupdateresult", 14) == 0) {
      s->swupdateresult = rep->value.integer;
    }
    if (oc_string_len(rep->name) == 13 &&
        memcmp(oc_string(rep->name), "swupdatestate", 13) == 0) {
      s->swupdatestate = str_to_state(oc_string(rep->value.string));
    }
    if (oc_string_len(rep->name) == 10 &&
        memcmp(oc_string(rep->name), "updatetime", 10) == 0) {
      s->updatetime = oc_clock_parse_time_rfc3339(
        oc_string(rep->value.string), oc_string_len(rep->value.string));
    }
    rep = rep->next;
  }

  if (s->updatetime != 0 && s->swupdateaction != 0) {
    oc_clock_time_t diff = s->updatetime;
    oc_clock_time_t now = oc_clock_time();
    if (diff > now) {
      diff -= now;
    } else {
      diff = 0;
    }
    oc_ri_add_timed_event_callback_ticks(s, schedule_update, diff);
  }
}

/**
 * post method for "/sw" resource.
* The function has as input the request body, which are the input values of the
* POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
* values.
* Resource Description:
* Mechanism to schedule a start of the software update.
*
* @param requestRep the request representation.
*/
static void
post_sw(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  const char *purl = NULL;
  oc_swupdate_action_t action = OC_SWUPDATE_UPGRADE + 1;
  oc_string_t *ut = NULL;
  oc_rep_t *rep = request->request_payload;
  /* loop over the request document to check if all inputs are ok */
  while (rep != NULL) {
    if (oc_string_len(rep->name) == 10 &&
        memcmp(oc_string(rep->name), "lastupdate", 10) == 0) {
      /* Read-only property */
      error_state = true;
    }
    if (oc_string_len(rep->name) == 2 &&
        memcmp(oc_string(rep->name), "nv", 2) == 0) {
      /* Read-only property */

      error_state = true;
    }
    if (oc_string_len(rep->name) == 4 &&
        memcmp(oc_string(rep->name), "purl", 4) == 0) {
      if (rep->type != OC_REP_STRING) {

        error_state = true;
      }
      if (oc_string_len(rep->value.string) >= 63) {
        error_state = true;
      }
      purl = oc_string(rep->value.string);
    }
    if (oc_string_len(rep->name) == 6 &&
        memcmp(oc_string(rep->name), "signed", 6) == 0) {
      error_state = true;
      if (rep->type != OC_REP_STRING) {
        error_state = true;
      }
      if (oc_string_len(rep->value.string) >= 63) {
        error_state = true;
      }
    }
    if (oc_string_len(rep->name) == 14 &&
        memcmp(oc_string(rep->name), "swupdateaction", 14) == 0) {
      if (rep->type != OC_REP_STRING) {
        error_state = true;
      }
      if (oc_string_len(rep->value.string) >= 63) {
        error_state = true;
      }
      action = str_to_action(oc_string(rep->value.string));
    }
    if (oc_string_len(rep->name) == 14 &&
        memcmp(oc_string(rep->name), "swupdateresult", 14) == 0) {
      /* Read-only property */
      error_state = true;
    }
    if (oc_string_len(rep->name) == 13 &&
        memcmp(oc_string(rep->name), "swupdatestate", 13) == 0) {
      /* Read-only property */
      error_state = true;
    }
    if (oc_string_len(rep->name) == 10 &&
        memcmp(oc_string(rep->name), "updatetime", 10) == 0) {
      if (rep->type != OC_REP_STRING) {
        error_state = true;
      }
      if (oc_string_len(rep->value.string) >= 63) {
        error_state = true;
      }
      oc_clock_time_t mytime = oc_clock_parse_time_rfc3339(
        oc_string(rep->value.string), oc_string_len(rep->value.string));
      if (mytime == 0) {
        error_state = true;
      } else if (mytime < oc_clock_time()) {
        error_state = true;
      }
      char m[64];
      oc_clock_encode_time_rfc3339(mytime, m, 64);
      ut = &rep->value.string;
    }
    rep = rep->next;
  }

  if (action >= OC_SWUPDATE_UPGRADE || !purl || !ut) {
    error_state = true;
  }
  if (action != OC_SWUPDATE_IDLE && action <= OC_SWUPDATE_UPGRADE && !purl) {
    error_state = true;
  }
  if (purl && (!cb || !cb->validate_purl || (cb->validate_purl(purl) < 0))) {
    error_state = true;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    oc_swupdate_decode(request->request_payload, request->resource->device);
    /* set the response */
    oc_swupdate_encode(OC_IF_RW, request->resource->device);

    oc_send_response(request, OC_STATUS_CHANGED);

    oc_dump_sw(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_NOT_ACCEPTABLE);
  }
}

/**
* get method for "/sw" resource.
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
get_sw(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;
  oc_swupdate_encode(interfaces, request->resource->device);
  oc_send_response(request, OC_STATUS_OK);
}

void
oc_create_swupdate_resource(size_t device)
{
  oc_core_populate_resource(OCF_SW_UPDATE, device, "sw",
                            OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                            OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE, get_sw,
                            0, post_sw, 0, 1, "oic.r.softwareupdate");
}
#else  /* OC_SOFTWARE_UPDATE */
typedef int dummy_declaration;
#endif /* OC_SOFTWARE_UPDATE */
