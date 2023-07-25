/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_acl_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_doxm_internal.h"
#include "oc_pstat_internal.h"
#include "oc_store.h"
#include "oc_tls_internal.h"
#include "port/oc_assert.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else /* !WIN32 */
#include <strings.h>
#endif /* WIN32 */

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#define OC_DOXM_OWNED "owned"
#define OC_DOXM_OXMSEL "oxmsel"
#define OC_DOXM_SCT "sct"
#define OC_DOXM_DEVICEUUID "deviceuuid"
#define OC_DOXM_DOWNERUUID "devowneruuid"
#define OC_DOXM_ROWNERUUID "rowneruuid"
#define OC_DOXM_OXMS "oxms"

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_doxm_t *g_doxm = NULL;
#else  /* !OC_DYNAMIC_ALLOCATION */
static oc_sec_doxm_t g_doxm[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* OC_DYNAMIC_ALLOCATION */

OC_LIST(g_oc_doxm_owned_cb_list);
OC_MEMB(g_oc_doxm_owned_cb_s, oc_doxm_owned_cb_t, OC_MAX_DOXM_OWNED_CBS);

static oc_select_oxms_cb_t g_oc_select_oxms_cb = NULL;
static void *g_oc_select_oxms_cb_user_data = NULL;

#ifdef OC_SERVER

typedef struct doxm_response_data_s
{
  struct doxm_response_data_s *next;
  size_t device;
  oc_interface_mask_t iface_mask;
  oc_separate_response_t separate_response;
} doxm_response_data_t;

OC_LIST(g_doxm_response_data_list);
OC_MEMB(g_doxm_response_data_s, doxm_response_data_t, OC_MAX_NUM_DEVICES);

static doxm_response_data_t *
doxm_add_separate_response_for_device(size_t device,
                                      oc_interface_mask_t iface_mask)
{
  doxm_response_data_t *d =
    (doxm_response_data_t *)oc_memb_alloc(&g_doxm_response_data_s);
  if (d == NULL) {
    OC_ERR("cannot allocate multicast discovery request data for device(%zu)",
           device);
    return NULL;
  }
  d->device = device;
  d->iface_mask = iface_mask;
  OC_LIST_STRUCT_INIT(&d->separate_response, requests);
  oc_list_add(g_doxm_response_data_list, d);
  return d;
}

static void
doxm_clear_separate_response(doxm_response_data_t *rd)
{
  oc_list_remove(g_doxm_response_data_list, rd);
  oc_memb_free(&g_doxm_response_data_s, rd);
}

static bool
doxm_has_separate_response_for_device(size_t device)
{
  const doxm_response_data_t *rd =
    (doxm_response_data_t *)oc_list_head(g_doxm_response_data_list);
  while (rd != NULL) {
    if (rd->device == device) {
      return true;
    }
    rd = rd->next;
  }
  return false;
}

// separate response handler, used for delaying the response to the client
// in order to avoid flooding the network when multicasts are used
static oc_event_callback_retval_t
doxm_handle_separate_response(void *data)
{
  doxm_response_data_t *d = (doxm_response_data_t *)data;
  if (d->separate_response.active) {
    oc_set_separate_response_buffer(&d->separate_response);
    if (oc_sec_encode_doxm(d->device, d->iface_mask, false) != CborNoError) {
      OC_ERR("oc_doxm: error encoding separate response");
      doxm_clear_separate_response(d);
      return OC_EVENT_DONE;
    }
    // TODO: shrink buffer
    oc_send_separate_response(&d->separate_response, OC_STATUS_OK);
  }
  doxm_clear_separate_response(d);
  return OC_EVENT_DONE;
}

#ifdef OC_TEST

static uint64_t g_separate_response_delay_ms = 0;

void
oc_test_set_doxm_separate_response_delay_ms(uint64_t delay_ms)
{
  g_separate_response_delay_ms = delay_ms;
}

#endif /* OC_TEST */

static uint64_t
doxm_get_separate_response_delay_ms(void)
{
#ifdef OC_TEST
  return g_separate_response_delay_ms;
#else  /* OC_TEST */
  return (uint64_t)(oc_random_value() % OC_MULTICAST_RESPONSE_JITTER_MS);
#endif /* !OC_TEST */
}

static int
doxm_add_and_schedule_separate_response(oc_request_t *request, size_t device,
                                        oc_interface_mask_t iface_mask)
{
  doxm_response_data_t *rd =
    doxm_add_separate_response_for_device(device, iface_mask);
  if (rd == NULL) {
    return -1;
  }

  oc_indicate_separate_response(request, &rd->separate_response);
  oc_set_delayed_callback_ms_v1(rd, doxm_handle_separate_response,
                                doxm_get_separate_response_delay_ms());
  return 0;
}

#endif /* OC_SERVER */

void
oc_sec_doxm_free(void)
{
  oc_ownership_status_free_all_cbs();
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_doxm != NULL) {
    free(g_doxm);
    g_doxm = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_doxm_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_doxm =
    (oc_sec_doxm_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_doxm_t));
  if (g_doxm == NULL) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_set_select_oxms_cb(NULL, NULL);
}

static void
doxm_evaluate_supported_oxms(size_t device)
{
  g_doxm[device].oxms[0] = OC_OXMTYPE_JW;
  g_doxm[device].oxms[1] = -1;
  g_doxm[device].oxms[2] = -1;
  g_doxm[device].num_oxms = 1;
  if (oc_tls_is_pin_otm_supported(device)) {
    g_doxm[device].oxms[g_doxm[device].num_oxms++] = OC_OXMTYPE_RDP;
  }
#ifdef OC_PKI
  if (oc_tls_is_cert_otm_supported(device)) {
    g_doxm[device].oxms[g_doxm[device].num_oxms++] = OC_OXMTYPE_MFG_CERT;
  }
#endif /* OC_PKI */
  if (g_oc_select_oxms_cb != NULL) {
    g_oc_select_oxms_cb(device, g_doxm[device].oxms, &g_doxm[device].num_oxms,
                        g_oc_select_oxms_cb_user_data);
  }
}

static int
doxm_sct_default(void)
{
#ifdef OC_PKI
  int sct = 9;
#else  /* OC_PKI */
  int sct = 1;
#endif /* !OC_PKI */
#ifdef OC_OSCORE
  sct |= OC_CREDTYPE_OSCORE;
#ifdef OC_CLIENT
  sct |= OC_CREDTYPE_OSCORE_MCAST_CLIENT;
#endif /* OC_CLIENT */
#ifdef OC_SERVER
  sct |= OC_CREDTYPE_OSCORE_MCAST_SERVER;
#endif /* OC_SERVER */
#endif /* OC_OSCORE */
  return sct;
}

void
oc_sec_doxm_set_default(oc_sec_doxm_t *doxm)
{
  /* In RESET, oxmsel shall be set to (4) "oic.sec.oxm.self" */
  doxm->oxmsel = 4;
  doxm->sct = doxm_sct_default();
  doxm->owned = false;
  memset(doxm->devowneruuid.id, 0, sizeof(doxm->devowneruuid.id));
  memset(doxm->rowneruuid.id, 0, sizeof(doxm->rowneruuid.id));
  /* Generate a new temporary device UUID */
  oc_gen_uuid(&doxm->deviceuuid);
}

void
oc_sec_doxm_default(size_t device)
{
  // invoke the device owned changed cb before the deviceuuid is reset
  if (g_doxm[device].owned) {
    oc_doxm_owned_cb_t *doxm_cb_item =
      (oc_doxm_owned_cb_t *)oc_list_head(g_oc_doxm_owned_cb_list);
    while (doxm_cb_item != NULL) {
      (doxm_cb_item->cb)(&g_doxm[device].deviceuuid, device, false,
                         doxm_cb_item->user_data);
      doxm_cb_item = doxm_cb_item->next;
    }
  }

  oc_sec_doxm_set_default(&g_doxm[device]);
  oc_device_info_t *d = oc_core_get_device_info(device);
  memcpy(d->di.id, g_doxm[device].deviceuuid.id, sizeof(d->di.id));
  oc_sec_dump_doxm(device);
}

CborError
oc_sec_encode_doxm(size_t device, oc_interface_mask_t iface_mask,
                   bool to_storage)
{
  oc_rep_start_root_object();
  if (to_storage || (iface_mask & OC_IF_BASELINE) != 0) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_DOXM, device));
  }
  /* oxms */
  if (!to_storage) {
    doxm_evaluate_supported_oxms(device);
    oc_rep_set_int_array(root, oxms, g_doxm[device].oxms,
                         g_doxm[device].num_oxms);
  }
  /* oxmsel */
  oc_rep_set_int(root, oxmsel, g_doxm[device].oxmsel);
  /* sct */
  oc_rep_set_int(root, sct, g_doxm[device].sct);
  /* owned */
  oc_rep_set_boolean(root, owned, g_doxm[device].owned);
  char uuid[OC_UUID_LEN];
  /* devowneruuid */
  oc_uuid_to_str(&g_doxm[device].devowneruuid, uuid, sizeof(uuid));
  oc_rep_set_text_string_v1(root, devowneruuid, uuid,
                            oc_strnlen(uuid, OC_UUID_LEN));
  /* deviceuuid */
  oc_uuid_to_str(&g_doxm[device].deviceuuid, uuid, sizeof(uuid));
  oc_rep_set_text_string_v1(root, deviceuuid, uuid,
                            oc_strnlen(uuid, OC_UUID_LEN));
  /* rowneruuid */
  oc_uuid_to_str(&g_doxm[device].rowneruuid, uuid, sizeof(uuid));
  oc_rep_set_text_string_v1(root, rowneruuid, uuid,
                            oc_strnlen(uuid, OC_UUID_LEN));
  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno();
}

oc_sec_doxm_t *
oc_sec_get_doxm(size_t device)
{
  assert(oc_core_device_is_valid(device));
#ifdef OC_DYNAMIC_ALLOCATION
  assert(g_doxm != NULL);
#endif /* OC_DYNAMIC_ALLOCATION */

  return &g_doxm[device];
}

static bool
doxm_check_owned(oc_request_t *request, const char *query, size_t query_len)
{
#define BOOLSTR_TRUE "true"
#define BOOLSTR_FALSE "false"
  int owned = -1;
  if (query_len == OC_CHAR_ARRAY_LEN(BOOLSTR_TRUE) &&
      strncasecmp(query, BOOLSTR_TRUE, OC_CHAR_ARRAY_LEN(BOOLSTR_TRUE)) == 0) {
    owned = 1;
  }
  if (query_len == OC_CHAR_ARRAY_LEN(BOOLSTR_FALSE) &&
      strncasecmp(query, BOOLSTR_FALSE, OC_CHAR_ARRAY_LEN(BOOLSTR_FALSE)) ==
        0) {
    owned = 0;
  }
#undef BOOLSTR_TRUE
#undef BOOLSTR_FALSE

  if (owned == -1) {
    // reply with BAD_REQUEST if ownership status query is invalid
    oc_send_response_internal(request, OC_STATUS_BAD_REQUEST,
                              APPLICATION_VND_OCF_CBOR, 0, true);
    return false;
  }

  size_t device = request->resource->device;
  if (owned == g_doxm[device].owned) {
    return true;
  }

  if (oc_endpoint_is_unicast(request->origin)) {
    // reply with BAD_REQUEST if ownership status does not match query
    // of unicast request
    oc_send_response_internal(request, OC_STATUS_BAD_REQUEST,
                              APPLICATION_VND_OCF_CBOR, 0, true);
    return false;
  }
  // ignore if ownership status does not match query of multicast request
  oc_ignore_request(request);
  return false;
}

static void
doxm_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *data)
{
  (void)data;

  assert((iface_mask & OCF_SEC_DOXM_IF_MASK) != 0);
  const char *q;
  int ql = oc_get_query_value_v1(request, OC_DOXM_OWNED,
                                 OC_CHAR_ARRAY_LEN(OC_DOXM_OWNED), &q);
  if (ql >= 0 && !doxm_check_owned(request, q, ql)) {
    return;
  }

  size_t device = request->resource->device;
// do not respond to /oic/sec/doxm requests if the value of the deviceuuid query
// parameter does not match the device's UUID FOR DEVELOPMENT USE ONLY
#ifdef OC_DOXM_UUID_FILTER
  const char *q2;
  int ql2 = oc_get_query_value_v1(request, OC_DOXM_DEVICEUUID,
                                  OC_CHAR_ARRAY_LEN(OC_DOXM_DEVICEUUID), &q2);

  // q2 is not null terminated, so we subtract 1 from the comparison length
  if (ql2 > 0) {
    oc_device_info_t *di = oc_core_get_device_info(device);
    char device_uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(&di->di, device_uuid, OC_UUID_LEN);
    if (strncasecmp(q2, device_uuid, OC_UUID_LEN - 1) != 0) {
      // ignore if deviceuuid does not match query
      oc_ignore_request(request);
      return;
    }
  }
#endif /* OC_DOXM_UUID_FILTER */
#ifdef OC_SERVER
  // delay response to multicast requests, to prevent congestion
  // during discovery in large networks
  if (oc_endpoint_is_multicast(request->origin)) {
    if (doxm_has_separate_response_for_device(device)) {
      // previous multicast discovery request has not been handled yet
      OC_WRN("duplicit multicast discovery request for device(%zu) ignored",
             device);
      oc_ignore_request(request);
      return;
    }

    if (doxm_add_and_schedule_separate_response(request, device, iface_mask) !=
        0) {
      oc_send_response_internal(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                APPLICATION_VND_OCF_CBOR, 0, true);
      return;
    }
  }
#endif /* OC_SERVER */

  // respond to unicasts immediately
  if (oc_sec_encode_doxm(device, iface_mask, false) != CborNoError) {
    oc_send_response_internal(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                              APPLICATION_VND_OCF_CBOR, 0, true);
    return;
  }
  // TODO: shrink buffer
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

typedef enum {
  OC_DOXM_DECODE_FLAG_FROM_STORAGE = 1 << 0,
  OC_DOXM_DECODE_FLAG_IS_DOC = 1 << 1,
} oc_doxm_decode_flag_t;

typedef struct
{
  const oc_string_t *deviceuuid;
  const oc_string_t *devowneruuid;
  const oc_string_t *rowneruuid;
  int oxmsel;
  int sct;
  bool owned;

  bool oxmsel_set;
  bool sct_set;
  bool owned_set;
} oc_doxm_decode_t;

static bool
doxm_decode_bool_property(const oc_rep_t *rep, unsigned flags,
                          oc_dostype_t state, oc_doxm_decode_t *decode)
{
  if (oc_rep_is_property(rep, OC_DOXM_OWNED,
                         OC_CHAR_ARRAY_LEN(OC_DOXM_OWNED))) {
    if ((flags & OC_DOXM_DECODE_FLAG_FROM_STORAGE) == 0) {
      if (state != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: can set %s property only in RFOTM", OC_DOXM_OWNED);
        return false;
      }
      if ((flags & OC_DOXM_DECODE_FLAG_IS_DOC) == 0) {
        OC_ERR("oc_doxm: cannot set %s property outside DOC", OC_DOXM_OWNED);
        return false;
      }
    }
    decode->owned = rep->value.boolean;
    decode->owned_set = true;
    return true;
  }
  OC_ERR("oc_doxm: Unknown boolean property %s", oc_string(rep->name));
  return false;
}

static bool
doxm_decode_int_property(const oc_rep_t *rep, unsigned flags,
                         oc_dostype_t state, size_t device,
                         oc_doxm_decode_t *decode)
{
  if (oc_rep_is_property(rep, OC_DOXM_OXMSEL,
                         OC_CHAR_ARRAY_LEN(OC_DOXM_OXMSEL))) {
    if ((flags & OC_DOXM_DECODE_FLAG_FROM_STORAGE) == 0) {
      if (state != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: Can set %s property only in RFOTM", OC_DOXM_OXMSEL);
        return false;
      }
      if ((flags & OC_DOXM_DECODE_FLAG_IS_DOC) != 0) {
        OC_ERR("oc_doxm: cannot set %s inside DOC", OC_DOXM_OXMSEL);
        return false;
      }
      doxm_evaluate_supported_oxms(device);
      assert(g_doxm[device].num_oxms <= 3);
      int oxm = 0;
      while (oxm < g_doxm[device].num_oxms) {
        if (g_doxm[device].oxms[oxm] == (int)rep->value.integer) {
          break;
        }
        oxm++;
      }
      if (oxm == g_doxm[device].num_oxms) {
        OC_ERR("oc_doxm: Attempting to select an unsupported OXM");
        return false;
      }
    }
    decode->oxmsel = (int)rep->value.integer;
    decode->oxmsel_set = true;
    return true;
  }

  if (oc_rep_is_property(rep, OC_DOXM_SCT, OC_CHAR_ARRAY_LEN(OC_DOXM_SCT))) {
    if ((flags & OC_DOXM_DECODE_FLAG_FROM_STORAGE) == 0) {
      OC_ERR("oc_doxm: cannot set %s property", OC_DOXM_SCT);
      return false;
    }
    decode->sct = (int)rep->value.integer;
    decode->sct_set = true;
    return true;
  }

  OC_ERR("oc_doxm: Unknown integer property %s", oc_string(rep->name));
  return false;
}

static bool
doxm_string_propery_is_writable(const char *prop, unsigned flags,
                                unsigned allowed_states, oc_dostype_t state)
{
  (void)prop;
  if ((flags & OC_DOXM_DECODE_FLAG_FROM_STORAGE) != 0) {
    return true;
  }
  if ((allowed_states & OC_PSTAT_DOS_ID_FLAG(state)) == 0) {
    OC_ERR("oc_doxm: cannot set %s property in given state(%d)", prop,
           (int)state);
    return false;
  }
  if ((flags & OC_DOXM_DECODE_FLAG_IS_DOC) == 0) {
    OC_ERR("oc_doxm: cannot set %s outside of DOC", prop);
    return false;
  }
  return true;
}

static bool
doxm_decode_string_property(const oc_rep_t *rep, unsigned flags,
                            oc_dostype_t state, oc_doxm_decode_t *decode)
{
  if (oc_rep_is_property(rep, OC_DOXM_DEVICEUUID,
                         OC_CHAR_ARRAY_LEN(OC_DOXM_DEVICEUUID))) {
    if (!doxm_string_propery_is_writable(OC_DOXM_DEVICEUUID, flags,
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFOTM),
                                         state)) {
      return false;
    }
    decode->deviceuuid = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_DOXM_DOWNERUUID,
                         OC_CHAR_ARRAY_LEN(OC_DOXM_DOWNERUUID))) {
    if (!doxm_string_propery_is_writable(OC_DOXM_DOWNERUUID, flags,
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFOTM),
                                         state)) {
      return false;
    }
    decode->devowneruuid = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_DOXM_ROWNERUUID,
                         OC_CHAR_ARRAY_LEN(OC_DOXM_ROWNERUUID))) {

    if (!doxm_string_propery_is_writable(OC_DOXM_ROWNERUUID, flags,
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFOTM) |
                                           OC_PSTAT_DOS_ID_FLAG(OC_DOS_SRESET),
                                         state)) {
      return false;
    }
    decode->rowneruuid = &rep->value.string;
    return true;
  }

  OC_ERR("oc_doxm: Unknown string property %s", oc_string(rep->name));
  return false;
}

static bool
doxm_decode_int_array_property(const oc_rep_t *rep)
{
  (void)rep;
  OC_ERR("oc_doxm: cannot set %s property", oc_string(rep->name));
  return false;
}

static bool
doxm_decode_property(const oc_rep_t *rep, unsigned flags, oc_dostype_t state,
                     size_t device, oc_doxm_decode_t *decode)
{
  if ((flags & OC_DOXM_DECODE_FLAG_FROM_STORAGE) != 0 &&
      oc_rep_is_baseline_interface_property(rep)) {
    OC_DBG("doxm decode: skipping baseline property(%s)", oc_string(rep->name));
    return true;
  }

  if (rep->type == OC_REP_BOOL) {
    /* owned */
    return doxm_decode_bool_property(rep, flags, state, decode);
  }

  if (rep->type == OC_REP_INT) {
    /* oxmsel and sct */
    return doxm_decode_int_property(rep, flags, state, device, decode);
  }

  if (rep->type == OC_REP_STRING) {
    /* deviceuuid, devowneruuid and rowneruuid */
    return doxm_decode_string_property(rep, flags, state, decode);
  }

  if (rep->type == OC_REP_INT_ARRAY) {
    /* oxms */
    return doxm_decode_int_array_property(rep);
  }

  OC_ERR("doxm decode: unknown property (name=%s, type=%d)",
         oc_string(rep->name), (int)rep->type);
  return false;
}

static bool
doxm_decode(const oc_rep_t *rep, unsigned flags, size_t device,
            oc_doxm_decode_t *decode)
{
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  for (; rep != NULL; rep = rep->next) {
    if (!doxm_decode_property(rep, flags, ps->s, device, decode)) {
      OC_ERR("doxm decode failed: invalid property");
      return false;
    }
  }
  return true;
}

static void
doxm_decode_copy(const oc_doxm_decode_t *src, oc_sec_doxm_t *dst)
{
  if (src->owned_set) {
    dst->owned = src->owned;
  }

  if (src->oxmsel_set) {
    dst->oxmsel = src->oxmsel;
  }

  if (src->sct_set) {
    dst->sct = src->sct;
  }

  if (src->deviceuuid != NULL) {
    oc_str_to_uuid(oc_string(*src->deviceuuid), &dst->deviceuuid);
  }

  if (src->devowneruuid != NULL) {
    oc_str_to_uuid(oc_string(*src->devowneruuid), &dst->devowneruuid);
  }

  if (src->rowneruuid != NULL) {
    oc_str_to_uuid(oc_string(*src->rowneruuid), &dst->rowneruuid);
  }
}

bool
oc_sec_decode_doxm(const oc_rep_t *rep, bool from_storage, bool doc,
                   size_t device)
{
  unsigned flags = 0;
  if (from_storage) {
    flags |= OC_DOXM_DECODE_FLAG_FROM_STORAGE;
  }
  if (doc) {
    flags |= OC_DOXM_DECODE_FLAG_IS_DOC;
  }
  oc_doxm_decode_t decode;
  memset(&decode, 0, sizeof(oc_doxm_decode_t));
  if (!doxm_decode(rep, flags, device, &decode)) {
    OC_ERR("decode doxm failed: invalid payload");
    return false;
  }

  OC_DBG("doxm update: (from_storage=%d, doc=%d): ", (int)from_storage,
         (int)doc);
  OC_DBG("\towned=%d (set:%d)", (int)decode.owned, (int)decode.owned_set);
  OC_DBG("\toxmsel=%d (set:%d)", decode.oxmsel, (int)decode.oxmsel_set);
  OC_DBG("\tsct=%d (set:%d)", decode.sct, (int)decode.sct_set);
  OC_DBG("\tdeviceuuid=%s",
         decode.deviceuuid != NULL ? oc_string(*decode.deviceuuid) : "NULL");
  OC_DBG("\tdevowneruuid=%s", decode.devowneruuid != NULL
                                ? oc_string(*decode.devowneruuid)
                                : "NULL");
  OC_DBG("\trowneruuid=%s",
         decode.rowneruuid != NULL ? oc_string(*decode.rowneruuid) : "NULL");
  doxm_decode_copy(&decode, &g_doxm[device]);

  if (decode.oxmsel_set && !from_storage &&
      g_doxm[device].oxmsel == OC_OXMTYPE_RDP) {
    oc_tls_generate_random_pin();
  }

  if (decode.deviceuuid != NULL) {
    oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
    memcpy(deviceuuid->id, g_doxm[device].deviceuuid.id,
           sizeof(deviceuuid->id));
  }

  if (decode.owned_set) {
    oc_doxm_owned_cb_t *doxm_cb_item =
      (oc_doxm_owned_cb_t *)oc_list_head(g_oc_doxm_owned_cb_list);
    while (doxm_cb_item != NULL) {
      oc_doxm_owned_cb_t *invokee = doxm_cb_item;
      doxm_cb_item = doxm_cb_item->next;
      (invokee->cb)(&g_doxm[device].deviceuuid, device, g_doxm[device].owned,
                    invokee->user_data);
    }
  }
  return true;
}

static void
doxm_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *data)
{
  (void)iface_mask;
  (void)data;
  const oc_tls_peer_t *p = oc_tls_get_peer(request->origin);
  if (!oc_sec_decode_doxm(request->request_payload, false,
                          p != NULL ? p->doc : false,
                          request->resource->device)) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
  oc_sec_dump_doxm(request->resource->device);
}

void
oc_sec_doxm_create_resource(size_t device)
{
  oc_core_populate_resource(OCF_SEC_DOXM, device, OCF_SEC_DOXM_URI,
                            OCF_SEC_DOXM_IF_MASK, OCF_SEC_DOXM_DEFAULT_IF,
                            OC_DISCOVERABLE, doxm_resource_get, /*put*/ NULL,
                            doxm_resource_post,
                            /*delete*/ NULL, 1, OCF_SEC_DOXM_RT);
}

bool
oc_sec_is_doxm_resource_uri(oc_string_view_t uri)
{
  return oc_resource_match_uri(OC_STRING_VIEW(OCF_SEC_DOXM_URI), uri);
}

void
oc_set_select_oxms_cb(oc_select_oxms_cb_t callback, void *user_data)
{
  if (callback == NULL) {
    g_oc_select_oxms_cb = NULL;
    g_oc_select_oxms_cb_user_data = NULL;
    return;
  }
  g_oc_select_oxms_cb = callback;
  g_oc_select_oxms_cb_user_data = user_data;
}

int
oc_add_ownership_status_cb_v1(oc_ownership_status_cb_t cb, void *user_data)
{
  oc_doxm_owned_cb_t *new_doxm_cb = oc_memb_alloc(&g_oc_doxm_owned_cb_s);
  if (new_doxm_cb == NULL) {
    OC_ERR("Insufficient memory to add ownership status callback");
    return -1;
  }
  new_doxm_cb->cb = cb;
  new_doxm_cb->user_data = user_data;
  oc_list_add(g_oc_doxm_owned_cb_list, new_doxm_cb);
  return 0;
}

void
oc_add_ownership_status_cb(oc_ownership_status_cb_t cb, void *user_data)
{
  if (oc_add_ownership_status_cb_v1(cb, user_data) != 0) {
    oc_abort("Insufficient memory");
  }
}

oc_doxm_owned_cb_t *
oc_ownership_status_get_cb(oc_ownership_status_cb_t cb, const void *user_data)
{
  oc_doxm_owned_cb_t *doxm_cb_item =
    (oc_doxm_owned_cb_t *)oc_list_head(g_oc_doxm_owned_cb_list);
  while (doxm_cb_item != NULL) {
    if (cb == doxm_cb_item->cb && user_data == doxm_cb_item->user_data) {
      return doxm_cb_item;
    }
    doxm_cb_item = doxm_cb_item->next;
  }
  return NULL;
}

void
oc_remove_ownership_status_cb(oc_ownership_status_cb_t cb,
                              const void *user_data)
{
  oc_doxm_owned_cb_t *doxm_cb_item = oc_ownership_status_get_cb(cb, user_data);
  if (doxm_cb_item != NULL) {
    oc_list_remove(g_oc_doxm_owned_cb_list, doxm_cb_item);
    oc_memb_free(&g_oc_doxm_owned_cb_s, doxm_cb_item);
  }
}

void
oc_ownership_status_free_all_cbs(void)
{
  oc_doxm_owned_cb_t *doxm_cb_item =
    (oc_doxm_owned_cb_t *)oc_list_pop(g_oc_doxm_owned_cb_list);
  while (doxm_cb_item != NULL) {
    oc_memb_free(&g_oc_doxm_owned_cb_s, doxm_cb_item);
    doxm_cb_item = (oc_doxm_owned_cb_t *)oc_list_pop(g_oc_doxm_owned_cb_list);
  }
}

bool
oc_is_owned_device(size_t device_index)
{
  if (!oc_core_device_is_valid(device_index)) {
    OC_ERR("invalid device index(%zu)", device_index);
    return false;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  if (g_doxm != NULL) {
    return g_doxm[device_index].owned;
  }
  return false;
#else  /* OC_DYNAMIC_ALLOCATION */
  return g_doxm[device_index].owned;
#endif /* !OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_SECURITY */
