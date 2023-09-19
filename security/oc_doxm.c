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

#include "oc_doxm_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_acl_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pstat_internal.h"
#include "oc_store.h"
#include "oc_tls_internal.h"
#include "port/oc_assert.h"
#include "port/oc_random.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#else /* !WIN32 */
#include <strings.h>
#endif /* WIN32 */

#define OC_DOXM_OWNED "owned"
#define OC_DOXM_OWNED_LEN (sizeof(OC_DOXM_OWNED) - 1)
#define OC_DOXM_OXMSEL "oxmsel"
#define OC_DOXM_OXMSEL_LEN (sizeof(OC_DOXM_OXMSEL) - 1)
#define OC_DOXM_SCT "sct"
#define OC_DOXM_SCT_LEN (sizeof(OC_DOXM_SCT) - 1)
#define OC_DOXM_DEVICEUUID "deviceuuid"
#define OC_DOXM_DEVICEUUID_LEN (sizeof(OC_DOXM_DEVICEUUID) - 1)
#define OC_DOXM_DOWNERUUID "devowneruuid"
#define OC_DOXM_DOWNERUUID_LEN (sizeof(OC_DOXM_DOWNERUUID) - 1)
#define OC_DOXM_ROWNERUUID "rowneruuid"
#define OC_DOXM_ROWNERUUID_LEN (sizeof(OC_DOXM_ROWNERUUID) - 1)
#define OC_DOXM_OXMS "oxms"
#define OC_DOXM_OXMS_LEN (sizeof(OC_DOXM_OXMS) - 1)

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
static oc_sec_doxm_t *g_doxm = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_doxm_t g_doxm[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */

typedef struct oc_doxm_owned_cb_s
{
  struct oc_doxm_owned_cb_s *next;
  oc_ownership_status_cb_t cb;
  void *user_data;
} oc_doxm_owned_cb_t;

OC_LIST(g_oc_doxm_owned_cb_list);
OC_MEMB(g_oc_doxm_owned_cb_s, oc_doxm_owned_cb_t, OC_MAX_DOXM_OWNED_CBS);

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
add_doxm_response_for_device(size_t device, oc_interface_mask_t iface_mask)
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
clear_doxm_response(doxm_response_data_t *rd)
{
  oc_list_remove(g_doxm_response_data_list, rd);
  oc_memb_free(&g_doxm_response_data_s, rd);
}

static bool
has_doxm_response_for_device(size_t device)
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

#endif /* OC_SERVER */

static oc_select_oxms_cb_t g_oc_select_oxms_cb;
static void *g_oc_select_oxms_cb_user_data;

void
oc_sec_doxm_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  oc_doxm_owned_cb_t *doxm_cb_item =
    (oc_doxm_owned_cb_t *)oc_list_pop(g_oc_doxm_owned_cb_list);
  while (doxm_cb_item) {
    free(doxm_cb_item);
    doxm_cb_item = (oc_doxm_owned_cb_t *)oc_list_pop(g_oc_doxm_owned_cb_list);
  }
  if (g_doxm) {
    free(g_doxm);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_doxm_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_doxm =
    (oc_sec_doxm_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_doxm_t));
  if (!g_doxm) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_set_select_oxms_cb(NULL, NULL);
}

static void
evaluate_supported_oxms(size_t device)
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

void
oc_sec_doxm_set_default(oc_sec_doxm_t *doxm)
{
  /* In RESET, oxmsel shall be set to (4) "oic.sec.oxm.self" */
  doxm->oxmsel = 4;
#ifdef OC_PKI
  doxm->sct = 9;
#else  /* OC_PKI */
  doxm->sct = 1;
#endif /* !OC_PKI */
#ifdef OC_OSCORE
  doxm->sct |= OC_CREDTYPE_OSCORE;
#ifdef OC_CLIENT
  doxm->sct |= OC_CREDTYPE_OSCORE_MCAST_CLIENT;
#endif /* OC_CLIENT */
#ifdef OC_SERVER
  doxm->sct |= OC_CREDTYPE_OSCORE_MCAST_SERVER;
#endif /* OC_SERVER */
#endif /* OC_OSCORE */
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
    while (doxm_cb_item) {
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

void
oc_sec_encode_doxm(size_t device, oc_interface_mask_t iface_mask,
                   bool to_storage)
{
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_DOXM, device));
  }
  /* oxms */
  if (!to_storage) {
    evaluate_supported_oxms(device);
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
  oc_rep_set_text_string(root, devowneruuid, uuid);
  /* deviceuuid */
  oc_uuid_to_str(&g_doxm[device].deviceuuid, uuid, sizeof(uuid));
  oc_rep_set_text_string(root, deviceuuid, uuid);
  /* rowneruuid */
  oc_uuid_to_str(&g_doxm[device].rowneruuid, uuid, sizeof(uuid));
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

oc_sec_doxm_t *
oc_sec_get_doxm(size_t device)
{
  return &g_doxm[device];
}

#ifdef OC_SERVER
// separate response handler, used for delaying the response to the client
// in order to avoid flooding the network when multicasts are used
static oc_event_callback_retval_t
handle_doxm_separate_response(void *data)
{
  doxm_response_data_t *d = (doxm_response_data_t *)data;
  if (d->separate_response.active) {
    oc_set_separate_response_buffer(&d->separate_response);
    oc_sec_encode_doxm(d->device, d->iface_mask, false);
    // TODO: shrink buffer
    oc_send_separate_response(&d->separate_response, OC_STATUS_OK);
  }
  clear_doxm_response(d);
  return OC_EVENT_DONE;
}
#endif /* OC_SERVER */

void
get_doxm(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  switch (iface_mask) {
  case OC_IF_RW:
  case OC_IF_BASELINE: {
    const char *q;
    int ql = oc_get_query_value_v1(request, OC_DOXM_OWNED,
                                   OC_CHAR_ARRAY_LEN(OC_DOXM_OWNED), &q);
    size_t device = request->resource->device;

    if (ql > 0 &&
        ((g_doxm[device].owned == 1 && strncasecmp(q, "false", 5) == 0) ||
         (g_doxm[device].owned == 0 && strncasecmp(q, "true", 4) == 0))) {
      if (request->origin != NULL &&
          (request->origin->flags & MULTICAST) == 0) {
        // reply with BAD_REQUEST if ownership status does not match query
        // of unicast request
        oc_send_response_internal(request, OC_STATUS_BAD_REQUEST,
                                  APPLICATION_VND_OCF_CBOR, 0, true);
        return;
      }
      // ignore if ownership status does not match query of multicast request
      oc_ignore_request(request);
      return;
    }

    // do not respond to /oic/sec/doxm requests if the value of the deviceuuid
    // query parameter does not match the device's UUID
    // FOR DEVELOPMENT USE ONLY
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
    if (request->origin != NULL && (request->origin->flags & MULTICAST) != 0) {
      if (has_doxm_response_for_device(device)) {
        // previous multicast discovery request has not been handled yet
        OC_WRN("duplicit multicast discovery request for device(%zu) ignored",
               device);
        oc_ignore_request(request);
        return;
      }

      doxm_response_data_t *rd =
        add_doxm_response_for_device(device, iface_mask);
      if (rd == NULL) {
        oc_send_response_internal(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                  APPLICATION_VND_OCF_CBOR, 0, true);
        return;
      }

      oc_indicate_separate_response(request, &rd->separate_response);
      uint64_t jitter =
        (uint64_t)(oc_random_value() % OC_MULTICAST_RESPONSE_JITTER_MS);
      oc_set_delayed_callback_ms_v1(rd, handle_doxm_separate_response, jitter);
      return;
    }
#endif /* OC_SERVER */

    // respond to unicasts immediately
    oc_sec_encode_doxm(device, iface_mask, false);
    // TODO: shrink buffer
    oc_send_response_with_callback(request, OC_STATUS_OK, true);
  } break;
  default:
    break;
  }
}

static bool
sec_validate_doxm_bool(const oc_rep_t *rep, const oc_sec_pstat_t *ps,
                       bool from_storage, bool doc)
{
  size_t len = oc_string_len(rep->name);
  if (len == OC_DOXM_OWNED_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_OWNED, OC_DOXM_OWNED_LEN) == 0) {
    if (!from_storage) {
      if (ps->s != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: can set %s property only in RFOTM", OC_DOXM_OWNED);
        return false;
      }
      if (!doc) {
        OC_ERR("oc_doxm: cannot set %s property outside DOC", OC_DOXM_OWNED);
        return false;
      }
    }
    return true;
  }
  OC_ERR("oc_doxm: Unknown property %s", oc_string(rep->name));
  return false;
}

static bool
sec_validate_doxm_int(const oc_rep_t *rep, const oc_sec_pstat_t *ps,
                      bool from_storage, bool doc, size_t device)
{
  size_t len = oc_string_len(rep->name);
  if (len == OC_DOXM_OXMSEL_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_OXMSEL, OC_DOXM_OXMSEL_LEN) == 0) {
    if (!from_storage) {
      if (ps->s != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: Can set %s property only in RFOTM", OC_DOXM_OXMSEL);
        return false;
      }
      evaluate_supported_oxms(device);
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
      if (doc) {
        OC_ERR("oc_doxm: cannot set %s inside DOC", OC_DOXM_OXMSEL);
        return false;
      }
    }
    return true;
  }

  if (from_storage && len == OC_DOXM_SCT_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_SCT, OC_DOXM_SCT_LEN) == 0) {
    return true;
  }
  OC_ERR("oc_doxm: Unknown property %s", oc_string(rep->name));
  return false;
}

static bool
sec_validate_doxm_string(const oc_rep_t *rep, const oc_sec_pstat_t *ps,
                         bool from_storage, bool doc)
{
  size_t len = oc_string_len(rep->name);
  if (len == OC_DOXM_DEVICEUUID_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_DEVICEUUID,
             OC_DOXM_DEVICEUUID_LEN) == 0) {
    if (!from_storage) {
      if (ps->s != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: can set %s property only in RFOTM",
               OC_DOXM_DEVICEUUID);
        return false;
      }
      if (!doc) {
        OC_ERR("oc_doxm: cannot set %s outside DOC", OC_DOXM_DEVICEUUID);
        return false;
      }
    }
    return true;
  }

  if (len == OC_DOXM_DOWNERUUID_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_DOWNERUUID,
             OC_DOXM_DOWNERUUID_LEN) == 0) {
    if (!from_storage) {
      if (ps->s != OC_DOS_RFOTM) {
        OC_ERR("oc_doxm: can set %s property only in RFOTM",
               OC_DOXM_DOWNERUUID);
        return false;
      }
      if (!doc) {
        OC_ERR("oc_doxm: cannot set %s outside DOC", OC_DOXM_DOWNERUUID);
        return false;
      }
    }
    return true;
  }

  if (len == OC_DOXM_ROWNERUUID_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_ROWNERUUID,
             OC_DOXM_ROWNERUUID_LEN) == 0) {
    if (!from_storage) {
      if (ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET) {
        OC_ERR("oc_doxm: can set %s property only in RFOTM",
               OC_DOXM_ROWNERUUID);
        return false;
      }
      if (!doc) {
        OC_ERR("oc_doxm: cannot set %s outside DOC", OC_DOXM_ROWNERUUID);
        return false;
      }
    }
    return true;
  }

  OC_ERR("oc_doxm: unknown property %s", oc_string(rep->name));
  return false;
}

static bool
sec_validate_doxm_int_array(const oc_rep_t *rep, bool from_storage)
{
  size_t len = oc_string_len(rep->name);
  if (!from_storage && len == OC_DOXM_OXMS_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_OXMS, OC_DOXM_OXMS_LEN) == 0) {
    OC_ERR("oc_doxm: cannot set %s property", OC_DOXM_OXMS);
    return false;
  }

  return true;
}

static bool
sec_validate_doxm_default(const oc_rep_t *rep)
{
  size_t len = oc_string_len(rep->name);
#define OC_DOXM_RT "rt"
#define OC_DOXM_RT_LEN (sizeof(OC_DOXM_RT) - 1)
  if (len == OC_DOXM_RT_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_RT, OC_DOXM_RT_LEN) == 0) {
    return true;
  }

#define OC_DOXM_IF "if"
#define OC_DOXM_IF_LEN (sizeof(OC_DOXM_IF) - 1)
  if (len == OC_DOXM_IF_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_IF, OC_DOXM_IF_LEN) == 0) {
    return true;
  }

  if (len == OC_DOXM_OXMS_LEN &&
      memcmp(oc_string(rep->name), OC_DOXM_OXMS, OC_DOXM_OXMS_LEN) == 0) {
    return true;
  }

  OC_ERR("oc_doxm: unknown property %s", oc_string(rep->name));
  return false;
}

static bool
sec_validate_doxm(const oc_rep_t *rep, bool from_storage, bool doc,
                  size_t device)
{
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  while (rep != NULL) {
    switch (rep->type) {
    /* owned */
    case OC_REP_BOOL:
      if (!sec_validate_doxm_bool(rep, ps, from_storage, doc)) {
        return false;
      }
      break;
    /* oxmsel and sct */
    case OC_REP_INT:
      if (!sec_validate_doxm_int(rep, ps, from_storage, doc, device)) {
        return false;
      }
      break;
    /* deviceuuid, devowneruuid and rowneruuid */
    case OC_REP_STRING:
      if (!sec_validate_doxm_string(rep, ps, from_storage, doc)) {
        return false;
      }
      break;
    /* oxms */
    case OC_REP_INT_ARRAY:
      if (!sec_validate_doxm_int_array(rep, from_storage)) {
        return false;
      }
      break;
    default:
      if (!sec_validate_doxm_default(rep)) {
        return false;
      }
      break;
    }
    rep = rep->next;
  }
  return true;
}

bool
oc_sec_decode_doxm(const oc_rep_t *rep, bool from_storage, bool doc,
                   size_t device)
{
  if (!sec_validate_doxm(rep, from_storage, doc, device)) {
    OC_ERR("decode doxm: invalid payload");
    return false;
  }

  bool owned = false;
  bool owned_changed = false;
  int oxmsel = -1;
  int sct = -1;
  const oc_string_t *deviceuuid_str = NULL;
  const oc_string_t *devowneruuid_str = NULL;
  const oc_string_t *rowneruuid_str = NULL;
  while (rep != NULL) {
    switch (rep->type) {
    /* owned */
    case OC_REP_BOOL:
      if (oc_rep_is_property(rep, OC_DOXM_OWNED, OC_DOXM_OWNED_LEN)) {
        owned_changed = true;
        owned = rep->value.boolean;
        break;
      }
      OC_ERR("decode doxm: invalid bool property(%s)", oc_string(rep->name));
      break;
    /* oxmsel and sct */
    case OC_REP_INT:
      if (oc_rep_is_property(rep, OC_DOXM_OXMSEL, OC_DOXM_OXMSEL_LEN)) {
        oxmsel = (int)rep->value.integer;
        break;
      }
      if (from_storage &&
          oc_rep_is_property(rep, OC_DOXM_SCT, OC_DOXM_SCT_LEN)) {
        sct = (int)rep->value.integer;
        break;
      }
      OC_ERR("decode doxm: invalid int property(%s)", oc_string(rep->name));
      break;
    /* deviceuuid, devowneruuid and rowneruuid */
    case OC_REP_STRING:
      if (oc_rep_is_property(rep, OC_DOXM_DEVICEUUID, OC_DOXM_DEVICEUUID_LEN)) {
        deviceuuid_str = &rep->value.string;
        break;
      }
      if (oc_rep_is_property(rep, OC_DOXM_DOWNERUUID, OC_DOXM_DOWNERUUID_LEN)) {
        devowneruuid_str = &rep->value.string;
        break;
      }
      if (oc_rep_is_property(rep, OC_DOXM_ROWNERUUID, OC_DOXM_ROWNERUUID_LEN)) {
        rowneruuid_str = &rep->value.string;
        break;
      }
      OC_ERR("decode doxm: invalid string property(%s)", oc_string(rep->name));
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  OC_DBG("doxm update (from_storage=%d): owned=%d (changed:%d) oxmsel=%d "
         "sct=%d, deviceuuid=%s, devowneruuid=%s, rowneruuid=%s",
         (int)from_storage, (int)owned, (int)owned_changed, oxmsel, sct,
         deviceuuid_str != NULL ? oc_string(*deviceuuid_str) : "NULL",
         devowneruuid_str != NULL ? oc_string(*devowneruuid_str) : "NULL",
         rowneruuid_str != NULL ? oc_string(*rowneruuid_str) : "NULL");

  if (owned_changed) {
    g_doxm[device].owned = owned;
  }

  if (oxmsel != -1) {
    g_doxm[device].oxmsel = oxmsel;
    if (!from_storage && g_doxm[device].oxmsel == OC_OXMTYPE_RDP) {
      oc_tls_generate_random_pin();
    }
  }

  if (sct != -1) {
    g_doxm[device].sct = sct;
  }

  if (deviceuuid_str != NULL) {
    oc_str_to_uuid(oc_string(*deviceuuid_str), &g_doxm[device].deviceuuid);
    oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
    memcpy(deviceuuid->id, g_doxm[device].deviceuuid.id,
           sizeof(deviceuuid->id));
  }

  if (devowneruuid_str != NULL) {
    oc_str_to_uuid(oc_string(*devowneruuid_str), &g_doxm[device].devowneruuid);
  }

  if (rowneruuid_str != NULL) {
    oc_str_to_uuid(oc_string(*rowneruuid_str), &g_doxm[device].rowneruuid);
  }

  if (owned_changed) {
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

void
post_doxm(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
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

void
oc_add_ownership_status_cb(oc_ownership_status_cb_t cb, void *user_data)
{
  oc_doxm_owned_cb_t *new_doxm_cb = oc_memb_alloc(&g_oc_doxm_owned_cb_s);
  if (!new_doxm_cb) {
    oc_abort("Insufficient memory");
  }
  new_doxm_cb->cb = cb;
  new_doxm_cb->user_data = user_data;
  oc_list_add(g_oc_doxm_owned_cb_list, new_doxm_cb);
}

void
oc_remove_ownership_status_cb(oc_ownership_status_cb_t cb,
                              const void *user_data)
{
  oc_doxm_owned_cb_t *doxm_cb_item =
    (oc_doxm_owned_cb_t *)oc_list_head(g_oc_doxm_owned_cb_list);
  while (doxm_cb_item) {
    if (cb == doxm_cb_item->cb && user_data == doxm_cb_item->user_data) {
      oc_list_remove(g_oc_doxm_owned_cb_list, doxm_cb_item);
      oc_memb_free(&g_oc_doxm_owned_cb_s, doxm_cb_item);
      break;
    }
    doxm_cb_item = doxm_cb_item->next;
  }
}

bool
oc_is_owned_device(size_t device_index)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_doxm) {
    return g_doxm[device_index].owned;
  }
  return false;
#else  /* OC_DYNAMIC_ALLOCATION */
  return g_doxm[device_index].owned;
#endif /* !OC_DYNAMIC_ALLOCATION */
}
#endif /* OC_SECURITY */
