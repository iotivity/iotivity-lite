/*
// Copyright (c) 2017 Intel Corporation
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

#ifdef OC_SECURITY

#include "oc_doxm.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_otm_state.h"
#include "oc_pstat.h"
#include "oc_store.h"
#include <stddef.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include "util/oc_mem.h"
static oc_sec_doxm_t *doxm;
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_doxm_t doxm[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

static oc_sec_change_owner_cb_t _oc_sec_change_owner_cb = NULL;

void
oc_sec_set_owner_cb(oc_sec_change_owner_cb_t cb)
{
  _oc_sec_change_owner_cb = cb;
}

void
oc_sec_doxm_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (doxm) {
    oc_mem_free(doxm);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_doxm_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  doxm = (oc_sec_doxm_t *)oc_mem_calloc(oc_core_get_num_devices(),
                                        sizeof(oc_sec_doxm_t));
  if (!doxm) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_set_doxm(oc_doxm_method_t oxmsel)
{
  int i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    oc_sec_doxm(i, oxmsel);
  }
}

void
oc_sec_doxm(size_t device, oc_doxm_method_t oxmsel)
{
  doxm[device].oxmsel = oxmsel;
  doxm[device].sct = 1;
  doxm[device].owned = false;
  memset(doxm[device].devowneruuid.id, 0, 16);
  memset(doxm[device].rowneruuid.id, 0, 16);
  oc_sec_dump_doxm(device);
}

void
oc_sec_encode_doxm(size_t device)
{
  int oxms[1] = { doxm[device].oxmsel };
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_DOXM, device));
  oc_rep_set_int_array(root, oxms, oxms, 1);
  oc_rep_set_int(root, oxmsel, doxm[device].oxmsel);
  oc_rep_set_int(root, sct, doxm[device].sct);
  oc_rep_set_boolean(root, owned, doxm[device].owned);
  oc_uuid_to_str(&doxm[device].devowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, devowneruuid, uuid);
  oc_uuid_to_str(&doxm[device].deviceuuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, deviceuuid, uuid);
  oc_uuid_to_str(&doxm[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

oc_sec_doxm_t *
oc_sec_get_doxm(size_t device)
{
  return &doxm[device];
}

void
get_doxm(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)data;
  switch (interface) {
  case OC_IF_BASELINE: {
    char *q;
    int ql = oc_get_query_value(request, "owned", &q);
    size_t device = request->resource->device;
    if (ql > 0 &&
        ((doxm[device].owned == 1 && strncasecmp(q, "false", 5) == 0) ||
         (doxm[device].owned == 0 && strncasecmp(q, "true", 4) == 0))) {
      if (request->origin && (request->origin->flags & MULTICAST) == 0) {
        request->response->response_buffer->code =
          oc_status_code(OC_STATUS_BAD_REQUEST);
      } else {
        oc_ignore_request(request);
      }
    } else {
      oc_sec_encode_doxm(device);
      oc_send_response(request, OC_STATUS_OK);
    }
  } break;
  default:
    break;
  }
}

bool
oc_sec_decode_doxm(oc_rep_t *rep, bool from_storage, size_t device)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  size_t len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_BOOL:
      if (len == 5 && memcmp(oc_string(t->name), "owned", 5) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM) {
          OC_ERR("oc_doxm: Can set owned property only in RFOTM");
          return false;
        }
      } else {
        OC_ERR("oc_doxm: Unknown property %s", oc_string(t->name));
        return false;
      }
      break;
    case OC_REP_INT:
      if (len == 6 && memcmp(oc_string(t->name), "oxmsel", 6) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM) {
          OC_ERR("oc_doxm: Can set oxmsel property only in RFOTM");
          return false;
        }
      } else if (from_storage && len == 3 &&
                 memcmp(oc_string(t->name), "sct", 3) == 0) {
#ifdef OC_SPEC_VER_OIC
      } else if (len == 18 &&
          memcmp(oc_string(t->name), "x.org.iotivity.mom", 18) == 0) {
          OC_WRN("oc_doxm: skip x.org.iotivity.mom");
#endif
      } else {
        OC_ERR("oc_doxm: Unknown property %s", oc_string(t->name));
        return false;
      }
      break;
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(t->name), "deviceuuid", 10) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM) {
          OC_ERR("oc_doxm: Can set deviceuuid property only in RFOTM");
          return false;
        }
      } else if (len == 12 &&
                 memcmp(oc_string(t->name), "devowneruuid", 12) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM) {
          OC_ERR("oc_doxm: Can set devowneruuid property only in RFOTM");
          return false;
        }
      } else if (len == 10 &&
                 memcmp(oc_string(t->name), "rowneruuid", 10) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET) {
          OC_ERR("oc_doxm: Can set rowneruuid property only in RFOTM");
          return false;
        }
      } else {
        OC_ERR("oc_doxm: Unknown property %s", oc_string(t->name));
        return false;
      }
      break;
    case OC_REP_INT_ARRAY:
      if (!from_storage && len == 4 &&
          memcmp(oc_string(t->name), "oxms", 4) == 0) {
        OC_ERR("oc_doxm: Can set oxms property");
        return false;
      }
      break;
    default: {
      if (!((len == 2 && (memcmp(oc_string(t->name), "rt", 2) == 0 ||
                          memcmp(oc_string(t->name), "if", 2) == 0))) &&
          !(len == 4 && memcmp(oc_string(t->name), "oxms", 4) == 0)) {
        OC_ERR("oc_doxm: Unknown property %s", oc_string(t->name));
        return false;
      }
    } break;
    }
    t = t->next;
  }

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_BOOL:
      if (len == 5 && memcmp(oc_string(rep->name), "owned", 5) == 0) {
        doxm[device].owned = rep->value.boolean;
      }
      break;
    case OC_REP_INT:
      if (len == 6 && memcmp(oc_string(rep->name), "oxmsel", 6) == 0) {
        doxm[device].oxmsel = rep->value.integer;
      } else if (from_storage && len == 3 &&
                 memcmp(oc_string(rep->name), "sct", 3) == 0) {
        doxm[device].sct = rep->value.integer;
      }
      break;
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "deviceuuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm[device].deviceuuid);
        oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
        memcpy(deviceuuid->id, doxm[device].deviceuuid.id, 16);
      } else if (len == 12 &&
                 memcmp(oc_string(rep->name), "devowneruuid", 12) == 0) {
        oc_uuid_t uuid;
        oc_str_to_uuid(oc_string(rep->value.string), &uuid);
        if (_oc_sec_change_owner_cb && !from_storage &&
            memcmp(&uuid, &doxm[device].devowneruuid, sizeof(oc_uuid_t)) != 0) {
          if (!_oc_sec_change_owner_cb()) {
            doxm[device].owned = false;
            return false;
          }
        }
        memcpy(&doxm[device].devowneruuid, &uuid, sizeof(oc_uuid_t));
#if !defined(OC_SPEC_VER_OIC)
        if (!from_storage) {
          int i;
          for (i = 0; i < 16; i++) {
            if (doxm[device].devowneruuid.id[i] != 0) {
              break;
            }
          }
          if (i != 16) {
            oc_core_regen_unique_ids(device);
          }
        }
#endif //!OC_SPEC_VER_OIC
      } else if (len == 10 &&
                 memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm[device].rowneruuid);
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
post_doxm(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  if (oc_sec_decode_doxm(request->request_payload, false,
                         request->resource->device)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_doxm(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    oc_sec_otm_err(request->resource->device, OC_SEC_ERR_DOXM);
  }
}

#endif /* OC_SECURITY */
