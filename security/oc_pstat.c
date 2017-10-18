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
#include "oc_pstat.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_doxm.h"
#include "oc_dtls.h"
#include "oc_store.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_pstat_t *pstat;
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_pstat_t pstat[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_pstat_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  pstat =
    (oc_sec_pstat_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_pstat_t));
  if (!pstat) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

static bool
nil_uuid(oc_uuid_t *uuid)
{
  int i;
  for (i = 0; i < 16; i++) {
    if (uuid->id[i] != 0) {
      return false;
    }
  }
  return true;
}

static bool
valid_transition(int device, oc_dostype_t state)
{
  switch (pstat[device].s) {
  case OC_DOS_RESET:
    if (state == OC_DOS_RESET || state == OC_DOS_RFOTM)
      return true;
    break;
  case OC_DOS_RFOTM:
    if (state == OC_DOS_SRESET)
      return false;
    break;
  case OC_DOS_RFPRO:
    if (state == OC_DOS_RFOTM)
      return false;
    break;
  case OC_DOS_RFNOP:
    if (state == OC_DOS_RFOTM)
      return false;
    break;
  case OC_DOS_SRESET:
    if (state == OC_DOS_RFOTM || state == OC_DOS_RFNOP)
      return false;
    break;
  }
  return true;
}

static bool oc_pstat_handle_state(int device);
static bool
oc_pstat_handle_state(int device)
{
  oc_sec_acl_t *acl = oc_sec_get_acl(device);
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_pstat_t *ps = &pstat[device];
  switch (ps->s) {
  case OC_DOS_RESET: {
    ps->p = true;
    oc_sec_pstat_default(device);
    oc_sec_doxm_default(device);
    oc_sec_cred_default(device);
    oc_sec_acl_default(device);
    oc_sec_dtls_update_psk_identity(device);
    ps->p = false;
  }
  case OC_DOS_RFOTM: {
    ps->p = true;
    ps->s = OC_DOS_RFOTM;
    ps->cm |= 0x02;
    ps->cm &= ~0x01; // cm=2
    ps->tm &= ~0x03; // tm=0
    if (doxm->owned || !nil_uuid(&doxm->devowneruuid) || ps->isop ||
        (ps->cm & 0xC3) != 2 || (ps->tm & 0xC3) != 0) {
      OC_ERR("ERROR in RFOTM..Performing a RESET\n\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_RFPRO: {
    ps->p = true;
    ps->cm &= ~0x03; // cm=0
    ps->tm &= ~0x03; // tm=0
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || ps->isop || (ps->cm & 0xC3) != 0 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
      OC_ERR("ERROR in RFPRO..Performing a RESET\n\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_RFNOP: {
    ps->p = true;
    ps->cm &= ~0x03; // cm=0
    ps->tm &= ~0x03; // tm=0
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || !ps->isop || (ps->cm & 0xC3) != 0 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
      OC_ERR("ERROR in RFNOP..Performing a RESET\n\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_SRESET: {
    ps->p = true;
    ps->cm |= ~0x01;
    ps->cm &= ~0x02; // cm=1
    ps->tm &= ~0x03; // tm=2
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || ps->isop || ps->cm != 1 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
      OC_ERR("ERROR in SRESET..Performing a RESET\n\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  default:
    return false;
    break;
  }
  return true;
pstat_state_error:
  ps->s = OC_DOS_RESET;
  oc_pstat_handle_state(device);
  return false;
}

oc_sec_pstat_t *
oc_sec_get_pstat(int device)
{
  return &pstat[device];
}

bool
oc_sec_is_operational(int device)
{
  return pstat[device].isop;
}

void
oc_sec_pstat_default(int device)
{
  pstat[device].p = false;
  pstat[device].s = 0;
  pstat[device].isop = false;
  pstat[device].cm = 1;
  pstat[device].tm = 2;
  pstat[device].om = 3;
  pstat[device].sm = 4;
  memset(pstat[device].rowneruuid.id, 0, 16);
}

void
oc_sec_encode_pstat(int device)
{
  char uuid[37];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_PSTAT, device));
  oc_rep_set_object(root, dos);
  oc_rep_set_boolean(dos, p, pstat[device].p);
  oc_rep_set_int(dos, s, pstat[device].s);
  oc_rep_close_object(root, dos);
  oc_rep_set_int(root, cm, pstat[device].cm);
  oc_rep_set_int(root, tm, pstat[device].tm);
  oc_rep_set_int(root, om, pstat[device].om);
  oc_rep_set_int(root, sm, pstat[device].sm);
  oc_rep_set_boolean(root, isop, pstat[device].isop);
  oc_uuid_to_str(&pstat[device].rowneruuid, uuid, 37);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

bool
oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage, int device)
{
  oc_dostype_t s = pstat[device].s;
  bool isop = pstat[device].isop;
  int cm = pstat[device].cm;
  int tm = pstat[device].tm;
  int om = pstat[device].om;
  int sm = pstat[device].sm;
  oc_uuid_t rowneruuid;
  memcpy(rowneruuid.id, pstat[device].rowneruuid.id, 16);

  while (rep != NULL) {
    switch (rep->type) {
    case OBJECT: {
      if (oc_string_len(rep->name) == 3 &&
          memcmp(oc_string(rep->name), "dos", 3) == 0) {
        oc_rep_t *dos = rep->value.object;
        while (dos != NULL) {
          switch (dos->type) {
          case INT: {
            if (oc_string_len(dos->name) == 1 &&
                oc_string(dos->name)[0] == 's') {
              s = dos->value.integer;
            } else {
              return false;
            }
          } break;
          default: {
            if (!from_storage && oc_string_len(dos->name) == 1 &&
                oc_string(dos->name)[0] == 'p') {
              return false;
            }
          } break;
          }
          dos = dos->next;
        }
      } else {
        return false;
      }
    } break;
    case BOOL:
      if (oc_string_len(rep->name) == 4 &&
          memcmp(oc_string(rep->name), "isop", 4) == 0) {
        isop = rep->value.boolean;
      } else {
        return false;
      }
      break;
    case INT:
      if (memcmp(oc_string(rep->name), "cm", 2) == 0) {
        cm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "tm", 2) == 0) {
        tm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "om", 2) == 0) {
        om = rep->value.integer;
      } else if (from_storage && memcmp(oc_string(rep->name), "sm", 2) == 0) {
        sm = rep->value.integer;
      } else {
        return false;
      }
      break;
    case STRING:
      if (oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &rowneruuid);
      } else {
        return false;
      }
      break;
    default:
      if (!(oc_string_len(rep->name) == 2 &&
            (memcmp(oc_string(rep->name), "rt", 2) == 0 ||
             memcmp(oc_string(rep->name), "if", 2) == 0))) {
        return false;
      }
      break;
    }
    rep = rep->next;
  }
  if (from_storage || valid_transition(device, s)) {
    pstat[device].s = s;
    pstat[device].p = false;
    pstat[device].cm = cm;
    pstat[device].tm = tm;
    pstat[device].sm = sm;
    pstat[device].om = om;
    pstat[device].isop = isop;
    memcpy(pstat[device].rowneruuid.id, rowneruuid.id, 16);
    if (from_storage) {
      return true;
    }
    return oc_pstat_handle_state(device);
  }
  return false;
}

void
get_pstat(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)data;
  switch (interface) {
  case OC_IF_BASELINE: {
    oc_sec_encode_pstat(request->resource->device);
    oc_send_response(request, OC_STATUS_OK);
  } break;
  default:
    break;
  }
}

void
post_pstat(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  int device = request->resource->device;
  if (oc_sec_decode_pstat(request->request_payload, false, device)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_pstat(device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

#endif /* OC_SECURITY */
