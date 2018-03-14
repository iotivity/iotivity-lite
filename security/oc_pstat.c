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
static bool set_post_otm_acl = true;

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

#ifdef OC_DEBUG
static void
dump_pstat_dos(oc_sec_pstat_t *ps)
{
  switch (ps->s) {
  case OC_DOS_RESET:
    OC_DBG("oc_pstat: dos is RESET\n");
    break;
  case OC_DOS_RFOTM:
    OC_DBG("oc_pstat: dos is RFOTM\n");
    break;
  case OC_DOS_RFPRO:
    OC_DBG("oc_pstat: dos is RFPRO\n");
    break;
  case OC_DOS_RFNOP:
    OC_DBG("oc_pstat: dos is RFNOP\n");
    break;
  case OC_DOS_SRESET:
    OC_DBG("oc_pstat: dos is SRESET\n");
    break;
  }
}
#endif /* OC_DEBUG */

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

static bool oc_pstat_handle_state(oc_sec_pstat_t *ps, int device);
static bool
oc_pstat_handle_state(oc_sec_pstat_t *ps, int device)
{
  oc_sec_acl_t *acl = oc_sec_get_acl(device);
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  switch (ps->s) {
  case OC_DOS_RESET: {
    ps->p = true;
    ps->isop = false;
    ps->cm = 1;
    ps->tm = 2;
    pstat->om = 3;
    ps->sm = 4;
    memset(ps->rowneruuid.id, 0, 16);
    oc_core_regen_unique_ids(device);
    oc_sec_doxm_default(device);
    oc_sec_cred_default(device);
    oc_sec_acl_default(device);
    oc_sec_dtls_update_psk_identity(device);
    set_post_otm_acl = true;
    ps->p = false;
  }
  /* fall through */
  case OC_DOS_RFOTM: {
    ps->p = true;
    ps->s = OC_DOS_RFOTM;
    ps->cm = 2;
    ps->tm = 0;
    if (doxm->owned || !nil_uuid(&doxm->devowneruuid) || ps->isop ||
        (ps->cm & 0xC3) != 2 || (ps->tm & 0xC3) != 0) {
#ifdef OC_DEBUG
      if (!nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("non-Nil doxm:devowneruuid in RFOTM\n");
      }
      OC_ERR("ERROR in RFOTM\n\n");
#endif /* OC_DEBUG */
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_RFPRO: {
    ps->p = true;
    ps->cm = 0;
    ps->tm = 0;
    ps->isop = false;
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || ps->isop || (ps->cm & 0xC3) != 0 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false\n");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil\n");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil\n");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil\n");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil\n");
      }
      if (!oc_sec_find_cred(&ps->rowneruuid, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&doxm->rowneruuid, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&acl->rowneruuid, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&creds->rowneruuid, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid\n");
      }
      OC_ERR("ERROR in RFPRO\n\n");
#endif /* OC_DEBUG */
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_RFNOP: {
    ps->p = true;
    ps->cm = 0;
    ps->tm = 0;
    ps->isop = true;
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || !ps->isop || (ps->cm & 0xC3) != 0 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false\n");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil\n");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil\n");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil\n");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil\n");
      }
      if (!oc_sec_find_cred(&ps->rowneruuid, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&doxm->rowneruuid, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&acl->rowneruuid, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&creds->rowneruuid, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid\n");
      }
      OC_ERR("ERROR in RFNOP\n\n");
#endif /* OC_DEBUG */
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_SRESET: {
    ps->p = true;
    ps->cm = 1;
    ps->tm = 0;
    ps->isop = false;
    if (!doxm->owned || nil_uuid(&doxm->devowneruuid) ||
        nil_uuid(&doxm->deviceuuid) || ps->isop || ps->cm != 1 ||
        (ps->tm & 0xC3) != 0 || nil_uuid(&ps->rowneruuid) ||
        nil_uuid(&doxm->rowneruuid) || nil_uuid(&acl->rowneruuid) ||
        nil_uuid(&creds->rowneruuid) ||
        !oc_sec_find_cred(&ps->rowneruuid, device) ||
        !oc_sec_find_cred(&doxm->rowneruuid, device) ||
        !oc_sec_find_cred(&acl->rowneruuid, device) ||
        !oc_sec_find_cred(&creds->rowneruuid, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false\n");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil\n");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil\n");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil\n");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil\n");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil\n");
      }
      if (!oc_sec_find_cred(&ps->rowneruuid, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&doxm->rowneruuid, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&acl->rowneruuid, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid\n");
      }
      if (!oc_sec_find_cred(&creds->rowneruuid, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid\n");
      }
      OC_ERR("ERROR in SRESET\n\n");
#endif /* OC_DEBUG */
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  default:
    return false;
    break;
  }
  memmove(&pstat[device], ps, sizeof(oc_sec_pstat_t));
  return true;
pstat_state_error:
  return false;
}

oc_sec_pstat_t *
oc_sec_get_pstat(int device)
{
#ifdef OC_DEBUG
  dump_pstat_dos(&pstat[device]);
#endif /* OC_DEBUG */
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
  pstat[device].s = OC_DOS_RESET;
  oc_pstat_handle_state(&pstat[device], device);
}

void
oc_sec_encode_pstat(int device)
{
#ifdef OC_DEBUG
  dump_pstat_dos(&pstat[device]);
#endif /* OC_DEBUG */
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

static oc_event_callback_retval_t
dump_acl_post_otm(void *data)
{
  oc_sec_dump_acl((long)data);
  oc_sec_dump_unique_ids((long)data);
  return OC_EVENT_DONE;
}

bool
oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage, int device)
{
  bool transition_state = false;
  oc_sec_pstat_t ps;
  memcpy(&ps, &pstat[device], sizeof(oc_sec_pstat_t));

#ifdef OC_DEBUG
  if (!from_storage) {
    dump_pstat_dos(&ps);
  }
#endif /* OC_DEBUG */

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_OBJECT: {
      if (oc_string_len(rep->name) == 3 &&
          memcmp(oc_string(rep->name), "dos", 3) == 0) {
        oc_rep_t *dos = rep->value.object;
        while (dos != NULL) {
          switch (dos->type) {
          case OC_REP_INT: {
            if (oc_string_len(dos->name) == 1 &&
                oc_string(dos->name)[0] == 's') {
              ps.s = dos->value.integer;
              transition_state = true;
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
    case OC_REP_BOOL:
      if (from_storage && oc_string_len(rep->name) == 4 &&
          memcmp(oc_string(rep->name), "isop", 4) == 0) {
        ps.isop = rep->value.boolean;
      } else {
        return false;
      }
      break;
    case OC_REP_INT:
      if (from_storage && memcmp(oc_string(rep->name), "cm", 2) == 0) {
        ps.cm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "tm", 2) == 0) {
        ps.tm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "om", 2) == 0) {
        ps.om = rep->value.integer;
      } else if (from_storage && memcmp(oc_string(rep->name), "sm", 2) == 0) {
        ps.sm = rep->value.integer;
      } else {
        return false;
      }
      break;
    case OC_REP_STRING:
      if ((from_storage || (ps.s != OC_DOS_RFPRO && ps.s != OC_DOS_RFNOP)) &&
          oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &ps.rowneruuid);
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
  if (from_storage || valid_transition(device, ps.s)) {
    if (!from_storage && transition_state) {
      bool transition_success = oc_pstat_handle_state(&ps, device);
      if (transition_success && ps.s == OC_DOS_RFNOP && set_post_otm_acl) {
        oc_sec_set_post_otm_acl(device);
        oc_ri_add_timed_event_callback_ticks((void *)(long)device,
                                             &dump_acl_post_otm, 0);
        set_post_otm_acl = false;
      }
      return transition_success;
    }
    memcpy(&pstat[device], &ps, sizeof(oc_sec_pstat_t));
    return true;
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
