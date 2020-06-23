/*
// Copyright (c) 2016-2019 Intel Corporation
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
#include "api/cloud/oc_cloud_internal.h"
#include "api/oc_main.h"
#include "messaging/coap/observe.h"
#include "oc_acl_internal.h"
#include "oc_ael.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm.h"
#include "oc_roles.h"
#include "oc_sdi.h"
#include "oc_sp.h"
#include "oc_store.h"
#include "oc_tls.h"
#ifdef OC_COLLECTIONS_IF_CREATE
#include "api/oc_resource_factory.h"
#endif /* OC_COLLECTIONS_IF_CREATE */

#ifdef OC_SOFTWARE_UPDATE
#include "api/oc_swupdate_internal.h"
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_pstat_t *pstat;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_pstat_t pstat[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_pstat_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (pstat) {
    free(pstat);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

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
    OC_DBG("oc_pstat: dos is RESET");
    break;
  case OC_DOS_RFOTM:
    OC_DBG("oc_pstat: dos is RFOTM");
    break;
  case OC_DOS_RFPRO:
    OC_DBG("oc_pstat: dos is RFPRO");
    break;
  case OC_DOS_RFNOP:
    OC_DBG("oc_pstat: dos is RFNOP");
    break;
  case OC_DOS_SRESET:
    OC_DBG("oc_pstat: dos is SRESET");
    break;
  }
}
#endif /* OC_DEBUG */

static bool
valid_transition(size_t device, oc_dostype_t state)
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

static bool
oc_pstat_handle_state(oc_sec_pstat_t *ps, size_t device, bool from_storage,
                      bool self_reset)
{
  OC_DBG("oc_pstat: Entering pstat_handle_state");
  oc_sec_acl_t *acl = oc_sec_get_acl(device);
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  switch (ps->s) {
  case OC_DOS_RESET: {
    ps->p = true;
    ps->isop = false;
    ps->cm = 1;
    ps->tm = 2;
    ps->om = 3;
    ps->sm = 4;
#ifdef OC_SERVER
#ifdef OC_CLIENT
#ifdef OC_CLOUD
    oc_cloud_reset_context(device);
#endif /* OC_CLOUD */
#endif /* OC_CLIENT */
#endif /* OC_SERVER */
    memset(ps->rowneruuid.id, 0, 16);
    oc_sec_doxm_default(device);
    oc_sec_cred_default(device);
    oc_sec_acl_default(device);
    oc_sec_ael_default(device);
    oc_sec_sdi_default(device);
    if (!from_storage && oc_get_con_res_announced()) {
      oc_device_info_t *di = oc_core_get_device_info(device);
      oc_free_string(&di->name);
    }
#ifdef OC_PKI
    oc_sec_free_roles_for_device(device);
#endif /* OC_PKI */
    oc_sec_sp_default(device);
#ifdef OC_SERVER
#if defined(OC_COLLECTIONS) && defined(OC_COLLECTIONS_IF_CREATE)
    oc_rt_factory_free_created_resources(device);
#endif /* OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */
    coap_remove_observers_on_dos_change(device, true);
#endif /* OC_SERVER */
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
        OC_ERR("non-Nil doxm:devowneruuid in RFOTM");
      }
      OC_ERR("ERROR in RFOTM\n");
#endif /* OC_DEBUG */
      goto pstat_state_error;
    }
    oc_factory_presets_t *fp = oc_get_factory_presets_cb();
    if (fp->cb != NULL) {
      if (self_reset) {
        oc_close_all_tls_sessions_for_device(device);
      }
      memcpy(&pstat[device], ps, sizeof(oc_sec_pstat_t));
      OC_DBG("oc_pstat: invoking the factory presets callback");
      fp->cb(device, fp->data);
      OC_DBG("oc_pstat: returned from the factory presets callback");
      memcpy(ps, &pstat[device], sizeof(oc_sec_pstat_t));
    }
    coap_status_code = CLOSE_ALL_TLS_SESSIONS;
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
        !oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil");
      }
      if (!oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid");
      }
      OC_ERR("ERROR in RFPRO\n");
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
        !oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil");
      }
      if (!oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid");
      }
      OC_ERR("ERROR in RFNOP\n");
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
        !oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device) ||
        !oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
#ifdef OC_DEBUG
      if (!doxm->owned) {
        OC_ERR("doxm:owned is false");
      }
      if (nil_uuid(&doxm->devowneruuid)) {
        OC_ERR("doxm:devowneruuid is nil");
      }
      if (nil_uuid(&doxm->deviceuuid)) {
        OC_ERR("doxm:deviceuuid is nil");
      }
      if (nil_uuid(&ps->rowneruuid)) {
        OC_ERR("pstat:rowneruuid is nil");
      }
      if (nil_uuid(&doxm->rowneruuid)) {
        OC_ERR("doxm:rowneruuid is nil");
      }
      if (nil_uuid(&acl->rowneruuid)) {
        OC_ERR("acl2:rowneruuid is nil");
      }
      if (nil_uuid(&creds->rowneruuid)) {
        OC_ERR("cred:rowneruuid is nil");
      }
      if (!oc_sec_find_creds_for_subject(&ps->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for pstat:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&doxm->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for doxm:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&acl->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for acl2:rowneruuid");
      }
      if (!oc_sec_find_creds_for_subject(&creds->rowneruuid, NULL, device)) {
        OC_ERR("Could not find credential for cred:rowneruuid");
      }
      OC_ERR("ERROR in SRESET\n");
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
#ifdef OC_SERVER
  if (ps->s == OC_DOS_RFNOP) {
    coap_remove_observers_on_dos_change(device, false);
  }
#endif /* OC_SERVER */
  OC_DBG("oc_pstat: leaving pstat_handle_state");
  return true;
pstat_state_error:
  OC_DBG("oc_pstat: leaving pstat_handle_state");
  return false;
}

oc_sec_pstat_t *
oc_sec_get_pstat(size_t device)
{
#ifdef OC_DEBUG
  dump_pstat_dos(&pstat[device]);
#endif /* OC_DEBUG */
  return &pstat[device];
}

bool
oc_sec_is_operational(size_t device)
{
  return pstat[device].isop;
}

void
oc_sec_pstat_default(size_t device)
{
  oc_sec_pstat_t ps = { .s = OC_DOS_RESET };
  oc_pstat_handle_state(&ps, device, true, false);
  oc_sec_dump_pstat(device);
}

void
oc_sec_encode_pstat(size_t device, oc_interface_mask_t iface_mask,
                    bool to_storage)
{
#ifdef OC_DEBUG
  dump_pstat_dos(&pstat[device]);
#endif /* OC_DEBUG */
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_PSTAT, device));
  }
  oc_rep_set_object(root, dos);
  oc_rep_set_boolean(dos, p, pstat[device].p);
  oc_rep_set_int(dos, s, pstat[device].s);
  oc_rep_close_object(root, dos);
  oc_rep_set_int(root, cm, pstat[device].cm);
  oc_rep_set_int(root, tm, pstat[device].tm);
  oc_rep_set_int(root, om, pstat[device].om);
  oc_rep_set_int(root, sm, pstat[device].sm);
  oc_rep_set_boolean(root, isop, pstat[device].isop);
  oc_uuid_to_str(&pstat[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

#ifdef OC_SOFTWARE_UPDATE
static void
oc_pstat_handle_target_mode(size_t device, oc_dpmtype_t *tm)
{
  if (*tm == OC_DPM_NSA) {
    oc_swupdate_perform_action(OC_SWUPDATE_ISAC, device);
    *tm = 0;
  } else if (*tm == OC_DPM_SVV) {
    oc_swupdate_perform_action(OC_SWUPDATE_ISVV, device);
    *tm = 0;
  } else if (*tm == OC_DPM_SSV) {
    oc_swupdate_perform_action(OC_SWUPDATE_UPGRADE, device);
    *tm = 0;
  }
}

void
oc_sec_pstat_set_current_mode(size_t device, oc_dpmtype_t cm)
{
  oc_sec_pstat_t *ps = &pstat[device];
  ps->cm = cm;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SEC_PSTAT, device));
#endif /* OC_SERVER */
}
#endif /* OC_SOFTWARE_UPDATE */

bool
oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage, size_t device)
{
  bool transition_state = false, target_mode = false;
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
        ps.cm = (int)rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "tm", 2) == 0) {
        target_mode = true;
        ps.tm = (int)rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "om", 2) == 0) {
        ps.om = (int)rep->value.integer;
      } else if (from_storage && memcmp(oc_string(rep->name), "sm", 2) == 0) {
        ps.sm = (int)rep->value.integer;
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
  (void)target_mode;
#ifdef OC_SOFTWARE_UPDATE
  if (target_mode) {
    oc_pstat_handle_target_mode(device, &ps.tm);
  }
#endif /* OC_SOFTWARE_UPDATE */
  if (from_storage || valid_transition(device, ps.s)) {
    if (!from_storage && transition_state) {
      bool transition_success =
        oc_pstat_handle_state(&ps, device, from_storage, false);
      return transition_success;
    }
    memcpy(&pstat[device], &ps, sizeof(oc_sec_pstat_t));
    return true;
  }
  return false;
}

void
get_pstat(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  switch (iface_mask) {
  case OC_IF_RW:
  case OC_IF_BASELINE: {
    oc_sec_encode_pstat(request->resource->device, iface_mask, false);
    oc_send_response(request, OC_STATUS_OK);
  } break;
  default:
    break;
  }
}

void
post_pstat(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device = request->resource->device;
  if (oc_sec_decode_pstat(request->request_payload, false, device)) {
    request->response->response_buffer->response_length = 0;
    oc_send_response(request, OC_STATUS_CHANGED);
    request->response->response_buffer->response_length = 0;
    oc_sec_dump_pstat(device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

bool
oc_pstat_reset_device(size_t device, bool self_reset)
{
  oc_sec_pstat_t ps = { .s = OC_DOS_RESET };
  bool ret = oc_pstat_handle_state(&ps, device, false, self_reset);
  oc_sec_dump_pstat(device);
  return ret;
}

void
oc_reset_device(size_t device)
{
  oc_pstat_reset_device(device, true);
}

void
oc_reset()
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_pstat_reset_device(device, true);
  }
}
#endif /* OC_SECURITY */
