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

#include "oc_pstat.h"
#include "api/oc_buffer_internal.h"
#include "api/oc_main.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/observe.h"
#include "oc_acl_internal.h"
#include "oc_ael.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm_internal.h"
#include "oc_keypair_internal.h"
#include "oc_roles_internal.h"
#include "oc_sdi_internal.h"
#include "oc_sp_internal.h"
#include "oc_store.h"
#include "oc_tls_internal.h"
#include "port/oc_assert.h"

#ifdef OC_CLOUD
#include "api/cloud/oc_cloud_internal.h"
#endif /* OC_CLOUD */

#ifdef OC_COLLECTIONS_IF_CREATE
#include "api/oc_resource_factory.h"
#endif /* OC_COLLECTIONS_IF_CREATE */

#ifdef OC_SOFTWARE_UPDATE
#include "api/oc_swupdate_internal.h"
#endif /* OC_SOFTWARE_UPDATE */

#include <assert.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
static oc_sec_pstat_t *g_pstat = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_pstat_t g_pstat[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_pstat_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_pstat != NULL) {
    free(g_pstat);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_pstat_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_pstat =
    (oc_sec_pstat_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_pstat_t));
  if (!g_pstat) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

static bool
nil_uuid(const oc_uuid_t *uuid)
{
  for (size_t i = 0; i < sizeof(uuid->id); ++i) {
    if (uuid->id[i] != 0) {
      return false;
    }
  }
  return true;
}

#if OC_DBG_IS_ENABLED
static void
print_pstat_dos(const oc_sec_pstat_t *ps)
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
#endif /* OC_DBG_IS_ENABLED */

static bool
valid_transition(size_t device, oc_dostype_t state)
{
  switch (g_pstat[device].s) {
  case OC_DOS_RESET:
    if (state == OC_DOS_RESET || state == OC_DOS_RFOTM)
      return true;
    break;
  case OC_DOS_RFOTM:
    if (state == OC_DOS_SRESET)
      return false;
    break;
  case OC_DOS_RFPRO:
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

static oc_event_callback_retval_t
close_all_tls_sessions(void *data)
{
  size_t device = (size_t)data;
  oc_close_all_tls_sessions_for_device(device);
  oc_set_drop_commands(device, false);
  if (coap_global_status_code() == CLOSE_ALL_TLS_SESSIONS) {
    coap_set_global_status_code(COAP_NO_ERROR);
  }
  return OC_EVENT_DONE;
}

static bool
pstat_check_ps_state(const oc_sec_pstat_t *ps)
{
  switch (ps->s) {
  case OC_DOS_RFPRO:
    if (ps->isop || (ps->cm & 0xC3) != 0 || (ps->tm & 0xC3) != 0) {
      return false;
    }
    break;
  case OC_DOS_RFNOP:
    if (!ps->isop || (ps->cm & 0xC3) != 0 || (ps->tm & 0xC3) != 0) {
      return false;
    }
    break;
  case OC_DOS_SRESET:
    if (ps->isop || ps->cm != 1 || (ps->tm & 0xC3)) {
      return false;
    }
    break;
  case OC_DOS_RESET:
  case OC_DOS_RFOTM:
    if (ps->isop || (ps->cm & 0xC3) != 2 || (ps->tm & 0xC3) != 0) {
      return false;
    }
    break;
  default:
    break;
  }

  return true;
}

static bool
pstat_check_state(const oc_sec_pstat_t *ps, size_t device)
{
  if (!pstat_check_ps_state(ps)) {
    OC_DBG("pstat:invalid state");
    return false;
  }

  if (nil_uuid(&ps->rowneruuid)) {
    OC_DBG("pstat:rowneruuid is nil");
    return false;
  }
  if (!oc_sec_find_creds_for_subject(NULL, &ps->rowneruuid, device)) {
    OC_DBG("Could not find credential for pstat:rowneruuid");
    return false;
  }

  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  if (!doxm->owned) {
    OC_DBG("doxm:owned is false");
    return false;
  }
  if (nil_uuid(&doxm->devowneruuid)) {
    OC_DBG("doxm:devowneruuid is nil");
    return false;
  }
  if (nil_uuid(&doxm->deviceuuid)) {
    OC_DBG("doxm:deviceuuid is nil");
    return false;
  }
  if (nil_uuid(&doxm->rowneruuid)) {
    OC_DBG("doxm:rowneruuid is nil");
    return false;
  }
  if (!oc_sec_find_creds_for_subject(NULL, &doxm->rowneruuid, device)) {
    OC_DBG("Could not find credential for doxm:rowneruuid");
    return false;
  }

  const oc_sec_acl_t *acl = oc_sec_get_acl(device);
  if (nil_uuid(&acl->rowneruuid)) {
    OC_DBG("acl2:rowneruuid is nil");
    return false;
  }
  if (!oc_sec_find_creds_for_subject(NULL, &acl->rowneruuid, device)) {
    OC_DBG("Could not find credential for acl2:rowneruuid");
    return false;
  }

  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  if (nil_uuid(&creds->rowneruuid)) {
    OC_DBG("cred:rowneruuid is nil");
    return false;
  }
  if (!oc_sec_find_creds_for_subject(NULL, &creds->rowneruuid, device)) {
    OC_DBG("Could not find credential for cred:rowneruuid");
    return false;
  }

  return true;
}

static bool
oc_pstat_handle_state(oc_sec_pstat_t *ps, size_t device, bool from_storage,
                      bool close_all_tls_connections_immediately)
{
  OC_DBG("oc_pstat: Entering pstat_handle_state");
  switch (ps->s) {
  case OC_DOS_RESET: {
    ps->p = true;
    ps->isop = false;
    ps->cm = 1;
    ps->tm = 2;
    ps->om = 3;
    ps->sm = 4;
#if defined(OC_SERVER) && defined(OC_CLIENT) && defined(OC_CLOUD)
    cloud_reset(device, true, 0);
    // TODO: we can allow async mode, but handling of OC_DOS_RESET that follows
    // the reset call must be invoked asynchronously in a callback after
    // cloud_reset finishes. Otherwise the cloud_reset won't execute correctly.
#endif /* OC_SERVER && OC_CLIENT && OC_CLOUD */
    memset(ps->rowneruuid.id, 0, 16);
    oc_sec_doxm_default(device);
    oc_sec_cred_default(device);
    oc_sec_acl_default(device);
    oc_sec_ael_default(device);
    oc_sec_sdi_default(device);
    if (!from_storage && oc_get_con_res_announced()) {
#if OC_WIPE_NAME
      oc_device_info_t *di = oc_core_get_device_info(device);
      oc_free_string(&di->name);
#endif /* OC_WIPE_NAME */

      oc_resource_t *oic_d = oc_core_get_resource_by_index(OCF_D, device);
      oc_locn_t oc_locn = oic_d->tag_locn;
      if (oc_locn > 0) {
        oc_resource_tag_locn(oic_d, OCF_LOCN_UNKNOWN);
      }
    }
#ifdef OC_PKI
    oc_sec_free_roles_for_device(device);
    // regenerate the key-pair for the identity device certificate.
    if (oc_sec_ecdsa_reset_keypair(device, true) < 0) {
      goto pstat_state_error;
    }
#endif /* OC_PKI */
    oc_sec_sp_default(device);
#ifdef OC_SERVER
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
    const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
    if (doxm->owned || !nil_uuid(&doxm->devowneruuid) ||
        !pstat_check_ps_state(ps)) {
#if OC_DBG_IS_ENABLED
      if (!nil_uuid(&doxm->devowneruuid)) {
        OC_DBG("non-Nil doxm:devowneruuid in RFOTM");
      }
      OC_DBG("ERROR in RFOTM\n");
#endif /* OC_DBG_IS_ENABLED */
      goto pstat_state_error;
    }
    oc_factory_presets_t *fp = oc_get_factory_presets_cb();
    coap_status_t status_code = COAP_NO_ERROR;
    if (close_all_tls_connections_immediately) {
      oc_remove_delayed_callback((void *)device, close_all_tls_sessions);
      oc_close_all_tls_sessions_for_device(device);
      oc_set_drop_commands(device, false);
    } else if (!from_storage) {
      // The request comes from oc_reset_v1 or API, so we must close all TLS
      // after a delay so the response can be sent.
      status_code = CLOSE_ALL_TLS_SESSIONS;
      oc_remove_delayed_callback((void *)device, close_all_tls_sessions);
      oc_set_delayed_callback((void *)device, close_all_tls_sessions, 2);
      // Don't accept any commands GET, POST, PUT, DELETE until all TLS sessions
      // are closed
      oc_set_drop_commands(device, true);
    }
    if (fp->cb != NULL) {
      oc_sec_pstat_copy(&g_pstat[device], ps);
      OC_DBG("oc_pstat: invoking the factory presets callback");
      fp->cb(device, fp->data);
      OC_DBG("oc_pstat: returned from the factory presets callback");
      oc_sec_pstat_copy(ps, &g_pstat[device]);
    }
    coap_set_global_status_code(status_code);
    ps->p = false;
  } break;
  case OC_DOS_RFPRO: {
    ps->p = true;
    ps->cm = 0;
    ps->tm = 0;
    ps->isop = false;
    if (!pstat_check_state(ps, device)) {
      OC_DBG("ERROR in RFPRO\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_RFNOP: {
    ps->p = true;
    ps->cm = 0;
    ps->tm = 0;
    ps->isop = true;
    if (!pstat_check_state(ps, device)) {
      OC_DBG("ERROR in RFNOP\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  case OC_DOS_SRESET: {
    ps->p = true;
    ps->cm = 1;
    ps->tm = 0;
    ps->isop = false;
    if (!pstat_check_state(ps, device)) {
      OC_DBG("ERROR in SRESET\n");
      goto pstat_state_error;
    }
    ps->p = false;
  } break;
  default:
    return false;
    break;
  }
  oc_sec_pstat_copy(&g_pstat[device], ps);
#ifdef OC_SERVER
  switch (ps->s) {
  case OC_DOS_RESET:
  case OC_DOS_RFOTM:
#if defined(OC_COLLECTIONS) && defined(OC_COLLECTIONS_IF_CREATE)
    oc_rt_factory_free_created_resources(device);
#endif /* OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */
    break;
  case OC_DOS_RFNOP:
    coap_remove_observers_on_dos_change(device, false);
    break;
  default:
    break;
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
#if OC_DBG_IS_ENABLED
  print_pstat_dos(&g_pstat[device]);
#endif /* OC_DBG_IS_ENABLED */
  return &g_pstat[device];
}

bool
oc_sec_is_operational(size_t device)
{
  return g_pstat[device].isop;
}

void
oc_sec_pstat_default(size_t device)
{
  oc_sec_pstat_t ps = { .s = OC_DOS_RESET };
  oc_pstat_handle_state(&ps, device, true, false);
  oc_sec_dump_pstat(device);
}

void
oc_sec_pstat_copy(oc_sec_pstat_t *dst, const oc_sec_pstat_t *src)
{
  assert(src != NULL);
  assert(dst != NULL);

  if (dst == src) {
    return;
  }

  dst->s = src->s;
  dst->p = src->p;
  dst->isop = src->isop;
  dst->cm = src->cm;
  dst->tm = src->tm;
  dst->om = src->om;
  dst->sm = src->sm;
  memcpy(&dst->rowneruuid.id, src->rowneruuid.id, sizeof(src->rowneruuid.id));
}

void
oc_sec_pstat_clear(oc_sec_pstat_t *ps)
{
  assert(ps != NULL);
  memset(ps, 0, sizeof(*ps));
}

void
oc_sec_encode_pstat(size_t device, oc_interface_mask_t iface_mask,
                    bool to_storage)
{
#if OC_DBG_IS_ENABLED
  print_pstat_dos(&g_pstat[device]);
#endif /* OC_DBG_IS_ENABLED */
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_PSTAT, device));
  }
  oc_rep_set_object(root, dos);
  oc_rep_set_boolean(dos, p, g_pstat[device].p);
  oc_rep_set_int(dos, s, g_pstat[device].s);
  oc_rep_close_object(root, dos);
  oc_rep_set_int(root, cm, g_pstat[device].cm);
  oc_rep_set_int(root, tm, g_pstat[device].tm);
  oc_rep_set_int(root, om, g_pstat[device].om);
  oc_rep_set_int(root, sm, g_pstat[device].sm);
  oc_rep_set_boolean(root, isop, g_pstat[device].isop);
  oc_uuid_to_str(&g_pstat[device].rowneruuid, uuid, OC_UUID_LEN);
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
  oc_sec_pstat_t *ps = &g_pstat[device];
  ps->cm = cm;
#ifdef OC_SERVER
  oc_notify_observers(oc_core_get_resource_by_index(OCF_SEC_PSTAT, device));
#endif /* OC_SERVER */
}
#endif /* OC_SOFTWARE_UPDATE */

bool
oc_sec_decode_pstat(const oc_rep_t *rep, bool from_storage, size_t device)
{
  oc_sec_pstat_t ps;
  oc_sec_pstat_copy(&ps, &g_pstat[device]);
#if OC_DBG_IS_ENABLED
  if (!from_storage) {
    print_pstat_dos(&ps);
  }
#endif /* OC_DBG_IS_ENABLED */

  bool transition_state = false;
  bool target_mode = false;
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
    oc_sec_pstat_copy(&g_pstat[device], &ps);
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
    oc_send_response_with_callback(request, OC_STATUS_OK, true);
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
    oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
    request->response->response_buffer->response_length = 0;
    oc_sec_dump_pstat(device);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
  }
}

bool
oc_pstat_reset_device(size_t device, bool close_all_tls_connections_immediately)
{
  oc_sec_pstat_t ps = { .s = OC_DOS_RESET };
  bool ret = oc_pstat_handle_state(&ps, device, false,
                                   close_all_tls_connections_immediately);
  oc_sec_dump_pstat(device);
  return ret;
}

void
oc_reset_device(size_t device)
{
  oc_pstat_reset_device(device, true);
}

bool
oc_reset_device_v1(size_t device, bool close_all_tls_connections_immediately)
{
  return oc_pstat_reset_device(device, close_all_tls_connections_immediately);
}

void
oc_reset_v1(bool close_all_tls_connections_immediately)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_reset_device_v1(device, close_all_tls_connections_immediately);
  }
}

void
oc_reset(void)
{
  oc_reset_v1(true);
}
#endif /* OC_SECURITY */
