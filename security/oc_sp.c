/****************************************************************************
 *
 * Copyright (c) 2018-2019 Intel Corporation
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
#include "oc_sp.h"
#include "oc_sp_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_pstat.h"
#include "oc_store.h"
#include "port/oc_assert.h"
#include "util/oc_macros.h"

#include <assert.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
static oc_sec_sp_t *g_sp = NULL;
static oc_sec_sp_t *g_sp_mfg_default = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_sp_t g_sp[OC_MAX_NUM_DEVICES] = { 0 };
static oc_sec_sp_t g_sp_mfg_default[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_pki_set_security_profile(size_t device, unsigned supported_profiles,
                            oc_sp_types_t current_profile, int mfg_credid)
{
  g_sp_mfg_default[device].supported_profiles |= supported_profiles;
  g_sp_mfg_default[device].current_profile = current_profile;
  g_sp_mfg_default[device].credid = mfg_credid;
  g_sp[device] = g_sp_mfg_default[device];
}

void
oc_sec_sp_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_sp = (oc_sec_sp_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sp_t));
  if (!g_sp) {
    oc_abort("Insufficient memory");
  }
  g_sp_mfg_default =
    (oc_sec_sp_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sp_t));
  if (!g_sp_mfg_default) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    g_sp_mfg_default[device].current_profile = OC_SP_BASELINE;
    g_sp_mfg_default[device].supported_profiles = OC_SP_BASELINE;
    g_sp_mfg_default[device].credid = -1;
  }
}

void
oc_sec_sp_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_sp) {
    free(g_sp);
  }
  if (g_sp_mfg_default) {
    free(g_sp_mfg_default);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_sp_default(size_t device)
{
  g_sp[device] = g_sp_mfg_default[device];
}

void
oc_sec_sp_copy(oc_sec_sp_t *dst, const oc_sec_sp_t *src)
{
  assert(src != NULL);
  assert(dst != NULL);

  if (dst == src) {
    return;
  }

  dst->supported_profiles = src->supported_profiles;
  dst->current_profile = src->current_profile;
  dst->credid = src->credid;
}

void
oc_sec_sp_clear(oc_sec_sp_t *sp)
{
  assert(sp != NULL);
  memset(sp, 0, sizeof(*sp));
}

oc_sp_types_t
oc_sec_sp_type_from_string(const char *str, size_t str_len)
{
  if (str_len == OC_CHAR_ARRAY_LEN(OC_SP_BASELINE_OID) &&
      memcmp(OC_SP_BASELINE_OID, str, str_len) == 0) {
    return OC_SP_BASELINE;
  }
  if (str_len == OC_CHAR_ARRAY_LEN(OC_SP_BLACK_OID) &&
      memcmp(OC_SP_BLACK_OID, str, str_len) == 0) {
    return OC_SP_BLACK;
  }
  if (str_len == OC_CHAR_ARRAY_LEN(OC_SP_BLUE_OID) &&
      memcmp(OC_SP_BLUE_OID, str, str_len) == 0) {
    return OC_SP_BLUE;
  }
  if (str_len == OC_CHAR_ARRAY_LEN(OC_SP_PURPLE_OID) &&
      memcmp(OC_SP_PURPLE_OID, str, str_len) == 0) {
    return OC_SP_PURPLE;
  }
  return 0;
}

const char *
oc_sec_sp_type_to_string(oc_sp_types_t sp_type)
{
  switch (sp_type) {
  case OC_SP_BASELINE:
    return OC_SP_BASELINE_OID;
  case OC_SP_BLACK:
    return OC_SP_BLACK_OID;
  case OC_SP_BLUE:
    return OC_SP_BLUE_OID;
  case OC_SP_PURPLE:
    return OC_SP_PURPLE_OID;
  }
  return NULL;
}

bool
oc_sec_decode_sp(const oc_rep_t *rep, size_t device)
{
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s == OC_DOS_RFNOP) {
    return false;
  }
  while (rep != NULL) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_STRING:
      if (len == 14 &&
          memcmp("currentprofile", oc_string(rep->name), 14) == 0) {
        oc_sp_types_t current_profile = oc_sec_sp_type_from_string(
          oc_string(rep->value.string), oc_string_len(rep->value.string));
        if ((current_profile & g_sp[device].supported_profiles) == 0) {
          return false;
        }
        g_sp[device].current_profile = current_profile;
      }
      break;
    case OC_REP_STRING_ARRAY:
      if (len == 17 &&
          memcmp("supportedprofiles", oc_string(rep->name), 17) == 0) {
        unsigned supported_profiles = 0;
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); ++i) {
          const char *p = oc_string_array_get_item(rep->value.array, i);
          supported_profiles |= oc_sec_sp_type_from_string(p, strlen(p));
        }
        g_sp[device].supported_profiles = supported_profiles;
      }
      break;
    default:
      return false;
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
oc_sec_encode_sp(size_t device, oc_interface_mask_t iface_mask, bool to_storage)
{
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_SP, device));
  }
  oc_rep_set_text_string(
    root, currentprofile,
    oc_sec_sp_type_to_string(g_sp[device].current_profile));
  oc_rep_set_array(root, supportedprofiles);
  if ((g_sp[device].supported_profiles & OC_SP_BASELINE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BASELINE));
  }
  if ((g_sp[device].supported_profiles & OC_SP_BLACK) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BLACK));
  }
  if ((g_sp[device].supported_profiles & OC_SP_BLUE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BLUE));
  }
  if ((g_sp[device].supported_profiles & OC_SP_PURPLE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_PURPLE));
  }
  oc_rep_close_array(root, supportedprofiles);
  oc_rep_end_root_object();
}

oc_sec_sp_t *
oc_sec_get_sp(size_t device)
{
  return &g_sp[device];
}

void
get_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  switch (iface_mask) {
  case OC_IF_RW:
  case OC_IF_BASELINE: {
    oc_sec_encode_sp(request->resource->device, iface_mask, false);
    oc_send_response_with_callback(request, OC_STATUS_OK, true);
  } break;
  default:
    break;
  }
}

void
post_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device = request->resource->device;
  if (oc_sec_decode_sp(request->request_payload, device)) {
    oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
    request->response->response_buffer->response_length = 0;
    oc_sec_dump_sp(device);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
  }
}

#endif /* OC_SECURITY */
