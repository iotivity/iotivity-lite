/*
// Copyright (c) 2018-2019 Intel Corporation
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
#include "oc_sp.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_pstat.h"
#include "oc_store.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_sp_t *sp;
static oc_sec_sp_t *sp_mfg_default;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_sp_t sp[OC_MAX_NUM_DEVICES];
static oc_sec_sp_t sp_mfg_default[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

#define OC_SP_BASELINE_OID "1.3.6.1.4.1.51414.0.0.1.0"
#define OC_SP_BLACK_OID "1.3.6.1.4.1.51414.0.0.2.0"
#define OC_SP_BLUE_OID "1.3.6.1.4.1.51414.0.0.3.0"
#define OC_SP_PURPLE_OID "1.3.6.1.4.1.51414.0.0.4.0"

void
oc_pki_set_security_profile(size_t device, oc_sp_types_t supported_profiles,
                            oc_sp_types_t current_profile, int mfg_credid)
{
  sp_mfg_default[device].supported_profiles |= supported_profiles;
  sp_mfg_default[device].current_profile = current_profile;
  sp_mfg_default[device].credid = mfg_credid;
  sp[device] = sp_mfg_default[device];
}

void
oc_sec_sp_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  sp = (oc_sec_sp_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sp_t));
  if (!sp) {
    oc_abort("Insufficient memory");
  }
  sp_mfg_default =
    (oc_sec_sp_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sp_t));
  if (!sp_mfg_default) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    sp_mfg_default[device].current_profile = OC_SP_BASELINE;
    sp_mfg_default[device].supported_profiles = OC_SP_BASELINE;
    sp_mfg_default[device].credid = -1;
  }
}

void
oc_sec_sp_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (sp) {
    free(sp);
  }
  if (sp_mfg_default) {
    free(sp_mfg_default);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_sp_default(size_t device)
{
  sp[device] = sp_mfg_default[device];
}

static oc_sp_types_t
string_to_sp(const char *sp_string)
{
  oc_sp_types_t sp = 0;
  if (strlen(sp_string) == strlen(OC_SP_BASELINE_OID) &&
      memcmp(OC_SP_BASELINE_OID, sp_string, strlen(OC_SP_BASELINE_OID)) == 0) {
    sp = OC_SP_BASELINE;
  } else if (strlen(sp_string) == strlen(OC_SP_BLACK_OID) &&
             memcmp(OC_SP_BLACK_OID, sp_string, strlen(OC_SP_BLACK_OID)) == 0) {
    sp = OC_SP_BLACK;
  } else if (strlen(sp_string) == strlen(OC_SP_BLUE_OID) &&
             memcmp(OC_SP_BLUE_OID, sp_string, strlen(OC_SP_BLUE_OID)) == 0) {
    sp = OC_SP_BLUE;
  } else if (strlen(sp_string) == strlen(OC_SP_PURPLE_OID) &&
             memcmp(OC_SP_PURPLE_OID, sp_string, strlen(OC_SP_PURPLE_OID)) ==
               0) {
    sp = OC_SP_PURPLE;
  }
  return sp;
}

bool
oc_sec_decode_sp(oc_rep_t *rep, size_t device)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s == OC_DOS_RFNOP) {
    return false;
  }
  while (rep != NULL) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_STRING:
      if (len == 14 &&
          memcmp("currentprofile", oc_string(rep->name), 14) == 0) {
        oc_sp_types_t current_profile =
          string_to_sp(oc_string(rep->value.string));
        if ((current_profile & sp[device].supported_profiles) == 0) {
          return false;
        }
        sp[device].current_profile = current_profile;
      }
      break;
    case OC_REP_STRING_ARRAY:
      if (len == 17 &&
          memcmp("supportedprofiles", oc_string(rep->name), 17) == 0) {
        oc_sp_types_t supported_profiles = 0;
        size_t profile;
        for (profile = 0;
             profile < oc_string_array_get_allocated_size(rep->value.array);
             profile++) {
          const char *p = oc_string_array_get_item(rep->value.array, profile);
          supported_profiles |= string_to_sp(p);
        }
        sp[device].supported_profiles = supported_profiles;
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

static const char *
sp_to_string(oc_sp_types_t sp_type)
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

void
oc_sec_encode_sp(size_t device, oc_interface_mask_t iface_mask, bool to_storage)
{
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_SP, device));
  }
  oc_rep_set_text_string(root, currentprofile,
                         sp_to_string(sp[device].current_profile));
  oc_rep_set_array(root, supportedprofiles);
  if ((sp[device].supported_profiles & OC_SP_BASELINE) != 0) {
    oc_rep_add_text_string(supportedprofiles, sp_to_string(OC_SP_BASELINE));
  }
  if ((sp[device].supported_profiles & OC_SP_BLACK) != 0) {
    oc_rep_add_text_string(supportedprofiles, sp_to_string(OC_SP_BLACK));
  }
  if ((sp[device].supported_profiles & OC_SP_BLUE) != 0) {
    oc_rep_add_text_string(supportedprofiles, sp_to_string(OC_SP_BLUE));
  }
  if ((sp[device].supported_profiles & OC_SP_PURPLE) != 0) {
    oc_rep_add_text_string(supportedprofiles, sp_to_string(OC_SP_PURPLE));
  }
  oc_rep_close_array(root, supportedprofiles);
  oc_rep_end_root_object();
}

oc_sec_sp_t *
oc_sec_get_sp(size_t device)
{
  return &sp[device];
}

void
get_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  switch (iface_mask) {
  case OC_IF_RW:
  case OC_IF_BASELINE: {
    oc_sec_encode_sp(request->resource->device, iface_mask, false);
    oc_send_response(request, OC_STATUS_OK);
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
    oc_send_response(request, OC_STATUS_CHANGED);
    request->response->response_buffer->response_length = 0;
    oc_sec_dump_sp(device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

#endif /* OC_SECURITY */
