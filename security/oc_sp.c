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

#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_sp.h"
#include "oc_sp_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_pstat_internal.h"
#include "oc_store.h"
#include "port/oc_assert.h"
#include "port/oc_log_internal.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

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

#ifdef OC_HAS_FEATURE_BRIDGE
void
oc_sec_sp_new_device(size_t device_index, bool need_realloc)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if ((device_index == (oc_core_get_num_devices() - 1)) && need_realloc) {
    g_sp = (oc_sec_sp_t *)realloc(g_sp, oc_core_get_num_devices() *
                                          sizeof(oc_sec_sp_t));
    if (!g_sp) {
      oc_abort("Insufficient memory");
    }

    g_sp_mfg_default = (oc_sec_sp_t *)realloc(
      g_sp_mfg_default, oc_core_get_num_devices() * sizeof(oc_sec_sp_t));
    if (!g_sp_mfg_default) {
      oc_abort("Insufficient memory");
    }
  }

  memset(&g_sp[device_index], 0, sizeof(oc_sec_sp_t));
  memset(&g_sp_mfg_default[device_index], 0, sizeof(oc_sec_sp_t));

  g_sp_mfg_default[device_index].current_profile = OC_SP_BASELINE;
  g_sp_mfg_default[device_index].supported_profiles = OC_SP_BASELINE;
  g_sp_mfg_default[device_index].credid = -1;

#endif /* OC_DYNAMIC_ALLOCATION */
}
#endif /* OC_HAS_FEATURE_BRIDGE */

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
  oc_sec_dump_sp(device);
}

oc_sec_sp_t *
oc_sec_sp_get(size_t device)
{
  return &g_sp[device];
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
oc_sec_sp_decode(const oc_rep_t *rep, int flags, oc_sec_sp_t *dst)
{
#define OC_SEC_SP_PROP_CURRENTPROFILE "currentprofile"
#define OC_SEC_SP_PROP_SUPPORTEDPROFILES "supportedprofiles"

  const oc_string_t *currentprofile = NULL;
  const oc_array_t *supportedprofiles = NULL;
  for (; rep != NULL; rep = rep->next) {
    if (oc_rep_is_property_with_type(
          rep, OC_REP_STRING, OC_SEC_SP_PROP_CURRENTPROFILE,
          OC_CHAR_ARRAY_LEN(OC_SEC_SP_PROP_CURRENTPROFILE))) {
      currentprofile = &rep->value.string;
      continue;
    }
    if (oc_rep_is_property_with_type(
          rep, OC_REP_STRING_ARRAY, OC_SEC_SP_PROP_SUPPORTEDPROFILES,
          OC_CHAR_ARRAY_LEN(OC_SEC_SP_PROP_SUPPORTEDPROFILES))) {
      supportedprofiles = &rep->value.array;
      continue;
    }

    if ((flags & OC_SEC_SP_DECODE_FLAG_IGNORE_UNKNOWN_PROPERTIES) == 0) {
      OC_ERR("oc_sp: unknown property (name=%s, type=%d)", oc_string(rep->name),
             (int)rep->type);
      return false;
    }
    OC_DBG("oc_sp: unknown property (name=%s, type=%d)", oc_string(rep->name),
           (int)rep->type);
  }

  if (supportedprofiles != NULL) {
    unsigned profiles = 0;
    for (size_t i = 0;
         i < oc_string_array_get_allocated_size(*supportedprofiles); ++i) {
      const char *p = oc_string_array_get_item(*supportedprofiles, i);
      oc_sp_types_t profile =
        oc_sec_sp_type_from_string(p, oc_strnlen(p, STRING_ARRAY_ITEM_MAX_LEN));
      if (profile == 0) {
        OC_ERR("oc_sp: invalid supportedprofiles item value([%zu]=%s)", i, p);
        return false;
      }
      profiles |= profile;
    }
    dst->supported_profiles = profiles;
  }

  if (currentprofile != NULL) {
    oc_sp_types_t profile = oc_sec_sp_type_from_string(
      oc_string(*currentprofile), oc_string_len(*currentprofile));
    if (profile == 0) {
      OC_ERR("oc_sp: invalid currentprofile value(%s)",
             oc_string(*currentprofile));
      return false;
    }
    if ((profile & dst->supported_profiles) == 0) {
      OC_ERR("oc_sp: currentprofile value(%s) not supported",
             oc_string(*currentprofile));
      return false;
    }
    dst->current_profile = profile;
  }

  return true;
}

bool
oc_sec_sp_decode_for_device(const oc_rep_t *rep, size_t device)
{
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s == OC_DOS_RFNOP) {
    return false;
  }
  return oc_sec_sp_decode(rep, 0, &g_sp[device]);
}

static bool
sp_encode_current_profile(oc_sp_types_t profile)
{
  oc_rep_set_text_string(root, currentprofile,
                         oc_sec_sp_type_to_string(profile));
  return g_err == 0;
}

static bool
sp_encode_supported_profiles(unsigned profiles)
{
  oc_rep_set_array(root, supportedprofiles);
  if ((profiles & OC_SP_BASELINE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BASELINE));
  }
  if ((profiles & OC_SP_BLACK) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BLACK));
  }
  if ((profiles & OC_SP_BLUE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_BLUE));
  }
  if ((profiles & OC_SP_PURPLE) != 0) {
    oc_rep_add_text_string(supportedprofiles,
                           oc_sec_sp_type_to_string(OC_SP_PURPLE));
  }
  oc_rep_close_array(root, supportedprofiles);
  return g_err == 0;
}

int
oc_sec_sp_encode_with_resource(const oc_sec_sp_t *sp,
                               const oc_resource_t *sp_res, int flags)
{
  assert(oc_rep_get_cbor_errno() == CborNoError);
  assert(sp != NULL);

  oc_rep_start_root_object();
  if ((flags & OC_SEC_SP_ENCODE_INCLUDE_BASELINE) != 0) {
    assert(sp_res != NULL);
    oc_process_baseline_interface(sp_res);
  }

  if (!sp_encode_current_profile(sp->current_profile)) {
    OC_ERR("oc_sp: failed to encode current_profile");
    return -1;
  }
  if (!sp_encode_supported_profiles(sp->supported_profiles)) {
    OC_ERR("oc_sp: failed to encode supported_profiles");
    return -1;
  }
  oc_rep_end_root_object();
  return g_err;
}

bool
oc_sec_sp_encode_for_device(size_t device, int flags)
{
  const oc_sec_sp_t *sp = oc_sec_sp_get(device);
  const oc_resource_t *sp_res = NULL;
  if ((flags & OC_SEC_SP_ENCODE_INCLUDE_BASELINE) != 0) {
    sp_res = oc_core_get_resource_by_index(OCF_SEC_SP, device);
  }
  return oc_sec_sp_encode_with_resource(sp, sp_res, flags) == 0;
}

static void
sp_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data)
{
  (void)data;
  oc_status_t code = OC_STATUS_BAD_REQUEST;
  switch (iface_mask) {
  case OC_IF_RW:
  case OC_IF_BASELINE:
    if (!oc_sec_sp_encode_for_device(request->resource->device,
                                     iface_mask == OC_IF_BASELINE
                                       ? OC_SEC_SP_ENCODE_INCLUDE_BASELINE
                                       : 0)) {

      code = OC_STATUS_INTERNAL_SERVER_ERROR;
      break;
    }
    code = OC_STATUS_OK;
    break;
  default:
    break;
  }
  oc_send_response_with_callback(request, code, true);
}

static void
sp_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device = request->resource->device;
  if (!oc_sec_sp_decode_for_device(request->request_payload, device)) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }
  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
  request->response->response_buffer->response_length = 0;
  oc_sec_dump_sp(device);
}

void
oc_sec_sp_create_resource(size_t device)
{
  oc_core_populate_resource(OCF_SEC_SP, device, OCF_SEC_SP_URI,
                            OCF_SEC_SP_IF_MASK, OCF_SEC_SP_DEFAULT_IF,
                            OC_DISCOVERABLE | OC_SECURE, sp_resource_get,
                            /*put*/ NULL, sp_resource_post,
                            /*delete*/ NULL, 1, OCF_SEC_SP_RT);
}

#endif /* OC_SECURITY */
