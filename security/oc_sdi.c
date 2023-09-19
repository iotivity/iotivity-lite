/****************************************************************************
 *
 * Copyright (c) 2020, Beijing OPPO telecommunications corp., ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_sdi_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_pstat_internal.h"
#include "oc_store.h"
#include "port/oc_assert.h"
#include "port/oc_log_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <stdlib.h>

#define OCF_SEC_SDI_PROP_UUID "uuid"
#define OCF_SEC_SDI_PROP_NAME "name"
#define OCF_SEC_SDI_PROP_PRIV "priv"

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_sdi_t *g_sdi = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_sdi_t g_sdi[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_sdi_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_sdi =
    (oc_sec_sdi_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sdi_t));
  if (g_sdi == NULL) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_sdi_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_sdi == NULL) {
    return;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    oc_free_string(&(g_sdi[device].name));
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(g_sdi);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_sdi_default(size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  assert(g_sdi != NULL);
#endif /* OC_DYNAMIC_ALLOCATION */
  g_sdi[device].priv = false;
  memset(&(g_sdi[device].uuid), 0, sizeof(oc_uuid_t));
  oc_free_string(&g_sdi[device].name);
  oc_sec_dump_sdi(device);
}

void
oc_sec_sdi_copy(oc_sec_sdi_t *dst, const oc_sec_sdi_t *src)
{
  assert(src != NULL);
  assert(dst != NULL);

  if (dst == src) {
    return;
  }

  dst->priv = src->priv;
  memcpy(&dst->uuid, &src->uuid, sizeof(src->uuid));
  oc_copy_string(&dst->name, &src->name);
}

void
oc_sec_sdi_clear(oc_sec_sdi_t *sdi)
{
  assert(sdi != NULL);
  sdi->priv = false;
  memset(&sdi->uuid, 0, sizeof(sdi->uuid));
  oc_free_string(&sdi->name);
}

typedef struct sdi_decode_data_t
{
  const oc_string_t *uuid;
  const oc_string_t *name;
  bool priv;
  bool priv_found;
} sdi_decode_data_t;

static bool
sdi_decode_string_property(const oc_rep_t *rep, oc_dostype_t state,
                           bool from_storage, sdi_decode_data_t *data)
{
  assert(rep->type == OC_REP_STRING);

  if (oc_rep_is_property(rep, OCF_SEC_SDI_PROP_UUID,
                         OC_CHAR_ARRAY_LEN(OCF_SEC_SDI_PROP_UUID))) {
    if (!from_storage && state != OC_DOS_RFOTM) {
      OC_ERR("oc_sdi: Can set uuid property only in RFOTM");
      return false;
    }
    if (oc_string_len(rep->value.string) < OC_UUID_LEN - 1) {
      OC_ERR("oc_sdi: Invalid uuid %s", oc_string(rep->value.string));
      return false;
    }
    data->uuid = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OCF_SEC_SDI_PROP_NAME,
                         OC_CHAR_ARRAY_LEN(OCF_SEC_SDI_PROP_NAME))) {
    if (!from_storage && state != OC_DOS_RFOTM && state != OC_DOS_RFPRO &&
        state != OC_DOS_SRESET) {
      OC_ERR("oc_sdi: Can't set name property in pstate %d", state);
      return false;
    }

    data->name = &rep->value.string;
    return true;
  }

  OC_ERR("oc_sdi: Unknown property %s", oc_string(rep->name));
  return true;
}

static bool
sdi_decode_bool_property(const oc_rep_t *rep, oc_dostype_t state,
                         bool from_storage, sdi_decode_data_t *data)
{
  assert(rep->type == OC_REP_BOOL);

  if (oc_rep_is_property(rep, OCF_SEC_SDI_PROP_PRIV,
                         OC_CHAR_ARRAY_LEN(OCF_SEC_SDI_PROP_PRIV))) {
    if (!from_storage && state != OC_DOS_RFOTM && state != OC_DOS_RFPRO &&
        state != OC_DOS_SRESET) {
      OC_ERR("oc_sdi: Can't set priv property in pstate %d", state);
      return false;
    }

    data->priv = rep->value.boolean;
    data->priv_found = true;
    return true;
  }

  OC_ERR("oc_sdi: Unknown property %s", oc_string(rep->name));
  return true;
}

bool
oc_sec_sdi_decode_with_state(const oc_rep_t *rep, oc_dostype_t state,
                             bool from_storage, oc_sec_sdi_t *sdi)
{
  assert(sdi != NULL);

  sdi_decode_data_t sdi_data;
  memset(&sdi_data, 0, sizeof(sdi_data));
  for (; rep != NULL; rep = rep->next) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (!sdi_decode_string_property(rep, state, from_storage, &sdi_data)) {
        return false;
      }
      break;
    case OC_REP_BOOL:
      if (!sdi_decode_bool_property(rep, state, from_storage, &sdi_data)) {
        return false;
      }
      break;
    default:
      OC_ERR("oc_sdi: Unknown type, property %s", oc_string(rep->name));
      break;
    }
  }

  if (sdi_data.uuid == NULL && sdi_data.name == NULL && !sdi_data.priv_found) {
    OC_DBG("no sdi property found");
    return false;
  }

  if (sdi_data.uuid != NULL) {
    oc_str_to_uuid(oc_string(*sdi_data.uuid), &sdi->uuid);
  }
  if (sdi_data.name != NULL) {
    oc_free_string(&sdi->name);
    if (oc_string_len(*sdi_data.name) > 0) {
      oc_new_string(&sdi->name, oc_string(*sdi_data.name),
                    oc_string_len(*sdi_data.name));
    }
  }
  if (sdi_data.priv_found) {
    sdi->priv = sdi_data.priv;
  }
  return true;
}

bool
oc_sec_sdi_decode(size_t device, const oc_rep_t *rep, bool from_storage)
{
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  return oc_sec_sdi_decode_with_state(rep, ps->s, from_storage,
                                      oc_sec_sdi_get(device));
}

int
oc_sec_sdi_encode_with_resource(const oc_sec_sdi_t *sdi,
                                const oc_resource_t *sdi_res,
                                oc_interface_mask_t iface_mask)
{
  assert(oc_rep_get_cbor_errno() == CborNoError);
  assert(sdi != NULL);

  oc_rep_start_root_object();
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    assert(sdi_res != NULL);
    oc_process_baseline_interface(sdi_res);
  }

  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(&sdi->uuid, uuid, sizeof(uuid));
  oc_rep_set_text_string(root, uuid, uuid);

  oc_rep_set_text_string(root, name, oc_string(sdi->name));

  oc_rep_set_boolean(root, priv, sdi->priv);

  oc_rep_end_root_object();

  return oc_rep_get_cbor_errno();
}

int
oc_sec_sdi_encode(size_t device, oc_interface_mask_t iface_mask)
{
  const oc_sec_sdi_t *sdi = oc_sec_sdi_get(device);
  const oc_resource_t *sdi_res = NULL;
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    sdi_res = oc_core_get_resource_by_index(OCF_SEC_SDI, device);
  }
  return oc_sec_sdi_encode_with_resource(sdi, sdi_res, iface_mask);
}

oc_sec_sdi_t *
oc_sec_sdi_get(size_t device)
{
  return &g_sdi[device];
}

static void
sdi_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data)
{
  (void)data;
  int err = oc_sec_sdi_encode(request->resource->device, iface_mask);
  if (err != CborNoError) {
    OC_ERR("oc_sdi: cannot encode GET request data(error=%d)", err);
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

static void
sdi_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device = request->resource->device;
  if (!oc_sec_sdi_decode(device, request->request_payload, false)) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }
  oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
  oc_sec_dump_sdi(device);
}

void
oc_sec_sdi_create_resource(size_t device)
{
  oc_core_populate_resource(
    OCF_SEC_SDI, device, OCF_SEC_SDI_URI, OCF_SEC_SDI_IF_MASK,
    OCF_SEC_SDI_DEFAULT_IF, OC_DISCOVERABLE | OC_SECURE, sdi_resource_get,
    /*put*/ NULL, sdi_resource_post, /*delete*/ NULL, 1, OCF_SEC_SDI_RT);
}

#endif /* OC_SECURITY */
