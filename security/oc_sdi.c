/*
// Copyright (c) 2020, Beijing OPPO telecommunications corp., ltd.
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
#include "oc_sdi.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_pstat.h"
#include "oc_store.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_sdi_t *sdi;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_sdi_t sdi[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_sdi_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  sdi = (oc_sec_sdi_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_sdi_t));
  if (!sdi) {
    oc_abort("Insufficient memory");
  }
#endif
}

void
oc_sec_sdi_free(void)
{
  size_t device;

  if (!sdi) {
    return;
  }

  for (device = 0; device < oc_core_get_num_devices(); device++) {
    if (oc_string_len(sdi[device].name) > 0) {
      oc_free_string(&(sdi[device].name));
    }
  }

#ifdef OC_DYNAMIC_ALLOCATION
  if (sdi) {
    free(sdi);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_sdi_default(size_t device)
{
  if (!sdi) {
    return;
  }

  sdi[device].priv = false;
  memset(&(sdi[device].uuid), 0, sizeof(oc_uuid_t));
  if (oc_string_len(sdi[device].name) > 0) {
    oc_free_string(&sdi[device].name);
  }
  oc_sec_dump_sdi(device);
}

bool
oc_sec_decode_sdi(oc_rep_t *rep, bool from_storage, size_t device)
{
  bool suc = false;
  oc_sec_sdi_t *s = oc_sec_get_sdi(device);
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);

  while (rep != NULL) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_STRING:
      if (len == 4 && memcmp("uuid", oc_string(rep->name), 4) == 0) {

        if (!from_storage && ps->s != OC_DOS_RFOTM) {
          OC_ERR("oc_sdi: Can set uuid property only in RFOTM");
          return false;
        }

        oc_str_to_uuid(oc_string(rep->value.string), &s->uuid);
        suc = true;
      } else if (len == 4 && memcmp("name", oc_string(rep->name), 4) == 0) {

        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_RFPRO &&
            ps->s != OC_DOS_SRESET) {
          OC_ERR("oc_sdi: Can't set name property in pstate %d", ps->s);
          return false;
        }

        if (oc_string_len(s->name) > 0) {
          oc_free_string(&s->name);
        }
	if (oc_string_len(rep->value.string) > 0) {
	  oc_new_string(&s->name, oc_string(rep->value.string),
			oc_string_len(rep->value.string));
	}
        suc = true;
      } else {
        OC_ERR("oc_sdi: Unknown property %s", oc_string(rep->name));
      }
      break;
    case OC_REP_BOOL:
      if (len == 4 && memcmp(oc_string(rep->name), "priv", 4) == 0) {

        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_RFPRO &&
            ps->s != OC_DOS_SRESET) {
          OC_ERR("oc_sdi: Can't set priv property in pstate %d", ps->s);
          return false;
        }

        s->priv = rep->value.boolean;
        suc = true;
      } else {
        OC_ERR("oc_sdi: Unknown property %s", oc_string(rep->name));
      }
      break;
    default:
      OC_ERR("oc_sdi: Unknown type, property %s", oc_string(rep->name));
      break;
    }
    rep = rep->next;
  }
  return suc;
}

void
oc_sec_encode_sdi(size_t device, bool to_storage)
{
  char uuid[37];
  oc_sec_sdi_t *s = oc_sec_get_sdi(device);

  oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);

  if (to_storage) {
    oc_rep_start_root_object();
  }

  oc_rep_set_text_string(root, uuid, uuid);

  oc_rep_set_text_string(root, name, oc_string(s->name));

  oc_rep_set_boolean(root, priv, s->priv);

  if (to_storage) {
    oc_rep_end_root_object();
  }
}

oc_sec_sdi_t *
oc_sec_get_sdi(size_t device)
{
  return &sdi[device];
}

void
get_sdi(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  switch (iface_mask) {
  case OC_IF_BASELINE: {

    oc_rep_start_root_object();

    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_SDI, request->resource->device));
    oc_sec_encode_sdi(request->resource->device, false);

    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_OK);
  } break;
  case OC_IF_RW: {
    oc_sec_encode_sdi(request->resource->device, true);
    oc_send_response(request, OC_STATUS_OK);
  } break;
  default:
    break;
  }
}

void
post_sdi(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device = request->resource->device;
  if (oc_sec_decode_sdi(request->request_payload, false, device)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    request->response->response_buffer->response_length = 0;
    oc_sec_dump_sdi(device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

#endif /* OC_SECURITY */
