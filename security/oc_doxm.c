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
#include "oc_store.h"
#include <stddef.h>
#include <string.h>

extern int strncasecmp(const char *s1, const char *s2, size_t n);

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_doxm_t *doxm;
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_doxm_t doxm[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_doxm_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  doxm =
    (oc_sec_doxm_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_doxm_t));
  if (!doxm) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_doxm_default(int device)
{
  doxm[device].oxmsel = 0;
  doxm[device].sct = 1;
  doxm[device].owned = false;
  oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
  oc_gen_uuid(deviceuuid);
  memcpy(&doxm[device].deviceuuid, deviceuuid, sizeof(oc_uuid_t));
  memset(doxm[device].devowneruuid.id, 0, 16);
  memset(doxm[device].rowneruuid.id, 0, 16);
}

void
oc_sec_encode_doxm(int device)
{
  int oxms[1] = { 0 };
  char uuid[37];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_DOXM, device));
  oc_rep_set_int_array(root, oxms, oxms, 1);
  oc_rep_set_int(root, oxmsel, doxm[device].oxmsel);
  oc_rep_set_int(root, sct, doxm[device].sct);
  oc_rep_set_boolean(root, owned, doxm[device].owned);
  oc_uuid_to_str(&doxm[device].deviceuuid, uuid, 37);
  oc_rep_set_text_string(root, deviceuuid, uuid);
  oc_uuid_to_str(&doxm[device].devowneruuid, uuid, 37);
  oc_rep_set_text_string(root, devowneruuid, uuid);
  oc_uuid_to_str(&doxm[device].rowneruuid, uuid, 37);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

oc_sec_doxm_t *
oc_sec_get_doxm(int device)
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
    int device = request->resource->device;
    if (ql > 0 &&
        ((doxm[device].owned == 1 && strncasecmp(q, "false", 5) == 0) ||
         (doxm[device].owned == 0 && strncasecmp(q, "true", 4) == 0))) {
      oc_ignore_request(request);
    } else {
      oc_sec_encode_doxm(device);
      oc_send_response(request, OC_STATUS_OK);
    }
  } break;
  default:
    break;
  }
}

static oc_event_callback_retval_t
dump_acl_post_otm(void *data)
{
  oc_sec_dump_acl((long)data);
  oc_sec_dump_unique_ids((long)data);
  return DONE;
}

bool
oc_sec_decode_doxm(oc_rep_t *rep, bool from_storage, int device)
{
  while (rep != NULL) {
    switch (rep->type) {
    case BOOL:
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "owned", 5) == 0) {
        doxm[device].owned = rep->value.boolean;
        if (!from_storage && doxm[device].owned) {
          oc_sec_set_post_otm_acl(device);
          oc_ri_add_timed_event_callback_ticks((void *)(long)device,
                                               &dump_acl_post_otm, 0);
        }
      } else {
        return false;
      }
      break;
    case INT:
      if (oc_string_len(rep->name) == 6 &&
          memcmp(oc_string(rep->name), "oxmsel", 6) == 0) {
        doxm[device].oxmsel = rep->value.integer;
      } else if (from_storage && memcmp(oc_string(rep->name), "sct", 3) == 0) {
        doxm[device].sct = rep->value.integer;
      } else {
        return false;
      }
      break;
    case STRING:
      if (oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "deviceuuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm[device].deviceuuid);
        oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
        memcpy(deviceuuid->id, doxm[device].deviceuuid.id, 16);
      } else if (oc_string_len(rep->name) == 12 &&
                 memcmp(oc_string(rep->name), "devowneruuid", 12) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string),
                       &doxm[device].devowneruuid);
      } else if (oc_string_len(rep->name) == 10 &&
                 memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm[device].rowneruuid);
      } else {
        return false;
      }
      break;
    default: {
      if (!((oc_string_len(rep->name) == 2 &&
             (memcmp(oc_string(rep->name), "rt", 2) == 0 ||
              memcmp(oc_string(rep->name), "if", 2) == 0))) &&
          !(oc_string_len(rep->name) == 4 &&
            memcmp(oc_string(rep->name), "oxms", 4) == 0)) {
        return false;
      }
    } break;
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
  }
}

#endif /* OC_SECURITY */
