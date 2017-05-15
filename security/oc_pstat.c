/*
// Copyright (c) 2016 Intel Corporation
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
#include "oc_doxm.h"
#include "oc_store.h"

static oc_sec_pstat_t pstat;

oc_sec_pstat_t *
oc_sec_get_pstat(void)
{
  return &pstat;
}

bool
oc_sec_provisioned(void)
{
  return pstat.isop;
}

void
oc_sec_pstat_default(void)
{
  pstat.isop = false;
  pstat.cm = 2;
  pstat.tm = 0;
  pstat.om = 3;
  pstat.sm = 4;
}

void
oc_sec_encode_pstat(void)
{
  char uuid[37];
  oc_sec_doxm_t *doxm = oc_sec_get_doxm();
  oc_rep_start_root_object();
  oc_process_baseline_interface(oc_core_get_resource_by_index(OCF_SEC_PSTAT));
  oc_rep_set_uint(root, cm, pstat.cm);
  oc_rep_set_uint(root, tm, pstat.tm);
  oc_rep_set_int(root, om, pstat.om);
  oc_rep_set_int(root, sm, pstat.sm);
  oc_rep_set_boolean(root, isop, pstat.isop);
  oc_uuid_to_str(&doxm->deviceuuid, uuid, 37);
  oc_rep_set_text_string(root, deviceuuid, uuid);
  oc_uuid_to_str(&doxm->rowneruuid, uuid, 37);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

bool
oc_sec_decode_pstat(oc_rep_t *rep, bool from_storage)
{
  pstat.sm = 4;
  oc_sec_doxm_t *doxm = oc_sec_get_doxm();
  while (rep != NULL) {
    switch (rep->type) {
    case BOOL:
      if (oc_string_len(rep->name) == 4 &&
          memcmp(oc_string(rep->name), "isop", 4) == 0) {
        pstat.isop = rep->value.boolean;
        if (pstat.isop) {
          oc_sec_set_post_otm_acl();
        }
      } else {
        return false;
      }
      break;
    case INT:
      if (memcmp(oc_string(rep->name), "cm", 2) == 0) {
        pstat.cm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "tm", 2) == 0) {
        pstat.tm = rep->value.integer;
      } else if (memcmp(oc_string(rep->name), "om", 2) == 0) {
        pstat.om = rep->value.integer;
      } else if (from_storage && memcmp(oc_string(rep->name), "sm", 2) == 0) {
        pstat.sm = rep->value.integer;
      } else {
        return false;
      }
      break;
    case STRING:
      if (memcmp(oc_string(rep->name), "deviceuuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm->deviceuuid);
      } else if (memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &doxm->rowneruuid);
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
  return true;
}

void
get_pstat(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)data;
  switch (interface) {
  case OC_IF_BASELINE: {
    oc_sec_encode_pstat();
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
  if (oc_sec_decode_pstat(request->request_payload, false)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_pstat();
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

#endif /* OC_SECURITY */
