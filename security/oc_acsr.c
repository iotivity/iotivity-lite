/*
// Copyright 2019 Samsung Electronics All Rights Reserved.
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

#include <stddef.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_store.h"
#include "oc_acsr.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#include "port/oc_assert.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_DYNAMIC_ALLOCATION
static size_t dev_cnt = 0;
static oc_sec_acsr_t *acsr = NULL;
#else /* OC_DYNAMIC_ALLOCATION */
static const size_t dev_cnt = OC_MAX_NUM_DEVICES;
static oc_sec_acsr_t acsr[OC_MAX_NUM_DEVICES];
#endif /* OC_DYNAMIC_ALLOCATION */

static void oc_sec_acsr_default_all(void);

void
oc_sec_acsr_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (acsr) {
    oc_sec_acsr_free();
  }
  dev_cnt = oc_core_get_num_devices();
  if (!(acsr = (oc_sec_acsr_t *)calloc(dev_cnt, sizeof(oc_sec_acsr_t)))) {
    oc_abort("oc_acsr: Out of memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_sec_acsr_default_all();
}

void
oc_sec_acsr_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  dev_cnt = 0;
  if (acsr) {
    free(acsr);
    acsr = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

bool
oc_sec_decode_acsr(oc_rep_t *rep, bool from_storage, size_t device)
{
  (void)from_storage;
  if (!rep || device >= dev_cnt) {
    return false;
  }

  for (; rep; rep = rep->next) {
    switch (rep->type) {
    /* owned */
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) == 5 &&
              memcmp(oc_string(rep->name), "owned", 5) == 0) {
        acsr[device].owned = rep->value.boolean;
      }
      break;
    default:
      break;
    }
  }
  return true;
}

bool
oc_sec_encode_acsr(size_t device)
{
  if (device >= dev_cnt) {
    return false;
  }
  oc_rep_start_root_object();
  oc_process_baseline_interface(oc_core_get_resource_by_index(OCF_SEC_ACSR, device));
  /* owned */
  oc_rep_set_boolean(root, owned, acsr[device].owned);
  oc_rep_end_root_object();
  return true;
}

oc_sec_acsr_t *
oc_sec_get_acsr(size_t device)
{
  return (device < dev_cnt) ? &acsr[device] : NULL;
}

void
oc_sec_acsr_default(size_t device)
{
  if (device < dev_cnt) {
    acsr[device].owned = false;
//    oc_sec_dump_acsr(device);
  }
}

void
get_acsr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  if (request) {
    switch (iface_mask) {
    case OC_IF_BASELINE: {
      if (oc_sec_encode_acsr(request->resource->device)) {
        oc_send_response(request, OC_STATUS_OK);
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
      }
    } break;
    default:
      break;
    }
  }
}

void
post_acsr(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data)
{
  (void)iface_mask;
  (void)data;
  if (request) {
    if (oc_sec_decode_acsr(request->request_payload, false,
                           request->resource->device)) {
      oc_send_response(request, OC_STATUS_CHANGED);
//      oc_sec_dump_acsr(request->resource->device);
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
  }
}

static void
oc_sec_acsr_default_all(void)
{
  for (size_t i = 0; i < dev_cnt; i++) {
    oc_sec_acsr_default(i);
  }
}

#endif /* OC_SECURITY */
