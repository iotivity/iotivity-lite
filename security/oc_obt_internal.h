/*
// Copyright (c) 2019 Intel Corporation
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

#ifndef OC_OBT_INTERNAL_H
#define OC_OBT_INTERNAL_H

#include "oc_endpoint.h"
#include "oc_uuid.h"
#include "security/oc_pstat.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISCOVERY_CB_PERIOD (5)
/* Worst case timeout for all onboarding/provisioning sequences */
#define OBT_CB_TIMEOUT (15)

/* Used for tracking owned/unowned devices in oc_obt's internal caches */
typedef struct oc_device_t
{
  struct oc_device_t *next;
  oc_endpoint_t *endpoint;
  oc_uuid_t uuid;
  void *ctx;
} oc_device_t;

/* Context for oc_obt_discover_owned/unowned cbs */
typedef struct oc_discovery_cb_t
{
  struct oc_discovery_cb_t *next;
  oc_obt_discovery_cb_t cb;
  void *data;
} oc_discovery_cb_t;

/* Context for oc_obt_provision_pairwise_credentials and switch_dos cb */
typedef struct
{
  oc_obt_status_cb_t cb;
  void *data;
} oc_status_cb_t;

/* Context for oc_obt_perform_just_works_otm, oc_obt_provision_ace,
 * oc_obt_device_hard_reset, oc_obt_request_random_pin() and
 * oc_obt_perform_random_pin_otm() cbs
 */
typedef struct
{
  oc_obt_device_status_cb_t cb;
  void *data;
} oc_device_status_cb_t;

/* Context to be maintained over OTM sequence */
typedef struct oc_otm_ctx_t
{
  struct oc_otm_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
} oc_otm_ctx_t;

/* Context to be maintained over dos transition sequence */
typedef struct oc_switch_dos_ctx_t
{
  struct oc_switch_dos_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device;
  oc_dostype_t dos;
} oc_switch_dos_ctx_t;

/* Context to be maintained over hard RESET sequence */
typedef struct
{
  oc_device_status_cb_t cb;
  oc_device_t *device;
  oc_switch_dos_ctx_t *switch_dos;
} oc_hard_reset_ctx_t;

/* Context to be maintained over pair-wise credential provisioning
 * sequence
 */
typedef struct oc_credprov_ctx_t
{
  struct oc_credprov_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device1;
  oc_device_t *device2;
  oc_switch_dos_ctx_t *switch_dos;
  uint8_t key[16];
} oc_credprov_ctx_t;

/* Context to be maintained over ACE provisioning sequence */
typedef struct oc_acl2prov_ctx_t
{
  struct oc_acl2prov_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
  oc_sec_ace_t *ace;
  oc_switch_dos_ctx_t *switch_dos;
} oc_acl2prov_ctx_t;

typedef enum {
  OC_OBT_OTM_JW = 0,
  OC_OBT_RDP,
  OC_OBT_OTM_RDP,
  OC_OBT_OTM_MFG
} oc_obt_otm_t;

oc_endpoint_t *oc_obt_get_unsecure_endpoint(oc_endpoint_t *endpoint);
oc_endpoint_t *oc_obt_get_secure_endpoint(oc_endpoint_t *endpoint);

oc_device_t *oc_obt_get_cached_device_handle(oc_uuid_t *uuid);
oc_device_t *oc_obt_get_owned_device_handle(oc_uuid_t *uuid);

bool oc_obt_is_owned_device(oc_uuid_t *uuid);
oc_dostype_t oc_obt_parse_dos(oc_rep_t *rep);

oc_otm_ctx_t *oc_obt_alloc_otm_ctx(void);
void oc_obt_free_otm_ctx(oc_otm_ctx_t *ctx, int status, oc_obt_otm_t);
oc_event_callback_retval_t oc_obt_otm_request_timeout_cb(void *data);
bool oc_obt_is_otm_ctx_valid(oc_otm_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_INTERNAL_H */
