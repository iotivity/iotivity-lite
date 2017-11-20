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

#ifndef OC_OBT_H
#define OC_OBT_H

#include "oc_api.h"
#include "security/oc_acl.h"

typedef struct oc_device_t
{
  struct oc_device_t *next;
  oc_endpoint_t *endpoint;
  oc_uuid_t uuid;
  void *ctx;
} oc_device_t;

typedef void (*oc_obt_devicelist_cb_t)(oc_device_t *, void *);

typedef void (*oc_obt_status_cb_t)(int, void *);

/* Call once at startup for OBT initialization */
void oc_obt_init(void);

/* Device discovery */
int oc_obt_discover_unowned_devices(oc_obt_devicelist_cb_t cb, void *data);
int oc_obt_discover_owned_devices(oc_obt_devicelist_cb_t cb, void *data);

/* Perform ownership transfer */
int oc_obt_perform_just_works_otm(oc_device_t *device, oc_obt_status_cb_t cb,
                                  void *data);

/* RESET device state */
int oc_obt_device_hard_reset(oc_device_t *device, oc_obt_status_cb_t cb,
                             void *data);

/* Provision pair-wise 128-bit shared keys */
int oc_obt_provision_pairwise_credentials(oc_device_t *device1,
                                          oc_device_t *device2,
                                          oc_obt_status_cb_t cb, void *data);

/* Provision access-control entries (ace2) */
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);

oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);
void oc_obt_ace_resource_set_num_rt(oc_ace_res_t *resource, int num_resources);
void oc_obt_ace_resource_bind_rt(oc_ace_res_t *resource, const char *rt);
void oc_obt_ace_resource_bind_if(oc_ace_res_t *resource,
                                 oc_interface_mask_t interface);
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);
void oc_obt_ace_add_permission(oc_sec_ace_t *ace,
                               oc_ace_permissions_t permission);

int oc_obt_provision_ace(oc_device_t *device, oc_sec_ace_t *ace,
                         oc_obt_status_cb_t cb, void *data);
void oc_obt_free_ace(oc_sec_ace_t *ace);

#endif /* OC_OBT_H */
