/*
// Copyright (c) 2017-2019 Intel Corporation
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
/**
  @file
*/
#ifndef OC_OBT_H
#define OC_OBT_H

#include "oc_api.h"
#include "oc_uuid.h"
#include "security/oc_acl.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*oc_obt_discovery_cb_t)(oc_uuid_t *, oc_endpoint_t *, void *);
typedef void (*oc_obt_device_status_cb_t)(oc_uuid_t *, int, void *);
typedef void (*oc_obt_status_cb_t)(int, void *);

/* Call once at startup for OBT initialization */
void oc_obt_init(void);
/* Called when the OBT terminates to free all resources */
void oc_obt_shutdown(void);

/* Device discovery */
int oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data);
int oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data);

/* Perform ownership transfer */
int oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                                  void *data);
int oc_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                              void *data);
int oc_obt_perform_random_pin_otm(oc_uuid_t *uuid, const unsigned char *pin,
                                  size_t pin_len, oc_obt_device_status_cb_t cb,
                                  void *data);

/* RESET device state */
int oc_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                             void *data);

/* Provision pair-wise 128-bit shared keys */
int oc_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2,
                                          oc_obt_status_cb_t cb, void *data);

/* Provision access-control entries (ace2) */
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);

oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);
void oc_obt_ace_resource_set_num_rt(oc_ace_res_t *resource, int num_resources);
void oc_obt_ace_resource_bind_rt(oc_ace_res_t *resource, const char *rt);
void oc_obt_ace_resource_bind_if(oc_ace_res_t *resource,
                                 oc_interface_mask_t iface_mask);
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);
void oc_obt_ace_add_permission(oc_sec_ace_t *ace,
                               oc_ace_permissions_t permission);

int oc_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace,
                         oc_obt_device_status_cb_t cb, void *data);
void oc_obt_free_ace(oc_sec_ace_t *ace);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_H */
