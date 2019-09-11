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
#include "oc_pki.h"
#include "oc_uuid.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct oc_ace_res_s oc_ace_res_t;
typedef struct oc_sec_ace_s oc_sec_ace_t;

typedef enum {
  OC_CONN_AUTH_CRYPT = 0,
  OC_CONN_ANON_CLEAR
} oc_ace_connection_type_t;

typedef enum {
  OC_ACE_NO_WC = 0,
  OC_ACE_WC_ALL = 0x111,
  OC_ACE_WC_ALL_SECURED = 0x01,
  OC_ACE_WC_ALL_PUBLIC = 0x10,
} oc_ace_wildcard_t;

typedef enum {
  OC_PERM_NONE = 0,
  OC_PERM_CREATE = (1 << 0),
  OC_PERM_RETRIEVE = (1 << 1),
  OC_PERM_UPDATE = (1 << 2),
  OC_PERM_DELETE = (1 << 3),
  OC_PERM_NOTIFY = (1 << 4)
} oc_ace_permissions_t;

typedef void (*oc_obt_discovery_cb_t)(oc_uuid_t *, oc_endpoint_t *, void *);
typedef void (*oc_obt_device_status_cb_t)(oc_uuid_t *, int, void *);
typedef void (*oc_obt_status_cb_t)(int, void *);

/* Call once at startup for OBT initialization */
int oc_obt_init(void);
/* Called when the OBT terminates to free all resources */
void oc_obt_shutdown(void);

/* Device discovery */
int oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data);
int oc_obt_discover_unowned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                     void *data);
int oc_obt_discover_unowned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                    void *data);
int oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data);
int oc_obt_discover_owned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                   void *data);
int oc_obt_discover_owned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                  void *data);
/* Perform ownership transfer */
int oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                                  void *data);
int oc_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                              void *data);
int oc_obt_perform_random_pin_otm(oc_uuid_t *uuid, const unsigned char *pin,
                                  size_t pin_len, oc_obt_device_status_cb_t cb,
                                  void *data);
int oc_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                            void *data);

/* RESET device state */
int oc_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                             void *data);

/* Provision pair-wise 128-bit pre-shared keys */
int oc_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2,
                                          oc_obt_status_cb_t cb, void *data);
/* Provision identity certificates */
int oc_obt_provision_identity_certificate(oc_uuid_t *uuid,
                                          oc_obt_status_cb_t cb, void *data);

/* Provision role certificates */
int oc_obt_provision_role_certificate(oc_role_t *roles, oc_uuid_t *uuid,
                                      oc_obt_status_cb_t cb, void *data);

oc_role_t *oc_obt_add_roleid(oc_role_t *roles, const char *role,
                             const char *authority);
void oc_obt_free_roleid(oc_role_t *roles);

/* Provision access-control entries (ace2) */
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);
oc_sec_ace_t *oc_obt_new_ace_for_role(const char *role, const char *authority);
oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);
void oc_obt_ace_add_permission(oc_sec_ace_t *ace,
                               oc_ace_permissions_t permission);

int oc_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace,
                         oc_obt_device_status_cb_t cb, void *data);
void oc_obt_free_ace(oc_sec_ace_t *ace);

/* Provision role ACE for wildcard "*" resource with RW permissions */
int oc_obt_provision_role_wildcard_ace(oc_uuid_t *subject, const char *role,
                                       const char *authority,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

/* Provision auth-crypt ACE for the wildcard "*" resource with RW permissions */
int oc_obt_provision_auth_wildcard_ace(oc_uuid_t *subject,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_H */
