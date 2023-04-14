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

#ifndef OC_ROLES_INTERNAL_H
#define OC_ROLES_INTERNAL_H

#include "oc_role.h"
#include "security/oc_cred_internal.h"
#include "security/oc_tls_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used on the server-side for handling role assertions via /oic/sec/roles */
oc_sec_cred_t *oc_sec_allocate_role(const oc_tls_peer_t *client, size_t device);
void oc_sec_free_role(const oc_sec_cred_t *role, const oc_tls_peer_t *client);
oc_sec_cred_t *oc_sec_get_roles(const oc_tls_peer_t *client);
void oc_sec_free_roles(const oc_tls_peer_t *client);
void oc_sec_free_roles_for_device(size_t device);
int oc_sec_free_role_by_credid(int credid, const oc_tls_peer_t *client);

/* Used on the client-side for asserting roles that had been provisioned to
 * /oic/sec/cred.
 */
void oc_sec_remove_role_cred(const char *role, const char *authority);
oc_role_t *oc_sec_add_role_cred(const char *role, const char *authority);
oc_role_t *oc_sec_get_role_creds(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_ROLES_INTERNAL_H */
