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

#include "api/oc_helpers_internal.h"
#include "oc_role.h"
#include "security/oc_cred_internal.h"
#include "security/oc_tls_internal.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_SEC_ROLES_URI "/oic/sec/roles"
#define OCF_SEC_ROLES_RT "oic.r.roles"

enum {
  OCF_SEC_ROLES_IF_MASK = OC_IF_BASELINE | OC_IF_RW,
  OCF_SEC_ROLES_DEFAULT_IF = OC_IF_RW,

  OCF_SEC_ROLES_MAX_NUM = 2,
};

/**
 * \defgroup server-roles Event timers
 *
 * Server-side API for handling role assertions via /oic/sec/roles
 *
 * @{
 */

/** Get head of the list of roles asserted by the client. */
oc_sec_cred_t *oc_sec_roles_get(const oc_tls_peer_t *client) OC_NONNULL();

/**
 * @brief Add a role to the list of roles asserted by the client.
 *
 * @param client client asserting the role (cannot be NULL)
 * @param device device index
 *
 * @return newly allocated role on success
 * @return NULL on failure
 *
 */
oc_sec_cred_t *oc_sec_roles_add(const oc_tls_peer_t *client, size_t device)
  OC_NONNULL();

/**
 * @brief Create roles (/oic/sec/roles) resource for given device.
 *
 * @param device device index
 */
void oc_sec_roles_create_resource(size_t device);

/**
 * @brief Remove role from the list of roles for given client and deallocate it.
 *
 * @param role role to remove (cannot be NULL)
 * @param client client asserting the role (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_free_role(const oc_sec_cred_t *role, const oc_tls_peer_t *client)
  OC_NONNULL();

/**
 * @brief Remove all roles asserted by given client and deallocate them.
 *
 * @param client client asserting the role (cannot be NULL)
 * @return number of roles removed
 */
int oc_sec_free_roles(const oc_tls_peer_t *client) OC_NONNULL();

/**
 * @brief Remove all roles asserted by given client for given device and
 * deallocate them.
 *
 * @param device device index
 * @return number of roles removed
 */
int oc_sec_free_roles_for_device(size_t device);

/**
 * @brief Remove role with given credid asserted by given client for given
 * device and deallocate them.
 *
 * @param credid credid of the role to remove
 * @param client client asserting the role (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_free_role_by_credid(int credid, const oc_tls_peer_t *client)
  OC_NONNULL();

/** @} */

#ifdef OC_CLIENT

enum {
  OC_ROLES_NUM_ROLE_CREDS = 2,
};

/**
 * \defgroup client-roles Event timers
 *
 * Client-side API for asserting roles that had been provisioned to
 * /oic/sec/cred.
 *
 * @{
 */

/** @brief Add a role (if it doesn't exist) to the list of roles asserted by the
 * client. */
oc_role_t *oc_sec_role_cred_add_or_get(oc_string_view_t role,
                                       oc_string_view_t authority);

/** @brief Remove a role from the list of roles asserted by the client. */
bool oc_sec_role_cred_remove(oc_string_view_t role, oc_string_view_t authority);

/** @brief Get the list of roles asserted by the client. */
oc_role_t *oc_sec_role_creds_get(void);

/** @brief Free the list of roles asserted by the client. */
void oc_sec_role_creds_free(void);

// TODO: if a cred is removed, the list of roles asserted by the client should
// be refreshed and if no longer asserted, the role should be removed from the
// list of roles asserted by the client.

/** @} */

#endif /* OC_CLIENT */

#ifdef __cplusplus
}
#endif

#endif /* OC_ROLES_INTERNAL_H */
