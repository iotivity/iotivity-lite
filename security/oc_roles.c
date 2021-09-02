/*
// Copyright (c) 2018-2019 Intel Corporation
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
#ifdef OC_PKI

#include "oc_roles.h"
#include "mbedtls/x509_crt.h"
#include "port/oc_log.h"
#include "security/oc_tls.h"

#define OC_ROLES_NUM_ROLE_CREDS (2)
#define OC_ROLES_NUM_ROLES (2)

#ifdef OC_CLIENT
OC_MEMB(role_creds_s, oc_role_t, OC_ROLES_NUM_ROLE_CREDS);
OC_LIST(role_creds);

oc_role_t *
oc_sec_get_role_creds(void)
{
  return oc_list_head(role_creds);
}

static oc_role_t *
allocate_role_cred(const char *role, const char *authority)
{
  oc_role_t *role_cred = (oc_role_t *)oc_memb_alloc(&role_creds_s);
  if (role) {
    oc_new_string(&role_cred->role, role, strlen(role));
    oc_new_string(&role_cred->authority, authority, strlen(authority));
    oc_list_add(role_creds, role_cred);
  }
  return role_cred;
}

static oc_role_t *
find_role_cred(const char *role, const char *authority)
{
  oc_role_t *role_cred = (oc_role_t *)oc_list_head(role_creds);
  size_t role_len = strlen(role);
  size_t authority_len = (authority ? strlen(authority) : 0);

  while (role_cred) {
    if ((oc_string_len(role_cred->role) == role_len) &&
        (memcmp(oc_string(role_cred->role), role, role_len) == 0)) {
      if (authority && (oc_string_len(role_cred->authority) == authority_len) &&
          (memcmp(oc_string(role_cred->authority), authority, authority_len) ==
           0)) {
        return role_cred;
      }
    }
    role_cred = role_cred->next;
  }

  return role_cred;
}

void
oc_sec_remove_role_cred(const char *role, const char *authority)
{
  oc_role_t *role_cred = find_role_cred(role, authority);
  if (role_cred) {
    oc_list_remove(role_creds, role_cred);
    oc_memb_free(&role_creds_s, role_cred);
  }
}

oc_role_t *
oc_sec_add_role_cred(const char *role, const char *authority)
{
  oc_role_t *role_cred = find_role_cred(role, authority);
  if (!role_cred) {
    role_cred = allocate_role_cred(role, authority);
  }
  return role_cred;
}
#endif /* OC_CLIENT */

typedef struct oc_sec_roles_t
{
  struct oc_sec_roles_t *next;
  OC_LIST_STRUCT(roles);
  oc_tls_peer_t *client;
  size_t device;
} oc_sec_roles_t;

OC_MEMB(x509_crt_s, mbedtls_x509_crt, OC_ROLES_NUM_ROLES);
OC_MEMB(roles_s, oc_sec_cred_t, OC_ROLES_NUM_ROLES);
OC_MEMB(clients_s, oc_sec_roles_t, OC_MAX_NUM_DEVICES);
OC_LIST(clients);

static oc_sec_roles_t *
get_roles_for_client(oc_tls_peer_t *client)
{
  oc_sec_roles_t *roles = (oc_sec_roles_t *)oc_list_head(clients);
  while (roles) {
    if (roles->client == client) {
      return roles;
    }
    roles = roles->next;
  }
  return roles;
}

static oc_sec_roles_t *
allocate_roles_for_client(oc_tls_peer_t *client, size_t device)
{
  oc_sec_roles_t *roles = (oc_sec_roles_t *)oc_memb_alloc(&clients_s);
  if (!roles) {
    return NULL;
  }
  roles->device = device;
  roles->client = client;
  OC_LIST_STRUCT_INIT(roles, roles);
  oc_list_add(clients, roles);
  return roles;
}

oc_sec_cred_t *
oc_sec_allocate_role(oc_tls_peer_t *client, size_t device)
{
  oc_sec_roles_t *roles = get_roles_for_client(client);
  if (!roles) {
    roles = allocate_roles_for_client(client, device);
  }
  if (roles) {
    oc_sec_cred_t *role = (oc_sec_cred_t *)oc_memb_alloc(&roles_s);
    if (role) {
      role->ctx = oc_memb_alloc(&x509_crt_s);
      if (role->ctx) {
        mbedtls_x509_crt_init(role->ctx);
        oc_list_add(roles->roles, role);
        return role;
      }
      oc_sec_free_role(role, client);
    }
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_get_roles(oc_tls_peer_t *client)
{
  oc_sec_roles_t *roles = get_roles_for_client(client);
  if (roles) {
    return (oc_sec_cred_t *)oc_list_head(roles->roles);
  }
  return NULL;
}

static void
free_cred_properties(oc_sec_cred_t *cred)
{
  oc_free_string(&cred->role.role);
  oc_free_string(&cred->role.authority);
  oc_free_string(&cred->publicdata.data);
}

void
oc_sec_free_role(oc_sec_cred_t *role, oc_tls_peer_t *client)
{
  oc_sec_roles_t *roles = get_roles_for_client(client);
  if (roles) {
    oc_sec_cred_t *r = (oc_sec_cred_t *)oc_list_head(roles->roles);
    while (r) {
      if (role == r) {
        oc_list_remove(roles->roles, r);
        mbedtls_x509_crt_free(r->ctx);
        oc_memb_free(&x509_crt_s, r->ctx);
        free_cred_properties(r);
        oc_memb_free(&roles_s, r);
        return;
      }
      r = r->next;
    }
  }
}

void
oc_sec_free_roles_for_device(size_t device)
{
  oc_sec_roles_t *roles = (oc_sec_roles_t *)oc_list_head(clients), *next;
  while (roles) {
    next = roles->next;
    if (roles->device == device) {
      oc_sec_free_roles(roles->client);
    }
    roles = next;
  }
}

void
oc_sec_free_roles(oc_tls_peer_t *client)
{
  oc_sec_roles_t *roles = get_roles_for_client(client);
  if (roles) {
    oc_sec_cred_t *r = (oc_sec_cred_t *)oc_list_pop(roles->roles);
    while (r) {
      mbedtls_x509_crt_free(r->ctx);
      oc_memb_free(&x509_crt_s, r->ctx);
      free_cred_properties(r);
      oc_memb_free(&roles_s, r);
      r = (oc_sec_cred_t *)oc_list_pop(roles->roles);
    }
    oc_list_remove(clients, roles);
    oc_memb_free(&clients_s, roles);
  }
}

int
oc_sec_free_role_by_credid(int credid, oc_tls_peer_t *client)
{
  oc_sec_roles_t *roles = get_roles_for_client(client);
  if (roles) {
    oc_sec_cred_t *r = (oc_sec_cred_t *)oc_list_head(roles->roles);
    while (r) {
      if (r->credid == credid) {
        oc_list_remove(roles->roles, r);
        mbedtls_x509_crt_free(r->ctx);
        oc_memb_free(&x509_crt_s, r->ctx);
        free_cred_properties(r);
        oc_memb_free(&roles_s, r);
        return 0;
      }
      r = r->next;
    }
  }
  return -1;
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */
