/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_enums_internal.h"
#include "api/oc_platform_internal.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "security/oc_ace_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_acl_util_internal.h"
#include "security/oc_certs_validate_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_roles_internal.h"
#include "security/oc_tls_internal.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if OC_DBG_IS_ENABLED

static void
print_acls(size_t device)
{
  // GCOVR_EXCL_START
  const oc_sec_acl_t *a = oc_sec_get_acl(device);
  const oc_sec_ace_t *ace = oc_list_head(a->subjects);
  OC_DBG("\nAccess Control List\n---------");
  while (ace != NULL) {
    OC_DBG("\n---------\nAce: %d\n---------", ace->aceid);
    switch (ace->subject_type) {
    case OC_SUBJECT_UUID: {
      char u[OC_UUID_LEN];
      oc_uuid_to_str(&ace->subject.uuid, u, OC_UUID_LEN);
      OC_DBG("UUID: %s", u);
    } break;
    case OC_SUBJECT_CONN: {
      switch (ace->subject.conn) {
      case OC_CONN_AUTH_CRYPT:
        OC_DBG("CONN: auth-crypt");
        break;
      case OC_CONN_ANON_CLEAR:
        OC_DBG("CONN: anon-clear");
        break;
      }
    } break;
    case OC_SUBJECT_ROLE: {
      OC_DBG("Role_RoleId: %s", oc_string(ace->subject.role.role));
      if (oc_string_len(ace->subject.role.authority) > 0) {
        OC_DBG("Role_Authority: %s", oc_string(ace->subject.role.authority));
      }
    } break;
    }

    oc_ace_res_t *r = oc_list_head(ace->resources);
    OC_DBG("\nResources:");
    while (r != NULL) {
      if (oc_string_len(r->href) > 0) {
        OC_DBG("href: %s", oc_string(r->href));
      }
      switch (r->wildcard) {
      case OC_ACE_NO_WC:
        OC_DBG("No wildcard");
        break;
      case OC_ACE_WC_ALL:
        OC_DBG("Wildcard: *");
        break;
      case OC_ACE_WC_ALL_SECURED:
        OC_DBG("Wildcard: +");
        break;
      case OC_ACE_WC_ALL_PUBLIC:
        OC_DBG("Wildcard: -");
        break;
      }
      OC_DBG("Permission: %d", ace->permission);
      r = r->next;
    }
    ace = ace->next;
  }
  // GCOVR_EXCL_STOP
}

#endif /* OC_DBG_IS_ENABLED */

static uint16_t
oc_ace_get_permission(const oc_sec_ace_t *ace, const oc_resource_t *resource,
                      bool is_DCR, bool is_public)
{
  /* If the resource is discoverable and exposes >=1 unsecured endpoints
   * then match with ACEs bearing any of the 3 wildcard resources.
   * If the resource is discoverable and does not expose any unsecured
   * endpoint, then match with ACEs bearing either OC_ACE_WC_ALL_SECURED or
   * OC_ACE_WC_ALL. If the resource is not discoverable, then match only with
   * ACEs bearing OC_ACE_WC_ALL.
   */
  uint16_t wc = 0;
  if (!is_DCR) {
    if (resource->properties & OC_DISCOVERABLE) {
      wc = OC_ACE_WC_ALL_SECURED;
      if (is_public) {
        wc |= OC_ACE_WC_ALL_PUBLIC;
      }
    } else {
      wc = OC_ACE_WC_ALL;
    }
  }

  uint16_t permission = 0;
  oc_ace_res_t *res =
    oc_sec_ace_find_resource(NULL, ace, oc_string_view2(&resource->uri), wc);
  while (res != NULL) {
    permission |= ace->permission;

    res =
      oc_sec_ace_find_resource(res, ace, oc_string_view2(&resource->uri), wc);
  }

  return permission;
}

static uint16_t
get_role_permissions(const oc_sec_cred_t *role_cred,
                     const oc_resource_t *resource, size_t device, bool is_DCR,
                     bool is_public)
{
  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  do {
    oc_ace_subject_view_t role_subject = {
      .role =
        (oc_ace_subject_role_view_t){
          .role = oc_string_view2(&role_cred->role.role),
          .authority = oc_string_view2(&role_cred->role.authority),
        }
    };
    match = oc_sec_acl_find_subject(match, OC_SUBJECT_ROLE, role_subject,
                                    /*aceid*/ -1, /*permission*/ 0,
                                    /*tag*/ OC_STRING_VIEW_NULL,
                                    /*match_tag*/ false, device);

    if (match != NULL) {
      permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
      OC_DBG("oc_check_acl: Found ACE with permission %d for matching role",
             permission);
    }
  } while (match != NULL);
  return permission;
}

static bool
eval_access(oc_method_t method, uint16_t permission)
{
  OC_DBG("oc_check_acl: Evaluating access for method %d with permission %d",
         method, permission);
  if (permission == 0) {
    return false;
  }
  if (method == OC_GET) {
    return (permission & OC_PERM_RETRIEVE) != 0 ||
           (permission & OC_PERM_NOTIFY) != 0;
  }

  if (method == OC_POST || method == OC_PUT) {
    return (permission & OC_PERM_CREATE) != 0 ||
           (permission & OC_PERM_UPDATE) != 0;
  }
  return (method == OC_DELETE) && (permission & OC_PERM_DELETE) != 0;
}

static bool
oc_sec_check_acl_on_get(const oc_resource_t *resource, bool is_otm)
{
  oc_string_view_t uriv = oc_string_view2(&resource->uri);

  /* Retrieve requests to "/oic/res", "/oic/d" and "/oic/p" shall be granted.
   */
  if (is_otm &&
      (oc_is_discovery_resource_uri(uriv) || oc_is_device_resource_uri(uriv) ||
       oc_is_platform_resource_uri(uriv))) {
    return true;
  }

#ifdef OC_HAS_FEATURE_PLGD_TIME
  if (plgd_is_time_resource_uri(uriv)) {
    return true;
  }
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_WKCORE
  /* if enabled also the .well-known/core will be granted access, since this
   * also a discovery resource. */
  if (oc_is_wkcore_resource_uri(uriv)) {
    return true;
  }
#endif /* OC_WKCORE */

#ifdef OC_DOXM_UUID_FILTER
  /* GET requests to /oic/sec/doxm are always granted.
   * This is to ensure that multicast discovery using UUID filtered requests
   * to /oic/sec/doxm is not blocked.
   *
   * The security implications of allowing universal read access to
   * /oic/sec/doxm have not been thoroughly discussed. Enabling the following
   * define is FOR DEVELOPMENT USE ONLY.
   */
  if (method == OC_GET && oc_sec_is_doxm_resource_uri(uriv)) {
    OC_DBG("oc_sec_check_acl: R access granted to /doxm");
    return true;
  }
#endif /* OC_DOXM_UUID_FILTER */
  return false;
}

static bool
oc_sec_check_acl_by_uuid(const oc_uuid_t *uuid, size_t device,
                         const oc_resource_t *resource)
{
  oc_string_view_t uriv = oc_string_view2(&resource->uri);
  if (oc_sec_is_acl_resource_uri(uriv) &&
      oc_sec_acl_is_owned_by(device, *uuid)) {
    OC_DBG("oc_acl: peer's UUID matches acl2's rowneruuid");
    return true;
  }
  if (oc_sec_is_doxm_resource_uri(uriv) &&
      oc_sec_doxm_is_owned_by(device, *uuid)) {
    OC_DBG("oc_acl: peer's UUID matches doxm's rowneruuid");
    return true;
  }
  if (oc_sec_is_pstat_resource_uri(uriv) &&
      oc_sec_pstat_is_owned_by(device, *uuid)) {
    OC_DBG("oc_acl: peer's UUID matches pstat's rowneruuid");
    return true;
  }
  if (oc_sec_is_cred_resource_uri(uriv) &&
      oc_sec_cred_is_owned_by(device, *uuid)) {
    OC_DBG("oc_acl: peer's UUID matches cred's rowneruuid");
    return true;
  }
  return false;
}

static bool
oc_sec_check_acl_in_rfotm_prior_to_doc(oc_method_t method,
                                       const oc_resource_t *resource)
{
  /* Anonymous Retrieve and Updates requests to “/oic/sec/doxm” shall be
       granted.
    */
  if (oc_sec_is_doxm_resource_uri(oc_string_view2(&resource->uri))) {
    OC_DBG("oc_sec_check_acl: RW access granted to doxm prior to DOC");
    return true;
  }
  /* All Retrieve requests to the “/oic/sec/pstat” Resource shall be
     granted. */
  if (method == OC_GET &&
      oc_sec_is_pstat_resource_uri(oc_string_view2(&resource->uri))) {
    OC_DBG("oc_sec_check_acl: R access granted to pstat prior to DOC");
    return true;
  }
  /* Reject all other requests */
  OC_DBG("oc_sec_check_acl: access denied to %s prior to DOC",
         oc_string(resource->uri));
  return false;
}

static uint16_t
get_peer_permissions(const oc_resource_t *resource, bool is_DCR, bool is_public,
                     const oc_endpoint_t *endpoint, const oc_tls_peer_t *peer)
{
  uint16_t permission = 0;
  if (oc_tls_uses_psk_cred(peer)) {
    const oc_uuid_t *uuid = &endpoint->di;
    oc_sec_cred_t *role_cred = NULL;
    do {
      role_cred = oc_sec_find_cred(role_cred, uuid, OC_CREDTYPE_PSK,
                                   OC_CREDUSAGE_NULL, endpoint->device);
      if (role_cred == NULL) {
        break;
      }
      if (!oc_string_is_empty(&role_cred->role.role)) {
        permission |= get_role_permissions(role_cred, resource,
                                           endpoint->device, is_DCR, is_public);
      }
      role_cred = role_cred->next;
    } while (role_cred != NULL);
  }
#ifdef OC_PKI
  else {
    const oc_sec_cred_t *role_cred = oc_sec_roles_get(peer);
    while (role_cred != NULL) {
      const oc_sec_cred_t *next = role_cred->next;
      uint32_t flags = 0;
      if (oc_certs_validate_role_cert(role_cred->ctx, &flags) < 0 ||
          flags != 0) {
        oc_sec_free_role(role_cred, peer);
        role_cred = next;
        continue;
      }
      oc_string_view_t ownerv = OC_STRING_VIEW(OCF_SEC_ROLE_OWNER);
      if (oc_string_view_is_equal(oc_string_view2(&role_cred->role.role),
                                  ownerv)) {
        OC_DBG("oc_acl: peer's role matches \"%s\"", OCF_SEC_ROLE_OWNER);
        return OC_PERM_ALL;
      }
      permission |= get_role_permissions(role_cred, resource, endpoint->device,
                                         is_DCR, is_public);
      role_cred = role_cred->next;
    }
  }
#endif /* OC_PKI */
  return permission;
}

static uint16_t
get_conn_permissions(const oc_resource_t *resource, bool is_DCR, bool is_public,
                     const oc_endpoint_t *endpoint)
{
  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  if ((endpoint->flags & SECURED) != 0) {
    oc_ace_subject_view_t auth_crypt = {
      .conn = OC_CONN_AUTH_CRYPT,
    };
    do {
      match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, auth_crypt,
                                      /*aceid*/ -1, /*permission*/ 0,
                                      /*tag*/ OC_STRING_VIEW_NULL,
                                      /*match_tag*/ false, endpoint->device);
      if (match == NULL) {
        continue;
      }
      permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
      OC_DBG("oc_check_acl: Found ACE with permission %d for auth-crypt "
             "connection",
             permission);
    } while (match != NULL);
  }

  oc_ace_subject_view_t anon_clear = {
    .conn = OC_CONN_ANON_CLEAR,
  };
  do {
    match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, anon_clear,
                                    /*aceid*/ -1, /*permission*/ 0,
                                    /*tag*/ OC_STRING_VIEW_NULL,
                                    /*match_tag*/ false, endpoint->device);
    if (match == NULL) {
      continue;
    }
    permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
    OC_DBG("oc_check_acl: Found ACE with permission %d for anon-clear "
           "connection",
           permission);
  } while (match != NULL);

  return permission;
}

static bool
oc_sec_check_acl_by_permissions(oc_method_t method,
                                const oc_resource_t *resource, bool is_DCR,
                                bool is_SVR, const oc_endpoint_t *endpoint,
                                const oc_tls_peer_t *peer)
{
  const bool is_public = ((resource->properties & OC_SECURE) == 0);
  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  do {
    oc_ace_subject_view_t subject = {
      .uuid = endpoint->di,
    };
    match =
      oc_sec_acl_find_subject(match, OC_SUBJECT_UUID, subject,
                              /*aceid*/ -1,
                              /*permission*/ 0, /*tag*/ OC_STRING_VIEW_NULL,
                              /*match_tag*/ false, endpoint->device);

    if (match == NULL) {
      continue;
    }
    permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
    OC_DBG("oc_check_acl: Found ACE with permission %d for subject UUID",
           permission);
  } while (match != NULL);

  if (peer != NULL) {
    permission |=
      get_peer_permissions(resource, is_DCR, is_public, endpoint, peer);
  }

  /* Access to SVRs via auth-crypt or anon-clear ACEs is prohibited */
  if (!is_SVR) {
    permission |= get_conn_permissions(resource, is_DCR, is_public, endpoint);
  }

  bool ok = eval_access(method, permission);
#ifdef OC_DBG_IS_ENABLED
  OC_DBG("oc_sec_check_acl: access %s to %s", ok ? "granted" : "denied",
         oc_string(resource->uri));
#endif /* OC_DBG_IS_ENABLED */
  return ok;
}

bool
oc_sec_check_acl(oc_method_t method, const oc_resource_t *resource,
                 const oc_endpoint_t *endpoint)
{
#if OC_DBG_IS_ENABLED
  print_acls(endpoint->device);
#endif /* OC_DBG_IS_ENABLED */

  const oc_sec_pstat_t *ps = oc_sec_get_pstat(endpoint->device);
  oc_dostype_t dos = ps->s;
  if (dos == OC_DOS_RFOTM && (endpoint->flags & SECURED) == 0) {
    /* All unicast requests which are not received over the open Device DOC
     * shall be rejected with an appropriate error message (e.g. forbidden),
     * regardless of the configuration of the ACEs in the "/oic/sec/acl2"
     * Resource.
     */
    if (oc_tls_num_peers(endpoint->device) == 1) {
      OC_DBG(
        "oc_sec_check_acl: unencrypted request received while DOC is open - "
        "access forbidden");
      return false;
    }

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    /* Allow access to resources in RFOTM mode if the feature is enabled and
     * permission match the method. */
    if ((resource->properties & OC_ACCESS_IN_RFOTM) == OC_ACCESS_IN_RFOTM &&
        eval_access(method, (uint16_t)resource->anon_permission_in_rfotm)) {
      OC_DBG("oc_sec_check_acl: access granted to %s via anon permission in "
             "RFOTM state",
             oc_string(resource->uri));
      return true;
    }
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  bool is_DCR = oc_core_is_DCR(resource, resource->device);
  /* NCRs are accessible only in RFNOP */
  if (!is_DCR && dos != OC_DOS_RFNOP) {
    OC_DBG("oc_sec_check_acl: resource is NCR and dos is not RFNOP");
    return false;
  }

  const bool is_vertical =
    !is_DCR && oc_core_is_vertical_resource(resource, resource->device);
  /* anon-clear access to vertical resources is prohibited */
  if (is_vertical && (endpoint->flags & SECURED) == 0) {
    OC_DBG("oc_sec_check_acl: anon-clear access to vertical resources is "
           "prohibited");
    return false;
  }

  /* All requests received over the DOC which target DCRs shall be granted,
   * regardless of the configuration of the ACEs in the "/oic/sec/acl2"
   * Resource.
   */
  const oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (is_DCR && peer != NULL && peer->doc) {
    OC_DBG("oc_sec_check_acl: connection is DOC and request directed to DCR - "
           "access granted");
    return true;
  }

  if (method == OC_GET &&
      oc_sec_check_acl_on_get(resource, dos == OC_DOS_RFOTM)) {
    OC_DBG("oc_sec_check_acl: access granted to %s via special GET rule",
           oc_string(resource->uri));
    return true;
  }

  /* Requests over unsecured channel prior to DOC */
  if (dos == OC_DOS_RFOTM && oc_tls_num_peers(endpoint->device) == 0) {
    return oc_sec_check_acl_in_rfotm_prior_to_doc(method, resource);
  }

  bool is_SVR = oc_core_is_SVR(resource, resource->device);
  /* anon-clear requests to SVRs while the dos is RFPRO, RFNOP or SRESET
   * should not be authorized regardless of the ACL configuration */
  if (is_SVR && (endpoint->flags & SECURED) == 0 &&
      oc_sec_pstat_is_in_dos_state(ps, OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFPRO) |
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP) |
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_SRESET))) {
    OC_DBG("oc_sec_check_acl: anon-clear access to SVRs in RFPRO, RFNOP and "
           "SRESET is prohibited");
    return false;
  }

  const oc_uuid_t *uuid = &endpoint->di;
  // access to "/oic/sec/acl2", "/oic/sec/doxm", "/oic/sec/pstat" and
  // "/oic/sec/cred" is granted to the owner of the device
  if (oc_sec_check_acl_by_uuid(uuid, endpoint->device, resource)) {
    return true;
  }

#ifdef OC_PKI
  if (oc_sec_is_roles_resource_uri(oc_string_view2(&resource->uri)) &&
      oc_sec_pstat_is_in_dos_state(ps, OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFPRO) |
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP) |
                                         OC_PSTAT_DOS_ID_FLAG(OC_DOS_SRESET))) {
    OC_DBG("oc_acl: peer has implicit access to /oic/sec/roles in RFPRO, "
           "RFNOP, SRESET");
    return true;
  }
#endif /* OC_PKI */

  return oc_sec_check_acl_by_permissions(method, resource, is_DCR, is_SVR,
                                         endpoint, peer);
}

#endif /* OC_SECURITY */
