/*
// Copyright (c) 2016-2019 Intel Corporation
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

#include "oc_acl_internal.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm.h"
#include "oc_pstat.h"
#include "oc_rep.h"
#include "oc_roles.h"
#include "oc_store.h"
#include "oc_tls.h"
#include "port/oc_assert.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_acl_t *aclist;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_acl_t aclist[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

static const char *wc_all = "*";
static const char *wc_secured = "+";
static const char *wc_public = "-";

#define MAX_NUM_RES_PERM_PAIRS                                                 \
  ((OC_MAX_NUM_SUBJECTS + 2) *                                                 \
   (OC_MAX_APP_RESOURCES + OCF_D * OC_MAX_NUM_DEVICES))
OC_MEMB(ace_l, oc_sec_ace_t, MAX_NUM_RES_PERM_PAIRS);
OC_MEMB(res_l, oc_ace_res_t, OC_MAX_APP_RESOURCES + OCF_D * OC_MAX_NUM_DEVICES);

void
oc_sec_acl_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  aclist =
    (oc_sec_acl_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_acl_t));
  if (!aclist) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    OC_LIST_STRUCT_INIT(&aclist[i], subjects);
  }
}

oc_sec_acl_t *
oc_sec_get_acl(size_t device)
{
  return &aclist[device];
}

static bool
unique_aceid(int aceid, size_t device)
{
  oc_sec_ace_t *ace = oc_list_head(aclist[device].subjects);
  while (ace != NULL) {
    if (ace->aceid == aceid)
      return false;
    ace = ace->next;
  }
  return true;
}

static int
get_new_aceid(size_t device)
{
  int aceid;
  do {
    aceid = oc_random_value() >> 1;
  } while (!unique_aceid(aceid, device));
  return aceid;
}

static oc_ace_res_t *
oc_sec_ace_find_resource(oc_ace_res_t *start, oc_sec_ace_t *ace,
                         const char *href, oc_ace_wildcard_t wildcard)
{
  int skip = 0;
  if (href && href[0] != '/')
    skip = 1;
  oc_ace_res_t *res = start;
  if (!res) {
    res = (oc_ace_res_t *)oc_list_head(ace->resources);
  } else {
    res = res->next;
  }

  while (res != NULL) {
    bool positive = false, match = true;
    if (href && oc_string_len(res->href) > 0) {
      if ((strlen(href) + skip) != oc_string_len(res->href) ||
          memcmp(oc_string(res->href) + skip, href,
                 oc_string_len(res->href) - skip) != 0) {
        match = false;
      } else {
        positive = true;
      }
    }

    if (match && wildcard != 0 && res->wildcard != 0) {
      if (wildcard != OC_ACE_WC_ALL && (wildcard & res->wildcard) != 0) {
        positive = true;
      } else if (wildcard == OC_ACE_WC_ALL && res->wildcard == OC_ACE_WC_ALL) {
        positive = true;
      } else {
        match = false;
      }
    }

    if (match && positive) {
      return res;
    }

    res = res->next;
  }

  return res;
}

static oc_sec_ace_t *
oc_sec_acl_find_subject(oc_sec_ace_t *start, oc_ace_subject_type_t type,
                        oc_ace_subject_t *subject, int aceid,
                        uint16_t permission, const char *tag, bool match_tag,
                        size_t device)
{
  oc_sec_ace_t *ace = start;
  if (!ace) {
    ace = (oc_sec_ace_t *)oc_list_head(aclist[device].subjects);
  } else {
    ace = ace->next;
  }
  size_t tag_len = tag != NULL ? strlen(tag) : 0;
  while (ace != NULL) {
    if (aceid != -1 && ace->aceid != aceid) {
      goto next_ace;
    }
    if (permission != 0 && ace->permission != permission) {
      goto next_ace;
    }
    if (match_tag) {
      if (tag == NULL) {
        if (oc_string(ace->tag) != NULL) {
          goto next_ace;
        }
      } else {
        if (oc_string(ace->tag) == NULL || oc_string_len(ace->tag) != tag_len ||
            memcmp(oc_string(ace->tag), tag, oc_string_len(ace->tag)) != 0) {
          goto next_ace;
        }
      }
    }
    if (ace->subject_type == type) {
      switch (type) {
      case OC_SUBJECT_UUID:
        if (memcmp(subject->uuid.id, ace->subject.uuid.id, 16) == 0) {
          return ace;
        }
        break;
      case OC_SUBJECT_ROLE:
        if ((oc_string_len(subject->role.role) ==
               oc_string_len(ace->subject.role.role) &&
             memcmp(oc_string(subject->role.role),
                    oc_string(ace->subject.role.role),
                    oc_string_len(subject->role.role)) == 0)) {
          if (oc_string_len(ace->subject.role.authority) == 0) {
            return ace;
          } else if (oc_string_len(ace->subject.role.authority) ==
                       oc_string_len(subject->role.authority) &&
                     memcmp(oc_string(subject->role.authority),
                            oc_string(ace->subject.role.authority),
                            oc_string_len(subject->role.authority)) == 0) {
            return ace;
          }
        }
        break;
      case OC_SUBJECT_CONN:
        if (subject->conn == ace->subject.conn) {
          return ace;
        }
        break;
      }
    }
  next_ace:
    ace = ace->next;
  }
  return ace;
}

static uint16_t
oc_ace_get_permission(oc_sec_ace_t *ace, oc_resource_t *resource, bool is_DCR,
                      bool is_public)
{
  uint16_t permission = 0;

  /* If the resource is discoverable and exposes >=1 unsecured endpoints
   * then match with ACEs bearing any of the 3 wildcard resources.
   * If the resource is discoverable and does not expose any unsecured endpoint,
   * then match with ACEs bearing either OC_ACE_WC_ALL_SECURED or OC_ACE_WC_ALL.
   * If the resource is not discoverable, then match only with ACEs bearing
   *  OC_ACE_WC_ALL.
   */
  oc_ace_wildcard_t wc = 0;
  if (!is_DCR) {
    if (resource->properties & OC_DISCOVERABLE) {
      if (is_public) {
        wc = OC_ACE_WC_ALL_PUBLIC | OC_ACE_WC_ALL_SECURED;
      } else {
        wc = OC_ACE_WC_ALL_SECURED;
      }
    } else {
      wc = OC_ACE_WC_ALL;
    }
  }

  oc_ace_res_t *res =
    oc_sec_ace_find_resource(NULL, ace, oc_string(resource->uri), wc);

  while (res != NULL) {
    permission |= ace->permission;

    res = oc_sec_ace_find_resource(res, ace, oc_string(resource->uri), wc);
  }

  return permission;
}

#ifdef OC_DEBUG
static void
dump_acl(size_t device)
{
  oc_sec_acl_t *a = &aclist[device];
  oc_sec_ace_t *ace = oc_list_head(a->subjects);
  PRINT("\nAccess Control List\n---------\n");
  while (ace != NULL) {
    PRINT("\n---------\nAce: %d\n---------\n", ace->aceid);
    switch (ace->subject_type) {
    case OC_SUBJECT_UUID: {
      char u[OC_UUID_LEN];
      oc_uuid_to_str(&ace->subject.uuid, u, OC_UUID_LEN);
      PRINT("UUID: %s\n", u);
    } break;
    case OC_SUBJECT_CONN: {
      switch (ace->subject.conn) {
      case OC_CONN_AUTH_CRYPT:
        PRINT("CONN: auth-crypt\n");
        break;
      case OC_CONN_ANON_CLEAR:
        PRINT("CONN: anon-clear\n");
        break;
      }
    } break;
    case OC_SUBJECT_ROLE: {
      PRINT("Role_RoleId: %s\n", oc_string(ace->subject.role.role));
      if (oc_string_len(ace->subject.role.authority) > 0) {
        PRINT("Role_Authority: %s\n", oc_string(ace->subject.role.authority));
      }
    } break;
    }

    oc_ace_res_t *r = oc_list_head(ace->resources);
    PRINT("\nResources:\n");
    while (r != NULL) {
      if (oc_string_len(r->href) > 0) {
        PRINT("href: %s\n", oc_string(r->href));
      }
      switch (r->wildcard) {
      case OC_ACE_NO_WC:
        PRINT("No wildcard\n");
        break;
      case OC_ACE_WC_ALL:
        PRINT("Wildcard: *\n");
        break;
      case OC_ACE_WC_ALL_SECURED:
        PRINT("Wildcard: +\n");
        break;
      case OC_ACE_WC_ALL_PUBLIC:
        PRINT("Wildcard: -\n");
        break;
      }
      PRINT("Permission: %d\n", ace->permission);
      r = r->next;
    }
    ace = ace->next;
  }
}
#endif /* OC_DEBUG */

static uint16_t
get_role_permissions(oc_sec_cred_t *role_cred, oc_resource_t *resource,
                     size_t device, bool is_DCR, bool is_public)
{
  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  do {
    match = oc_sec_acl_find_subject(match, OC_SUBJECT_ROLE,
                                    (oc_ace_subject_t *)&role_cred->role,
                                    /*aceid*/ -1, /*permission*/ 0,
                                    /*tag*/ NULL, /*match_tag*/ false, device);

    if (match) {
      permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
      OC_DBG("oc_check_acl: Found ACE with permission %d for matching role",
             permission);
    }
  } while (match);
  return permission;
}

bool
oc_sec_check_acl(oc_method_t method, oc_resource_t *resource,
                 oc_endpoint_t *endpoint)
{
#ifdef OC_DEBUG
  dump_acl(endpoint->device);
#endif /* OC_DEBUG */

  bool is_DCR = oc_core_is_DCR(resource, resource->device);
  bool is_SVR = oc_core_is_SVR(resource, resource->device);
  bool is_public = ((resource->properties & OC_SECURE) == 0);
  bool is_vertical = false;
  if (!is_DCR) {
    is_vertical = oc_core_is_vertical_resource(resource, resource->device);
  }

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(endpoint->device);
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  /* All unicast requests which are not received over the open Device DOC
   * shall be rejected with an appropriate error message (e.g. forbidden),
   * regardless of the configuration of the ACEs in the "/oic/sec/acl2"
   * Resource.
   */
  if (pstat->s == OC_DOS_RFOTM && !(endpoint->flags & SECURED) &&
      oc_tls_num_peers(endpoint->device) == 1) {
    OC_DBG("oc_sec_check_acl: unencrypted request received while DOC is open - "
           "acess forbidden");
    return false;
  }
  /* NCRs are accessible only in RFNOP */
  if (!is_DCR && pstat->s != OC_DOS_RFNOP) {
    OC_DBG("oc_sec_check_acl: resource is NCR and dos is not RFNOP");
    return false;
  }
  /* anon-clear access to vertical resources is prohibited */
  if (is_vertical && !(endpoint->flags & SECURED)) {
    OC_DBG("oc_sec_check_acl: anon-clear access to vertical resources is "
           "prohibited");
    return false;
  }
  /* All requests received over the DOC which target DCRs shall be granted,
   * regardless of the configuration of the ACEs in the "/oic/sec/acl2"
   * Resource.
   */
  if (peer && peer->doc && is_DCR) {
    OC_DBG("oc_sec_check_acl: connection is DOC and request directed to DCR - "
           "access granted");
    return true;
  }
  /*  Retrieve requests to "/oic/res", "/oic/d" and "/oic/p" shall be
      granted.
      if enabled also the .well-known/core will be granted access,
      since this also a discovery resource.
  */
  if (pstat->s == OC_DOS_RFOTM && method == OC_GET &&
      ((oc_string_len(resource->uri) == 8 &&
        memcmp(oc_string(resource->uri), "/oic/res", 8) == 0) ||
       (oc_string_len(resource->uri) == 6 &&
        memcmp(oc_string(resource->uri), "/oic/d", 6) == 0) ||
       (oc_string_len(resource->uri) == 6 &&
        memcmp(oc_string(resource->uri), "/oic/p", 6) == 0))) {
    return true;
  }

#ifdef OC_WKCORE
  if (method == OC_GET &&
      (oc_string_len(resource->uri) == 17 &&
       memcmp(oc_string(resource->uri), "/.well-known/core", 17) == 0)) {
    return true;
  }
#endif

  /* GET requests to /oic/sec/doxm are always granted.
   * This is to ensure that multicast discovery using UUID filtered requests
   * to /oic/sec/doxm is not blocked.
   *
   * The security implications of allowing universal read access to
   * /oic/sec/doxm have not been thoroughly discussed. Enabling the following
   * define is FOR DEVELOPMENT USE ONLY.
   */
#ifdef OC_DOXM_UUID_FILTER
  if (oc_string_len(resource->uri) == 13 && method == OC_GET &&
      memcmp(oc_string(resource->uri), "/oic/sec/doxm", 13) == 0) {
    OC_DBG("oc_sec_check_acl: R access granted to /doxm");
    return true;
  }
#endif

  /* Requests over unsecured channel prior to DOC */
  if (pstat->s == OC_DOS_RFOTM && oc_tls_num_peers(endpoint->device) == 0) {
    /* Anonymous Retrieve and Updates requests to “/oic/sec/doxm” shall be
       granted.
    */
    if (oc_string_len(resource->uri) == 13 &&
        memcmp(oc_string(resource->uri), "/oic/sec/doxm", 13) == 0) {
      OC_DBG("oc_sec_check_acl: RW access granted to /doxm  prior to DOC");
      return true;
    }
    /* All Retrieve requests to the “/oic/sec/pstat” Resource shall be
       granted.
    */
    else if (oc_string_len(resource->uri) == 14 &&
             memcmp(oc_string(resource->uri), "/oic/sec/pstat", 14) == 0 &&
             method == OC_GET) {
      OC_DBG("oc_sec_check_acl: R access granted to pstat prior to DOC");
      return true;
    }
    /* Reject all other requests */
    else {
      return false;
    }
  }

  if ((pstat->s == OC_DOS_RFPRO || pstat->s == OC_DOS_RFNOP ||
       pstat->s == OC_DOS_SRESET) &&
      !(endpoint->flags & SECURED)) {
    /* anon-clear requests to SVRs while the
     * dos is RFPRO, RFNOP or SRESET should not be authorized
     * regardless of the ACL configuration.
     */
    if (is_SVR) {
      OC_DBG("oc_sec_check_acl: anon-clear access to SVRs in RFPRO, RFNOP and "
             "SRESET is prohibited");
      return false;
    }
  }

  oc_uuid_t *uuid = &endpoint->di;

  if (uuid) {
    oc_sec_doxm_t *doxm = oc_sec_get_doxm(endpoint->device);
    oc_sec_creds_t *creds = oc_sec_get_creds(endpoint->device);
    if (memcmp(uuid->id, aclist[endpoint->device].rowneruuid.id, 16) == 0 &&
        oc_string_len(resource->uri) == 13 &&
        memcmp(oc_string(resource->uri), "/oic/sec/acl2", 13) == 0) {
      OC_DBG("oc_acl: peer's UUID matches acl2's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, doxm->rowneruuid.id, 16) == 0 &&
        oc_string_len(resource->uri) == 13 &&
        memcmp(oc_string(resource->uri), "/oic/sec/doxm", 13) == 0) {
      OC_DBG("oc_acl: peer's UUID matches doxm's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, pstat->rowneruuid.id, 16) == 0 &&
        oc_string_len(resource->uri) == 14 &&
        memcmp(oc_string(resource->uri), "/oic/sec/pstat", 14) == 0) {
      OC_DBG("oc_acl: peer's UUID matches pstat's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, creds->rowneruuid.id, 16) == 0 &&
        oc_string_len(resource->uri) == 13 &&
        memcmp(oc_string(resource->uri), "/oic/sec/cred", 13) == 0) {
      OC_DBG("oc_acl: peer's UUID matches cred's rowneruuid");
      return true;
    }

    if ((pstat->s == OC_DOS_RFPRO || pstat->s == OC_DOS_RFNOP ||
         pstat->s == OC_DOS_SRESET) &&
        oc_string_len(resource->uri) == 14 &&
        memcmp(oc_string(resource->uri), "/oic/sec/roles", 14) == 0) {
      OC_DBG("oc_acl: peer has implicit access to /oic/sec/roles in RFPRO, "
             "RFNOP, SRESET");
      return true;
    }
  }

  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  if (uuid) {
    do {
      match = oc_sec_acl_find_subject(
        match, OC_SUBJECT_UUID, (oc_ace_subject_t *)uuid, /*aceid*/ -1,
        /*permission*/ 0, /*tag*/ NULL, /*match_tag*/ false, endpoint->device);

      if (match) {
        permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
        OC_DBG("oc_check_acl: Found ACE with permission %d for subject UUID",
               permission);
      }
    } while (match);

    if (peer && oc_tls_uses_psk_cred(peer)) {
      oc_sec_cred_t *role_cred = NULL;
      do {
        role_cred = oc_sec_find_cred(role_cred, uuid, OC_CREDTYPE_PSK,
                                     OC_CREDUSAGE_NULL, endpoint->device);
        if (role_cred == NULL) {
          break;
        }
        if (oc_string_len(role_cred->role.role) > 0) {
          permission |= get_role_permissions(
            role_cred, resource, endpoint->device, is_DCR, is_public);
        }
        role_cred = role_cred->next;
      } while (role_cred != NULL);
    }
#ifdef OC_PKI
    else {
      oc_sec_cred_t *role_cred = peer ? oc_sec_get_roles(peer) : NULL, *next;
      while (role_cred) {
        next = role_cred->next;
        if (oc_certs_validate_role_cert(role_cred->ctx) < 0) {
          oc_sec_free_role(role_cred, peer);
          role_cred = next;
          continue;
        }
        if (oc_string_len(role_cred->role.role) == strlen("oic.role.owner") &&
            memcmp(oc_string(role_cred->role.role), "oic.role.owner",
                   oc_string_len(role_cred->role.role)) == 0) {
          OC_DBG("oc_acl: peer's role matches \"oic.role.owner\"");
          return true;
        }
        permission |= get_role_permissions(role_cred, resource,
                                           endpoint->device, is_DCR, is_public);
        role_cred = role_cred->next;
      }
    }
#endif /* OC_PKI */
  }

  /* Access to SVRs via auth-crypt ACEs is prohibited */
  if (!is_SVR && endpoint->flags & SECURED) {
    oc_ace_subject_t _auth_crypt;
    memset(&_auth_crypt, 0, sizeof(oc_ace_subject_t));
    _auth_crypt.conn = OC_CONN_AUTH_CRYPT;
    do {
      match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, &_auth_crypt,
                                      /*aceid*/ -1, /*permission*/ 0,
                                      /*tag*/ NULL, /*match_tag*/ false,
                                      endpoint->device);
      if (match) {
        permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
        OC_DBG("oc_check_acl: Found ACE with permission %d for auth-crypt "
               "connection",
               permission);
      }
    } while (match);
  }

  /* Access to SVRs via anon-clear ACEs is prohibited */
  if (!is_SVR) {
    oc_ace_subject_t _anon_clear;
    memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
    _anon_clear.conn = OC_CONN_ANON_CLEAR;
    do {
      match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, &_anon_clear,
                                      /*aceid*/ -1, /*permission*/ 0,
                                      /*tag*/ NULL, /*match_tag*/ false,
                                      endpoint->device);
      if (match) {
        permission |= oc_ace_get_permission(match, resource, is_DCR, is_public);
        OC_DBG("oc_check_acl: Found ACE with permission %d for anon-clear "
               "connection",
               permission);
      }
    } while (match);
  }
  if (permission != 0) {
    switch (method) {
    case OC_GET:
      if ((permission & OC_PERM_RETRIEVE) || (permission & OC_PERM_NOTIFY)) {
        return true;
      }
      break;
    case OC_PUT:
    case OC_POST:
      if ((permission & OC_PERM_CREATE) || (permission & OC_PERM_UPDATE)) {
        return true;
      }
      break;
    case OC_DELETE:
      if (permission & OC_PERM_DELETE) {
        return true;
      }
      break;
    default:
      break;
    }
  }
  return false;
}

bool
oc_sec_encode_acl(size_t device, oc_interface_mask_t iface_mask,
                  bool to_storage)
{
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_ACL, device));
  }
  oc_rep_set_array(root, aclist2);
  oc_sec_ace_t *sub = oc_list_head(aclist[device].subjects);

  while (sub != NULL) {
    oc_rep_object_array_start_item(aclist2);
    oc_rep_set_object(aclist2, subject);
    switch (sub->subject_type) {
    case OC_SUBJECT_UUID:
      oc_uuid_to_str(&sub->subject.uuid, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(subject, uuid, uuid);
      break;
    case OC_SUBJECT_ROLE:
      oc_rep_set_text_string(subject, role, oc_string(sub->subject.role.role));
      if (oc_string_len(sub->subject.role.authority) > 0) {
        oc_rep_set_text_string(subject, authority,
                               oc_string(sub->subject.role.authority));
      }
      break;
    case OC_SUBJECT_CONN: {
      switch (sub->subject.conn) {
      case OC_CONN_AUTH_CRYPT:
        oc_rep_set_text_string(subject, conntype, "auth-crypt");
        break;
      case OC_CONN_ANON_CLEAR:
        oc_rep_set_text_string(subject, conntype, "anon-clear");
        break;
      }
    } break;
    }
    oc_rep_close_object(aclist2, subject);

    oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(sub->resources);
    oc_rep_set_array(aclist2, resources);

    while (res != NULL) {
      oc_rep_object_array_start_item(resources);
      if (oc_string_len(res->href) > 0) {
        oc_rep_set_text_string(resources, href, oc_string(res->href));
      } else {
        switch (res->wildcard) {
        case OC_ACE_WC_ALL_SECURED:
          oc_rep_set_text_string(resources, wc, wc_secured);
          break;
        case OC_ACE_WC_ALL_PUBLIC:
          oc_rep_set_text_string(resources, wc, wc_public);
          break;
        case OC_ACE_WC_ALL:
          oc_rep_set_text_string(resources, wc, wc_all);
          break;
        default:
          break;
        }
      }
      oc_rep_object_array_end_item(resources);
      res = res->next;
    }
    oc_rep_close_array(aclist2, resources);
    oc_rep_set_uint(aclist2, permission, sub->permission);
    oc_rep_set_int(aclist2, aceid, sub->aceid);
    if (to_storage) {
      if (oc_string_len(sub->tag) > 0) {
        oc_rep_set_text_string(aclist2, tag, oc_string(sub->tag));
      }
    }
    oc_rep_object_array_end_item(aclist2);
    sub = sub->next;
  }
  oc_rep_close_array(root, aclist2);
  oc_uuid_to_str(&aclist[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();

  return true;
}

static oc_sec_ace_t *
oc_sec_add_new_ace(oc_ace_subject_type_t type, oc_ace_subject_t *subject,
                   int aceid, uint16_t permission, const char *tag,
                   size_t device)
{
  oc_sec_ace_t *ace = oc_memb_alloc(&ace_l);
  if (!ace) {
    OC_WRN("insufficient memory to add new ACE");
    return NULL;
  }

  OC_LIST_STRUCT_INIT(ace, resources);

  if (type == OC_SUBJECT_ROLE) {
    OC_DBG("Adding ACE for role %s", oc_string(subject->role.role));
    oc_new_string(&ace->subject.role.role, oc_string(subject->role.role),
                  oc_string_len(subject->role.role));
    if (oc_string_len(subject->role.authority) > 0) {
      oc_new_string(&ace->subject.role.authority,
                    oc_string(subject->role.authority),
                    oc_string_len(subject->role.authority));
    }
  } else {
    memcpy(&ace->subject, subject, sizeof(oc_ace_subject_t));
#ifdef OC_DEBUG
    if (type == OC_SUBJECT_UUID) {
      char c[OC_UUID_LEN];
      oc_uuid_to_str(&ace->subject.uuid, c, OC_UUID_LEN);
      OC_DBG("Adding ACE for subject %s", c);
    } else if (type == OC_SUBJECT_CONN) {
      if (ace->subject.conn == OC_CONN_ANON_CLEAR) {
        OC_DBG("Adding ACE for anon-clear connection");
      } else {
        OC_DBG("Adding ACE for auth-crypt connection");
      }
    }
#endif /* OC_DEBUG */
  }

  ace->subject_type = type;

  if (aceid == -1) {
    ace->aceid = get_new_aceid(device);
  } else {
    ace->aceid = aceid;
  }

  ace->permission = permission;
  if (tag) {
    oc_new_string(&ace->tag, tag, strlen(tag));
  }

  oc_list_add(aclist[device].subjects, ace);
  return ace;
}

static oc_ace_res_t *
oc_sec_add_new_ace_res(const char *href, oc_ace_wildcard_t wildcard,
                       uint16_t permission)
{
  oc_ace_res_t *res = oc_memb_alloc(&res_l);
  if (!res) {
    OC_WRN("insufficient memory to add new resource to ACE");
    return NULL;
  }
  res->wildcard = 0;
  if (wildcard != OC_ACE_NO_WC) {
    res->wildcard = wildcard;
  }
#ifdef OC_DEBUG
  switch (res->wildcard) {
  case OC_ACE_WC_ALL_SECURED:
    OC_DBG("Adding wildcard resource + with permission %d", permission);
    break;
  case OC_ACE_WC_ALL_PUBLIC:
    OC_DBG("Adding wildcard resource - with permission %d", permission);
    break;
  case OC_ACE_WC_ALL:
    OC_DBG("Adding wildcard resource * with permission %d", permission);
    break;
  default:
    break;
  }
#else  /* !OC_DEBUG */
  (void)permission;
#endif /* OC_DEBUG */

  if (href) {
    oc_new_string(&res->href, href, strlen(href));
    OC_DBG("Adding resource %s with permission %d", href, permission);
  }
  return res;
}

typedef struct oc_ace_res_data_t
{
  oc_ace_res_t *res;
  bool created;
} oc_ace_res_data_t;

static oc_ace_res_data_t
oc_sec_ace_get_res(oc_sec_ace_t *ace, const char *href,
                   oc_ace_wildcard_t wildcard, uint16_t permission, bool create)
{
  oc_assert(ace != NULL);
  oc_ace_res_t *res = oc_sec_ace_find_resource(NULL, ace, href, wildcard);
  if (res) {
    oc_ace_res_data_t data = { res, false };
    return data;
  }
  if (create) {
    res = oc_sec_add_new_ace_res(href, wildcard, permission);
  }
  if (!res) {
    oc_ace_res_data_t data = { NULL, false };
    return data;
  }
  oc_list_add(ace->resources, res);
  oc_ace_res_data_t data = { res, true };
  return data;
}

typedef struct oc_sec_ace_update_data_t
{
  oc_sec_ace_t *ace;
  bool created;
  bool created_resource;
} oc_sec_ace_update_data_t;

static bool
oc_sec_ace_update_res(oc_ace_subject_type_t type, oc_ace_subject_t *subject,
                      int aceid, uint16_t permission, const char *tag,
                      const char *href, oc_ace_wildcard_t wildcard,
                      size_t device, oc_sec_ace_update_data_t *data)
{
  oc_sec_ace_t *ace = oc_sec_acl_find_subject(
    NULL, type, subject, aceid, permission, tag, /*match_tag*/ true, device);
  bool created = false;
  if (!ace) {
    ace = oc_sec_add_new_ace(type, subject, aceid, permission, tag, device);
    if (!ace) {
      return false;
    }
    created = true;
  }
  oc_ace_res_data_t res_data =
    oc_sec_ace_get_res(ace, href, wildcard, permission, true);
  if (res_data.res == NULL) {
    oc_sec_remove_ace(ace, device);
    return false;
  }

  if (data) {
    data->ace = ace;
    data->created = created;
    data->created_resource = res_data.created;
  }
  return true;
}

static void
oc_ace_free_resources(size_t device, oc_sec_ace_t **ace, const char *href)
{
  oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head((*ace)->resources),
               *next = NULL;
  while (res != NULL) {
    next = res->next;
    if (href == NULL ||
        (oc_string_len(res->href) == strlen(href) &&
         memcmp(href, oc_string(res->href), strlen(href)) == 0)) {
      oc_free_string(&res->href);
      oc_list_remove((*ace)->resources, res);
      oc_memb_free(&res_l, res);
    }
    res = next;
  }

  if (href && oc_list_length((*ace)->resources) == 0) {
    oc_list_remove(aclist[device].subjects, *ace);
    oc_memb_free(&ace_l, *ace);
    *ace = NULL;
  }
}

static void
oc_acl_free_ace(oc_sec_ace_t *ace, size_t device)
{
  oc_ace_free_resources(device, &ace, NULL);
  if (ace->subject_type == OC_SUBJECT_ROLE) {
    oc_free_string(&ace->subject.role.role);
    oc_free_string(&ace->subject.role.authority);
  }
  oc_free_string(&ace->tag);
  oc_memb_free(&ace_l, ace);
}

oc_sec_ace_t *
oc_sec_get_ace_by_aceid(int aceid, size_t device)
{
  oc_sec_ace_t *ace = oc_list_head(aclist[device].subjects);
  while (ace != NULL) {
    if (ace->aceid == aceid) {
      return ace;
    }
    ace = ace->next;
  }
  return NULL;
}

static oc_sec_ace_t *
oc_acl_remove_ace_from_device(oc_sec_ace_t *ace, size_t device)
{
  return oc_list_remove2(aclist[device].subjects, ace);
}

static oc_sec_ace_t *
oc_acl_remove_ace_from_device_by_aceid(int aceid, size_t device)
{
  oc_sec_ace_t *ace = oc_sec_get_ace_by_aceid(aceid, device);
  if (ace) {
    return oc_acl_remove_ace_from_device(ace, device);
  }
  return false;
}

void
oc_sec_remove_ace(oc_sec_ace_t *ace, size_t device)
{
  oc_acl_remove_ace_from_device(ace, device);
  oc_acl_free_ace(ace, device);
}

bool
oc_sec_remove_ace_by_aceid(int aceid, size_t device)
{
  bool removed = false;
  oc_sec_ace_t *ace = oc_acl_remove_ace_from_device_by_aceid(aceid, device);
  if (ace != NULL) {
    oc_acl_free_ace(ace, device);
    removed = true;
  }
  return removed;
}

static void
oc_sec_clear_acl(size_t device)
{
  oc_sec_acl_t *acl_d = &aclist[device];
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_list_pop(acl_d->subjects);
  while (ace != NULL) {
    oc_acl_free_ace(ace, device);
    ace = (oc_sec_ace_t *)oc_list_pop(acl_d->subjects);
  }
}

void
oc_sec_acl_free(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_clear_acl(device);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (aclist) {
    free(aclist);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

#if defined(OC_SERVER) && defined(OC_COLLECTIONS) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
bool
oc_sec_acl_add_created_resource_ace(const char *href, oc_endpoint_t *client,
                                    size_t device, bool collection)
{
  oc_uuid_t *uuid = &client->di;

  oc_ace_subject_t subject;
  memset(&subject, 0, sizeof(oc_ace_subject_t));
  memcpy(subject.uuid.id, uuid->id, sizeof(oc_uuid_t));

  oc_ace_permissions_t perm =
    OC_PERM_RETRIEVE | OC_PERM_DELETE | OC_PERM_UPDATE;
  if (collection) {
    perm |= OC_PERM_CREATE;
  }

  return oc_sec_ace_update_res(OC_SUBJECT_UUID, &subject, -1, perm, NULL, href,
                               0, device, NULL);
}
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

void
oc_sec_acl_default(size_t device)
{
  oc_sec_clear_acl(device);
  memset(&aclist[device].rowneruuid, 0, sizeof(oc_uuid_t));
  oc_sec_dump_acl(device);
}

bool
oc_sec_decode_acl(oc_rep_t *rep, bool from_storage, size_t device,
                  oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                  void *on_apply_ace_data)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  size_t len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(t->name), "rowneruuid", 10) == 0) {
        if (!from_storage && (ps->s == OC_DOS_RFNOP || ps->s == OC_DOS_RFPRO)) {
          OC_ERR("oc_acl: Cannot set rowneruuid in RFNOP/RFPRO");
          return false;
        }
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      if (!from_storage && ps->s == OC_DOS_RFNOP) {
        OC_ERR("oc_acl: Cannot provision ACE in RFNOP");
        return false;
      }
    } break;
    default:
      break;
    }
    t = t->next;
  }

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string),
                       &aclist[device].rowneruuid);
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *aclist2 = rep->value.object_array;
      while (aclist2 != NULL) {
        oc_ace_subject_t subject;
        oc_ace_subject_type_t subject_type = 0;
        uint16_t permission = 0;
        int aceid = -1;
        char *tag = NULL;
        oc_rep_t *resources = 0;
        memset(&subject, 0, sizeof(oc_ace_subject_t));
        oc_rep_t *ace = aclist2->value.object;
        while (ace != NULL) {
          len = oc_string_len(ace->name);
          switch (ace->type) {
          case OC_REP_INT:
            if (len == 10 &&
                memcmp(oc_string(ace->name), "permission", 10) == 0) {
              permission = (uint16_t)ace->value.integer;
            } else if (len == 5 &&
                       memcmp(oc_string(ace->name), "aceid", 5) == 0) {
              aceid = (int)ace->value.integer;
            }
            break;

          case OC_REP_STRING:
            if (len == 3 && memcmp(oc_string(ace->name), "tag", 3) == 0) {
              tag = oc_string(ace->value.string);
            }
            break;
          case OC_REP_OBJECT_ARRAY:
            if (len == 9 && memcmp(oc_string(ace->name), "resources", 9) == 0)
              resources = ace->value.object_array;
            break;
          case OC_REP_OBJECT: {
            oc_rep_t *sub = ace->value.object;
            while (sub != NULL) {
              len = oc_string_len(sub->name);
              if (len == 4 && memcmp(oc_string(sub->name), "uuid", 4) == 0) {
                oc_str_to_uuid(oc_string(sub->value.string), &subject.uuid);
                subject_type = OC_SUBJECT_UUID;
              } else if (len == 4 &&
                         memcmp(oc_string(sub->name), "role", 4) == 0) {
                oc_new_string(&subject.role.role, oc_string(sub->value.string),
                              oc_string_len(sub->value.string));
                subject_type = OC_SUBJECT_ROLE;
              } else if (len == 9 &&
                         memcmp(oc_string(sub->name), "authority", 9) == 0) {
                oc_new_string(&subject.role.authority,
                              oc_string(sub->value.string),
                              oc_string_len(sub->value.string));
                subject_type = OC_SUBJECT_ROLE;
              } else if (len == 8 &&
                         memcmp(oc_string(sub->name), "conntype", 8) == 0) {
                if (oc_string_len(sub->value.string) == 10 &&
                    memcmp(oc_string(sub->value.string), "auth-crypt", 10) ==
                      0) {
                  subject.conn = OC_CONN_AUTH_CRYPT;
                } else if (oc_string_len(sub->value.string) == 10 &&
                           memcmp(oc_string(sub->value.string), "anon-clear",
                                  10) == 0) {
                  subject.conn = OC_CONN_ANON_CLEAR;
                }
                subject_type = OC_SUBJECT_CONN;
              }
              sub = sub->next;
            }
          } break;
          default:
            break;
          }
          ace = ace->next;
        }

        oc_sec_ace_t *upd_ace = NULL;
        oc_sec_ace_t *replaced_ace = NULL;
        bool created = false;
        bool created_resource = false;
        if (aceid != -1 && !unique_aceid(aceid, device)) {
          replaced_ace = oc_acl_remove_ace_from_device_by_aceid(aceid, device);
        }

        while (resources != NULL) {
          oc_ace_wildcard_t wc = OC_ACE_NO_WC;
          oc_rep_t *resource = resources->value.object;
          const char *href = 0;
          /*
      #ifdef OC_SERVER
          oc_resource_properties_t wc_r = 0;
      #endif
          */

          while (resource != NULL) {
            switch (resource->type) {
            case OC_REP_STRING:
              if (oc_string_len(resource->name) == 4 &&
                  memcmp(oc_string(resource->name), "href", 4) == 0) {
                href = oc_string(resource->value.string);
              } else if (oc_string_len(resource->name) == 2 &&
                         memcmp(oc_string(resource->name), "wc", 2) == 0) {
                if (oc_string(resource->value.string)[0] == '*') {
                  wc = OC_ACE_WC_ALL;
                  /*
            #ifdef OC_SERVER
                  wc_r = ~0;
            #endif
                  */
                }
                if (oc_string(resource->value.string)[0] == '+') {
                  wc = OC_ACE_WC_ALL_SECURED;
                  /*
            #ifdef OC_SERVER
                  wc_r = ~0;
            #endif
                  */
                }
                if (oc_string(resource->value.string)[0] == '-') {
                  wc = OC_ACE_WC_ALL_PUBLIC;
                  /*
            #ifdef OC_SERVER
                  wc_r = ~OC_DISCOVERABLE;
            #endif
                  */
                }
              }
              break;
            default:
              break;
            }

            resource = resource->next;
          }

          oc_sec_ace_update_data_t ace_upd = { NULL, false, false };
          if (oc_sec_ace_update_res(subject_type, &subject, aceid, permission,
                                    tag, href, wc, device, &ace_upd)) {
            upd_ace = ace_upd.ace;
            created |= ace_upd.created;
            created_resource |= ace_upd.created_resource;
          } else {
            OC_WRN("failed to create resource(href:%s wildcard:%d)",
                   href != NULL ? href : "", wc);
          }

          /* The following code block attaches "coap" endpoints to
                   resources linked to an anon-clear ACE. This logic is being
                   currently disabled to comply with the SH spec which requires
                   that all vertical resources not expose a "coap" endpoint.
      #ifdef OC_SERVER
                if (subject_type == OC_SUBJECT_CONN &&
                    subject.conn == OC_CONN_ANON_CLEAR) {
                  if (href) {
                    oc_resource_t *r =
                      oc_ri_get_app_resource_by_uri(href, strlen(href), device);
                    if (r) {
                      oc_resource_make_public(r);
                    }
                  } else {
                    oc_resource_t *r = oc_ri_get_app_resources();
                    while (r != NULL) {
                      if ((r->properties & wc_r) == r->properties) {
                        oc_resource_make_public(r);
                      }
                      r = r->next;
                    }
                  }
                }
      #endif
          */
          resources = resources->next;
        }

        if (on_apply_ace_cb != NULL) {
          if (upd_ace != NULL) {
            oc_sec_on_apply_acl_data_t acl_data = { aclist[device].rowneruuid,
                                                    upd_ace, replaced_ace,
                                                    created, created_resource };
            on_apply_ace_cb(acl_data, on_apply_ace_data);
          }
        }

        if (replaced_ace) {
          oc_acl_free_ace(replaced_ace, device);
        }

        if (subject_type == OC_SUBJECT_ROLE) {
          oc_free_string(&subject.role.role);
          oc_free_string(&subject.role.authority);
        }

        aclist2 = aclist2->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

bool
oc_sec_acl_add_bootstrap_acl(size_t device)
{
  oc_ace_subject_t _anon_clear;
  memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
  _anon_clear.conn = OC_CONN_ANON_CLEAR;

  bool ret = true;
  if (!oc_sec_ace_update_res(OC_SUBJECT_CONN, &_anon_clear, -1,
                             OC_PERM_RETRIEVE, NULL, "/oic/res", OC_ACE_NO_WC,
                             device, NULL)) {
    OC_ERR("oc_acl: Failed to bootstrap %s resource", "/oic/res");
    ret = false;
  }
  if (!oc_sec_ace_update_res(OC_SUBJECT_CONN, &_anon_clear, -1,
                             OC_PERM_RETRIEVE, NULL, "/oic/d", OC_ACE_NO_WC,
                             device, NULL)) {
    OC_ERR("oc_acl: Failed to bootstrap %s resource", "/oic/d");
    ret = false;
  }
  if (!oc_sec_ace_update_res(OC_SUBJECT_CONN, &_anon_clear, -1,
                             OC_PERM_RETRIEVE, NULL, "/oic/p", OC_ACE_NO_WC,
                             device, NULL)) {
    OC_ERR("oc_acl: Failed to bootstrap %s resource", "/oic/p");
    ret = false;
  }
#ifdef OC_WKCORE
  if (!oc_sec_ace_update_res(OC_SUBJECT_CONN, &_anon_clear, -1,
                             OC_PERM_RETRIEVE, NULL, "/.well-known/core",
                             OC_ACE_NO_WC, device, NULL)) {
    OC_ERR("oc_acl: Failed to bootstrap %s resource", "/.well-known/core");
    ret = false;
  }
#endif
  return ret;
}

int
oc_sec_apply_acl(oc_rep_t *rep, size_t device,
                 oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                 void *on_apply_ace_data)
{
  if (oc_sec_decode_acl(rep, false, device, on_apply_ace_cb,
                        on_apply_ace_data)) {
    return 0;
  }
  return -1;
}

void
post_acl(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  if (oc_sec_decode_acl(request->request_payload, false,
                        request->resource->device, NULL, NULL)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_acl(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
delete_acl(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  oc_sec_pstat_t *ps = oc_sec_get_pstat(request->resource->device);
  if (ps->s == OC_DOS_RFNOP) {
    OC_ERR("oc_acl: Cannot DELETE ACE in RFNOP");
    oc_send_response(request, OC_STATUS_FORBIDDEN);
    return;
  }

  bool success = false;
  char *query_param = 0;
  int ret = oc_get_query_value(request, "aceid", &query_param);
  int aceid = 0;
  if (ret != -1) {
    aceid = (int)strtoul(query_param, NULL, 10);
    if (aceid != 0) {
      if (oc_sec_remove_ace_by_aceid(aceid, request->resource->device)) {
        success = true;
      }
    }
  } else if (ret == -1) {
    oc_sec_clear_acl(request->resource->device);
    success = true;
  }

  if (success) {
    oc_send_response(request, OC_STATUS_DELETED);
    oc_sec_dump_acl(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_NOT_FOUND);
  }
}

void
get_acl(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  if (oc_sec_encode_acl(request->resource->device, iface_mask, false)) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

#endif /* OC_SECURITY */
