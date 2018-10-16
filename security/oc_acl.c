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

#ifdef OC_SECURITY

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_doxm.h"
#include "oc_otm_state.h"
#include "oc_pstat.h"
#include "oc_rep.h"
#include "oc_store.h"
#include "oc_tls.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef OC_DYNAMIC_ALLOCATION

#include "port/oc_assert.h"
#include "util/oc_mem.h"

static oc_sec_acl_t *aclist;
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_acl_t aclist[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

static const char *auth_crypt = "auth-crypt";
static const char *anon_clear = "anon-clear";
static const char *wc_all = "*";
static const char *wc_discoverable = "+";
static const char *wc_non_discoverable = "-";

#define MAX_NUM_RES_PERM_PAIRS                                                 \
  ((OC_MAX_NUM_SUBJECTS + 2) *                                                 \
   (OC_MAX_APP_RESOURCES + OCF_D * OC_MAX_NUM_DEVICES))
OC_MEMB(ace_l, oc_sec_ace_t, MAX_NUM_RES_PERM_PAIRS);
OC_MEMB(res_l, oc_ace_res_t, OC_MAX_APP_RESOURCES + OCF_D * OC_MAX_NUM_DEVICES);

void
oc_sec_acl_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  aclist = (oc_sec_acl_t *)oc_mem_calloc(oc_core_get_num_devices(),
                                         sizeof(oc_sec_acl_t));
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
                         const char *href, oc_string_array_t *rt,
                         oc_interface_mask_t interfaces,
                         oc_ace_wildcard_t wildcard)
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
    bool match = true;
#if defined(OC_SPEC_VER_OIC)
    if (res->href.size == 2 && *oc_string(res->href) == '*')
      return res;
#endif //OC_SPEC_VER_OIC
    if (href && oc_string_len(res->href) > 0) {
      if ((strlen(href) + skip) != oc_string_len(res->href) ||
          memcmp(oc_string(res->href) + skip, href,
                 oc_string_len(res->href) - skip) != 0) {
        match = false;
      }
    }
    if (match && rt && oc_string_array_get_allocated_size(res->types) > 0) {
      size_t i, j;
      bool rt_match = false;
      for (i = 0; i < oc_string_array_get_allocated_size(*rt); i++) {
        const char *t = oc_string_array_get_item(*rt, i);
        for (j = 0; j < oc_string_array_get_allocated_size(res->types); j++) {
          const char *u = oc_string_array_get_item(res->types, j);
          if (strlen(u) == 1 && u[0] == '*') {
            break;
          }
          if (strlen(t) == strlen(u) && memcmp(t, u, strlen(t)) == 0) {
            rt_match = true;
            break;
          }
        }
      }
      if (!rt_match) {
        match = false;
      }
    }
    if (match && interfaces != 0 && res->interfaces != 0) {
      if ((interfaces & res->interfaces) == 0) {
        match = false;
      }
    }

    if (match && wildcard != 0 && res->wildcard != 0) {
      if ((wildcard & res->wildcard) == 0) {
        match = false;
      }
    }

    if (match) {
      return res;
    }

    res = res->next;
  }

  return res;
}

static oc_sec_ace_t *
oc_sec_acl_find_subject(oc_sec_ace_t *start, oc_ace_subject_type_t type,
                        oc_ace_subject_t *subject, int aceid,
                        uint16_t permission, size_t device)
{
  oc_sec_ace_t *ace = start;
  if (!ace) {
    ace = (oc_sec_ace_t *)oc_list_head(aclist[device].subjects);
  } else {
    ace = ace->next;
  }
  while (ace != NULL) {
    if (aceid != -1 && ace->aceid != aceid) {
      goto next_ace;
    }
    if (permission != 0 && ace->permission != permission) {
      goto next_ace;
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
          if (oc_string_len(ace->subject.role.authority) ==
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
oc_ace_get_permission(oc_sec_ace_t *ace, oc_resource_t *resource)
{
  uint16_t permission = 0;
  oc_ace_wildcard_t wc = (resource->properties & OC_DISCOVERABLE)
                           ? OC_ACE_WC_ALL_DISCOVERABLE
                           : OC_ACE_WC_ALL_NON_DISCOVERABLE;
  oc_ace_res_t *res =
    oc_sec_ace_find_resource(NULL, ace, oc_string(resource->uri),
                             &resource->types, resource->interfaces, wc);
  while (res != NULL) {
    switch (res->wildcard) {
    case OC_ACE_WC_ALL_DISCOVERABLE:
      if (resource->properties & OC_DISCOVERABLE) {
        permission |= ace->permission;
      }
      break;
    case OC_ACE_WC_ALL_NON_DISCOVERABLE:
      if (!(resource->properties & OC_DISCOVERABLE)) {
        permission |= ace->permission;
      }
      break;
    default:
      permission |= ace->permission;
      break;
    }

    res = oc_sec_ace_find_resource(res, ace, oc_string(resource->uri),
                                   &resource->types, resource->interfaces, wc);
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
      case OC_ACE_WC_ALL_DISCOVERABLE:
        PRINT("Wildcard: +\n");
        break;
      case OC_ACE_WC_ALL_NON_DISCOVERABLE:
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

bool
oc_sec_check_acl(oc_method_t method, oc_resource_t *resource,
                 oc_endpoint_t *endpoint)
{
#ifdef OC_DEBUG
  dump_acl(endpoint->device);
#endif /* OC_DEBUG */
  oc_uuid_t *uuid = oc_tls_get_peer_uuid(endpoint);

  if (uuid) {
    oc_sec_doxm_t *doxm = oc_sec_get_doxm(endpoint->device);
    oc_sec_creds_t *creds = oc_sec_get_creds(endpoint->device);
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(endpoint->device);
    if (memcmp(uuid->id, aclist[endpoint->device].rowneruuid.id, 16) == 0 &&
        memcmp(oc_string(resource->uri), "/oic/sec/acl2",
#if !defined(OC_SPEC_VER_OIC)
            13
#else
            endpoint->version == OIC_VER_1_1_0 ? 12 : 13
#endif //!OC_SPEC_VER_OIC
            ) == 0) {
      OC_DBG("oc_acl: peer's UUID matches acl's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, doxm->rowneruuid.id, 16) == 0 &&
        memcmp(oc_string(resource->uri), "/oic/sec/doxm", 13) == 0) {
      OC_DBG("oc_acl: peer's UUID matches doxm's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, pstat->rowneruuid.id, 16) == 0 &&
        memcmp(oc_string(resource->uri), "/oic/sec/pstat", 14) == 0) {
      OC_DBG("oc_acl: peer's UUID matches pstat's rowneruuid");
      return true;
    }
    if (memcmp(uuid->id, creds->rowneruuid.id, 16) == 0 &&
        memcmp(oc_string(resource->uri), "/oic/sec/cred", 13) == 0) {
      OC_DBG("oc_acl: peer's UUID matches cred's rowneruuid");
      return true;
    }
  }

  uint16_t permission = 0;
  oc_sec_ace_t *match = NULL;
  if (uuid) {
    do {
      match = oc_sec_acl_find_subject(match, OC_SUBJECT_UUID,
                                      (oc_ace_subject_t *)uuid, -1, 0,
                                      endpoint->device);

      if (match) {
        permission |= oc_ace_get_permission(match, resource);
        OC_DBG("oc_check_acl: Found ACE with permission %d for subject UUID",
               permission);
      }
    } while (match);

    oc_sec_cred_t *role_cred = oc_sec_find_cred(uuid, endpoint->device);
    if (role_cred && oc_string_len(role_cred->role.role) > 0) {
      do {
        match = oc_sec_acl_find_subject(match, OC_SUBJECT_ROLE,
                                        (oc_ace_subject_t *)&role_cred->role,
                                        -1, 0, endpoint->device);

        if (match) {
          permission |= oc_ace_get_permission(match, resource);
          OC_DBG(
            "oc_check_acl: Found ACE with permission %d for matching role",
            permission);
        }
      } while (match);
    }
  }

  if (endpoint->flags & SECURED) {
    oc_ace_subject_t _auth_crypt;
    memset(&_auth_crypt, 0, sizeof(oc_ace_subject_t));
    _auth_crypt.conn = OC_CONN_AUTH_CRYPT;
    do {
      match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, &_auth_crypt, -1,
                                      0, endpoint->device);
      if (match) {
        permission |= oc_ace_get_permission(match, resource);
        OC_DBG("oc_check_acl: Found ACE with permission %d for auth-crypt "
               "connection",
               permission);
      }
    } while (match);
  }

  oc_ace_subject_t _anon_clear;
  memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
  _anon_clear.conn = OC_CONN_ANON_CLEAR;
  do {
    match = oc_sec_acl_find_subject(match, OC_SUBJECT_CONN, &_anon_clear, -1, 0,
                                    endpoint->device);
    if (match) {
      permission |= oc_ace_get_permission(match, resource);
      OC_DBG("oc_check_acl: Found ACE with permission %d for anon-clear "
             "connection",
             permission);
    }
  } while (match);

  if (permission != 0) {
    switch (method) {
    case OC_GET:
      if (permission & OC_PERM_RETRIEVE || permission & OC_PERM_NOTIFY) {
        return true;
      }
      break;
    case OC_PUT:
    case OC_POST:
      if (permission & OC_PERM_CREATE || permission & OC_PERM_UPDATE) {
        return true;
      }
      break;
    case OC_DELETE:
      if (permission & OC_PERM_DELETE) {
        return true;
      }
      break;
    }
  }
  return false;
}

bool
oc_sec_encode_acl(size_t device)
{
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_ACL, device));
#if !defined(OC_SPEC_VER_OIC)
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
        oc_rep_set_text_string(subject, conntype, auth_crypt);
        break;
      case OC_CONN_ANON_CLEAR:
        oc_rep_set_text_string(subject, conntype, anon_clear);
        break;
      }
    } break;
    }
    oc_rep_close_object(aclist2, subject);

    oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(sub->resources);
    oc_rep_set_array(aclist2, resources);

    while (res != NULL) {
      oc_rep_object_array_start_item(resources);
      if (res->interfaces != 0) {
        oc_core_encode_interfaces_mask(oc_rep_object(resources),
                                       res->interfaces);
      }
      if (oc_string_array_get_allocated_size(res->types) > 0) {
        oc_rep_set_string_array(resources, rt, res->types);
      }
      if (oc_string_len(res->href) > 0) {
        oc_rep_set_text_string(resources, href, oc_string(res->href));
      } else {
        switch (res->wildcard) {
        case OC_ACE_WC_ALL_DISCOVERABLE:
          oc_rep_set_text_string(resources, wc, wc_discoverable);
          break;
        case OC_ACE_WC_ALL_NON_DISCOVERABLE:
          oc_rep_set_text_string(resources, wc, wc_non_discoverable);
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
    oc_rep_object_array_end_item(aclist2);
    sub = sub->next;
  }
  oc_rep_close_array(root, aclist2);
#else //!OC_SPEC_VER_OIC
  oc_rep_set_object(root, aclist);
  oc_rep_set_array(aclist, aces);

  oc_sec_ace_t *aces = oc_list_head(aclist[device].subjects);
  while (aces) {
    oc_rep_object_array_start_item(aces);
    switch (aces->subject_type) {
    case OC_SUBJECT_UUID:
      oc_uuid_to_str(&aces->subject.uuid, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(aces, subjectuuid, uuid);
      break;
    case OC_SUBJECT_ROLE:
      oc_rep_set_text_string(aces, role, oc_string(aces->subject.role.role));
      if (oc_string_len(aces->subject.role.authority) > 0)
        oc_rep_set_text_string(aces, authority, oc_string(aces->subject.role.authority));
      break;
    case OC_SUBJECT_CONN: {
      switch (aces->subject.conn) {
      case OC_CONN_AUTH_CRYPT:
        oc_rep_set_text_string(aces, conntype, auth_crypt);
        break;
      case OC_CONN_ANON_CLEAR:
        oc_rep_set_text_string(aces, conntype, anon_clear);
        break;
      }
    } break;
    }

    oc_rep_set_array(aces, resources);
    oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(aces->resources);
    while (res != NULL) {
      oc_rep_object_array_start_item(resources);
      if (res->interfaces != 0) {
        oc_core_encode_interfaces_mask(oc_rep_object(resources),
                                       res->interfaces);
      }
      if (oc_string_array_get_allocated_size(res->types) > 0) {
        oc_rep_set_string_array(resources, rt, res->types);
      }
      if (res->href.size > 0) {
        oc_rep_set_text_string(resources, href, res->href.ptr);
      } else {
        switch (res->wildcard) {
        case OC_ACE_WC_ALL_DISCOVERABLE:
          oc_rep_set_text_string(resources, wc, wc_discoverable);
          break;
        case OC_ACE_WC_ALL_NON_DISCOVERABLE:
          oc_rep_set_text_string(resources, wc, wc_non_discoverable);
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
    oc_rep_close_array(aces, resources);

    oc_rep_set_uint(aces, permission, aces->permission);
    oc_rep_set_int(aces, aceid, aces->aceid);

    oc_rep_object_array_end_item(aces);
    aces = aces->next;
  }

  oc_rep_close_array(aclist, aces);
  oc_rep_close_object(root, aclist);
#endif //! OC_SPEC_VER_OIC
  oc_uuid_to_str(&aclist[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();

  return true;
}

static oc_ace_res_t *
oc_sec_ace_get_res(oc_ace_subject_type_t type, oc_ace_subject_t *subject,
                   const char *href, oc_ace_wildcard_t wildcard,
                   oc_string_array_t *rt, oc_interface_mask_t interfaces,
                   int aceid, uint16_t permission, size_t device, bool create)
{
  oc_sec_ace_t *ace =
    oc_sec_acl_find_subject(NULL, type, subject, aceid, permission, device);
  oc_ace_res_t *res = NULL;

  if (ace) {
    goto got_ace;
  }

  if (create) {
    goto new_ace;
  }

  goto done;

got_ace:
  res = oc_sec_ace_find_resource(NULL, ace, href, rt, interfaces, wildcard);
  if (!res && create)
    goto new_res;

  goto done;

new_ace:
  ace = oc_memb_alloc(&ace_l);

  if (!ace) {
    OC_WRN("insufficient memory to add new ACE");
    goto done;
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

  oc_list_add(aclist[device].subjects, ace);

new_res:
  res = oc_memb_alloc(&res_l);

  if (res) {
    res->wildcard = wildcard;
#ifdef OC_DEBUG
    switch (res->wildcard) {
    case OC_ACE_WC_ALL_DISCOVERABLE:
      OC_DBG("Adding wildcard resource + with permission %d", permission);
      break;
    case OC_ACE_WC_ALL_NON_DISCOVERABLE:
      OC_DBG("Adding wildcard resource - with permission %d", permission);
      break;
    case OC_ACE_WC_ALL:
      OC_DBG("Adding wildcard resource * with permission %d", permission);
      break;
    default:
      break;
    }
#endif /* OC_DEBUG */

    if (href) {
      oc_new_string(&res->href, href, strlen(href));
      OC_DBG("Adding resource %s with permission %d", href, permission);
    }

    if (rt) {
      oc_new_string_array(&res->types, oc_string_array_get_allocated_size(*rt));
      int i;
      for (i = 0; i < (int)oc_string_array_get_allocated_size(*rt); i++) {
        oc_string_array_add_item(res->types, oc_string_array_get_item(*rt, i));
      }
    }

    res->interfaces = interfaces;

    oc_list_add(ace->resources, res);
  } else {
    OC_WRN("insufficient memory to add new resource to ACE");
  }

done:
  return res;
}

static bool
oc_sec_ace_update_res(oc_ace_subject_type_t type, oc_ace_subject_t *subject,
                      int aceid, uint16_t permission, const char *href,
                      oc_ace_wildcard_t wildcard, oc_string_array_t *rt,
                      oc_interface_mask_t interfaces, size_t device)
{
  if (oc_sec_ace_get_res(type, subject, href, wildcard, rt, interfaces, aceid,
                         permission, device, true))
    return true;
  return false;
}

#if defined(OC_SERVER)
bool
oc_sec_ace_update_conn_anon_clear(const char *uri, int aceid,
                                  uint16_t permission, int device)
{
  oc_resource_t *resource =
    oc_ri_get_app_resource_by_uri(uri, strlen(uri), device);
  if (!resource)
    return false;
  oc_ace_subject_t anon_clear = { .conn = OC_CONN_ANON_CLEAR };
  return oc_sec_ace_update_res(OC_SUBJECT_CONN, &anon_clear, aceid, permission,
                               oc_string(resource->uri), OC_ACE_NO_WC, &resource->types,
                               resource->interfaces, device);
}
#endif // OC_SERVER
static void
oc_ace_free_resources(size_t device, oc_sec_ace_t **ace, const char *href)
{
  oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head((*ace)->resources),
               *next = NULL;
  while (res != NULL) {
    next = res->next;
    if (href == NULL ||
        (
#if !defined(OC_SPEC_VER_OIC)
        oc_string_len(res->href) == strlen(href) &&
#endif //!OC_SPEC_VER_OIC
        memcmp(href, oc_string(res->href), strlen(href)) == 0)) {
      if (oc_string_array_get_allocated_size(res->types) > 0) {
        oc_free_string_array(&res->types);
      }
      if (oc_string_len(res->href) > 0) {
        oc_free_string(&res->href);
      }
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

static bool
oc_acl_remove_ace(int aceid, size_t device)
{
  bool removed = false;
  oc_sec_ace_t *ace = oc_list_head(aclist[device].subjects), *next = 0;
  while (ace != NULL) {
    next = ace->next;
    if (ace->aceid == aceid) {
      oc_ace_free_resources(device, &ace, NULL);
      oc_list_remove(aclist[device].subjects, ace);
      oc_memb_free(&ace_l, ace);
      removed = true;
      break;
    }
    ace = next;
  }
  return removed;
}

static void
oc_sec_clear_acl(size_t device)
{
  oc_sec_acl_t *acl_d = &aclist[device];
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_list_pop(acl_d->subjects);
  while (ace != NULL) {
    oc_ace_free_resources(device, &ace, NULL);
    if (ace->subject_type == OC_SUBJECT_ROLE) {
      oc_free_string(&ace->subject.role.role);
      if (oc_string_len(ace->subject.role.authority) > 0) {
        oc_free_string(&ace->subject.role.authority);
      }
    }
    oc_memb_free(&ace_l, ace);
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
    oc_mem_free(aclist);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_acl_default(size_t device)
{
  oc_sec_clear_acl(device);
  bool success = true;
  oc_resource_t *resource;
  int i;
  oc_ace_subject_t _auth_crypt, _anon_clear;
  memset(&_auth_crypt, 0, sizeof(oc_ace_subject_t));
  _auth_crypt.conn = OC_CONN_AUTH_CRYPT;
  memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
  _anon_clear.conn = OC_CONN_ANON_CLEAR;

  for (i = 0; i < OC_NUM_CORE_RESOURCES_PER_DEVICE; i++) {
    resource = oc_core_get_resource_by_index(i, device);
    if (oc_string_len(resource->uri) <= 0) {
      continue;
    }
    if (i < OCF_SEC_DOXM || i > OCF_SEC_CRED) {
      success &= oc_sec_ace_update_res(
        OC_SUBJECT_CONN, &_anon_clear, 1, 2, oc_string(resource->uri), -1,
        &resource->types, resource->interfaces, device);
    }
    if (i >= OCF_SEC_DOXM && i <= OCF_SEC_CRED) {
      success &= oc_sec_ace_update_res(
        OC_SUBJECT_CONN, &_anon_clear, 2, 14, oc_string(resource->uri), -1,
        &resource->types, resource->interfaces, device);
    }
  }

#if defined(OC_SERVER) && defined(OC_SPEC_VER_OIC)
  success &=
    oc_sec_ace_update_conn_anon_clear("/sec/provisioninginfo", 2, 14, device);
#endif

  memset(&aclist[device].rowneruuid, 0, sizeof(oc_uuid_t));
  oc_sec_dump_acl(device);

  if (!success) {
    OC_WRN("%s", __func__);
  }
}

void
oc_sec_set_post_otm_acl(size_t device)
{
  oc_ace_subject_t _auth_crypt, _anon_clear;
  memset(&_auth_crypt, 0, sizeof(oc_ace_subject_t));
  _auth_crypt.conn = OC_CONN_AUTH_CRYPT;
  memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
  _anon_clear.conn = OC_CONN_ANON_CLEAR;

  // pre otm:
  // anon-clear R: res, p, d
  // anon-clear RWD: doxm, pstat, acl2, cred
  // post otm:
  // anon-clear R: res, p, d
  // anon-clear RWD: doxm, pstat

  /* Remove anon-clear RWD access to acl2 and cred */
  oc_sec_ace_t *__anon_clear = NULL;
  do {
    __anon_clear = oc_sec_acl_find_subject(__anon_clear, OC_SUBJECT_CONN,
                                           &_anon_clear, -1, 14, device);
    if (__anon_clear) {
      oc_ace_free_resources(device, &__anon_clear,
#if !defined(OC_SPEC_VER_OIC)
      "/oic/sec/acl2"
#else
      "/oic/sec/acl"
#endif //!OC_SPEC_VER_OIC
      );
    }
    if (__anon_clear) {
      oc_ace_free_resources(device, &__anon_clear, "/oic/sec/cred");
    }
  } while (__anon_clear);
}

bool
oc_sec_decode_acl(oc_rep_t *rep, bool from_storage, size_t device)
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
#if defined(OC_SPEC_VER_OIC)
    case OC_REP_OBJECT: {
      oc_rep_t *aces = rep->value.object;
      while (aces) {
        switch (aces->type) {
          case OC_REP_OBJECT_ARRAY: {
            oc_rep_t *ace = aces->value.object_array;
            while(ace) {
              oc_ace_subject_t subject;
              oc_ace_subject_type_t subject_type = 0;
              uint16_t permission = 0;
              int aceid = -1;
              memset(&subject, 0, sizeof(oc_ace_subject_t));
              oc_ace_wildcard_t wc = OC_ACE_NO_WC;
              const char *href = 0;
              oc_string_array_t *rt = 0;
              oc_interface_mask_t interfaces = 0;
              oc_rep_t *resource = 0;
              switch(ace->type)
              {
                case OC_REP_OBJECT: {
                  oc_rep_t *resources = ace->value.object;
                  while(resources) {
                    switch(resources->type) {
                      case OC_REP_STRING: {
                        if (resources->name.size == 12 && memcmp(resources->name.ptr, "subjectuuid", 11) == 0) {
                          oc_str_to_uuid(resources->value.string.ptr, &subject.uuid);
                          subject_type = OC_SUBJECT_UUID;
                        } else if (resources->name.size == 5 && memcmp(resources->name.ptr, "role", 4) == 0) {
                          oc_new_string(&subject.role.role, resources->value.string.ptr,
                              resources->value.string.size);
                          subject_type = OC_SUBJECT_ROLE;
                        } else if (resources->name.size == 9 && memcmp(resources->name.ptr, "conntype", 8) == 0) {
                          subject_type = OC_SUBJECT_CONN;
                          if (resources->value.string.size - 1 == strlen(auth_crypt) &&
                             memcmp(resources->value.string.ptr, auth_crypt, strlen(auth_crypt)) == 0)
                              subject.conn = OC_CONN_AUTH_CRYPT;
                          else if (resources->value.string.size - 1 == strlen(anon_clear) &&
                             memcmp(resources->value.string.ptr, anon_clear, strlen(anon_clear)) == 0)
                              subject.conn = OC_CONN_ANON_CLEAR;
                        }
                      } break;
                      case OC_REP_OBJECT_ARRAY: {
                        resource = resources->value.object_array;
                      }
                      break;
                      case OC_REP_INT:
                        if (resources->name.size == 11 &&
                          memcmp(resources->name.ptr, "permission", 10) == 0)
                            permission = (uint16_t)resources->value.integer;
                        else if (resources->name.size == 6 &&
                          memcmp(resources->name.ptr, "aceid", 5) == 0)
                            aceid = resources->value.integer;
                      break;
                      default: break;
                    }
                    resources = resources->next;
                  }
                } break;
                default: break;
              }
              while(resource) {
                switch(resource->type) {
                case OC_REP_OBJECT: {
                  oc_rep_t *r = resource->value.object;
                  while(r) {
                    switch(r->type) {
                    case OC_REP_STRING:
                      if (r->name.size == 5 && memcmp(r->name.ptr, "href", 4) == 0)
                        href = oc_string(r->value.string);
                     break;
                     case OC_REP_STRING_ARRAY: {
                       if (r->name.size == 3) {
                         if (memcmp(r->name.ptr, "if", 2) == 0) {
                           for (int i = 0; i < (int)oc_string_array_get_allocated_size(r->value.array); i++) {
                             const char *f = oc_string_array_get_item(r->value.array, i);
                               if (strlen(f) == 1 && f[0] == '*') {
                                 interfaces |= 0xFE;
                                 break;
                               }
                               interfaces |= oc_ri_get_interface_mask((char *)f, strlen(f));
                            }
                          } else if (strncasecmp(r->name.ptr, "rt", 2) == 0)
                            rt = &r->value.array;
                          }
                        }
                      break;
                      default: break;
                      }
                    r = r->next;
                    }
                    } break;
                    default: break;
                  }
                  oc_sec_ace_update_res(subject_type, &subject, aceid == -1 ? get_new_aceid(device) : aceid,
                    permission, href, wc, rt, interfaces, device);
                  resource = resource->next;
                  }
              ace = ace->next;
            }
          } break;
          default:
          break;
        }
        aces = aces->next;
        }
      }
      break;
#else //OC_SPEC_VER_OIC
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *aclist2 = rep->value.object_array;
      while (aclist2 != NULL) {
        oc_ace_subject_t subject;
        oc_ace_subject_type_t subject_type = 0;
        uint16_t permission = 0;
        int aceid = -1;
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
              aceid = ace->value.integer;
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
                if (oc_string_len(sub->value.string) == strlen(auth_crypt) &&
                    memcmp(oc_string(sub->value.string), auth_crypt,
                           strlen(auth_crypt)) == 0) {
                  subject.conn = OC_CONN_AUTH_CRYPT;
                } else if (oc_string_len(sub->value.string) ==
                             strlen(anon_clear) &&
                           memcmp(oc_string(sub->value.string), anon_clear,
                                  strlen(anon_clear)) == 0) {
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

        if (aceid != -1 && !unique_aceid(aceid, device)) {
          oc_acl_remove_ace(aceid, device);
        }

        while (resources != NULL) {
          oc_ace_wildcard_t wc = OC_ACE_NO_WC;
          oc_rep_t *resource = resources->value.object;
          const char *href = 0;
#ifdef OC_SERVER
          oc_resource_properties_t wc_r = 0;
#endif /* OC_SERVER */
          oc_interface_mask_t interfaces = 0;
          oc_string_array_t *rt = 0;
          int i;

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
#ifdef OC_SERVER
                  wc_r = ~0;
#endif /* OC_SERVER */
                }
                if (oc_string(resource->value.string)[0] == '+') {
                  wc = OC_ACE_WC_ALL_DISCOVERABLE;
#ifdef OC_SERVER
                  wc_r = ~0;
#endif /* OC_SERVER */
                }
                if (oc_string(resource->value.string)[0] == '-') {
                  wc = OC_ACE_WC_ALL_NON_DISCOVERABLE;
#ifdef OC_SERVER
                  wc_r = ~OC_DISCOVERABLE;
#endif /* OC_SERVER */
                }
              }
              break;
            case OC_REP_STRING_ARRAY: {
              if (oc_string_len(resource->name) == 2) {
                if (memcmp(oc_string(resource->name), "if", 2) == 0) {
                  for (i = 0; i < (int)oc_string_array_get_allocated_size(
                                    resource->value.array);
                       i++) {
                    const char *f =
                      oc_string_array_get_item(resource->value.array, i);
                    if (strlen(f) == 1 && f[0] == '*') {
                      interfaces |= 0xFE;
                      break;
                    }
                    interfaces |=
                      oc_ri_get_interface_mask((char *)f, strlen(f));
                  }
                } else if (strncasecmp(oc_string(resource->name), "rt", 2) ==
                           0) {
                  rt = &resource->value.array;
                }
              }
            } break;
            default:
              break;
            }

            resource = resource->next;
          }

          oc_sec_ace_update_res(subject_type, &subject, aceid, permission, href,
                                wc, rt, interfaces, device);

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
#endif /* OC_SERVER */
          resources = resources->next;
        }

        if (subject_type == OC_SUBJECT_ROLE) {
          oc_free_string(&subject.role.role);
          if (oc_string_len(subject.role.authority) > 0) {
            oc_free_string(&subject.role.authority);
          }
        }

        aclist2 = aclist2->next;
      }
    } break;
#endif //OC_SPEC_VER_OIC
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
post_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  if (oc_sec_decode_acl(request->request_payload, false,
                        request->resource->device)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_acl(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    oc_sec_otm_err(request->resource->device, OC_SEC_ERR_ACL);
  }
}

void
delete_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  bool success = false;
  char *query_param = 0;
  int ret = oc_get_query_value(request, "aceid", &query_param);
  int aceid = 0;
  if (ret != -1) {
    aceid = (int)strtoul(query_param, NULL, 10);
    if (aceid != 0) {
      if (oc_acl_remove_ace(aceid, request->resource->device)) {
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
get_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  if (oc_sec_encode_acl(request->resource->device)) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

#endif /* OC_SECURITY */
