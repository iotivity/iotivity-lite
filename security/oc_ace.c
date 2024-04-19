/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#include "api/oc_helpers_internal.h"
#include "api/oc_ri_internal.h"
#include "port/oc_log_internal.h"
#include "security/oc_ace_internal.h"
#include "util/oc_features.h"
#include "util/oc_memb.h"

#include <assert.h>

#define MAX_NUM_RES_PERM_PAIRS                                                 \
  ((OC_MAX_NUM_SUBJECTS + 2) *                                                 \
   (OC_MAX_APP_RESOURCES + OC_NUM_CORE_PLATFORM_RESOURCES +                    \
    OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * OC_MAX_NUM_DEVICES))
OC_MEMB(g_ace_l, oc_sec_ace_t, MAX_NUM_RES_PERM_PAIRS);
OC_MEMB(g_res_l, oc_ace_res_t,
        OC_MAX_APP_RESOURCES + OC_NUM_CORE_PLATFORM_RESOURCES +
          OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * OC_MAX_NUM_DEVICES);

oc_sec_ace_t *
oc_sec_add_new_ace(oc_ace_subject_type_t type, const oc_ace_subject_t *subject,
                   int aceid, uint16_t permission, oc_string_view_t tag)
{
  oc_sec_ace_t *ace = oc_memb_alloc(&g_ace_l);
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
#if OC_DBG_IS_ENABLED
    // GCOVR_EXCL_START
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
    // GCOVR_EXCL_STOP
#endif /* OC_DBG_IS_ENABLED */
  }
  ace->aceid = aceid;
  ace->subject_type = type;
  ace->permission = permission;
  if (tag.data != 0) {
    oc_new_string(&ace->tag, tag.data, tag.length);
  }

  return ace;
}

static oc_ace_res_t *
oc_sec_add_new_ace_res(oc_string_view_t href, oc_ace_wildcard_t wildcard,
                       uint16_t permission)
{
  oc_ace_res_t *res = oc_memb_alloc(&g_res_l);
  if (!res) {
    OC_WRN("insufficient memory to add new resource to ACE");
    return NULL;
  }
  res->wildcard = 0;
  if (wildcard != OC_ACE_NO_WC) {
    res->wildcard = wildcard;
  }
#if OC_DBG_IS_ENABLED
  // GCOVR_EXCL_START
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
  // GCOVR_EXCL_STOP
#else  /* !OC_DBG_IS_ENABLED */
  (void)permission;
#endif /* OC_DBG_IS_ENABLED */

  if (href.data != NULL) {
    oc_new_string(&res->href, href.data, href.length);
    OC_DBG("Adding resource %s with permission %d", href.data, permission);
  }
  return res;
}

oc_ace_res_data_t
oc_sec_ace_get_or_add_res(oc_sec_ace_t *ace, oc_string_view_t href,
                          oc_ace_wildcard_t wildcard, uint16_t permission,
                          bool create)
{
  assert(ace != NULL);
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

static void
oc_ace_free_resources(oc_sec_ace_t *ace)
{
  oc_ace_res_t *res = (oc_ace_res_t *)oc_list_pop(ace->resources);
  while (res != NULL) {
    oc_free_string(&res->href);
    oc_memb_free(&g_res_l, res);
    res = (oc_ace_res_t *)oc_list_pop(ace->resources);
  }
}

void
oc_free_ace(oc_sec_ace_t *ace)
{
  oc_ace_free_resources(ace);
  if (ace->subject_type == OC_SUBJECT_ROLE) {
    oc_free_string(&ace->subject.role.role);
    oc_free_string(&ace->subject.role.authority);
  }
  oc_free_string(&ace->tag);
  oc_memb_free(&g_ace_l, ace);
}

static bool
ace_has_matching_tag(const oc_sec_ace_t *ace, oc_string_view_t tag)
{
  if (tag.data == NULL) {
    return oc_string(ace->tag) == NULL;
  }
  return oc_string(ace->tag) != NULL &&
         oc_string_is_cstr_equal(&ace->tag, tag.data, tag.length);
}

static bool
ace_has_matching_subject(const oc_sec_ace_t *ace, oc_ace_subject_type_t type,
                         const oc_ace_subject_t *subject)
{
  if (ace->subject_type != type) {
    return false;
  }
  switch (type) {
  case OC_SUBJECT_UUID:
    return memcmp(subject->uuid.id, ace->subject.uuid.id,
                  OC_ARRAY_SIZE(subject->uuid.id)) == 0;
  case OC_SUBJECT_ROLE:
    return oc_string_is_equal(&subject->role.role, &ace->subject.role.role) &&
           (oc_string_len(ace->subject.role.authority) == 0 ||
            oc_string_is_equal(&subject->role.authority,
                               &ace->subject.role.authority));
  case OC_SUBJECT_CONN:
    return subject->conn == ace->subject.conn;
  }
  return false;
}

oc_sec_ace_t *
oc_sec_ace_find_subject(oc_sec_ace_t *ace, oc_ace_subject_type_t type,
                        const oc_ace_subject_t *subject, int aceid,
                        uint16_t permission, oc_string_view_t tag,
                        bool match_tag)
{
  while (ace != NULL) {
    if (aceid != -1 && ace->aceid != aceid) {
      goto next_ace;
    }
    if (permission != 0 && ace->permission != permission) {
      goto next_ace;
    }
    if (match_tag && !ace_has_matching_tag(ace, tag)) {
      goto next_ace;
    }
    if (ace_has_matching_subject(ace, type, subject)) {
      return ace;
    }

  next_ace:
    ace = ace->next;
  }
  return ace;
}

static oc_ace_res_t *
oc_sec_ace_res_find_resource(oc_ace_res_t *res, oc_string_view_t href,
                             oc_ace_wildcard_t wildcard)
{
  int skip = 0;
  if (href.data != NULL && href.data[0] != '/') {
    skip = 1;
  }
  while (res != NULL) {
    bool positive = false;
    bool match = true;
    if (href.data != NULL && oc_string_len(res->href) > 0) {
      if ((href.length + skip) != oc_string_len(res->href) ||
          memcmp(oc_string(res->href) + skip, href.data,
                 oc_string_len(res->href) - skip) != 0) {
        match = false;
      } else {
        positive = true;
      }
    }

    if (match && wildcard != 0 && res->wildcard != 0) {
      if ((wildcard != OC_ACE_WC_ALL && (wildcard & res->wildcard) != 0) ||
          (wildcard == OC_ACE_WC_ALL && res->wildcard == OC_ACE_WC_ALL)) {
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

oc_ace_res_t *
oc_sec_ace_find_resource(oc_ace_res_t *start, const oc_sec_ace_t *ace,
                         oc_string_view_t href, oc_ace_wildcard_t wildcard)
{
  oc_ace_res_t *res = start;
  if (!res) {
    res = (oc_ace_res_t *)oc_list_head(ace->resources);
  } else {
    res = res->next;
  }
  return oc_sec_ace_res_find_resource(res, href, wildcard);
}

#endif /* OC_SECURITY */
