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
#include "api/oc_resource_internal.h"
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

#if OC_DBG_IS_ENABLED
static void
log_new_ace(const oc_sec_ace_t *ace)
{
  // GCOVR_EXCL_START
  if (ace->subject_type == OC_SUBJECT_ROLE) {
    const char *role = oc_string(ace->subject.role.role);
    const char *authority = oc_string_len(ace->subject.role.authority) > 0
                              ? oc_string(ace->subject.role.authority)
                              : "";
    OC_DBG("Adding ACE(%d) for role (role=%s, authority=%s)", ace->aceid, role,
           authority);
  } else if (ace->subject_type == OC_SUBJECT_UUID) {
    char c[OC_UUID_LEN];
    oc_uuid_to_str(&ace->subject.uuid, c, OC_UUID_LEN);
    OC_DBG("Adding ACE(%d) for subject %s", ace->aceid, c);
  } else if (ace->subject_type == OC_SUBJECT_CONN) {
    if (ace->subject.conn == OC_CONN_ANON_CLEAR) {
      OC_DBG("Adding ACE(%d) for anon-clear connection", ace->aceid);
    } else {
      OC_DBG("Adding ACE(%d) for auth-crypt connection", ace->aceid);
    }
  }

  const char *tag =
    oc_string(ace->tag) != NULL ? oc_string(ace->tag) : "(NULL)";
  OC_DBG("\t with permission=%d and tag=%s", ace->permission, tag);
  // GCOVR_EXCL_STOP
}

#endif /* OC_DBG_IS_ENABLED */

oc_sec_ace_t *
oc_sec_new_ace(oc_ace_subject_type_t type, const oc_ace_subject_t *subject,
               int aceid, uint16_t permission, oc_string_view_t tag)
{
  oc_sec_ace_t *ace = oc_memb_alloc(&g_ace_l);
  if (ace == NULL) {
    OC_WRN("insufficient memory to add new ACE");
    return NULL;
  }

  OC_LIST_STRUCT_INIT(ace, resources);

  if (type == OC_SUBJECT_ROLE) {
    oc_copy_string(&ace->subject.role.role, &subject->role.role);
    if (!oc_string_is_empty(&subject->role.authority)) {
      oc_copy_string(&ace->subject.role.authority, &subject->role.authority);
    }
  } else {
    memcpy(&ace->subject, subject, sizeof(oc_ace_subject_t));
  }
  ace->aceid = aceid;
  ace->subject_type = type;
  ace->permission = permission;
  if (tag.data != NULL) {
    oc_new_string(&ace->tag, tag.data, tag.length);
  }
#if OC_DBG_IS_ENABLED
  log_new_ace(ace);
#endif /* OC_DBG_IS_ENABLED */

  return ace;
}

#if OC_DBG_IS_ENABLED
static void
log_new_ace_resource(const oc_ace_res_t *res, uint16_t permission)
{
  // GCOVR_EXCL_START
  switch (res->wildcard) {
  case OC_ACE_WC_ALL_SECURED:
    OC_DBG("Adding wildcard resource %s with permission %d",
           OC_ACE_WC_ALL_SECURED_STR, permission);
    break;
  case OC_ACE_WC_ALL_PUBLIC:
    OC_DBG("Adding wildcard resource %s with permission %d",
           OC_ACE_WC_ALL_PUBLIC_STR, permission);
    break;
  case OC_ACE_WC_ALL:
    OC_DBG("Adding wildcard resource %s with permission %d", OC_ACE_WC_ALL_STR,
           permission);
    break;
  default:
    break;
  }
  if (oc_string(res->href) != NULL) {
    OC_DBG("Adding resource %s with permission %d", oc_string(res->href),
           permission);
  }
  // GCOVR_EXCL_STOP
}
#endif /* OC_DBG_IS_ENABLED */

static oc_ace_res_t *
oc_sec_add_new_ace_res(oc_string_view_t href, oc_ace_wildcard_t wildcard)
{
  oc_ace_res_t *res = oc_memb_alloc(&g_res_l);
  if (res == NULL) {
    OC_WRN("insufficient memory to add new resource to ACE");
    return NULL;
  }
  res->wildcard = 0;
  if (wildcard != OC_ACE_NO_WC) {
    res->wildcard = wildcard;
  }
  if (href.data != NULL) {
    assert(href.length > 0);
    assert(href.data[0] == '/');
    oc_new_string(&res->href, href.data, href.length);
  }
  return res;
}

oc_ace_res_data_t
oc_sec_ace_get_or_add_res(oc_sec_ace_t *ace, oc_string_view_t href,
                          oc_ace_wildcard_t wildcard, bool create)
{
  assert(ace != NULL);
  oc_ace_res_t *res =
    oc_sec_ace_find_resource(NULL, ace, href, (uint16_t)wildcard);
  if (res != NULL) {
    return (oc_ace_res_data_t){ res, false };
  }
  if (create) {
    res = oc_sec_add_new_ace_res(href, wildcard);
  }
  if (res == NULL) {
    OC_ERR("could not %s resource for ACE", create ? "create" : "find");
    return (oc_ace_res_data_t){ NULL, false };
  }
#if OC_DBG_IS_ENABLED
  log_new_ace_resource(res, ace->permission);
#endif /* OC_DBG_IS_ENABLED */
  oc_list_add(ace->resources, res);
  return (oc_ace_res_data_t){ res, true };
}

static void
ace_free_resources(oc_sec_ace_t *ace)
{
  oc_ace_res_t *res = (oc_ace_res_t *)oc_list_pop(ace->resources);
  while (res != NULL) {
    oc_free_string(&res->href);
    oc_memb_free(&g_res_l, res);
    res = (oc_ace_res_t *)oc_list_pop(ace->resources);
  }
}

void
oc_sec_free_ace(oc_sec_ace_t *ace)
{
  ace_free_resources(ace);
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
  return oc_string_is_cstr_equal(&ace->tag, tag.data, tag.length);
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
    return oc_uuid_is_equal(ace->subject.uuid, subject->uuid);
  case OC_SUBJECT_ROLE:
    return oc_string_is_equal(&subject->role.role, &ace->subject.role.role) &&
           (oc_string_is_empty(&ace->subject.role.authority) ||
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
  for (; ace != NULL; ace = ace->next) {
    if (aceid != -1 && ace->aceid != aceid) {
      continue;
    }
    if (permission != 0 && ace->permission != permission) {
      continue;
    }
    if (match_tag && !ace_has_matching_tag(ace, tag)) {
      continue;
    }
    if (ace_has_matching_subject(ace, type, subject)) {
      return ace;
    }
  }
  return NULL;
}

static bool
ace_res_match_wild_card(uint16_t wc, uint16_t reswc)
{
  if (wc == OC_ACE_WC_ALL) {
    return reswc == OC_ACE_WC_ALL;
  }
  return (wc & reswc) != 0;
}

static oc_ace_res_t *
ace_res_find_resource(oc_ace_res_t *res, oc_string_view_t href,
                      uint16_t wildcard)
{
  for (; res != NULL; res = res->next) {
    bool match = false;
    // match href
    if (href.data != NULL && !oc_string_is_empty(&res->href)) {
      if (!oc_resource_match_uri(oc_string_view2(&res->href), href)) {
        continue;
      }
      match = true;
    }

    // match wildcard
    if (wildcard != 0 && res->wildcard != 0) {
      if (ace_res_match_wild_card(wildcard, (uint16_t)res->wildcard)) {
        match = true;
      } else {
        continue;
      }
    }

    if (match) {
      return res;
    }
  }

  return res;
}

oc_ace_res_t *
oc_sec_ace_find_resource(oc_ace_res_t *start, const oc_sec_ace_t *ace,
                         oc_string_view_t href, uint16_t wildcard)
{
  assert(start != NULL || ace != NULL);
  oc_ace_res_t *res = start;
  if (res == NULL) {
    res = (oc_ace_res_t *)oc_list_head(ace->resources);
  } else {
    res = res->next;
  }
  return ace_res_find_resource(res, href, wildcard);
}

#endif /* OC_SECURITY */
