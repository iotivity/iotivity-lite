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
#include "api/oc_rep_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "port/oc_log_internal.h"
#include "security/oc_ace_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#include <assert.h>
#include <inttypes.h>

#define OC_ACE_PROP_SUBJECT "subject"
#define OC_ACE_PROP_SUBJECT_UUID "uuid"
#define OC_ACE_PROP_SUBJECT_ROLE "role"
#define OC_ACE_PROP_SUBJECT_AUTHORITY "authority"
#define OC_ACE_PROP_SUBJECT_CONNTYPE "conntype"
#define OC_ACE_PROP_PERMISSION "permission"
#define OC_ACE_PROP_ACEID "aceid"
#define OC_ACE_PROP_TAG "tag"
#define OC_ACE_PROP_RESOURCES "resources"
#define OC_ACE_PROP_RESOURCE_HREF "href"
#define OC_ACE_PROP_RESOURCE_WILDCARD "wc"

#define MAX_NUM_RES_PERM_PAIRS                                                 \
  ((OC_MAX_NUM_SUBJECTS + 2) *                                                 \
   (OC_MAX_APP_RESOURCES + OC_NUM_CORE_PLATFORM_RESOURCES +                    \
    OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * OC_MAX_NUM_DEVICES))
OC_MEMB(g_ace_l, oc_sec_ace_t, MAX_NUM_RES_PERM_PAIRS);
OC_MEMB(g_res_l, oc_ace_res_t,
        OC_MAX_APP_RESOURCES + OC_NUM_CORE_PLATFORM_RESOURCES +
          OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * OC_MAX_NUM_DEVICES);

oc_string_view_t
oc_ace_wildcard_to_string(oc_ace_wildcard_t wc)
{
  if (wc == OC_ACE_WC_ALL) {
    return OC_STRING_VIEW(OC_ACE_WC_ALL_STR);
  }
  if (wc == OC_ACE_WC_ALL_SECURED) {
    return OC_STRING_VIEW(OC_ACE_WC_ALL_SECURED_STR);
  }
  if (wc == OC_ACE_WC_ALL_PUBLIC) {
    return OC_STRING_VIEW(OC_ACE_WC_ALL_PUBLIC_STR);
  }
  return OC_STRING_VIEW_NULL;
}

int
oc_ace_wildcard_from_string(oc_string_view_t str)
{
  if (oc_string_view_is_equal(str, OC_STRING_VIEW(OC_ACE_WC_ALL_STR))) {
    return OC_ACE_WC_ALL;
  }
  if (oc_string_view_is_equal(str, OC_STRING_VIEW(OC_ACE_WC_ALL_SECURED_STR))) {
    return OC_ACE_WC_ALL_SECURED;
  }
  if (oc_string_view_is_equal(str, OC_STRING_VIEW(OC_ACE_WC_ALL_PUBLIC_STR))) {
    return OC_ACE_WC_ALL_PUBLIC;
  }
  return -1;
}

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
oc_sec_new_ace(oc_ace_subject_type_t type, oc_ace_subject_view_t subject,
               int aceid, uint16_t permission, oc_string_view_t tag)
{
  oc_sec_ace_t *ace = oc_memb_alloc(&g_ace_l);
  if (ace == NULL) {
    OC_WRN("insufficient memory to add new ACE");
    return NULL;
  }

  OC_LIST_STRUCT_INIT(ace, resources);

  assert(type == OC_SUBJECT_UUID || type == OC_SUBJECT_ROLE ||
         type == OC_SUBJECT_CONN);
  if (type == OC_SUBJECT_UUID) {
    ace->subject.uuid = subject.uuid;
  } else if (type == OC_SUBJECT_ROLE) {
    oc_new_string(&ace->subject.role.role, subject.role.role.data,
                  subject.role.role.length);
    if (subject.role.authority.length > 0) {
      oc_new_string(&ace->subject.role.authority, subject.role.authority.data,
                    subject.role.authority.length);
    }
  } else if (type == OC_SUBJECT_CONN) {
    ace->subject.conn = subject.conn;
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
  oc_string_view_t wcv = oc_ace_wildcard_to_string(res->wildcard);
  if (wcv.data != NULL) {
    OC_DBG("Adding wildcard resource %s with permission %d", wcv.data,
           permission);
  }
  const char *href = oc_string(res->href);
  if (href != NULL) {
    OC_DBG("Adding resource %s with permission %d", href, permission);
  }
  // GCOVR_EXCL_STOP
}
#endif /* OC_DBG_IS_ENABLED */

static oc_ace_res_t *
oc_sec_add_new_ace_res(oc_string_view_t href, oc_ace_wildcard_t wildcard)
{
  if (wildcard == OC_ACE_NO_WC && href.data == NULL) {
    OC_ERR("wildcard and href cannot both be empty");
    return NULL;
  }

  oc_ace_res_t *res = oc_memb_alloc(&g_res_l);
  if (res == NULL) {
    OC_WRN("insufficient memory to add new resource to ACE");
    return NULL;
  }
  res->wildcard = OC_ACE_NO_WC;
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

bool
oc_ace_has_matching_tag(const oc_sec_ace_t *ace, oc_string_view_t tag)
{
  if (tag.data == NULL) {
    return oc_string(ace->tag) == NULL;
  }
  return oc_string_is_cstr_equal(&ace->tag, tag.data, tag.length);
}

bool
oc_ace_has_matching_subject(const oc_sec_ace_t *ace, oc_ace_subject_type_t type,
                            oc_ace_subject_view_t subject)
{
  if (ace->subject_type != type) {
    return false;
  }
  if (type == OC_SUBJECT_UUID) {
    return oc_uuid_is_equal(ace->subject.uuid, subject.uuid);
  }
  if (type == OC_SUBJECT_ROLE) {
    return oc_string_view_is_equal(subject.role.role,
                                   oc_string_view2(&ace->subject.role.role)) &&
           (oc_string_is_empty(&ace->subject.role.authority) ||
            oc_string_view_is_equal(
              subject.role.authority,
              oc_string_view2(&ace->subject.role.authority)));
  }
  assert(type == OC_SUBJECT_CONN);
  return subject.conn == ace->subject.conn;
}

oc_sec_ace_t *
oc_sec_ace_find_subject(oc_sec_ace_t *ace, oc_ace_subject_type_t type,
                        oc_ace_subject_view_t subject, int aceid,
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
    if (match_tag && !oc_ace_has_matching_tag(ace, tag)) {
      continue;
    }
    if (oc_ace_has_matching_subject(ace, type, subject)) {
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

oc_string_view_t
oc_ace_connection_type_to_string(oc_ace_connection_type_t type)
{
  if (type == OC_CONN_AUTH_CRYPT) {
    return OC_STRING_VIEW(OC_CONN_AUTH_CRYPT_STR);
  }
  if (type == OC_CONN_ANON_CLEAR) {
    return OC_STRING_VIEW(OC_CONN_ANON_CLEAR_STR);
  }
  return OC_STRING_VIEW_NULL;
}

int
oc_ace_connection_type_from_string(oc_string_view_t str)
{
  if (oc_string_view_is_equal(str, OC_STRING_VIEW(OC_CONN_AUTH_CRYPT_STR))) {
    return OC_CONN_AUTH_CRYPT;
  }
  if (oc_string_view_is_equal(str, OC_STRING_VIEW(OC_CONN_ANON_CLEAR_STR))) {
    return OC_CONN_ANON_CLEAR;
  }
  return -1;
}

static void
ace_encode_subject(CborEncoder *encoder, const oc_sec_ace_t *sub)
{
  if (sub->subject_type == OC_SUBJECT_UUID) {
    char uuid[OC_UUID_LEN];
    int len = oc_uuid_to_str_v1(&sub->subject.uuid, uuid, OC_UUID_LEN);
    assert(len > 0);
    oc_string_view_t key = OC_STRING_VIEW(OC_ACE_PROP_SUBJECT_UUID);
    g_err |= oc_rep_object_set_text_string(encoder, key.data, key.length, uuid,
                                           (size_t)len);
    return;
  }

  if (sub->subject_type == OC_SUBJECT_ROLE) {
    oc_string_view_t role_key = OC_STRING_VIEW(OC_ACE_PROP_SUBJECT_ROLE);
    g_err |= oc_rep_object_set_text_string(
      encoder, role_key.data, role_key.length,
      oc_string(sub->subject.role.role),
      oc_string_len_unsafe(sub->subject.role.role));
    if (!oc_string_is_empty(&sub->subject.role.authority)) {
      oc_string_view_t authority_key =
        OC_STRING_VIEW(OC_ACE_PROP_SUBJECT_AUTHORITY);
      g_err |= oc_rep_object_set_text_string(
        encoder, authority_key.data, authority_key.length,
        oc_string(sub->subject.role.authority),
        oc_string_len_unsafe(sub->subject.role.authority));
    }
    return;
  }

  if (sub->subject_type == OC_SUBJECT_CONN) {
    oc_string_view_t conntype_key =
      OC_STRING_VIEW(OC_ACE_PROP_SUBJECT_CONNTYPE);
    oc_string_view_t conntype =
      oc_ace_connection_type_to_string(sub->subject.conn);
    g_err |= oc_rep_object_set_text_string(encoder, conntype_key.data,
                                           conntype_key.length, conntype.data,
                                           conntype.length);
    return;
  }
}

static void
ace_encode_subject_resource(CborEncoder *encoder, const oc_ace_res_t *res)
{
  size_t href_len = oc_string_len(res->href);
  if (href_len > 0) {
    oc_string_view_t href_key = OC_STRING_VIEW(OC_ACE_PROP_RESOURCE_HREF);
    g_err |= oc_rep_object_set_text_string(
      encoder, href_key.data, href_key.length, oc_string(res->href), href_len);
    return;
  }

  oc_string_view_t wcv = oc_ace_wildcard_to_string(res->wildcard);
  if (wcv.length > 0) {
    oc_string_view_t wc_key = OC_STRING_VIEW(OC_ACE_PROP_RESOURCE_WILDCARD);
    g_err |= oc_rep_object_set_text_string(encoder, wc_key.data, wc_key.length,
                                           wcv.data, wcv.length);
    return;
  }
}

static void
ace_encode_subject_resources(CborEncoder *encoder, const oc_ace_res_t *res)
{
  if (res == NULL) {
    return;
  }
  oc_string_view_t key = OC_STRING_VIEW(OC_ACE_PROP_RESOURCES);
  g_err |= oc_rep_encode_text_string(encoder, key.data, key.length);
  oc_rep_begin_array(encoder, resources);
  for (; res != NULL; res = res->next) {
    oc_rep_object_array_begin_item(resources);
    ace_encode_subject_resource(oc_rep_object(resources), res);
    oc_rep_object_array_end_item(resources);
  }
  oc_rep_end_array(encoder, resources);
}

void
oc_sec_encode_ace(CborEncoder *encoder, const oc_sec_ace_t *sub,
                  bool to_storage)
{
  oc_string_view_t subject_key = OC_STRING_VIEW(OC_ACE_PROP_SUBJECT);
  g_err |=
    oc_rep_encode_text_string(encoder, subject_key.data, subject_key.length);
  oc_rep_begin_object(encoder, subject);
  ace_encode_subject(oc_rep_object(subject), sub);
  oc_rep_end_object(encoder, subject);

  ace_encode_subject_resources(
    encoder, (const oc_ace_res_t *)oc_list_head(sub->resources));

  oc_string_view_t permission_key = OC_STRING_VIEW(OC_ACE_PROP_PERMISSION);
  g_err |= oc_rep_object_set_uint(encoder, permission_key.data,
                                  permission_key.length, sub->permission);

  oc_string_view_t aceid_key = OC_STRING_VIEW(OC_ACE_PROP_ACEID);
  g_err |= oc_rep_object_set_int(encoder, aceid_key.data, aceid_key.length,
                                 sub->aceid);
  if (to_storage && !oc_string_is_empty(&sub->tag)) {
    oc_string_view_t tag_key = OC_STRING_VIEW(OC_ACE_PROP_TAG);
    g_err |= oc_rep_object_set_text_string(
      encoder, tag_key.data, tag_key.length, oc_string(sub->tag),
      oc_string_len_unsafe(sub->tag)); // safe: oc_string_is_empty check above
  }
}

typedef struct
{
  const oc_string_t *uuid;
  const oc_string_t *role;
  const oc_string_t *authority;
  const oc_string_t *conntype;
} ace_subject_decode_t;

static bool
ace_decode_subject_string_property(const oc_rep_t *rep,
                                   ace_subject_decode_t *decode)
{
  if (oc_rep_is_property(rep, OC_ACE_PROP_SUBJECT_UUID,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_SUBJECT_UUID))) {
    decode->uuid = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_ACE_PROP_SUBJECT_ROLE,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_SUBJECT_ROLE))) {
    decode->role = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_ACE_PROP_SUBJECT_AUTHORITY,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_SUBJECT_AUTHORITY))) {
    decode->authority = &rep->value.string;
    return true;
  }

  if (oc_rep_is_property(rep, OC_ACE_PROP_SUBJECT_CONNTYPE,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_SUBJECT_CONNTYPE))) {
    decode->conntype = &rep->value.string;
    return true;
  }
  return false;
}

static int
ace_decode_subject(const oc_rep_t *rep, oc_ace_subject_view_t *subject)
{
  ace_subject_decode_t decode = { NULL, NULL, NULL, NULL };
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_STRING &&
        ace_decode_subject_string_property(rep, &decode)) {
      continue;
    }
    OC_ERR("ACE decode subject: unknown property (name=%s, type=%d)",
           oc_string(rep->name) != NULL ? oc_string(rep->name) : "(null)",
           (int)rep->type);
    return -1;
  }

  bool has_uuid = decode.uuid != NULL;
  bool has_role = decode.role != NULL || decode.authority != NULL;
  bool has_conntype = decode.conntype != NULL;
  if (has_uuid) {
    if (has_role || has_conntype) {
      OC_ERR("ACE decode subject: uuid cannot be used with role or conntype");
      return -1;
    }
    oc_uuid_t id;
    if (oc_str_to_uuid_v1(oc_string(*decode.uuid),
                          oc_string_len_unsafe(*decode.uuid), &id) < 0) {
      OC_ERR("ACE decode subject: uuid(%s) is invalid",
             oc_string(*decode.uuid));
      return -1;
    }
    subject->uuid = id;
    return OC_SUBJECT_UUID;
  }

  if (has_role) {
    if (decode.role == NULL) {
      OC_ERR("ACE decode subject: role is missing");
      return -1;
    }
    if (has_conntype) {
      OC_ERR("ACE decode subject: conntype cannot be used with role");
      return -1;
    }
    subject->role = (oc_ace_subject_role_view_t){
      .role = oc_string_view2(decode.role),
      .authority = oc_string_view2(decode.authority),
    };
    return OC_SUBJECT_ROLE;
  }

  if (has_conntype) {
    int conn =
      oc_ace_connection_type_from_string(oc_string_view2(decode.conntype));
    if (conn < 0) {
      OC_ERR("ACE decode subject: conntype(%s) is invalid",
             oc_string(*decode.conntype));
      return -1;
    }
    subject->conn = (oc_ace_connection_type_t)conn;
    return OC_SUBJECT_CONN;
  }

  OC_ERR("ACE decode subject: subject is missing");
  return -1;
}

static bool
ace_decode_property(const oc_rep_t *rep, oc_sec_ace_decode_t *acedecode)
{
  if (rep->type == OC_REP_INT) {
    if (oc_rep_is_property(rep, OC_ACE_PROP_PERMISSION,
                           OC_CHAR_ARRAY_LEN(OC_ACE_PROP_PERMISSION))) {
      if (rep->value.integer > UINT16_MAX) {
        OC_ERR("ACE permission value(%" PRId64 ") is invalid",
               rep->value.integer);
        return false;
      }
      acedecode->permission = (uint16_t)rep->value.integer;
      return true;
    }
    if (oc_rep_is_property(rep, OC_ACE_PROP_ACEID,
                           OC_CHAR_ARRAY_LEN(OC_ACE_PROP_ACEID))) {
      if (rep->value.integer > INT_MAX) {
        OC_ERR("ACE aceid value(%" PRId64 ") is invalid", rep->value.integer);
        return false;
      }
      acedecode->aceid = (int)rep->value.integer;
      return true;
    }
    goto unknown_property;
  }

  if (rep->type == OC_REP_STRING) {
    if (oc_rep_is_property(rep, OC_ACE_PROP_TAG,
                           OC_CHAR_ARRAY_LEN(OC_ACE_PROP_TAG))) {
      acedecode->tag = &rep->value.string;
      return true;
    }
    goto unknown_property;
  }

  if (rep->type == OC_REP_OBJECT) {
    if (oc_rep_is_property(rep, OC_ACE_PROP_SUBJECT,
                           OC_CHAR_ARRAY_LEN(OC_ACE_PROP_SUBJECT))) {
      int subject_type =
        ace_decode_subject(rep->value.object, &acedecode->subject);
      if (subject_type < 0) {
        OC_ERR("ACE decode: subject is invalid");
        return false;
      }
      acedecode->subject_type = (oc_ace_subject_type_t)subject_type;
      return true;
    }
    goto unknown_property;
  }

  if (rep->type == OC_REP_OBJECT_ARRAY) {
    if (oc_rep_is_property(rep, OC_ACE_PROP_RESOURCES,
                           OC_CHAR_ARRAY_LEN(OC_ACE_PROP_RESOURCES))) {
      acedecode->resources = rep->value.object_array;
      return true;
    }
    goto unknown_property;
  }

unknown_property:
  OC_ERR("ACE decode: unknown property (name=%s, type=%d)",
         oc_string(rep->name) != NULL ? oc_string(rep->name) : "(null)",
         (int)rep->type);
  return false;
}

bool
oc_sec_decode_ace(const oc_rep_t *rep, oc_sec_ace_decode_t *acedecode)
{

  for (; rep != NULL; rep = rep->next) {
    if (!ace_decode_property(rep, acedecode)) {
      return false;
    }
    OC_DBG("aceid: %d, permission: %" PRIu16 ", subject_type: %d",
           acedecode->aceid, acedecode->permission, acedecode->subject_type);
  }
  return true;
}

static bool
ace_decode_resource_string_property(const oc_rep_t *rep,
                                    oc_sec_ace_res_decode_t *aceresdecode)
{
  if (oc_rep_is_property(rep, OC_ACE_PROP_RESOURCE_HREF,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_RESOURCE_HREF))) {
    aceresdecode->href = &rep->value.string;
    return true;
  }
  if (oc_rep_is_property(rep, OC_ACE_PROP_RESOURCE_WILDCARD,
                         OC_CHAR_ARRAY_LEN(OC_ACE_PROP_RESOURCE_WILDCARD))) {
    int wc = oc_ace_wildcard_from_string(oc_string_view2(&rep->value.string));
    if (wc == -1) {
      OC_ERR("ACE decode resource: wildcard(%s) is invalid",
             oc_string(rep->value.string));
      return false;
    }
    aceresdecode->wildcard = (oc_ace_wildcard_t)wc;
    return true;
  }
  return false;
}

static bool
ace_decode_resource(const oc_rep_t *rep, oc_sec_ace_res_decode_t *aceresdecode)
{
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_STRING &&
        ace_decode_resource_string_property(rep, aceresdecode)) {
      continue;
    }
    if (rep->type == OC_REP_STRING_ARRAY &&
        oc_rep_is_property(rep, "if", OC_CHAR_ARRAY_LEN("if"))) {
      // TODO: remove from plgd tests
      continue;
    }
    OC_ERR("ACE decode resource: unknown property (name=%s, type=%d)",
           oc_string(rep->name) != NULL ? oc_string(rep->name) : "(null)",
           (int)rep->type);
    return false;
  }

#if 0
#ifdef OC_SERVER
  oc_resource_properties_t wc_r = 0;
  if (wc == OC_ACE_WC_ALL || wc == OC_ACE_WC_ALL_SECURED) {
    wc_r = ~0;
  }
  if (wc == OC_ACE_WC_ALL_PUBLIC) {
    wc_r = ~OC_DISCOVERABLE;
  }
  aceresdecode->wc_r = wc_r;
#endif /* OC_SERVER */
#endif

  return true;
}

bool
oc_sec_decode_ace_resources(const oc_rep_t *rep,
                            oc_sec_on_decode_ace_resource_fn_t on_decode,
                            void *decode_fn_data)
{
  for (; rep != NULL; rep = rep->next) {
    oc_sec_ace_res_decode_t aceres_decode;
    memset(&aceres_decode, 0, sizeof(oc_sec_ace_res_decode_t));
    if (!ace_decode_resource(rep->value.object, &aceres_decode)) {
      return false;
    }
    on_decode(&aceres_decode, decode_fn_data);
  }
  return true;
}
#endif /* OC_SECURITY */
