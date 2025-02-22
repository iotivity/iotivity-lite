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

#include "api/oc_core_res_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_platform_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_store.h"
#include "port/oc_assert.h"
#include "port/oc_random.h"
#include "security/oc_ace_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_pstat_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_acl_t *g_aclist;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_acl_t g_aclist[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_acl_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_aclist =
    (oc_sec_acl_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_acl_t));
  if (g_aclist == NULL) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    OC_LIST_STRUCT_INIT(&g_aclist[i], subjects);
  }
}

oc_sec_acl_t *
oc_sec_get_acl(size_t device)
{
  return &g_aclist[device];
}

oc_sec_ace_t *
oc_sec_acl_find_subject(oc_sec_ace_t *start, oc_ace_subject_type_t type,
                        oc_ace_subject_view_t subject, int aceid,
                        uint16_t permission, oc_string_view_t tag,
                        bool match_tag, size_t device)
{
  oc_sec_ace_t *ace = start;
  if (!ace) {
    ace = (oc_sec_ace_t *)oc_list_head(g_aclist[device].subjects);
  } else {
    ace = ace->next;
  }
  return oc_sec_ace_find_subject(ace, type, subject, aceid, permission, tag,
                                 match_tag);
}

static bool
acl_unique_aceid(int aceid, size_t device)
{
  const oc_sec_ace_t *ace = oc_list_head(g_aclist[device].subjects);
  while (ace != NULL) {
    if (ace->aceid == aceid) {
      return false;
    }
    ace = ace->next;
  }
  return true;
}

static int
acl_get_new_aceid(size_t device)
{
  int aceid;
  do {
    aceid = (int)(oc_random_value() >> 1);
  } while (!acl_unique_aceid(aceid, device));
  return aceid;
}

static void
acl_encode_subjects(oc_list_t subjects, bool to_storage)
{
  oc_rep_open_array(root, aclist2);
  for (const oc_sec_ace_t *sub = oc_list_head(subjects); sub != NULL;
       sub = sub->next) {
    oc_rep_object_array_begin_item(aclist2);
    oc_sec_encode_ace(oc_rep_object(aclist2), sub, to_storage);
    oc_rep_object_array_end_item(aclist2);
  }
  oc_rep_close_array(root, aclist2);
}

bool
oc_sec_encode_acl(size_t device, oc_interface_mask_t iface_mask,
                  bool to_storage)
{
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_ACL, device));
  }

  acl_encode_subjects(g_aclist[device].subjects, to_storage);

  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(&g_aclist[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();

  return true;
}

bool
oc_sec_acl_update_res(oc_ace_subject_type_t type, oc_ace_subject_view_t subject,
                      int aceid, uint16_t permission, oc_string_view_t tag,
                      oc_string_view_t href, oc_ace_wildcard_t wildcard,
                      size_t device, oc_sec_ace_update_data_t *data)
{
  oc_sec_ace_t *ace = oc_sec_acl_find_subject(
    NULL, type, subject, aceid, permission, tag, /*match_tag*/ true, device);
  bool created = false;
  if (!ace) {
    if (aceid == -1) {
      aceid = acl_get_new_aceid(device);
    }
    ace = oc_sec_new_ace(type, subject, aceid, permission, tag);
    if (ace == NULL) {
      return false;
    }
    oc_list_add(g_aclist[device].subjects, ace);
    created = true;
  }
  oc_ace_res_data_t res_data =
    oc_sec_ace_get_or_add_res(ace, href, wildcard, true);
  if (res_data.res == NULL) {
    oc_sec_remove_ace(ace, device);
    return false;
  }

  if (data != NULL) {
    data->ace = ace;
    data->created = created;
    data->created_resource = res_data.created;
  }
  return true;
}

oc_sec_ace_t *
oc_sec_get_ace_by_aceid(int aceid, size_t device)
{
  oc_sec_ace_t *ace = oc_list_head(g_aclist[device].subjects);
  while (ace != NULL) {
    if (ace->aceid == aceid) {
      return ace;
    }
    ace = ace->next;
  }
  return NULL;
}

static oc_sec_ace_t *
oc_acl_remove_ace_from_device(const oc_sec_ace_t *ace, size_t device)
{
  return oc_list_remove2(g_aclist[device].subjects, ace);
}

static oc_sec_ace_t *
oc_acl_remove_ace_from_device_by_aceid(int aceid, size_t device)
{
  const oc_sec_ace_t *ace = oc_sec_get_ace_by_aceid(aceid, device);
  if (ace != NULL) {
    return oc_acl_remove_ace_from_device(ace, device);
  }
  return false;
}

void
oc_sec_remove_ace(oc_sec_ace_t *ace, size_t device)
{
  oc_acl_remove_ace_from_device(ace, device);
  oc_sec_free_ace(ace);
}

bool
oc_sec_remove_ace_by_aceid(int aceid, size_t device)
{
  bool removed = false;
  oc_sec_ace_t *ace = oc_acl_remove_ace_from_device_by_aceid(aceid, device);
  if (ace != NULL) {
    oc_sec_free_ace(ace);
    removed = true;
  }
  return removed;
}

void
oc_sec_acl_clear(size_t device, oc_sec_ace_filter_t filter, void *user_data)
{
  oc_sec_acl_t *acl_d = &g_aclist[device];
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_list_head(acl_d->subjects);
  while (ace != NULL) {
    oc_sec_ace_t *ace_next = ace->next;
    if (filter == NULL || filter(ace, user_data)) {
      oc_list_remove(acl_d->subjects, ace);
      oc_sec_free_ace(ace);
    }
    ace = ace_next;
  }
}

void
oc_sec_acl_free(void)
{
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    oc_sec_acl_clear(device, NULL, NULL);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_aclist != NULL) {
    free(g_aclist);
    g_aclist = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

#if defined(OC_SERVER) && defined(OC_COLLECTIONS) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
bool
oc_sec_acl_add_created_resource_ace(oc_string_view_t href,
                                    const oc_endpoint_t *client, size_t device,
                                    bool collection)
{
  oc_ace_subject_view_t subject = {
    .uuid = client->di,
  };

  uint16_t perm = OC_PERM_RETRIEVE | OC_PERM_DELETE | OC_PERM_UPDATE;
  if (collection) {
    perm |= OC_PERM_CREATE;
  }

  return oc_sec_acl_update_res(OC_SUBJECT_UUID, subject, -1, perm,
                               OC_STRING_VIEW_NULL, href, 0, device, NULL);
}
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

void
oc_sec_acl_default(size_t device)
{
  oc_sec_acl_clear(device, NULL, NULL);
  memset(&g_aclist[device].rowneruuid, 0, sizeof(oc_uuid_t));
  oc_sec_dump_acl(device);
}

typedef struct
{
  oc_sec_ace_decode_t *ace_decode;
  size_t device;
  oc_sec_ace_t *ace;
  bool created;
  bool created_resource;
} acl_decode_ace_resources_data_t;

static void
acl_decode_ace_resources(const oc_sec_ace_res_decode_t *aceres_decode,
                         void *user_data)
{
  acl_decode_ace_resources_data_t *dard =
    (acl_decode_ace_resources_data_t *)user_data;

  oc_sec_ace_update_data_t ace_upd = { NULL, false, false };
  if (oc_sec_acl_update_res(dard->ace_decode->subject_type,
                            dard->ace_decode->subject, dard->ace_decode->aceid,
                            dard->ace_decode->permission,
                            oc_string_view2(dard->ace_decode->tag),
                            oc_string_view2(aceres_decode->href),
                            aceres_decode->wildcard, dard->device, &ace_upd)) {
    dard->ace = ace_upd.ace;
    dard->created |= ace_upd.created;
    dard->created_resource |= ace_upd.created_resource;
  } else {
    OC_WRN("failed to create resource(href:%s wildcard:%d)",
           aceres_decode->href != NULL ? oc_string(*aceres_decode->href) : "",
           aceres_decode->wildcard);
  }

#if 0
  /* The following code block attaches "coap" endpoints to resources linked to
     an anon-clear ACE. This logic is being currently disabled to comply with
     the SH spec which requires that all vertical resources not expose a "coap"
     endpoint. */
#ifdef OC_SERVER
  if (dard->ace_decode->subject_type == OC_SUBJECT_CONN && dard->ace_decode->subject.conn == OC_CONN_ANON_CLEAR) {
    if (href) {
      oc_resource_t *r =
        oc_ri_get_app_resource_by_uri(href, strlen(href), device);
      if (r) {
        oc_resource_make_public(r);
      }
    } else {
      oc_resource_t *r = oc_ri_get_app_resources();
      while (r != NULL) {
        if ((r->properties & aceres_decode->wc_r) == r->properties) {
          oc_resource_make_public(r);
        }
        r = r->next;
      }
    }
  }
#endif /* OC_SERVER */
#endif
}

bool
oc_sec_decode_acl(const oc_rep_t *rep, bool from_storage, size_t device,
                  oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                  void *on_apply_ace_data)
{
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  const oc_rep_t *t = rep;
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
                       &g_aclist[device].rowneruuid);
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      for (const oc_rep_t *aclist2 = rep->value.object_array; aclist2 != NULL;
           aclist2 = aclist2->next) {
        oc_sec_ace_decode_t ace_decode;
        memset(&ace_decode, 0, sizeof(oc_sec_ace_decode_t));
        ace_decode.aceid = -1;
        if (!oc_sec_decode_ace(aclist2->value.object, &ace_decode)) {
          OC_ERR("oc_acl: error decoding ACE");
          return false;
        }

        oc_sec_ace_t *replaced_ace = NULL;
        if (ace_decode.aceid != -1 &&
            !acl_unique_aceid(ace_decode.aceid, device)) {
          replaced_ace =
            oc_acl_remove_ace_from_device_by_aceid(ace_decode.aceid, device);
        }

        acl_decode_ace_resources_data_t dard = {
          .ace_decode = &ace_decode,
          .device = device,
        };
        if (!oc_sec_decode_ace_resources(ace_decode.resources,
                                         acl_decode_ace_resources, &dard)) {
          OC_ERR("oc_acl: error decoding ACE resources");
          return false;
        }

        if (on_apply_ace_cb != NULL && dard.ace != NULL) {
          oc_sec_on_apply_acl_data_t acl_data = { g_aclist[device].rowneruuid,
                                                  dard.ace, replaced_ace,
                                                  dard.created,
                                                  dard.created_resource };
          on_apply_ace_cb(acl_data, on_apply_ace_data);
        }

        if (replaced_ace) {
          oc_sec_free_ace(replaced_ace);
        }
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

static bool
oc_sec_acl_anon_connection(size_t device, oc_string_view_t href,
                           uint16_t permission)
{
  assert(href.data != NULL);
  oc_ace_subject_view_t anon_clear = {
    .conn = OC_CONN_ANON_CLEAR,
  };
  if (!oc_sec_acl_update_res(OC_SUBJECT_CONN, anon_clear, -1, permission,
                             OC_STRING_VIEW_NULL, href, OC_ACE_NO_WC, device,
                             NULL)) {
    OC_ERR("oc_acl: Failed to bootstrap %s resource", href.data);
    return false;
  }
  return true;
}

bool
oc_sec_acl_add_bootstrap_acl(size_t device)
{
  bool ret = oc_sec_acl_anon_connection(device, OC_STRING_VIEW(OCF_RES_URI),
                                        OC_PERM_RETRIEVE);
  ret = oc_sec_acl_anon_connection(device, OC_STRING_VIEW(OCF_D_URI),
                                   OC_PERM_RETRIEVE) &&
        ret;
  ret = oc_sec_acl_anon_connection(device, OC_STRING_VIEW(OCF_PLATFORM_URI),
                                   OC_PERM_RETRIEVE) &&
        ret;
#ifdef OC_WKCORE
  ret = oc_sec_acl_anon_connection(device, OC_STRING_VIEW(OC_WELLKNOWNCORE_URI),
                                   OC_PERM_RETRIEVE) &&
        ret;
#endif /* OC_WKCORE */
#ifdef OC_HAS_FEATURE_PLGD_TIME
  ret = oc_sec_acl_anon_connection(device, OC_STRING_VIEW(PLGD_TIME_URI),
                                   OC_PERM_RETRIEVE) &&
        ret;
#endif /* OC_HAS_FEATURE_PLGD_TIME */

  return ret;
}

int
oc_sec_apply_acl(const oc_rep_t *rep, size_t device,
                 oc_sec_on_apply_acl_cb_t on_apply_ace_cb,
                 void *on_apply_ace_data)
{
  return oc_sec_decode_acl(rep, false, device, on_apply_ace_cb,
                           on_apply_ace_data)
           ? 0
           : 1;
}

static void
acl_resource_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *data)
{
  (void)iface_mask;
  (void)data;
  if (oc_sec_decode_acl(request->request_payload, false,
                        request->resource->device, NULL, NULL)) {
    oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
    oc_sec_dump_acl(request->resource->device);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
  }
}

static void
acl_resource_delete(oc_request_t *request, oc_interface_mask_t iface_mask,
                    void *data)
{
  (void)iface_mask;
  (void)data;

  const oc_sec_pstat_t *ps = oc_sec_get_pstat(request->resource->device);
  if (ps->s == OC_DOS_RFNOP) {
    OC_ERR("oc_acl: Cannot DELETE ACE in RFNOP");
    oc_send_response_with_callback(request, OC_STATUS_FORBIDDEN, true);
    return;
  }

  bool success = false;
  const char *query_param = 0;
  int ret = oc_get_query_value_v1(request, "aceid", OC_CHAR_ARRAY_LEN("aceid"),
                                  &query_param);
  int aceid = 0;
  if (ret != -1) {
    aceid = (int)strtoul(query_param, NULL, 10);
    if (aceid != 0) {
      if (oc_sec_remove_ace_by_aceid(aceid, request->resource->device)) {
        success = true;
      }
    }
  } else if (ret == -1) {
    oc_sec_acl_clear(request->resource->device, NULL, NULL);
    success = true;
  }

  if (success) {
    oc_send_response_with_callback(request, OC_STATUS_DELETED, true);
    oc_sec_dump_acl(request->resource->device);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_NOT_FOUND, true);
  }
}

static void
acl_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data)
{
  (void)data;
  if (oc_sec_encode_acl(request->resource->device, iface_mask, false)) {
    oc_send_response_with_callback(request, OC_STATUS_OK, true);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
  }
}

void
oc_sec_acl_create_resource(size_t device)
{
  oc_core_populate_resource(
    OCF_SEC_ACL, device, OCF_SEC_ACL_URI, OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
    OC_DISCOVERABLE | OC_SECURE, acl_resource_get, /*put*/ NULL,
    acl_resource_post, acl_resource_delete, 1, OCF_SEC_ACL_RT);
}

bool
oc_sec_is_acl_resource_uri(oc_string_view_t uri)
{
  return oc_resource_match_uri(OC_STRING_VIEW(OCF_SEC_ACL_URI), uri);
}

bool
oc_sec_acl_is_owned_by(size_t device, oc_uuid_t uuid)
{
  const oc_sec_acl_t *acl = oc_sec_get_acl(device);
  return oc_uuid_is_equal(acl->rowneruuid, uuid);
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
void
oc_resource_set_access_in_RFOTM(oc_resource_t *resource, bool state,
                                oc_ace_permissions_t permission)
{
  if (state) {
    resource->properties |= OC_ACCESS_IN_RFOTM;
    resource->anon_permission_in_rfotm = permission;
    return;
  }
  resource->properties &= ~OC_ACCESS_IN_RFOTM;
  resource->anon_permission_in_rfotm = OC_PERM_NONE;
}
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_SECURITY */
