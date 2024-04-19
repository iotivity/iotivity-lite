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
                        const oc_ace_subject_t *subject, int aceid,
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
  const oc_sec_ace_t *sub = oc_list_head(g_aclist[device].subjects);

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
          oc_rep_set_text_string(resources, wc, OC_ACE_WC_ALL_SECURED_STR);
          break;
        case OC_ACE_WC_ALL_PUBLIC:
          oc_rep_set_text_string(resources, wc, OC_ACE_WC_ALL_PUBLIC_STR);
          break;
        case OC_ACE_WC_ALL:
          oc_rep_set_text_string(resources, wc, OC_ACE_WC_ALL_STR);
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
  oc_uuid_to_str(&g_aclist[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();

  return true;
}

bool
oc_sec_acl_update_res(oc_ace_subject_type_t type,
                      const oc_ace_subject_t *subject, int aceid,
                      uint16_t permission, oc_string_view_t tag,
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
    oc_sec_ace_get_or_add_res(ace, href, wildcard, permission, true);
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
  const oc_uuid_t *uuid = &client->di;

  oc_ace_subject_t subject;
  memset(&subject, 0, sizeof(oc_ace_subject_t));
  memcpy(subject.uuid.id, uuid->id, sizeof(oc_uuid_t));

  oc_ace_permissions_t perm =
    OC_PERM_RETRIEVE | OC_PERM_DELETE | OC_PERM_UPDATE;
  if (collection) {
    perm |= OC_PERM_CREATE;
  }

  return oc_sec_acl_update_res(OC_SUBJECT_UUID, &subject, -1, perm,
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
      const oc_rep_t *aclist2 = rep->value.object_array;
      while (aclist2 != NULL) {
        oc_ace_subject_t subject;
        memset(&subject, 0, sizeof(oc_ace_subject_t));
        oc_ace_subject_type_t subject_type = 0;
        uint16_t permission = 0;
        int aceid = -1;
        const oc_string_t *tag = NULL;
        const oc_rep_t *resources = 0;
        const oc_rep_t *ace = aclist2->value.object;
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
              tag = &ace->value.string;
            }
            break;
          case OC_REP_OBJECT_ARRAY:
            if (len == 9 && memcmp(oc_string(ace->name), "resources", 9) == 0)
              resources = ace->value.object_array;
            break;
          case OC_REP_OBJECT: {
            const oc_rep_t *sub = ace->value.object;
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
        if (aceid != -1 && !acl_unique_aceid(aceid, device)) {
          replaced_ace = oc_acl_remove_ace_from_device_by_aceid(aceid, device);
        }

        while (resources != NULL) {
          oc_ace_wildcard_t wc = OC_ACE_NO_WC;
          oc_rep_t *resource = resources->value.object;
          const oc_string_t *href = NULL;
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
                href = &resource->value.string;
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
          if (oc_sec_acl_update_res(subject_type, &subject, aceid, permission,
                                    oc_string_view2(tag), oc_string_view2(href),
                                    wc, device, &ace_upd)) {
            upd_ace = ace_upd.ace;
            created |= ace_upd.created;
            created_resource |= ace_upd.created_resource;
          } else {
            OC_WRN("failed to create resource(href:%s wildcard:%d)",
                   href != NULL ? oc_string(*href) : "", wc);
          }

          /* The following code block attaches "coap" endpoints to
                   resources linked to an anon-clear ACE. This logic is being
                   currently disabled to comply with the SH spec which
      requires that all vertical resources not expose a "coap" endpoint.
      #ifdef OC_SERVER
                if (subject_type == OC_SUBJECT_CONN &&
                    subject.conn == OC_CONN_ANON_CLEAR) {
                  if (href) {
                    oc_resource_t *r =
                      oc_ri_get_app_resource_by_uri(href, strlen(href),
      device); if (r) { oc_resource_make_public(r);
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
            oc_sec_on_apply_acl_data_t acl_data = { g_aclist[device].rowneruuid,
                                                    upd_ace, replaced_ace,
                                                    created, created_resource };
            on_apply_ace_cb(acl_data, on_apply_ace_data);
          }
        }

        if (replaced_ace) {
          oc_sec_free_ace(replaced_ace);
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

static bool
oc_sec_acl_anon_connection(size_t device, oc_string_view_t href,
                           uint16_t permission)
{
  assert(href.data != NULL);
  oc_ace_subject_t _anon_clear;
  memset(&_anon_clear, 0, sizeof(oc_ace_subject_t));
  _anon_clear.conn = OC_CONN_ANON_CLEAR;
  if (!oc_sec_acl_update_res(OC_SUBJECT_CONN, &_anon_clear, -1, permission,
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
