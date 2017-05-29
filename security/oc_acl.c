/*
// Copyright (c) 2016 Intel Corporation
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
#include "config.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_doxm.h"
#include "oc_dtls.h"
#include "oc_rep.h"
#include "oc_store.h"
#include <stddef.h>
#include <string.h>

extern int strncasecmp(const char *s1, const char *s2, size_t n);

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#else /* OC_DYNAMIC_ALLOCATION */
#define MAX_NUM_PERM_GROUPS (OC_MAX_APP_RESOURCES + NUM_OC_CORE_RESOURCES)
#endif /* !OC_DYNAMIC_ALLOCATION */
#define MAX_NUM_RES_PERM_PAIRS                                                 \
  ((OC_MAX_NUM_SUBJECTS + 1) * (OC_MAX_APP_RESOURCES + NUM_OC_CORE_RESOURCES))
OC_MEMB(ace_l, oc_sec_ace_t, OC_MAX_NUM_SUBJECTS + 1);
OC_MEMB(res_l, oc_sec_acl_res_t, MAX_NUM_RES_PERM_PAIRS);
static oc_uuid_t WILDCARD_SUB = {.id = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0 } };
static oc_sec_acl_t ac_list = { 0 };

static void
get_sub_perm_groups(oc_sec_ace_t *ace, uint16_t *groups, int *n)
{
  int i = 0, j;
  oc_sec_acl_res_t *res = oc_list_head(ace->resources);
  while (res != NULL) {
    groups[i++] = res->permissions;
    res = res->next;
  }
  for (i = 0; i < (*n - 1); i++) {
    for (j = (i + 1); j < *n; j++) {
      if (groups[i] > groups[j]) {
        uint16_t t = groups[i];
        groups[i] = groups[j];
        groups[j] = t;
      }
    }
  }
  j = 0;
  for (i = 1; i < *n; i++) {
    if (groups[j] != groups[i])
      groups[++j] = groups[i];
  }
  *n = j + 1;
}

bool
oc_sec_encode_acl(void)
{
  int i, n = 0;
  char uuid[37];
  oc_rep_start_root_object();
  oc_process_baseline_interface(oc_core_get_resource_by_index(OCF_SEC_ACL));
  oc_rep_set_object(root, aclist);
  oc_rep_set_array(aclist, aces);
  oc_sec_ace_t *sub = oc_list_head(ac_list.subjects);
  while (sub != NULL) {
    if (memcmp(sub->subjectuuid.id, WILDCARD_SUB.id, 16) == 0) {
      goto next_sub;
    } else {
      oc_uuid_to_str(&sub->subjectuuid, uuid, 37);
    }
    OC_DBG("oc_sec_acl_encode: subject %s\n", uuid);
    n = oc_list_length(sub->resources);
#ifdef OC_DYNAMIC_ALLOCATION
    uint16_t *groups = malloc(n * sizeof(uint16_t));
    if (!groups) {
      return false;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint16_t groups[MAX_NUM_PERM_GROUPS];
#endif /* !OC_DYNAMIC_ALLOCATION */
    get_sub_perm_groups(sub, groups, &n);
    for (i = 0; i < n; i++) {
      oc_rep_object_array_start_item(aces);
      oc_rep_set_text_string(aces, subjectuuid, uuid);
      oc_rep_set_uint(aces, permission, groups[i]);
      oc_rep_set_array(aces, resources);
      oc_sec_acl_res_t *res = oc_list_head(sub->resources);
      while (res != NULL) {
        if (res->permissions == groups[i]) {
          // TODO: Check if we need to track rts in ACEs for resources
          // The spec isn't clear on how they're used for access-control.
          if (!res->wildcard) {
            OC_DBG("oc_sec_acl_encode: adding resource %s\n",
                   oc_string(res->resource->uri));
            oc_rep_object_array_start_item(resources);
            oc_rep_set_text_string(resources, href,
                                   oc_string(res->resource->uri));
            oc_core_encode_interfaces_mask(oc_rep_object(resources),
                                           res->interfaces);
            oc_rep_set_string_array(resources, rt, res->types);
            oc_rep_object_array_end_item(resources);
          } else {
            OC_DBG("oc_sec_acl_encode: adding resource *\n");
            oc_rep_object_array_start_item(resources);
            oc_rep_set_text_string(resources, href, "*");
            oc_rep_set_array(resources, if);
            oc_rep_add_text_string(if, "*");
            oc_rep_close_array(resources, if);
            oc_rep_set_array(resources, rt);
            oc_rep_add_text_string(rt, "*");
            oc_rep_close_array(resources, rt);
            oc_rep_object_array_end_item(resources);
          }
        }
        res = res->next;
      }
      oc_rep_close_array(aces, resources);
      oc_rep_object_array_end_item(aces);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(groups);
#endif /* OC_DYNAMIC_ALLOCATION */
  next_sub:
    sub = sub->next;
  }
  oc_rep_close_array(aclist, aces);
  oc_rep_close_object(root, aclist);
  oc_uuid_to_str(&ac_list.rowneruuid, uuid, 37);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();

  return true;
}

static oc_sec_acl_res_t *
oc_sec_acl_get_ace(oc_uuid_t *subjectuuid, oc_resource_t *resource,
                   bool wildcard, bool create)
{
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_list_head(ac_list.subjects);
  oc_sec_acl_res_t *res = NULL;

#ifdef OC_DEBUG
  char uuid[37];
  oc_uuid_to_str(subjectuuid, uuid, 37);
#endif

  while (ace != NULL) {
    if (memcmp(ace->subjectuuid.id, subjectuuid->id, 16) == 0)
      goto got_ace;
    ace = oc_list_item_next(ace);
  }

  if (create)
    goto new_ace;

  OC_DBG("Could not find ACE for subject %s\n", uuid);

  goto done;

got_ace:
  OC_DBG("Found ACE for subject %s\n", uuid);
  res = (oc_sec_acl_res_t *)oc_list_head(ace->resources);

  while (res != NULL) {
    if (res->resource == resource || res->wildcard == true) {
#ifdef OC_DEBUG
      if (res->wildcard)
        OC_DBG("Found resource * in ACE\n");
      else
        OC_DBG("Found resource %s in ACE\n", oc_string(res->resource->uri));
#endif
      goto done;
    }
    res = oc_list_item_next(res);
  }

  if (create)
    goto new_res;

  goto done;

new_ace:
  ace = oc_memb_alloc(&ace_l);

  if (!ace)
    goto done;

  OC_DBG("Created new ACE for subject %s\n", uuid);

  OC_LIST_STRUCT_INIT(ace, resources);
  memcpy(ace->subjectuuid.id, subjectuuid->id, 16);
  oc_list_add(ac_list.subjects, ace);

new_res:
  res = oc_memb_alloc(&res_l);
  if (res) {
    res->resource = resource;
    res->wildcard = wildcard;
    memset(&res->types, 0, sizeof(oc_string_array_t));
#ifdef OC_DEBUG
    if (wildcard)
      OC_DBG("Adding new resource * to ACE\n");
    else
      OC_DBG("Adding new resource %s to ACE\n", oc_string(res->resource->uri));
#endif /* OC_DBG */
    oc_list_add(ace->resources, res);
  }

done:
  return res;
}

static oc_sec_acl_res_t *
oc_sec_update_acl(oc_uuid_t *subjectuuid, oc_resource_t *resource,
                  bool wildcard, oc_string_array_t *rt,
                  oc_interface_mask_t interfaces, uint16_t permissions)
{
  oc_sec_acl_res_t *res =
    oc_sec_acl_get_ace(subjectuuid, resource, wildcard, true);

  if (!res)
    return false;

  if (oc_string_array_get_allocated_size(res->types) > 0)
    oc_free_string_array(&res->types);
  oc_new_string_array(&res->types, oc_string_array_get_allocated_size(*rt));
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(*rt); i++) {
    oc_string_array_add_item(res->types, oc_string_array_get_item(*rt, i));
  }
  res->interfaces = interfaces;
  res->permissions = permissions;

#ifdef OC_DEBUG
  if (wildcard)
    OC_DBG("Setting permissions %d for resource *\n", res->permissions);
  else
    OC_DBG("Setting permissions %d for resource %s\n", res->permissions,
           oc_string(resource->uri));
#endif /* OC_DBG */

  return res;
}

void
oc_sec_acl_init(void)
{
  OC_LIST_STRUCT_INIT(&ac_list, subjects);
}

static bool
oc_sec_remove_subject(const char *subject)
{
  bool removed = false;
  oc_uuid_t subjectuuid;
  oc_str_to_uuid(subject, &subjectuuid);

  oc_sec_ace_t *sub = oc_list_head(ac_list.subjects), *next_sub = 0;
  while (sub != NULL) {
    next_sub = sub->next;
    if (memcmp(subjectuuid.id, sub->subjectuuid.id, 16) == 0) {
      oc_sec_acl_res_t *res = oc_list_head(sub->resources), *next_res = 0;
      while (res != NULL) {
        next_res = res->next;
        oc_list_remove(sub->resources, res);
        oc_memb_free(&res_l, res);
        res = next_res;
      }
      oc_list_remove(ac_list.subjects, sub);
      oc_memb_free(&ace_l, sub);
      removed = true;
      break;
    }
    sub = next_sub;
  }

  return removed;
}

void
oc_sec_set_post_otm_acl(void)
{
  const char wildcard_sub[36] = "00000000-0000-0000-0000-000000000000";
  oc_sec_remove_subject(wildcard_sub);
  oc_resource_t *resource;
  int i,
    num_core_resources = NUM_OC_CORE_RESOURCES - 1 + oc_core_get_num_devices();
  for (i = 0; i < num_core_resources; i++) {
    resource = oc_core_get_resource_by_index(i);
    if (i < OCF_SEC_DOXM || i > OCF_SEC_CRED || i == OCF_SEC_DOXM) {
      oc_sec_update_acl(&WILDCARD_SUB, resource, false, &resource->types,
                        OC_IF_BASELINE, 2);
    }
  }
}

void
oc_sec_acl_default(void)
{
  bool success = true;
  oc_resource_t *resource;
  int i,
    num_core_resources = NUM_OC_CORE_RESOURCES - 1 + oc_core_get_num_devices();
  for (i = 0; i < num_core_resources; i++) {
    resource = oc_core_get_resource_by_index(i);
    if (i < OCF_SEC_DOXM || i > OCF_SEC_CRED)
      success &=
        (oc_sec_update_acl(&WILDCARD_SUB, resource, false, &resource->types,
                           OC_IF_BASELINE, 2) != NULL);
    else if (i == OCF_SEC_ACL)
      success &=
        (oc_sec_update_acl(&WILDCARD_SUB, resource, false, &resource->types,
                           OC_IF_BASELINE, 14) != NULL);
    else
      success &=
        (oc_sec_update_acl(&WILDCARD_SUB, resource, false, &resource->types,
                           OC_IF_BASELINE, 6) != NULL);
  }
  OC_DBG("ACL for core resources initialized %d\n", success);
  oc_uuid_t *device = oc_core_get_device_id(0);
  memcpy(&ac_list.rowneruuid, device, sizeof(oc_uuid_t));
}

bool
oc_sec_check_acl(oc_method_t method, oc_resource_t *resource,
                 oc_endpoint_t *endpoint)
{
  bool granted = false;
  oc_sec_acl_res_t *res = NULL;
  oc_uuid_t *identity = (oc_uuid_t *)oc_sec_dtls_get_peer_uuid(endpoint);

  if (identity) {
    oc_sec_doxm_t *doxm = oc_sec_get_doxm();
    if (memcmp(identity->id, doxm->devowneruuid.id, 16) == 0) {
      return true;
    }

    res = oc_sec_acl_get_ace(identity, resource, false, false);

    if (!res) {
      res = oc_sec_acl_get_ace(identity, resource, true, false);
    }

    if (!res) {
      if (memcmp(identity->id, ac_list.rowneruuid.id, 16) == 0 &&
          (memcmp(oc_string(resource->uri), "/oic/sec/acl", 12) == 0 ||
           memcmp(oc_string(resource->uri), "/oic/sec/doxm", 13) == 0 ||
           memcmp(oc_string(resource->uri), "/oic/sec/pstat", 14) == 0)) {
        return true;
      }
    }
  }

  if (!res) { // Try Anonymous
    res = oc_sec_acl_get_ace(&WILDCARD_SUB, resource, false, false);
  }

  if (!res) {
    return false;
  }

  OC_DBG("Got permissions mask %d\n", res->permissions);

  if (res->permissions & OC_PERM_CREATE || res->permissions & OC_PERM_UPDATE) {
    switch (method) {
    case OC_PUT:
    case OC_POST:
      granted = true;
      break;
    default:
      break;
    }
  }

  if (res->permissions & OC_PERM_RETRIEVE ||
      res->permissions & OC_PERM_NOTIFY) {
    switch (method) {
    case OC_GET:
      granted = true;
      break;
    default:
      break;
    }
  }

  if (res->permissions & OC_PERM_DELETE) {
    switch (method) {
    case OC_DELETE:
      granted = true;
      break;
    default:
      break;
    }
  }

  return granted;
}

bool
oc_sec_decode_acl(oc_rep_t *rep)
{
  uint16_t permissions = 0;
  oc_uuid_t subjectuuid;
  oc_rep_t *resources = 0;
  int len = 0;
  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &ac_list.rowneruuid);
      }
      break;
    case OBJECT: {
      oc_rep_t *aclist = rep->value.object;
      while (aclist != NULL) {
        switch (aclist->type) {
        case OBJECT_ARRAY: {
          oc_rep_t *aces = aclist->value.object_array;
          while (aces != NULL) {
            oc_rep_t *ace = aces->value.object;
            while (ace != NULL) {
              len = oc_string_len(ace->name);
              switch (ace->type) {
              case STRING:
                if (len == 11 &&
                    memcmp(oc_string(ace->name), "subjectuuid", 11) == 0) {
                  if (memcmp(oc_string(ace->value.string), "*", 1) == 0)
                    memcpy(subjectuuid.id, WILDCARD_SUB.id, 16);
                  else
                    oc_str_to_uuid(oc_string(ace->value.string), &subjectuuid);
                }
                break;
              case INT:
                if (len == 10 &&
                    memcmp(oc_string(ace->name), "permission", 10) == 0)
                  permissions = ace->value.integer;
                break;
              case OBJECT_ARRAY:
                if (len == 9 &&
                    memcmp(oc_string(ace->name), "resources", 9) == 0)
                  resources = ace->value.object_array;
                break;
              default:
                break;
              }
              ace = ace->next;
            }

            while (resources != NULL) {
              oc_rep_t *resource = resources->value.object;
              bool wildcard = false;
              oc_sec_acl_res_t *ace_res = NULL;
              oc_resource_t *res = NULL;
              oc_interface_mask_t interfaces = 0;
              oc_string_array_t *rt = 0;
              int i;

              while (resource != NULL) {
                switch (resource->type) {
                case STRING:
                  if (oc_string_len(resource->name) == 4 &&
                      strncasecmp(oc_string(resource->name), "href", 4) == 0) {
                    res = oc_core_get_resource_by_uri(
                      oc_string(resource->value.string));

#ifdef OC_SERVER
                    if (!res)
                      res = oc_ri_get_app_resource_by_uri(
                        oc_string(resource->value.string),
                        oc_string_len(resource->value.string));
#endif /* OC_SERVER */

                    if (!res) {
                      if (memcmp(oc_string(resource->value.string), "*", 1) ==
                          0)
                        wildcard = true;
                      else {
                        OC_DBG("\n\noc_sec_acl_decode: could not find resource "
                               "%s\n\n",
                               oc_string(resource->value.string));
                        return false;
                      }
                    }
                  }
                  break;
                case STRING_ARRAY: {
                  if (oc_string_len(resource->name) == 2) {
                    if (strncasecmp(oc_string(resource->name), "if", 2) == 0) {
                      for (i = 0; i < (int)oc_string_array_get_allocated_size(
                                        resource->value.array);
                           i++) {
                        if (wildcard ||
                            memcmp(oc_string_array_get_item(
                                     resource->value.array, i),
                                   "*", 1) == 0) {
                          wildcard = true;
                          break;
                        }
                        interfaces |= oc_ri_get_interface_mask(
                          oc_string_array_get_item(resource->value.array, i),
                          oc_string_array_get_item_size(resource->value.array,
                                                        i));
                      }
                    } else if (strncasecmp(oc_string(resource->name), "rt",
                                           2) == 0) {
                      rt = &resource->value.array;
                    }
                  }
                } break;
                default:
                  break;
                }

                resource = resource->next;
              }

#ifdef OC_DEBUG
              if (wildcard)
                OC_DBG("\n\noc_sec_acl_decode: Updating resource * in ACE\n");
              else
                OC_DBG("\n\noc_sec_acl_decode: Updating resource %s in ACE\n",
                       oc_string(res->uri));
#endif /* OC_DBG */

              ace_res = oc_sec_update_acl(&subjectuuid, res, wildcard, rt,
                                          interfaces, permissions);
              if (ace_res == NULL) {
#ifdef OC_DEBUG
                if (wildcard)
                  OC_DBG("\n\noc_sec_acl_decode: could not update ACE with "
                         "resource * permissions\n\n");
                else
                  OC_DBG("\n\noc_sec_acl_decode: could not update ACE with "
                         "resource %s permissions\n\n",
                         oc_string(res->uri));
#endif /* OC_DBG */
                return false;
              }

              resources = resources->next;
            }
            aces = aces->next;
          }
        } break;
        default:
          break;
        }
        aclist = aclist->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

/*
  {
  "aclist":
  {
  "aces":
  [
  {
  "subjectuuid": "61646d69-6e44-6576-6963-655575696430",
  "resources":
  [
  {"href": "/led/1", "rt": [...], "if": [...]},
  {"href": "/switch/1", "rt": [...], "if": [...]}
  ],
  "permission": 31
  }
  ]
  },
  "rowneruuid": "5cdf40b1-c12e-432b-67a2-aa79a3f08c59"
  }
*/
void
post_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  if (oc_sec_decode_acl(request->request_payload)) {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_acl();
  } else {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

void
delete_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  char *subjectuuid = 0;
  int ret = oc_get_query_value(request, "subjectuuid", &subjectuuid);
  if (ret != -1 && oc_sec_remove_subject(subjectuuid)) {
    oc_send_response(request, OC_STATUS_DELETED);
    oc_sec_dump_acl();
    return;
  }
  oc_send_response(request, OC_STATUS_NOT_FOUND);
}

void
get_acl(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  if (oc_sec_encode_acl()) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

#endif /* OC_SECURITY */
