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

#include "oc_cred.h"
#include "config.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_core_res.h"
#include "oc_doxm.h"
#include "oc_dtls.h"
#include "oc_pstat.h"
#include "oc_store.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <stdlib.h>

OC_MEMB(creds, oc_sec_cred_t, OC_MAX_NUM_DEVICES *OC_MAX_NUM_SUBJECTS + 1);
#define OXM_JUST_WORKS "oic.sec.doxm.jw"

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
static oc_sec_creds_t *devices;
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_creds_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_sec_cred_default(int device)
{
  oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_pop(devices[device].creds);
  while (cred != NULL) {
    oc_memb_free(&creds, cred);
    cred = (oc_sec_cred_t *)oc_list_pop(devices[device].creds);
  }
  memset(devices[device].rowneruuid.id, 0, 16);
}

oc_sec_creds_t *
oc_sec_get_creds(int device)
{
  return &devices[device];
}

void
oc_sec_cred_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  devices =
    (oc_sec_creds_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_creds_t));
  if (!devices) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  int i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    OC_LIST_STRUCT_INIT(&devices[i], creds);
  }
}

static bool
unique_credid(int credid, int device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credid == credid)
      return false;
    cred = cred->next;
  }
  return true;
}

static int
get_new_credid(int device)
{
  int credid;
  do {
    credid = oc_random_value() >> 1;
  } while (!unique_credid(credid, device));
  return credid;
}

static void
oc_sec_remove_cred(oc_sec_cred_t *cred, int device)
{
  oc_list_remove(devices[device].creds, cred);
  if (oc_string_len(cred->role.role) > 0) {
    oc_free_string(&cred->role.role);
    if (oc_string_len(cred->role.authority) > 0) {
      oc_free_string(&cred->role.authority);
    }
  }
  oc_memb_free(&creds, cred);
}

static bool
oc_sec_remove_cred_by_credid(int credid, int device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credid == credid) {
      oc_sec_remove_cred(cred, device);
      return true;
    }
    cred = cred->next;
  }
  return false;
}

static void
oc_sec_clear_creds(int device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds), *next;
  while (cred != NULL) {
    next = cred->next;
    oc_sec_remove_cred(cred, device);
    cred = next;
  }
}

oc_sec_cred_t *
oc_sec_find_cred(oc_uuid_t *subjectuuid, int device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (memcmp(cred->subjectuuid.id, subjectuuid->id, 16) == 0) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_get_cred(oc_uuid_t *subjectuuid, int device)
{
  oc_sec_cred_t *cred = oc_sec_find_cred(subjectuuid, device);
  if (cred == NULL) {
    cred = oc_memb_alloc(&creds);
    if (cred != NULL) {
      memcpy(cred->subjectuuid.id, subjectuuid->id, 16);
      oc_list_add(devices[device].creds, cred);
    } else {
      OC_WRN("insufficient memory to add new credential\n");
    }
  }
  return cred;
}

void
oc_sec_encode_cred(bool persist, int device)
{
  oc_sec_cred_t *cr = oc_list_head(devices[device].creds);
  char uuid[37];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_CRED, device));
  oc_rep_set_array(root, creds);
  while (cr != NULL) {
    oc_rep_object_array_start_item(creds);
    oc_rep_set_int(creds, credid, cr->credid);
    oc_rep_set_int(creds, credtype, cr->credtype);
    oc_uuid_to_str(&cr->subjectuuid, uuid, 37);
    oc_rep_set_text_string(creds, subjectuuid, uuid);
    if (oc_string_len(cr->role.role) > 0) {
      oc_rep_set_object(creds, roleid);
      oc_rep_set_text_string(roleid, role, oc_string(cr->role.role));
      if (oc_string_len(cr->role.authority) > 0) {
        oc_rep_set_text_string(roleid, authority,
                               oc_string(cr->role.authority));
      }
      oc_rep_close_object(creds, roleid);
    }
    oc_rep_set_object(creds, privatedata);
    if (persist) {
      oc_rep_set_byte_string(privatedata, data, cr->key, 16);
    } else {
      oc_rep_set_byte_string(privatedata, data, cr->key, 0);
    }
    oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
    oc_rep_close_object(creds, privatedata);
    oc_rep_object_array_end_item(creds);
    cr = cr->next;
  }
  oc_rep_close_array(root, creds);
  oc_uuid_to_str(&devices[device].rowneruuid, uuid, 37);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

bool
oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                   int device)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(t->name), "rowneruuid", 10) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET) {
          OC_ERR("oc_cred: Can set rowneruuid only in RFOTM/SRESET\n");
          return false;
        }
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET &&
          ps->s != OC_DOS_RFPRO) {
        OC_ERR("oc_cred: Can set cred only in RFOTM/SRESET/RFPRO\n");
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
                       &devices[device].rowneruuid);
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *creds_array = rep->value.object_array;
      while (creds_array != NULL) {
        oc_rep_t *cred = creds_array->value.object;
        int credid = -1, credtype = 0;
        oc_string_t *role = 0, *authority = 0, *subjectuuid = 0;
        uint8_t key[24];
        bool non_empty = false;
        bool got_key = false, base64_key = false;
        while (cred != NULL) {
          len = oc_string_len(cred->name);
          non_empty = true;
          switch (cred->type) {
          case OC_REP_INT:
            if (len == 6 && memcmp(oc_string(cred->name), "credid", 6) == 0)
              credid = cred->value.integer;
            else if (len == 8 &&
                     memcmp(oc_string(cred->name), "credtype", 8) == 0)
              credtype = cred->value.integer;
            break;
          case OC_REP_STRING:
            if (len == 11 &&
                memcmp(oc_string(cred->name), "subjectuuid", 11) == 0) {
              subjectuuid = &cred->value.string;
            }
            break;
          case OC_REP_OBJECT: {
            oc_rep_t *data = cred->value.object;
            if (len == 11 &&
                memcmp(oc_string(cred->name), "privatedata", 11) == 0) {
              while (data != NULL) {
                switch (data->type) {
                case OC_REP_STRING: {
                  if (oc_string_len(data->name) == 8 &&
                      memcmp("encoding", oc_string(data->name), 8) == 0) {
                    if (oc_string_len(data->value.string) == 23 &&
                        memcmp("oic.sec.encoding.base64",
                               oc_string(data->value.string), 23) == 0) {
                      base64_key = true;
                    }
                  } else if (oc_string_len(data->name) == 4 &&
                             memcmp(oc_string(data->name), "data", 4) == 0) {
                    uint8_t *p = oc_cast(data->value.string, uint8_t);
                    int size = oc_string_len(data->value.string);
                    if (size == 0)
                      goto next_item;
                    if (size != 24) {
                      OC_ERR("oc_cred: Invalid key\n");
                      return false;
                    }
                    got_key = true;
                    memcpy(key, p, size);
                  }
                } break;
                case OC_REP_BYTE_STRING: {
                  uint8_t *p = oc_cast(data->value.string, uint8_t);
                  int size = oc_string_len(data->value.string);
                  if (size == 0)
                    goto next_item;
                  if (size != 16) {
                    OC_ERR("oc_cred: Invalid key\n");
                    return false;
                  }
                  got_key = true;
                  memcpy(key, p, 16);
                } break;
                default:
                  break;
                }
              next_item:
                data = data->next;
              }
              if (got_key && base64_key) {
                oc_base64_decode(key, 24);
              }
            } else if (len == 6 &&
                       memcmp(oc_string(cred->name), "roleid", 6) == 0) {
              while (data != NULL) {
                len = oc_string_len(data->name);
                if (len == 4 && memcmp(oc_string(data->name), "role", 4) == 0) {
                  role = &data->value.string;
                } else if (len == 9 &&
                           memcmp(oc_string(data->name), "authority", 9) == 0) {
                  authority = &data->value.string;
                }
                data = data->next;
              }
            }
          } break;
          default:
            break;
          }
          cred = cred->next;
        }
        if (non_empty) {
          oc_uuid_t subject;
          if (!subjectuuid) {
            return false;
          }
          oc_str_to_uuid(oc_string(*subjectuuid), &subject);
          if (!unique_credid(credid, device)) {
            oc_sec_remove_cred_by_credid(credid, device);
          }
          if (credid == -1) {
            credid = get_new_credid(device);
          }
          oc_sec_cred_t *credobj = oc_sec_get_cred(&subject, device);
          if (!credobj) {
            return false;
          }
          credobj->credid = credid;
          credobj->credtype = credtype;
          if (role) {
            oc_new_string(&credobj->role.role, oc_string(*role),
                          oc_string_len(*role));
            if (authority) {
              oc_new_string(&credobj->role.authority, oc_string(*authority),
                            oc_string_len(*authority));
            }
          }
          if (got_key) {
            memcpy(credobj->key, key, 16);
          } else {
            if (owner) {
              *owner = credobj;
            }
          }
        }
        creds_array = creds_array->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
get_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  oc_sec_encode_cred(false, request->resource->device);
  oc_send_response(request, OC_STATUS_OK);
}

bool
oc_cred_remove_subject(const char *subjectuuid, int device)
{
  oc_uuid_t _subjectuuid;
  oc_str_to_uuid(subjectuuid, &_subjectuuid);
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds), *next = 0;
  while (cred != NULL) {
    next = cred->next;
    if (memcmp(cred->subjectuuid.id, _subjectuuid.id, 16) == 0) {
      oc_sec_remove_cred(cred, device);
      return true;
    }
    cred = next;
  }
  return false;
}

void
delete_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  bool success = false;
  char *query_param = 0;
  int ret = oc_get_query_value(request, "credid", &query_param);
  int credid = 0;
  if (ret != -1) {
    credid = (int)strtoul(query_param, NULL, 10);
    if (credid != 0) {
      if (oc_sec_remove_cred_by_credid(credid, request->resource->device)) {
        success = true;
      }
    }
  } else {
    oc_sec_clear_creds(request->resource->device);
    success = true;
  }

  if (success) {
    oc_send_response(request, OC_STATUS_DELETED);
    oc_sec_dump_cred(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_NOT_FOUND);
  }
}

void
post_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(request->resource->device);
  oc_sec_cred_t *owner = NULL;
  bool success = oc_sec_decode_cred(request->request_payload, &owner, false,
                                    request->resource->device);
  if (success && owner &&
      memcmp(owner->subjectuuid.id,
             devices[request->resource->device].rowneruuid.id, 16) == 0) {
    success = oc_sec_derive_owner_psk(
      request->origin, (const uint8_t *)OXM_JUST_WORKS, strlen(OXM_JUST_WORKS),
      doxm->deviceuuid.id, 16, owner->subjectuuid.id, 16, owner->key, 16);
  }
  if (!success) {
    if (owner) {
      oc_sec_remove_cred_by_credid(owner->credid, request->resource->device);
    }
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  } else {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_cred(request->resource->device);
  }
}

#endif /* OC_SECURITY */
