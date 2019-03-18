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

#include "oc_core_res.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_discovery.h"
#include "oc_introspection.h"
#include "oc_rep.h"

#ifdef OC_SECURITY
#include "security/oc_doxm.h"
#include "security/oc_pstat.h"
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

#include "port/oc_assert.h"
#include <stdarg.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include "oc_endpoint.h"
#include <stdlib.h>
static oc_resource_t *core_resources = NULL;
static oc_device_info_t *oc_device_info = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_resource_t core_resources[1 + OCF_D * OC_MAX_NUM_DEVICES];
static oc_device_info_t oc_device_info[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */
static oc_platform_info_t oc_platform_info;

static bool announce_con_res = true;
static size_t device_count = 0;

/* Although used several times in the OCF spec, "/oic/con" is not
   accepted by the spec. Use a private prefix instead.
   Update OC_NAMELEN_CON_RES if changing the value.
   String must not have a leading slash. */
#define OC_NAME_CON_RES "oc/con"
/* Number of characters of OC_NAME_CON_RES */
#define OC_NAMELEN_CON_RES 6

void
oc_core_init(void)
{
  oc_core_shutdown();

#ifdef OC_DYNAMIC_ALLOCATION
  core_resources = (oc_resource_t *)calloc(1, sizeof(oc_resource_t));
  if (!core_resources) {
    oc_abort("Insufficient memory");
  }

  oc_device_info = NULL;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static void
oc_core_free_device_info_properties(oc_device_info_t *oc_device_info_item)
{

  if (oc_device_info_item) {
    if (oc_string_len(oc_device_info_item->name))
      oc_free_string(&(oc_device_info_item->name));
    if (oc_string_len(oc_device_info_item->icv))
      oc_free_string(&(oc_device_info_item->icv));
    if (oc_string_len(oc_device_info_item->dmv))
      oc_free_string(&(oc_device_info_item->dmv));
  }
}

void
oc_core_shutdown(void)
{
  size_t i;
  if (oc_string_len(oc_platform_info.mfg_name))
    oc_free_string(&(oc_platform_info.mfg_name));

#ifdef OC_DYNAMIC_ALLOCATION
  if (oc_device_info) {
#endif /* OC_DYNAMIC_ALLOCATION */
    for (i = 0; i < device_count; ++i) {
      oc_device_info_t *oc_device_info_item = &oc_device_info[i];
      oc_core_free_device_info_properties(oc_device_info_item);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(oc_device_info);
    oc_device_info = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_DYNAMIC_ALLOCATION
  if (core_resources) {
#endif /* OC_DYNAMIC_ALLOCATION */
    for (i = 0; i < 1 + (OCF_D * device_count); ++i) {
      oc_resource_t *core_resource = &core_resources[i];
      oc_ri_free_resource_properties(core_resource);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(core_resources);
    core_resources = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  device_count = 0;
}

void
oc_core_encode_interfaces_mask(CborEncoder *parent,
                               oc_interface_mask_t iface_mask)
{
  oc_rep_set_key((parent), "if");
  oc_rep_start_array((parent), if);
  if (iface_mask & OC_IF_LL) {
    oc_rep_add_text_string(if, "oic.if.ll");
  }
  if (iface_mask & OC_IF_B) {
    oc_rep_add_text_string(if, "oic.if.b");
  }
  if (iface_mask & OC_IF_R) {
    oc_rep_add_text_string(if, "oic.if.r");
  }
  if (iface_mask & OC_IF_RW) {
    oc_rep_add_text_string(if, "oic.if.rw");
  }
  if (iface_mask & OC_IF_A) {
    oc_rep_add_text_string(if, "oic.if.a");
  }
  if (iface_mask & OC_IF_S) {
    oc_rep_add_text_string(if, "oic.if.s");
  }
  if (iface_mask & OC_IF_BASELINE) {
    oc_rep_add_text_string(if, "oic.if.baseline");
  }
  oc_rep_end_array((parent), if);
}

#ifdef OC_SECURITY
void
oc_core_regen_unique_ids(size_t device)
{
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  oc_device_info_t *d = &oc_device_info[device];
  oc_gen_uuid(&doxm->deviceuuid);
  memcpy(d->di.id, doxm->deviceuuid.id, 16);
  oc_gen_uuid(&d->piid);
  oc_gen_uuid(&oc_platform_info.pi);
}
#endif /* OC_SECURITY */

static void
oc_core_device_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                       void *data)
{
  (void)data;
  size_t device = request->resource->device;
  oc_rep_start_root_object();

  char di[OC_UUID_LEN], piid[OC_UUID_LEN];
  oc_uuid_to_str(&oc_device_info[device].di, di, OC_UUID_LEN);
  if (request->origin && request->origin->version != OIC_VER_1_1_0) {
    oc_uuid_to_str(&oc_device_info[device].piid, piid, OC_UUID_LEN);
  }

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_text_string(root, di, di);
    if (request->origin && request->origin->version != OIC_VER_1_1_0) {
      oc_rep_set_text_string(root, piid, piid);
    }
    oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));
    oc_rep_set_text_string(root, icv, oc_string(oc_device_info[device].icv));
    oc_rep_set_text_string(root, dmv, oc_string(oc_device_info[device].dmv));
    if (oc_device_info[device].add_device_cb) {
      oc_device_info[device].add_device_cb(oc_device_info[device].data);
    }
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
oc_core_con_handler_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)data;
  size_t device = request->resource->device;
  oc_rep_start_root_object();

  switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
    /* fall through */
    case OC_IF_RW: {
      /* oic.wk.d attribute n shall always be the same value as
      oic.wk.con attribute n. */
      oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));
    } break;
    default:
      break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
oc_core_con_handler_post(oc_request_t *request, oc_interface_mask_t iface_mask,
                         void *data)
{
  (void)iface_mask;
  oc_rep_t *rep = request->request_payload;
  bool changed = false;
  size_t device = request->resource->device;

  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), "n") == 0) {
      if (rep->type != OC_REP_STRING || oc_string_len(rep->value.string) == 0) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }

      oc_free_string(&oc_device_info[device].name);
      oc_new_string(&oc_device_info[device].name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      oc_rep_start_root_object();
      oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));
      oc_rep_end_root_object();
      /* notify_observers is automatically triggered in
         oc_ri_invoke_coap_entity_handler() for oic.wk.con,
         we cannot notify name change of oic.wk.d, as this
         is not observable */
      changed = true;
      break;
    }
    rep = rep->next;
  }

  if (data) {
    oc_con_write_cb_t cb = *(oc_con_write_cb_t *)(&data);
    cb(device, request->request_payload);
  }

  if (changed) {
    oc_send_response(request, OC_STATUS_CHANGED);
  }
  else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

size_t
oc_core_get_num_devices(void)
{
  return device_count;
}

bool
oc_get_con_res_announced(void)
{
  return announce_con_res;
}

void
oc_set_con_res_announced(bool announce)
{
  announce_con_res = announce;
}

oc_device_info_t *
oc_core_add_new_device(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version,
                       oc_core_add_device_cb_t add_device_cb, void *data)
{
  (void)data;
#ifndef OC_DYNAMIC_ALLOCATION
  if (device_count == OC_MAX_NUM_DEVICES) {
    OC_ERR("device limit reached");
    return NULL;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  size_t new_num = 1 + OCF_D * (device_count + 1);
  core_resources =
    (oc_resource_t *)realloc(core_resources, new_num * sizeof(oc_resource_t));

  if (!core_resources) {
    oc_abort("Insufficient memory");
  }
  oc_resource_t *device = &core_resources[new_num - OCF_D];
  memset(device, 0, OCF_D * sizeof(oc_resource_t));

  oc_device_info = (oc_device_info_t *)realloc(
    oc_device_info, (device_count + 1) * sizeof(oc_device_info_t));

  if (!oc_device_info) {
    oc_abort("Insufficient memory");
  }
  memset(&oc_device_info[device_count], 0, sizeof(oc_device_info_t));

#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_SECURITY
  oc_gen_uuid(&oc_device_info[device_count].di);
#endif /* !OC_SECURITY */

  /* Construct device resource */
  if (strlen(rt) == 8 && strncmp(rt, "oic.wk.d", 8) == 0) {
    oc_core_populate_resource(
      OCF_D, device_count, uri, OC_IF_R | OC_IF_BASELINE, OC_IF_R,
      OC_DISCOVERABLE, oc_core_device_handler, 0, 0, 0, 1, rt);
  } else {
    oc_core_populate_resource(
      OCF_D, device_count, uri, OC_IF_R | OC_IF_BASELINE, OC_IF_R,
      OC_DISCOVERABLE, oc_core_device_handler, 0, 0, 0, 2, rt, "oic.wk.d");
  }

#ifndef OC_SECURITY
  oc_gen_uuid(&oc_device_info[device_count].piid);
#endif /* !OC_SECURITY */

  oc_new_string(&oc_device_info[device_count].name, name, strlen(name));
  oc_new_string(&oc_device_info[device_count].icv, spec_version,
                strlen(spec_version));
  oc_new_string(&oc_device_info[device_count].dmv, data_model_version,
                strlen(data_model_version));
  oc_device_info[device_count].add_device_cb = add_device_cb;

  if (oc_get_con_res_announced()) {
    /* Construct oic.wk.con resource for this device. */
    oc_core_populate_resource(
      OCF_CON, device_count, "/" OC_NAME_CON_RES, OC_IF_RW | OC_IF_BASELINE,
      OC_IF_RW, OC_DISCOVERABLE | OC_OBSERVABLE, oc_core_con_handler_get,
      oc_core_con_handler_post, oc_core_con_handler_post, 0, 1, "oic.wk.con");
  }

  oc_create_discovery_resource(OCF_RES, device_count);

  oc_create_introspection_resource(device_count);

  oc_device_info[device_count].data = data;

  if (oc_connectivity_init(device_count) < 0) {
    oc_abort("error initializing connectivity for device");
  }

  device_count++;

  return &oc_device_info[device_count - 1];
}

static void
oc_core_platform_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                         void *data)
{
  (void)data;
  oc_rep_start_root_object();

  char pi[OC_UUID_LEN];
  oc_uuid_to_str(&oc_platform_info.pi, pi, OC_UUID_LEN);

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_text_string(root, pi, pi);
    oc_rep_set_text_string(root, mnmn, oc_string(oc_platform_info.mfg_name));
    if (oc_platform_info.init_platform_cb) {
      oc_platform_info.init_platform_cb(oc_platform_info.data);
    }
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

oc_platform_info_t *
oc_core_init_platform(const char *mfg_name, oc_core_init_platform_cb_t init_cb,
                      void *data)
{
  if (oc_platform_info.mfg_name.size > 0) {
    return &oc_platform_info;
  }

  /* Populating resource obuject */
  oc_core_populate_resource(OCF_P, 0, "oic/p", OC_IF_R | OC_IF_BASELINE,
                            OC_IF_R, OC_DISCOVERABLE,
                            oc_core_platform_handler, 0, 0, 0, 1, "oic.wk.p");

#ifndef OC_SECURITY
  oc_gen_uuid(&oc_platform_info.pi);
#endif /* !OC_SECURITY */

  oc_new_string(&oc_platform_info.mfg_name, mfg_name, strlen(mfg_name));
  oc_platform_info.init_platform_cb = init_cb;
  oc_platform_info.data = data;

  return &oc_platform_info;
}

void
oc_store_uri(const char *s_uri, oc_string_t *d_uri)
{
  if (s_uri[0] != '/') {
    size_t s_len = strlen(s_uri);
    oc_alloc_string(d_uri, s_len + 2);
    memcpy((char *)oc_string(*d_uri) + 1, s_uri, s_len);
    ((char *)oc_string(*d_uri))[0] = '/';
    ((char *)oc_string(*d_uri))[s_len + 1] = '\0';
  } else {
    oc_new_string(d_uri, s_uri, strlen(s_uri));
  }
}

void
oc_core_populate_resource(int core_resource, size_t device_index, const char *uri,
                          oc_interface_mask_t iface_mask,
                          oc_interface_mask_t default_interface,
                          int properties,
                          oc_request_callback_t get, oc_request_callback_t put,
                          oc_request_callback_t post,
                          oc_request_callback_t delete, int num_resource_types,
                          ...)
{
  oc_resource_t *r = oc_core_get_resource_by_index(core_resource, device_index);
  if (!r) {
    return;
  }
  r->device = device_index;
  oc_store_uri(uri, &r->uri);
  r->properties = properties;
  va_list rt_list;
  int i;
  va_start(rt_list, num_resource_types);
  oc_new_string_array(&r->types, num_resource_types);
  for (i = 0; i < num_resource_types; i++) {
    oc_string_array_add_item(r->types, va_arg(rt_list, const char *));
  }
  va_end(rt_list);
  r->interfaces = iface_mask;
  r->default_interface = default_interface;
  r->get_handler.cb = get;
  r->put_handler.cb = put;
  r->post_handler.cb = post;
  r->delete_handler.cb = delete;
}

oc_uuid_t *
oc_core_get_device_id(size_t device)
{
  if (device >= device_count) {
    return NULL;
  }
  return &oc_device_info[device].di;
}

oc_device_info_t *
oc_core_get_device_info(size_t device)
{
  if (device >= device_count) {
    return NULL;
  }
  return &oc_device_info[device];
}

oc_platform_info_t *
oc_core_get_platform_info(void)
{
  return &oc_platform_info;
}

oc_resource_t *
oc_core_get_resource_by_index(int type, size_t device)
{
  if (type == OCF_P) {
    return &core_resources[0];
  }
  return &core_resources[OCF_D * device + type];
}

bool
oc_core_is_DCR(oc_resource_t *resource, size_t device)
{
  if (resource == &core_resources[0]) {
    return true;
  }

  size_t device_resources = OCF_D * device;

  size_t DCRs_start = device_resources + OCF_RES,
         DCRs_end = device_resources + OCF_D, i;
  for (i = DCRs_start; i <= DCRs_end; i++) {
    if (resource == &core_resources[i]) {
      return true;
    }
  }

  return false;
}

oc_resource_t *
oc_core_get_resource_by_uri(const char *uri, size_t device)
{
  int skip = 0, type = 0;
  if (uri[0] == '/')
    skip = 1;
  if ((strlen(uri) - skip) == 5) {
    if (memcmp(uri + skip, "oic/p", 5) == 0) {
      return &core_resources[0];
    } else if (memcmp(uri + skip, "oic/d", 5) == 0) {
      type = OCF_D;
    }
  } else if ((strlen(uri) - skip) == 7 &&
             memcmp(uri + skip, "oic/res", 7) == 0) {
    type = OCF_RES;
  } else if (oc_get_con_res_announced() &&
             (strlen(uri) - skip) == OC_NAMELEN_CON_RES &&
             memcmp(uri + skip, OC_NAME_CON_RES, OC_NAMELEN_CON_RES) == 0) {
    type = OCF_CON;
  } else if ((strlen(uri) - skip) == 19 &&
             memcmp(uri + skip, "oc/wk/introspection", 19) == 0) {
    type = OCF_INTROSPECTION_WK;
  } else if ((strlen(uri) - skip) == 16 &&
             memcmp(uri + skip, "oc/introspection", 16) == 0) {
    type = OCF_INTROSPECTION_DATA;
  }
#ifdef OC_SECURITY
  else if ((strlen(uri) - skip) == 12) {
    if (memcmp(uri + skip, "oic/sec/doxm", 12) == 0) {
      type = OCF_SEC_DOXM;
    } else if (memcmp(uri + skip, "oic/sec/pstat", 12) == 0) {
      type = OCF_SEC_PSTAT;
    } else if (memcmp(uri + skip, "oic/sec/acl2", 12) == 0) {
      type = OCF_SEC_ACL;
    } else if (memcmp(uri + skip, "oic/sec/cred", 12) == 0) {
      type = OCF_SEC_CRED;
    }
  }
#ifdef OC_PKI
  else if ((strlen(uri) - skip) == 10 &&
           memcmp(uri + skip, "oic/sec/sp", 10) == 0) {
    type = OCF_SEC_SP;
  } else if ((strlen(uri) - skip) == 11 &&
             memcmp(uri + skip, "oic/sec/csr", 11) == 0) {
    type = OCF_SEC_CSR;
  } else if ((strlen(uri) - skip) == 13 &&
             memcmp(uri + skip, "oic/sec/roles", 13) == 0) {
    type = OCF_SEC_ROLES;
  }
#endif /* OC_PKI */
#endif /* OC_SECURITY */
  else {
    return NULL;
  }
  size_t res = OCF_D * device + type;
  return &core_resources[res];
}

bool
oc_filter_resource_by_rt(oc_resource_t *resource, oc_request_t *request)
{
  bool match = true, more_query_params = false;
  char *rt = NULL;
  int rt_len = -1;
  oc_init_query_iterator();
  do {
    more_query_params =
      oc_iterate_query_get_values(request, "rt", &rt, &rt_len);
    if (rt_len > 0) {
      match = false;
      int i;
      for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
           i++) {
        size_t size = oc_string_array_get_item_size(resource->types, i);
        const char *t =
          (const char *)oc_string_array_get_item(resource->types, i);
        if (rt_len == (int)size && strncmp(rt, t, rt_len) == 0) {
          return true;
        }
      }
    }
  } while (more_query_params);
  return match;
}
