/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "api/oc_con_resource_internal.h"
#include "api/oc_platform_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include "oc_csr.h"
#include "oc_discovery_internal.h"
#include "oc_endpoint.h"
#include "oc_introspection_internal.h"
#include "oc_rep.h"
#include "oc_resource_internal.h"
#include "oc_ri_internal.h"
#include "oc_main_internal.h"
#include "oc_server_api_internal.h"
#include "oc_swupdate_internal.h"
#include "port/oc_assert.h"
#include "util/oc_atomic.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_HAS_FEATURE_BRIDGE
#include "security/oc_svr_internal.h"
#include "security/oc_ael_internal.h"
#include "oc_acl.h"
#include "oc_cred.h"
#endif

#ifdef OC_CLOUD
#include "api/cloud/oc_cloud_resource_internal.h"
#endif /* OC_CLOUD */

#ifdef OC_MNT
#include "api/oc_mnt_internal.h"
#endif /* OC_MNT */

#ifdef OC_SECURITY
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_roles_internal.h"
#include "security/oc_sdi_internal.h"
#include "security/oc_sp_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
static oc_resource_t *g_core_resources = NULL;
static oc_device_info_t *g_oc_device_info = NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_resource_t g_core_resources[OC_NUM_CORE_PLATFORM_RESOURCES +
                                      (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES *
                                       OC_MAX_NUM_DEVICES)] = { 0 };
static oc_device_info_t g_oc_device_info[OC_MAX_NUM_DEVICES] = { 0 };
#endif /* !OC_DYNAMIC_ALLOCATION */

static int g_res_latency = 0;
static OC_ATOMIC_UINT32_T g_device_count = 0;

void
oc_core_init(void)
{
  oc_core_shutdown();

#ifdef OC_DYNAMIC_ALLOCATION
  g_core_resources = (oc_resource_t *)calloc(1, OC_NUM_CORE_PLATFORM_RESOURCES *
                                                  sizeof(oc_resource_t));
  if (g_core_resources == NULL) {
    oc_abort("Insufficient memory");
  }

  g_oc_device_info = NULL;
#else  /* !OC_DYNAMIC_ALLOCATION */
  memset(g_core_resources, 0, sizeof(g_core_resources));
  memset(g_oc_device_info, 0, sizeof(g_oc_device_info));
#endif /* OC_DYNAMIC_ALLOCATION */
}

static void
oc_core_free_device_info_properties(oc_device_info_t *oc_device_info_item)
{
  if (oc_device_info_item) {
    oc_free_string(&(oc_device_info_item->name));
    oc_free_string(&(oc_device_info_item->icv));
    oc_free_string(&(oc_device_info_item->dmv));
  }
}

void
oc_core_shutdown(void)
{
  oc_platform_deinit();

  uint32_t device_count = OC_ATOMIC_LOAD32(g_device_count);

  /*
   * 1. Removed All Core Resources
   */
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_core_resources != NULL) {
#endif /* OC_DYNAMIC_ALLOCATION */
    for (size_t i = 0;
         i < OC_NUM_CORE_PLATFORM_RESOURCES +
               (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device_count);
         ++i) {
      oc_resource_t *core_resource = &g_core_resources[i];

#ifdef OC_HAS_FEATURE_BRIDGE
      if ( (i < OC_NUM_CORE_PLATFORM_RESOURCES)
          || ((i >= OC_NUM_CORE_PLATFORM_RESOURCES) && (oc_core_get_device_info((i-OC_NUM_CORE_PLATFORM_RESOURCES)/OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES)->is_removed == false)) ) {
#endif /* OC_HAS_FEATURE_BRIDGE */
        oc_ri_free_resource_properties(core_resource);
#ifdef OC_HAS_FEATURE_BRIDGE
      }
#endif /* OC_HAS_FEATURE_BRIDGE */

    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(g_core_resources);
    g_core_resources = NULL;
  }

  /*
   * 2. Removed All Devices
   */
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_oc_device_info != NULL) {
#endif /* OC_DYNAMIC_ALLOCATION */
    for (uint32_t i = 0; i < device_count; ++i) {
      oc_device_info_t *oc_device_info_item = &g_oc_device_info[i];
      oc_core_free_device_info_properties(oc_device_info_item);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(g_oc_device_info);
    g_oc_device_info = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

#endif /* OC_DYNAMIC_ALLOCATION */
  OC_ATOMIC_STORE32(g_device_count, 0);
}

void
oc_core_encode_interfaces_mask(CborEncoder *parent, unsigned iface_mask,
                               bool include_private)
{
  oc_rep_set_key((parent), "if");
  oc_rep_start_array((parent), if);
  if ((iface_mask & OC_IF_R) != 0) {
    oc_rep_add_text_string(if, OC_IF_R_STR);
  }
  if ((iface_mask & OC_IF_RW) != 0) {
    oc_rep_add_text_string(if, OC_IF_RW_STR);
  }
  if ((iface_mask & OC_IF_A) != 0) {
    oc_rep_add_text_string(if, OC_IF_A_STR);
  }
  if ((iface_mask & OC_IF_S) != 0) {
    oc_rep_add_text_string(if, OC_IF_S_STR);
  }
  if ((iface_mask & OC_IF_LL) != 0) {
    oc_rep_add_text_string(if, OC_IF_LL_STR);
  }
  if ((iface_mask & OC_IF_CREATE) != 0) {
    oc_rep_add_text_string(if, OC_IF_CREATE_STR);
  }
  if ((iface_mask & OC_IF_B) != 0) {
    oc_rep_add_text_string(if, OC_IF_B_STR);
  }
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    oc_rep_add_text_string(if, OC_IF_BASELINE_STR);
  }
  if ((iface_mask & OC_IF_W) != 0) {
    oc_rep_add_text_string(if, OC_IF_W_STR);
  }
  if ((iface_mask & OC_IF_STARTUP) != 0) {
    oc_rep_add_text_string(if, OC_IF_STARTUP_STR);
  }
  if ((iface_mask & OC_IF_STARTUP_REVERT) != 0) {
    oc_rep_add_text_string(if, OC_IF_STARTUP_REVERT_STR);
  }
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  if (include_private && (iface_mask & PLGD_IF_ETAG) != 0) {
    oc_rep_add_text_string(if, PLGD_IF_ETAG_STR);
  }
#else  /* OC_HAS_FEATURE_ETAG_INTERFACE */
  (void)include_private;
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  oc_rep_end_array((parent), if);
}

static void
oc_core_device_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                       void *data)
{
  (void)data;
  size_t device = request->resource->device;
  oc_rep_start_root_object();

  char di[OC_UUID_LEN];
  oc_uuid_to_str(&g_oc_device_info[device].di, di, OC_UUID_LEN);
  char piid[OC_UUID_LEN];
  if (request->origin && request->origin->version != OIC_VER_1_1_0) {
    oc_uuid_to_str(&g_oc_device_info[device].piid, piid, OC_UUID_LEN);
  }

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    OC_FALLTHROUGH;
  case OC_IF_R: {
    oc_rep_set_text_string(root, di, di);
    if (request->origin && request->origin->version != OIC_VER_1_1_0) {
      oc_rep_set_text_string(root, piid, piid);
    }
    oc_rep_set_text_string(root, n, oc_string(g_oc_device_info[device].name));
    oc_rep_set_text_string(root, icv, oc_string(g_oc_device_info[device].icv));
    oc_rep_set_text_string(root, dmv, oc_string(g_oc_device_info[device].dmv));
    if (g_oc_device_info[device].add_device_cb) {
      g_oc_device_info[device].add_device_cb(g_oc_device_info[device].data);
    }
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

size_t
oc_core_get_num_devices(void)
{
  return OC_ATOMIC_LOAD32(g_device_count);
}

bool
oc_core_device_is_valid(size_t device)
{
  return device < OC_ATOMIC_LOAD32(g_device_count);
}

void
oc_core_set_latency(int latency)
{
  g_res_latency = latency;
}

int
oc_core_get_latency(void)
{
  return g_res_latency;
}

static void
core_update_device_data(uint32_t device_count, oc_add_new_device_t cfg)
{
#ifdef OC_DYNAMIC_ALLOCATION
  size_t new_num = OC_NUM_CORE_PLATFORM_RESOURCES +
                   (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * (device_count + 1));
  oc_resource_t *core_resources =
    (oc_resource_t *)realloc(g_core_resources, new_num * sizeof(oc_resource_t));
  if (core_resources == NULL) {
    oc_abort("Insufficient memory");
  }
  oc_resource_t *device =
    &core_resources[new_num - OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES];
  memset(device, 0,
         OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * sizeof(oc_resource_t));
  g_core_resources = core_resources;

  oc_device_info_t *device_info = (oc_device_info_t *)realloc(
    g_oc_device_info, (device_count + 1) * sizeof(oc_device_info_t));

  if (device_info == NULL) {
    oc_abort("Insufficient memory");
  }
  memset(&device_info[device_count], 0, sizeof(oc_device_info_t));
  g_oc_device_info = device_info;
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_gen_uuid(&g_oc_device_info[device_count].di);
  oc_gen_uuid(&g_oc_device_info[device_count].piid);

  oc_new_string(&g_oc_device_info[device_count].name, cfg.name,
                strlen(cfg.name));
  oc_new_string(&g_oc_device_info[device_count].icv, cfg.spec_version,
                strlen(cfg.spec_version));
  oc_new_string(&g_oc_device_info[device_count].dmv, cfg.data_model_version,
                strlen(cfg.data_model_version));
  g_oc_device_info[device_count].add_device_cb = cfg.add_device_cb;
  g_oc_device_info[device_count].data = cfg.add_device_cb_data;
}

static void
oc_create_device_resource(size_t device_count, const char *uri, const char *rt)
{
  /* Construct device resource */
  int properties = OC_DISCOVERABLE;
#ifdef OC_CLOUD
  properties |= OC_OBSERVABLE;
#endif /* OC_CLOUD */
  if (oc_strnlen(rt, OC_CHAR_ARRAY_LEN(OCF_D_RT) + 1) ==
        OC_CHAR_ARRAY_LEN(OCF_D_RT) &&
      strncmp(rt, OCF_D_RT, OC_CHAR_ARRAY_LEN(OCF_D_RT)) == 0) {
    oc_core_populate_resource(OCF_D, device_count, uri,
                              OC_IF_R | OC_IF_BASELINE, OC_IF_R, properties,
                              oc_core_device_handler, /*put*/ NULL,
                              /*post*/ NULL, /*delete*/ NULL, 1, rt);
  } else {
    oc_core_populate_resource(OCF_D, device_count, uri,
                              OC_IF_R | OC_IF_BASELINE, OC_IF_R, properties,
                              oc_core_device_handler, /*put*/ NULL,
                              /*post*/ NULL, /*delete*/ NULL, 2, rt, OCF_D_RT);
  }
}

#ifdef OC_HAS_FEATURE_BRIDGE
static void
core_update_existing_device_data(size_t device_count, oc_add_new_device_t cfg)
{
  oc_gen_uuid(&g_oc_device_info[device_count].di);
  oc_gen_uuid(&g_oc_device_info[device_count].piid);

  oc_new_string(&g_oc_device_info[device_count].name, cfg.name,
                strlen(cfg.name));
  oc_new_string(&g_oc_device_info[device_count].icv, cfg.spec_version,
                strlen(cfg.spec_version));
  oc_new_string(&g_oc_device_info[device_count].dmv, cfg.data_model_version,
                strlen(cfg.data_model_version));
  g_oc_device_info[device_count].add_device_cb = cfg.add_device_cb;
  g_oc_device_info[device_count].data = cfg.add_device_cb_data;
}

static void
core_set_device_removed(size_t index, bool is_removed)
{
  g_oc_device_info[index].is_removed = is_removed;

  return;
}
#endif /* OC_HAS_FEATURE_BRIDGE */

oc_device_info_t *
oc_core_add_new_device(oc_add_new_device_t cfg)
{
  assert(cfg.uri != NULL);
  assert(cfg.rt != NULL);
  assert(cfg.name != NULL);
  assert(cfg.spec_version != NULL);
  assert(cfg.data_model_version != NULL);

  uint32_t device_count = OC_ATOMIC_LOAD32(g_device_count);

  bool exchanged = false;
  while (!exchanged) {
#ifndef OC_DYNAMIC_ALLOCATION
    if (device_count == OC_MAX_NUM_DEVICES) {
      OC_ERR("device limit reached");
      return NULL;
    }
#endif /* !OC_DYNAMIC_ALLOCATION */
    if ((uint64_t)device_count == (uint64_t)MIN(SIZE_MAX, UINT32_MAX)) {
      OC_ERR("limit of value type of g_device_count reached");
      return NULL;
    }
    OC_ATOMIC_COMPARE_AND_SWAP32(g_device_count, device_count, device_count + 1,
                                 exchanged);
  }

  core_update_device_data(device_count, cfg);

  oc_create_device_resource(device_count, cfg.uri, cfg.rt);

  if (oc_get_con_res_announced()) {
    /* Construct oic.wk.con resource for this device. */
    oc_create_con_resource(device_count);
  }

  oc_create_discovery_resource(device_count);

#ifdef OC_WKCORE
  oc_create_wkcore_resource(device_count);
#endif /* OC_WKCORE */

#ifdef OC_INTROSPECTION
  oc_create_introspection_resource(device_count);
#endif /* OC_INTROSPECTION */

#ifdef OC_MNT
  oc_create_maintenance_resource(device_count);
#endif /* OC_MNT */
#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  oc_create_cloudconf_resource(device_count);
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_HAS_FEATURE_PUSH
  oc_create_pushconf_resource(device_count);
  oc_create_pushreceiver_resource(device_count);
#endif /* OC_HAS_FEATURE_PUSH */

  if (oc_connectivity_init(device_count, cfg.ports) < 0) {
    oc_abort("error initializing connectivity for device");
  }

#ifdef OC_HAS_FEATURE_BRIDGE
  core_set_device_removed(device_count, false);
#endif

  return &g_oc_device_info[device_count];
}

#ifdef OC_HAS_FEATURE_BRIDGE
oc_device_info_t *
oc_core_add_new_device_at_index(oc_add_new_device_t cfg, size_t index)
{
  assert(cfg.uri != NULL);
  assert(cfg.rt != NULL);
  assert(cfg.name != NULL);
  assert(cfg.spec_version != NULL);
  assert(cfg.data_model_version != NULL);

  uint32_t device_count = OC_ATOMIC_LOAD32(g_device_count);

#if defined(OC_SECURITY) || defined(OC_SOFTWARE_UPDATE)
  bool is_realloc = false;
#endif

  if (index > device_count) {
    OC_ERR(
      "designated device index is bigger than current number of all Devices");
    return NULL;
  } else if (index < device_count) {
    /*
     * If an existing Device is being replaced with new Device..
     * - check if the Device on designated `index` is still alive or removed
     * before.
     */
    if (g_oc_device_info[index].is_removed == false) {
      OC_ERR("Trying to replace existing normal Device with new one...! \
          To insert new Device in the middle of the g_oc_device_info[], \
          remove the existing one first");
      return NULL;
    }

    /* store new `oc_device_info_t` entry to existing memory slot */
    core_update_existing_device_data(index, cfg);
    device_count = (uint32_t)index;
  } else if (index == device_count) {
    /*
     * if `index` is same as the next normal index of Device,
     * follow normal procedure.
     */
    bool exchanged = false;
    while (!exchanged) {
#ifndef OC_DYNAMIC_ALLOCATION
      if (device_count == OC_MAX_NUM_DEVICES) {
        OC_ERR("device limit reached");
        return NULL;
      }
#endif /* !OC_DYNAMIC_ALLOCATION */
      if ((uint64_t)device_count == (uint64_t)MIN(SIZE_MAX, UINT32_MAX)) {
        OC_ERR("limit of value type of g_device_count reached");
        return NULL;
      }
      /* store (device_count+1) to g_device_count */
      OC_ATOMIC_COMPARE_AND_SWAP32(g_device_count, device_count,
                                   device_count + 1, exchanged);
    }

    /* extend memory allocated to `g_oc_device_info` to add new Device
     * and add new `oc_device_info_t` entry */
    core_update_device_data(device_count, cfg);

#if defined(OC_SECURITY) || defined(OC_SOFTWARE_UPDATE)
    is_realloc = true;
#endif
  }

  /* Construct device resource */
  oc_create_device_resource(device_count, cfg.uri, cfg.rt);

  if (oc_get_con_res_announced()) {
    /* Construct oic.wk.con resource for this device. */
    oc_create_con_resource(device_count);
  }

  oc_create_discovery_resource(device_count);

#ifdef OC_WKCORE
  oc_create_wkcore_resource(device_count);
#endif /* OC_WKCORE */

#ifdef OC_INTROSPECTION
  oc_create_introspection_resource(device_count);
#endif /* OC_INTROSPECTION */

#ifdef OC_MNT
  oc_create_maintenance_resource(device_count);
#endif /* OC_MNT */
#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  oc_create_cloudconf_resource(device_count);
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_HAS_FEATURE_PUSH
  oc_create_pushconf_resource(device_count);
  oc_create_pushreceiver_resource(device_count);
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_SECURITY
  /*
   * Do what "main_init_resources()" does for all Devices here...
   * refer to "main_init_resources()"
   */
  if ((g_device_count == (device_count + 1)) && is_realloc) {
    /* realloc memory and populate SVR Resources
     * only if new Device is attached to the end of `g_oc_device_info[]` */
    oc_sec_svr_create_new_device(device_count, true);
  } else {
    oc_sec_svr_create_new_device(device_count, false);
  }
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  /*
   * Do what "main_init_resources()" does for all Devices here...
   * refer to "main_init_resources()"
   */
  if ((g_device_count == (device_count + 1)) && is_realloc) {
    /* realloc memory and populate SVR Resources
     * only if new Device is attached to the end of `g_oc_device_info[]` */
    oc_swupdate_create_new_device(device_count, true);
  } else {
    oc_swupdate_create_new_device(device_count, false);
  }
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_SECURITY
  /*
   * Do what "main_load_resources()" does for all Devices here...
   * refer to "main_load_resources()"
   */
  oc_sec_svr_init_new_device(device_count);
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  /*
   * Do what "main_load_resources()" does for all Devices here...
   * refer to "main_load_resources()"
   */
  OC_DBG("oc_core_add_new_device_at_index(): loading swupdate(%d)", device_count);
  oc_swupdate_load(device_count);
#endif /* OC_SOFTWARE_UPDATE */

  core_set_device_removed(device_count, false);
  return &g_oc_device_info[device_count];
}

static void
core_delete_app_resources_per_device(size_t index)
{
  oc_ri_delete_app_resources_per_device(index);

  return;
}

bool
oc_core_remove_device_at_index(size_t index)
{
  if (index >= g_device_count) {
    OC_ERR("Device index value is out of valid range! : \
        Device index %zu, current Device count %d",
           index, g_device_count);
    return false;
  }

#ifdef OC_SECURITY
  oc_reset_device(index);
  /*
   * oc_sec_sdi_clear(oc_sec_sdi_get(index)); => already done in
   * oc_reset_device()
   * oc_sec_ael_free_device(index); => already done in
   * oc_reset_device()
   * oc_sec_cred_clear(index, NULL, NULL); => already done in
   * oc_reset_device()
   * oc_sec_acl_clear(index, NULL, NULL); => already done in
   * oc_reset_device()
   */
#endif /* OC_SECURITY */

  /* 1. remove core Resources mapped to this Device */
  for (size_t i = OC_NUM_CORE_PLATFORM_RESOURCES + (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * index);
      i < OC_NUM_CORE_PLATFORM_RESOURCES + (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * (index + 1)); ++i) {
    oc_resource_t *core_resource = &g_core_resources[i];
    oc_ri_free_resource_properties(core_resource);
    memset(core_resource, 0, sizeof(oc_resource_t));
  }

#ifdef OC_HAS_FEATURE_PUSH
  /*
   * TODO4ME <2024/01/23> oc_core_remove_device_at_index() :
   * - make function to delete receivers object list per VOD
   */
#if 0
  oc_push_free();
#endif
#endif /* OC_HAS_FEATURE_PUSH */

  /* 2. remove all application Resources (including collections) mapped to this
   * Device */
  /*
   * TODO4ME <2023/12/11> oc_core_remove_device_at_index() : do we need to
   * delete observer too? (e.g. oc_ri_reset())
   */
  core_delete_app_resources_per_device(index);

  /* 3. clean all Properties of this Device */
  oc_core_free_device_info_properties(&g_oc_device_info[index]);
  memset(&g_oc_device_info[index], 0, sizeof(oc_device_info_t));

  /* 4. mark this Device is removed */
  core_set_device_removed(index, true);

  return true;
}

int
oc_core_get_device_index(oc_uuid_t di, size_t *device)
{
  for (size_t i = 0; i < g_device_count; i++) {
    if (oc_uuid_is_equal(g_oc_device_info[i].di, di)) {
      *device = i;
      return 0;
    }
  }
  return -1;
}

#endif /* OC_HAS_FEATURE_BRIDGE */

static void
oc_device_bind_rt(size_t device_index, const char *rt)
{
  oc_resource_t *r = oc_core_get_resource_by_index(OCF_D, device_index);
  if (!r) {
    return;
  }

  oc_string_array_t types;
  memcpy(&types, &r->types, sizeof(oc_string_array_t));

  size_t num_types = oc_string_array_get_allocated_size(types);
  ++num_types;

  memset(&r->types, 0, sizeof(oc_string_array_t));
  oc_new_string_array(&r->types, num_types);
  for (size_t i = 0; i < num_types; i++) {
    if (i == 0) {
      oc_string_array_add_item(r->types, rt);
      continue;
    }
    oc_string_array_add_item(r->types,
                             oc_string_array_get_item(types, (i - 1)));
  }
  oc_free_string_array(&types);
}

void
oc_core_device_set_name(size_t device, const char *name, size_t name_len)
{
  oc_device_info_t *d = oc_core_get_device_info(device);
  if (d == NULL) {
    return;
  }
  oc_set_string(&d->name, name, name_len);
}

void
oc_device_bind_resource_type(size_t device, const char *type)
{
  assert(type != NULL);
  oc_device_bind_rt(device, type);
}

void
oc_store_uri(const char *s_uri, oc_string_t *d_uri)
{
  size_t s_len = oc_strnlen(s_uri, OC_MAX_STRING_LENGTH);
  if (s_len >= OC_MAX_STRING_LENGTH) {
    OC_ERR("Invalid URI");
    return;
  }

  if (s_uri[0] == '/') {
    oc_set_string(d_uri, s_uri, s_len);
    return;
  }

  oc_string_t uri;
  oc_alloc_string(&uri, s_len + 2);
  memcpy(oc_string(uri) + 1, s_uri, s_len);
  (oc_string(uri))[0] = '/';
  (oc_string(uri))[s_len + 1] = '\0';
  oc_new_string(d_uri, oc_string(uri), oc_string_len(uri));
  oc_free_string(&uri);
}

static oc_resource_t *
core_get_resource_memory_by_index(int type, size_t device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_core_resources == NULL) {
    return NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  if (type < 0 || type > OCF_D) {
    return NULL;
  }
  if (type < OCF_CON) {
    return &g_core_resources[type];
  }
  if (!oc_core_device_is_valid(device)) {
    return NULL;
  }
  return &g_core_resources[OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device +
                           type];
}

oc_resource_t *
oc_core_get_resource_by_index(int type, size_t device)
{
  oc_resource_t *r = core_get_resource_memory_by_index(type, device);
  if (r == NULL) {
    return NULL;
  }
  if (!oc_resource_is_initialized(r)) {
    return NULL;
  }
  return r;
}

void
oc_core_populate_resource(int core_resource, size_t device_index,
                          const char *uri, oc_interface_mask_t iface_mask,
                          oc_interface_mask_t default_interface, int properties,
                          oc_request_callback_t get, oc_request_callback_t put,
                          oc_request_callback_t post,
                          oc_request_callback_t delete, int num_resource_types,
                          ...)
{
  oc_resource_t *r =
    core_get_resource_memory_by_index(core_resource, device_index);
  if (r == NULL) {
    OC_ERR("Could not find resource(type:%d device:%zu)", core_resource,
           device_index);
    return;
  }
  r->device = device_index;
  oc_store_uri(uri, &r->uri);
  r->properties = properties;
  va_list rt_list;
  va_start(rt_list, num_resource_types);
  oc_new_string_array(&r->types, num_resource_types);
  for (int i = 0; i < num_resource_types; ++i) {
    oc_string_array_add_item(r->types, va_arg(rt_list, const char *));
  }
  va_end(rt_list);
  r->interfaces = iface_mask;
  r->default_interface = default_interface;
  r->get_handler.cb = get;
  r->put_handler.cb = put;
  r->post_handler.cb = post;
  r->delete_handler.cb = delete;
#ifdef OC_HAS_FEATURE_ETAG
  r->etag = oc_etag_get();
#endif /* OC_HAS_FEATURE_ETAG */
}

oc_uuid_t *
oc_core_get_device_id(size_t device)
{
  if (!oc_core_device_is_valid(device)) {
    return NULL;
  }
  return &g_oc_device_info[device].di;
}

oc_device_info_t *
oc_core_get_device_info(size_t device)
{
  if (!oc_core_device_is_valid(device)) {
    return NULL;
  }
  return &g_oc_device_info[device];
}

#ifdef OC_SECURITY
bool
oc_core_is_SVR(const oc_resource_t *resource, size_t device)
{
  if (resource == NULL) {
    return false;
  }
  if (!oc_core_device_is_valid(device)) {
    return false;
  }

  size_t device_svrs =
    (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device) + OCF_SEC_DOXM;
  size_t SVRs_end = (OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device) + OCF_D - 1;
  for (size_t i = device_svrs; i <= SVRs_end; i++) {
    if (resource == &g_core_resources[i]) {
      return true;
    }
  }
  return false;
}
#endif /* OC_SECURITY */

static bool
core_is_platform_resource(const oc_resource_t *resource)
{
  for (size_t i = 0; i < OCF_CON; ++i) {
    if (resource == &g_core_resources[i]) {
      return true;
    }
  }
  return false;
}

bool
oc_core_is_vertical_resource(const oc_resource_t *resource, size_t device)
{
  if (resource == NULL) {
    return false;
  }

  if (core_is_platform_resource(resource)) {
    return true;
  }

  if (!oc_core_device_is_valid(device)) {
    return false;
  }

  size_t device_resources = OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device;
  size_t DCRs_start = device_resources + OCF_CON;
  size_t DCRs_end = device_resources + OCF_D;
  for (size_t i = DCRs_start; i <= DCRs_end; ++i) {
    if (resource == &g_core_resources[i]) {
      return false;
    }
  }

  return true;
}

bool
oc_core_is_DCR(const oc_resource_t *resource, size_t device)
{
  if (resource == NULL) {
    return false;
  }

  if (core_is_platform_resource(resource)) {
    return true;
  }

  if (!oc_core_device_is_valid(device)) {
    return false;
  }

  size_t device_resources = OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device;
  size_t DCRs_start = device_resources + OCF_CON;
  size_t DCRs_end = device_resources + OCF_D;
  for (size_t i = DCRs_start; i <= DCRs_end; ++i) {
    if (resource == &g_core_resources[i]) {
#ifdef OC_INTROSPECTION
      if (i == (device_resources + OCF_INTROSPECTION_WK) ||
          i == (device_resources + OCF_INTROSPECTION_DATA)) {
        return false;
      }
#endif /* OC_INTROSPECTION */
      if (i == (device_resources + OCF_CON)) {
        return false;
      }
      return true;
    }
  }

  return false;
}

static bool
core_is_resource_uri(const char *uri, size_t uri_len, const char *r_uri,
                     size_t r_uri_len)
{
  if (uri[0] == '/') {
    uri = &uri[1];
    --uri_len;
  }
  if (r_uri[0] == '/') {
    r_uri = &r_uri[1];
    --r_uri_len;
  }

  return uri_len == r_uri_len &&
         (uri_len == 0 || memcmp(uri, r_uri, uri_len) == 0);
}

int
oc_core_get_resource_type_by_uri(const char *uri, size_t uri_len)
{
  if (oc_is_platform_resource_uri(oc_string_view(uri, uri_len))) {
    return OCF_P;
  }
  if (core_is_resource_uri(uri, uri_len, OCF_D_URI,
                           OC_CHAR_ARRAY_LEN(OCF_D_URI))) {
    return OCF_D;
  }
  if (oc_is_discovery_resource_uri(oc_string_view(uri, uri_len))) {
    return OCF_RES;
  }
  if (oc_get_con_res_announced() &&
      core_is_resource_uri(uri, uri_len, OC_CON_URI,
                           OC_CHAR_ARRAY_LEN(OC_CON_URI))) {
    return OCF_CON;
  }
#ifdef OC_INTROSPECTION
  if (core_is_resource_uri(uri, uri_len, OC_INTROSPECTION_WK_URI,
                           OC_CHAR_ARRAY_LEN(OC_INTROSPECTION_WK_URI))) {
    return OCF_INTROSPECTION_WK;
  }
  if (core_is_resource_uri(uri, uri_len, OC_INTROSPECTION_DATA_URI,
                           OC_CHAR_ARRAY_LEN(OC_INTROSPECTION_DATA_URI))) {
    return OCF_INTROSPECTION_DATA;
  }
#endif /* OC_INTROSPECTION */
#ifdef OC_HAS_FEATURE_PLGD_TIME
  if (core_is_resource_uri(uri, uri_len, PLGD_TIME_URI,
                           OC_CHAR_ARRAY_LEN(PLGD_TIME_URI))) {
    return PLGD_TIME;
  }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_WKCORE
  if (core_is_resource_uri(uri, uri_len, OC_WELLKNOWNCORE_URI,
                           OC_CHAR_ARRAY_LEN(OC_WELLKNOWNCORE_URI))) {
    return WELLKNOWNCORE;
  }
#endif /* OC_WKCORE */
#ifdef OC_MNT
  if (oc_is_maintenance_resource_uri(oc_string_view(uri, uri_len))) {
    return OCF_MNT;
  }
#endif /* OC_MNT */
#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  if (core_is_resource_uri(uri, uri_len, "/CoapCloudConfResURI",
                           OC_CHAR_ARRAY_LEN("/CoapCloudConfResURI"))) {
    return OCF_COAPCLOUDCONF;
  }
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */
#ifdef OC_SECURITY
  if (core_is_resource_uri(uri, uri_len, "/oic/sec/pstat",
                           OC_CHAR_ARRAY_LEN("/oic/sec/pstat"))) {
    return OCF_SEC_PSTAT;
  }
  if (oc_sec_is_doxm_resource_uri(oc_string_view(uri, uri_len))) {
    return OCF_SEC_DOXM;
  }
  if (core_is_resource_uri(uri, uri_len, "/oic/sec/acl2",
                           OC_CHAR_ARRAY_LEN("/oic/sec/acl2"))) {
    return OCF_SEC_ACL;
  }
  if (core_is_resource_uri(uri, uri_len, "/oic/sec/cred",
                           OC_CHAR_ARRAY_LEN("/oic/sec/cred"))) {
    return OCF_SEC_CRED;
  }
  if (core_is_resource_uri(uri, uri_len, "/oic/sec/ael",
                           OC_CHAR_ARRAY_LEN("/oic/sec/ael"))) {
    return OCF_SEC_AEL;
  }
  if (core_is_resource_uri(uri, uri_len, OCF_SEC_SP_URI,
                           OC_CHAR_ARRAY_LEN(OCF_SEC_SP_URI))) {
    return OCF_SEC_SP;
  }
#ifdef OC_PKI
  if (core_is_resource_uri(uri, uri_len, OCF_SEC_CSR_URI,
                           OC_CHAR_ARRAY_LEN(OCF_SEC_CSR_URI))) {
    return OCF_SEC_CSR;
  }
  if (core_is_resource_uri(uri, uri_len, OCF_SEC_ROLES_URI,
                           OC_CHAR_ARRAY_LEN(OCF_SEC_ROLES_URI))) {
    return OCF_SEC_ROLES;
  }
#endif /* OC_PKI */
  if (core_is_resource_uri(uri, uri_len, OCF_SEC_SDI_URI,
                           OC_CHAR_ARRAY_LEN(OCF_SEC_SDI_URI))) {
    return OCF_SEC_SDI;
  }
#endif /* OC_SECURITY */
#ifdef OC_SOFTWARE_UPDATE
  if (core_is_resource_uri(uri, uri_len, OCF_SW_UPDATE_URI,
                           OC_CHAR_ARRAY_LEN(OCF_SW_UPDATE_URI))) {
    return OCF_SW_UPDATE;
  }
#endif /* OC_SOFTWARE_UPDATE */
  return -1;
}

oc_resource_t *
oc_core_get_resource_by_uri_v1(const char *uri, size_t uri_len, size_t device)
{
  int type = oc_core_get_resource_type_by_uri(uri, uri_len);
  if (type < 0) {
    return NULL;
  }
  if (type < OCF_CON) {
    return &g_core_resources[type];
  }
  if (!oc_core_device_is_valid(device)) {
    return NULL;
  }
  size_t res = OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * device + type;
  return &g_core_resources[res];
}

oc_resource_t *
oc_core_get_resource_by_uri(const char *uri, size_t device)
{
  size_t uri_len = oc_strnlen(uri, OC_MAX_OCF_URI_PATH_SIZE);
  if (uri_len == OC_MAX_OCF_URI_PATH_SIZE) {
    return NULL;
  }
  return oc_core_get_resource_by_uri_v1(uri, uri_len, device);
}

bool
oc_filter_resource_by_rt(const oc_resource_t *resource,
                         const oc_request_t *request)
{
  bool match = true;
  bool more_query_params = false;
  oc_init_query_iterator();
  do {
    const char *rt = NULL;
    int rt_len = -1;
    more_query_params = oc_iterate_query_get_values_v1(
      request, "rt", OC_CHAR_ARRAY_LEN("rt"), &rt, &rt_len);
    if (rt_len <= 0) {
      continue;
    }
    match = false;
    for (size_t i = 0; i < oc_string_array_get_allocated_size(resource->types);
         ++i) {
      size_t size = oc_string_array_get_item_size(resource->types, i);
      const char *t =
        (const char *)oc_string_array_get_item(resource->types, i);
      if ((size_t)rt_len == size && strncmp(rt, t, rt_len) == 0) {
        return true;
      }
    }
  } while (more_query_params);
  return match;
}
