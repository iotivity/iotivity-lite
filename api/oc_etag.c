/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG

#include "api/oc_etag_internal.h"
#include "api/oc_resource_internal.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"

#ifdef OC_STORAGE
#include "api/oc_storage_internal.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS */

#endif /* OC_STORAGE */

#include <inttypes.h>
#include <stdint.h>

static uint64_t g_etag = 0;

static uint64_t
etag_random(void)
{
  return (oc_random_value() % 1000) + 1;
}

uint64_t
oc_etag_global(void)
{
  return g_etag;
}

uint64_t
oc_etag_set_global(uint64_t etag)
{
  if (etag == OC_ETAG_UNINITALIZED) {
    etag = 1;
  }
  if (etag < g_etag) {
    // TODO: handle wrap around = all resource etags must be reinitialized
    OC_DBG("etag wrap around detected: %" PRIu64 " -> %" PRIu64, g_etag, etag);
  }
  return (g_etag = etag);
}

uint64_t
oc_etag_get(void)
{
  uint64_t now = oc_clock_time();
  uint64_t etag = g_etag;
  if (now > etag) {
    etag = now;
  }
  etag += etag_random();
  return oc_etag_set_global(etag);
}

#ifdef OC_STORAGE

bool
oc_etag_clear_storage(void)
{
  bool success = true;
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!oc_storage_data_clear(OC_ETAG_STORE_NAME, i)) {
      OC_ERR("failed to clear etag storage for device %zu", i);
      success = false;
    }
  }
  return success;
}

typedef int (*etag_process_resource_fn_t)(oc_resource_t *resource, void *data);

static bool
etag_iterate_resources(size_t device, etag_process_resource_fn_t process_fn,
                       void *data)
{
  bool success = true;
  if (device == 0) {
    // platform resources
    for (int type = 0; type < OCF_CON; ++type) {
      oc_resource_t *platform_res = oc_core_get_resource_by_index(type, 0);
      if (process_fn(platform_res, data) != 0) {
        OC_ERR("failed to process platform resource(%s)",
               oc_string(platform_res->uri));
        success = false;
      }
    }
  }

  // core resources
  for (int type = OCF_CON; type <= OCF_D; ++type) {
    oc_resource_t *core_res = oc_core_get_resource_by_index(type, device);
    if (process_fn(core_res, data) != 0) {
      OC_ERR("failed to process core resource(%s)", oc_string(core_res->uri));
      success = false;
    }
  }

  // app resources
  for (oc_resource_t *app_res = oc_ri_get_app_resources(); app_res != NULL;
       app_res = app_res->next) {
    if (app_res->device != device) {
      continue;
    }
    if (process_fn(app_res, data) != 0) {
      OC_ERR("failed to process dynamic resource(%s)", oc_string(app_res->uri));
      success = false;
    }
  }

#ifdef OC_COLLECTIONS
  // collections
  for (oc_collection_t *col = oc_collection_get_all(); col != NULL;
       col = (oc_collection_t *)col->res.next) {
    if (col->res.device != device) {
      continue;
    }
    if (process_fn(&col->res, data) != 0) {
      OC_ERR("failed to process collection(%s)", oc_string(col->res.uri));
      success = false;
    }
  }
#endif /* OC_COLLECTIONS */

  return success;
}

static int
etag_iterate_encode_resource(oc_resource_t *resource, void *data)
{
  (void)data;
  OC_DBG("encoding resource [%zu:]%s", resource->device,
         oc_string(resource->uri));
  uint64_t etag = oc_resource_get_etag(resource);
  if (etag == OC_ETAG_UNINITALIZED) {
    OC_DBG("skipping uninitialized etag for resource %s",
           oc_string(resource->uri));
    return 0;
  }
  CborError err =
    oc_rep_encode_text_string(oc_rep_object(root), oc_string(resource->uri),
                              oc_string_len(resource->uri));
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  err |= oc_rep_encoder_create_map(oc_rep_object(root), &etag_map,
                                   CborIndefiniteLength);
  err |=
    oc_rep_encode_text_string(&etag_map, "etag", OC_CHAR_ARRAY_LEN("etag"));
  err |= oc_rep_encode_uint(&etag_map, etag);
  err |= oc_rep_encoder_close_container(oc_rep_object(root), &etag_map);

#if OC_ERR_IS_ENABLED
  if (err != CborNoError) {
    OC_ERR("failed to encode device(%zu) resource %s", resource->device,
           oc_string(resource->uri));
  }
#endif /* OC_ERR_IS_ENABLED */
  return err;
}

static int
etag_store_encode(size_t device, void *data)
{
  (void)data;
  oc_rep_start_root_object();
  if (!etag_iterate_resources(device, etag_iterate_encode_resource, NULL)) {
    return -1;
  }
  oc_rep_end_root_object();
  return 0;
}

bool
oc_etag_dump_for_device(size_t device)
{
  long ret =
    oc_storage_data_save(OC_ETAG_STORE_NAME, device, etag_store_encode, NULL);
  if (ret <= 0) {
    OC_ERR("failed to dump etag for device %zu", device);
    return false;
  }
  return true;
}

bool
oc_etag_dump(void)
{
  bool success = true;
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!oc_etag_dump_for_device(i)) {
      success = false;
    }
  }
  return success;
}

typedef struct etag_update_from_rep_data_t
{
  const oc_rep_t *rep;
  uint64_t *etag;
} etag_update_from_rep_data_t;

static int
etag_iterate_update_resources_by_rep(oc_resource_t *resource, void *data)
{
  etag_update_from_rep_data_t *rep_data = (etag_update_from_rep_data_t *)data;
  oc_rep_t *res_rep;
  if (!oc_rep_get_object(rep_data->rep, oc_string(resource->uri), &res_rep)) {
    OC_DBG("no representation for resource %s", oc_string(resource->uri));
    return 0;
  }

  int64_t etag = 0;
  if (!oc_rep_get_int(res_rep, "etag", &etag) || etag < 0 ||
      etag == OC_ETAG_UNINITALIZED) {
    OC_DBG("ignoring invalid etag for resource %s", oc_string(resource->uri));
    return 0;
  }

  oc_resource_set_etag(resource, (uint64_t)etag);
  if ((uint64_t)etag > *rep_data->etag) {
    *rep_data->etag = (uint64_t)etag;
  }
  return 0;
}

static int
etag_iterate_clear_etag(oc_resource_t *resource, void *data)
{
  (void)data;
  oc_resource_set_etag(resource, OC_ETAG_UNINITALIZED);
  return 0;
}

static int
etag_store_decode_etags(const oc_rep_t *rep, size_t device, void *data)
{
  // iterate all resources update etag from rep and find the max etag value in
  // rep
  uint64_t *etag = (uint64_t *)data;
  etag_update_from_rep_data_t rep_data = { rep, etag };
  bool ret = etag_iterate_resources(
    device, etag_iterate_update_resources_by_rep, &rep_data);
  // return value should always be true because etag_iterate_resources always
  // returns 0
  assert(ret);
  (void)ret;
  return 0;
}

static int
etag_iterate_update_empty_etag(oc_resource_t *resource, void *data)
{
  (void)data;
  if (oc_resource_get_etag(resource) == OC_ETAG_UNINITALIZED) {
    oc_resource_set_etag(resource, oc_etag_get());
  }
  return 0;
}

bool
oc_etag_load_from_storage(bool from_storage_only)
{
  bool success = true;
  // load g_etag and resource etags from storage
  uint64_t etag = oc_clock_time();
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    if (!from_storage_only) {
      // clear all etags
      // return value not checked - etag_iterate_clear_etag always returns 0
      bool ret = etag_iterate_resources(i, etag_iterate_clear_etag, NULL);
      assert(ret);
      (void)ret;
    }

    // load etags from storage
    long ret = oc_storage_data_load(OC_ETAG_STORE_NAME, i,
                                    etag_store_decode_etags, &etag);
    if (ret <= 0) {
      OC_ERR("failed to load etags for device %zu", i);
      success = false;
    }
  }
  etag += etag_random();
  oc_etag_set_global(etag);
  OC_DBG("g_tag: %" PRIu64, oc_etag_global());

  if (!from_storage_only) {
    // update empty etags
    for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
      // return value not checked - etag_iterate_update_empty_etag always
      // returns 0
      bool ret =
        etag_iterate_resources(i, etag_iterate_update_empty_etag, NULL);
      assert(ret);
      (void)ret;
    }
  }
  return success;
}

bool
oc_etag_load_and_clear(void)
{
  bool success = oc_etag_load_from_storage(false);
  success = oc_etag_clear_storage() && success;
  return success;
}

#endif /* OC_STORAGE */

void
oc_resource_set_etag(oc_resource_t *resource, uint64_t etag)
{
  assert(resource != NULL);
  resource->etag = etag;
  OC_DBG("oc_etag: set resource %s etag to %" PRIu64, oc_string(resource->uri),
         etag);
}

uint64_t
oc_resource_get_etag(const oc_resource_t *resource)
{
  assert(resource != NULL);
  return resource->etag;
}

void
oc_resource_update_etag(oc_resource_t *resource)
{
  oc_resource_set_etag(resource, oc_etag_get());
}

#endif /* OC_HAS_FEATURE_ETAG */
