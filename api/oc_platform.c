/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.
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

#include "api/oc_core_res_internal.h"
#include "api/oc_platform_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_build_info.h"
#include "util/oc_compiler.h"
#include "util/oc_secure_string_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static struct
{
  oc_platform_info_t info;
  bool initialized;
} g_platform;

static int
platform_encode(const oc_resource_t *resource, oc_interface_mask_t iface)
{
  oc_rep_start_root_object();

  if (iface == OC_IF_BASELINE) {
    oc_process_baseline_interface(resource);
  }

  char pi[OC_UUID_LEN] = { 0 };
  int pi_len = oc_uuid_to_str_v1(&g_platform.info.pi, pi, OC_UUID_LEN);
  assert(pi_len >= 0);
  oc_rep_set_text_string_v1(root, pi, pi, (size_t)pi_len);
  oc_rep_set_text_string_v1(root, mnmn, oc_string(g_platform.info.mfg_name),
                            oc_string_len(g_platform.info.mfg_name));
  oc_rep_set_int(root, x.org.iotivity.version, IOTIVITY_LITE_VERSION);
  if (g_platform.info.init_platform_cb != NULL) {
    g_platform.info.init_platform_cb(g_platform.info.data);
  }

  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno();
}

static void
platform_resource_get(oc_request_t *request, oc_interface_mask_t iface,
                      void *data)
{
  (void)data;
  CborError err = platform_encode(request->resource, iface);
  if (err != CborNoError) {
    OC_ERR("encoding platform resource failed(error=%d)", (int)err);
    return;
  }
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

bool
oc_is_platform_resource_uri(oc_string_view_t uri)
{
  return oc_resource_match_uri(OC_STRING_VIEW(OCF_PLATFORM_URI), uri);
}

static void
platform_create_resource(void)
{
  int interfaces = OC_IF_R | OC_IF_BASELINE;
  oc_interface_mask_t default_interface = OC_IF_R;
  assert((interfaces & default_interface) == default_interface);

  int properties = OC_DISCOVERABLE;
#ifdef OC_CLOUD
  properties |= OC_OBSERVABLE;
#endif /* OC_CLOUD */
  oc_core_populate_resource(OCF_P, 0, OCF_PLATFORM_URI, interfaces,
                            default_interface, properties,
                            platform_resource_get, /*put*/ NULL,
                            /*post*/ NULL, /*delete*/ NULL, 1, OCF_PLATFORM_RT);
}

oc_platform_info_t *
oc_platform_init(const char *mfg_name, oc_core_init_platform_cb_t init_cb,
                 void *data)
{
  if (g_platform.initialized) {
    return &g_platform.info;
  }

  size_t mfg_name_len = oc_strnlen(mfg_name, OC_MAX_STRING_LENGTH);
  if (mfg_name_len >= OC_MAX_STRING_LENGTH) {
    OC_ERR("Invalid manufacturer name");
    return NULL;
  }

  platform_create_resource();

  oc_gen_uuid(&g_platform.info.pi);
  oc_new_string(&g_platform.info.mfg_name, mfg_name, mfg_name_len);
  g_platform.info.init_platform_cb = init_cb;
  g_platform.info.data = data;

  g_platform.initialized = true;
  return &g_platform.info;
}

oc_platform_info_t *
oc_core_get_platform_info(void)
{
  return &g_platform.info;
}

void
oc_platform_deinit(void)
{
  if (!g_platform.initialized) {
    return;
  }

  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, 0);
  assert(p != NULL);
  oc_ri_free_resource_properties(p);
  oc_free_string(&(g_platform.info.mfg_name));
  g_platform.initialized = false;
}
