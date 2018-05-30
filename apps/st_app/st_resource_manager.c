/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "st_resource_manager.h"
#include "st_port.h"
#include "oc_api.h"
#include "sc_easysetup.h"

static st_resource_handler g_resource_get_handler = NULL;
static st_resource_handler g_resource_set_handler = NULL;

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const int switch_rt_num = 1;
static const char *switch_rsc_rt[1] = { "x.com.st.powerswitch" };
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const int switchleve_rt_num = 1;
static const char *switchlevel_rsc_rt[1] = { "oic.r.light.dimming" };
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";
static const int color_temp_rt_num = 1;
static const char *color_temp_rsc_rt[1] = { "x.com.st.color.temperature" };

static void
st_resource_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;
  st_print_log("[St_rsc_mgr] st_resource_get_handler: %s\n",
               oc_string(request->resource->uri));

  if (!g_resource_get_handler) {
    st_print_log("[St_rsc_mgr] please initialize valid handler first");
    oc_send_response(request, OC_STATUS_NOT_IMPLEMENTED);
    return;
  }

  oc_rep_start_root_object();
  if (interface & OC_IF_BASELINE) {
    oc_process_baseline_interface(request->resource);
  }
  if (!g_resource_get_handler(request)) {
    oc_rep_reset();
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
st_resource_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                         void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("[St_rsc_mgr] st_resource_post_handler: %s\n",
               oc_string(request->resource->uri));

  if (!g_resource_set_handler) {
    st_print_log("[St_rsc_mgr] please initialize valid handler first");
    oc_send_response(request, OC_STATUS_NOT_IMPLEMENTED);
    return;
  }

  oc_rep_start_root_object();
  if (interface & OC_IF_BASELINE) {
    oc_process_baseline_interface(request->resource);
  }
  if (!g_resource_set_handler(request)) {
    oc_rep_reset();
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
st_register_resource(const char *uri, const char **rt, int rt_num,
                     uint8_t interface, uint8_t default_interface, int device)
{
  st_print_log("uri : %s\n", uri);
  oc_resource_t *resource = oc_new_resource(NULL, uri, rt_num, device);
  int i;
  for (i = 0; i < rt_num; i++) {
    oc_resource_bind_resource_type(resource, rt[i]);
    st_print_log("rt : %s\n", rt[i]);
  }
  st_print_log("interface : %d\n", interface);
  oc_resource_bind_resource_interface(resource, interface);
  st_print_log("default_interface : %d\n", default_interface);
  oc_resource_set_default_interface(resource, default_interface);
  oc_resource_set_discoverable(resource, true);
  oc_resource_set_observable(resource, true);
  oc_resource_set_request_handler(resource, OC_GET, st_resource_get_handler,
                                  NULL);
  oc_resource_set_request_handler(resource, OC_POST, st_resource_post_handler,
                                  NULL);
  oc_add_resource(resource);
}

void
st_register_resources(int device)
{
  st_register_resource(switch_rsc_uri, switch_rsc_rt, switch_rt_num,
                       OC_IF_A | OC_IF_BASELINE, OC_IF_A, device);

  st_register_resource(switchlevel_rsc_uri, switchlevel_rsc_rt,
                       switchleve_rt_num, OC_IF_A, OC_IF_A, device);

  st_register_resource(color_temp_rsc_uri, color_temp_rsc_rt, color_temp_rt_num,
                       OC_IF_A | OC_IF_S | OC_IF_BASELINE, OC_IF_A, device);

  init_provisioning_info_resource(NULL);
}

void
st_register_resource_handler(st_resource_handler get_handler,
                             st_resource_handler set_handler)
{
  if (!get_handler || !set_handler) {
    st_print_log("[St_rsc_mgr] invalid parameter.");
    return;
  }

  g_resource_get_handler = get_handler;
  g_resource_set_handler = set_handler;
}