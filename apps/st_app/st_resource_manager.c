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
#include "oc_api.h"
#include "samsung/sc_easysetup.h"
#include "st_port.h"
#include "st_process.h"

#ifdef JSON_ENABLED
#include "st_json_parser.h"
#include "port/oc_assert.h"
#endif //JSON_ENABLED

static st_resource_handler g_resource_get_handler = NULL;
static st_resource_handler g_resource_set_handler = NULL;

#ifndef JSON_ENABLED
static const char *switch_rsc_uri = "/capability/switch/main/0";
static const int switch_rt_num = 1;
static const char *switch_rsc_rt[1] = { "x.com.st.powerswitch" };
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const int switchleve_rt_num = 1;
static const char *switchlevel_rsc_rt[1] = { "oic.r.light.dimming" };
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";
static const int color_temp_rt_num = 1;
static const char *color_temp_rsc_rt[1] = { "x.com.st.color.temperature" };
#endif //JSON_ENABLED

static int device_index = 0;

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
                     uint8_t interface, uint8_t default_interface,
                     bool discoverable, bool observable, int device)
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
  oc_resource_set_discoverable(resource, discoverable);
  oc_resource_set_observable(resource, observable);
  oc_resource_set_request_handler(resource, OC_GET, st_resource_get_handler,
                                  NULL);
  oc_resource_set_request_handler(resource, OC_POST, st_resource_post_handler,
                                  NULL);
  oc_add_resource(resource);
}

#ifdef JSON_ENABLED
struct if_types_to_mask_s{
  const char *if_type;
  const int if_type_len;
  const oc_interface_mask_t if_mask;
};

static const int k_if_mask_map_count = 7;
static struct if_types_to_mask_s if_mask_map[] = {
  {"oic.if.baseline", sizeof("oic.if.baseline"), OC_IF_BASELINE},
  {"oic.if.ll", sizeof("oic.if.ll"), OC_IF_LL},
  {"oic.if.b", sizeof("oic.if.b"), OC_IF_B},
  {"oic.if.r", sizeof("oic.if.r"), OC_IF_R},
  {"oic.if.rw", sizeof("oic.if.rw"), OC_IF_RW},
  {"oic.if.a", sizeof("oic.if.a"), OC_IF_A},
  {"oic.if.s", sizeof("oic.if.s"), OC_IF_S},
};

static oc_interface_mask_t if_types_to_if_mask(char **if_types, int if_cnt){
  oc_interface_mask_t  mask = 0;
  for(int i = 0; i < if_cnt; ++i){
    for(int j = 0; j < k_if_mask_map_count; ++j){
      if(!(mask & if_mask_map[j].if_mask) &&
          0 == strncmp(if_types[i],if_mask_map[j].if_type,if_mask_map[j].if_type_len)) {
        mask |= if_mask_map[j].if_mask;
      }

    }
  }
  return mask;
}
#endif //JSON_ENABLED

void
st_register_resources(int device)
{
#ifdef JSON_ENABLED
  st_device_s *d = st_manager_json_get_device(device);
  oc_assert(d != NULL);
  oc_assert(d->single != NULL);
  oc_assert(d->sig_cnt > 0);

  for(int i = 0; i < d->sig_cnt; ++i){
    things_resource_info_s *r = &d->single[i];
    oc_interface_mask_t mask = if_types_to_if_mask(r->interface_types, r->if_cnt);
    bool discoverable = (r->policy & 0x1 ? true: false);
    bool observable   = (r->policy & 0x2 ? true: false);

    st_register_resource(r->uri, (const char**)r->resource_types, r->rt_cnt, mask, OC_IF_A, discoverable, observable, device);
  }
#else
  st_register_resource(switch_rsc_uri, switch_rsc_rt, switch_rt_num,
                      OC_IF_A | OC_IF_BASELINE, OC_IF_A, true, true, device);

  st_register_resource(switchlevel_rsc_uri, switchlevel_rsc_rt,
                      switchleve_rt_num, OC_IF_A, OC_IF_A, true, true, device);

  st_register_resource(color_temp_rsc_uri, color_temp_rsc_rt, color_temp_rt_num,
                       OC_IF_A | OC_IF_S | OC_IF_BASELINE, OC_IF_A, true, true, device);

#endif //JSON_ENABLED

  init_provisioning_info_resource(NULL);

  device_index = device;
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

void
st_notify_back(const char *uri)
{
  if (!uri) {
    st_print_log("[St_rsc_mgr] invalid parameter.");
    return;
  }

  st_process_app_sync_lock();
  oc_resource_t *resource =
    oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
  if (!resource) {
    st_print_log("[St_rsc_mgr] invalid resource uri(%s)\n", uri);
    return;
  }

  oc_notify_observers(resource);
  st_process_app_sync_unlock();
  _oc_signal_event_loop();
}
