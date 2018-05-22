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

static bool g_discoverable = true;
static bool g_observable = true;

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const char *switch_rsc_rt = "x.com.st.powerswitch";
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const char *switchlevel_rsc_rt = "oic.r.light.dimming";
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";
static const char *color_temp_rsc_rt = "x.com.st.color.temperature";

static char power[10] = "on";
static int dimmingSetting = 50;

static int ct = 50;
static int range[2] = { 0, 100 };

static oc_link_t *publish_res;


static void
switch_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_text_string(root, power, power);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
switch_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                   void *user_data)
{
  (void)user_data;

  st_print_log("[St_rsc_mgr] switch_get_handler:\n");
  switch_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
switch_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                    void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("[St_rsc_mgr] switch_post_handler:\n");
  st_print_log("[St_rsc_mgr]   Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));

    switch (rep->type) {
    case OC_REP_STRING:
      if (strcmp(oc_string(rep->name), "power") == 0) {
        strcpy(power, oc_string(rep->value.string));
        st_print_log(" %s\n", power);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  switch_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
switchlevel_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, dimmingSetting, dimmingSetting);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
switchlevel_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;

  st_print_log("[St_rsc_mgr] switchlevel_get_handler:\n");
  switchlevel_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
switchlevel_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                         void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("[St_rsc_mgr] switchlevel_post_handler:\n");
  st_print_log("[St_rsc_mgr]   Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (strcmp(oc_string(rep->name), "dimmingSetting") == 0) {
        dimmingSetting = rep->value.integer;
        st_print_log(" %d\n", dimmingSetting);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  switchlevel_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
color_temp_construct(oc_request_t *request, oc_interface_mask_t interface)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_int(root, ct, ct);
    oc_rep_set_int_array(root, range, range, 2);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
color_temp_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                       void *user_data)
{
  (void)user_data;

  st_print_log("[St_rsc_mgr] color_temp_get_handler:\n");
  color_temp_construct(request, interface);
  oc_send_response(request, OC_STATUS_OK);
}

static void
color_temp_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("[St_rsc_mgr] color_temp_post_handler:\n");
  st_print_log("[St_rsc_mgr]   Key : Value\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    st_print_log("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT:
      if (strcmp(oc_string(rep->name), "ct") == 0) {
        ct = rep->value.integer;
        st_print_log(" %d\n", ct);
      }
      break;
    default:
      st_print_log(" NULL\n");
      break;
    }
    rep = rep->next;
  }
  color_temp_construct(request, interface);
  oc_send_response(request, OC_STATUS_CHANGED);
}

void
st_register_resources(int device)
{
  oc_resource_t *switch_resource = oc_new_resource(NULL, switch_rsc_uri, 1, device);
  oc_resource_bind_resource_type(switch_resource, switch_rsc_rt);
  oc_resource_bind_resource_interface(switch_resource, OC_IF_A);
  oc_resource_set_default_interface(switch_resource, OC_IF_BASELINE);
  oc_resource_set_discoverable(switch_resource, g_discoverable);
  oc_resource_set_observable(switch_resource, g_observable);
  oc_resource_set_request_handler(switch_resource, OC_GET, switch_get_handler,
                                  NULL);
  oc_resource_set_request_handler(switch_resource, OC_POST, switch_post_handler,
                                  NULL);
  oc_add_resource(switch_resource);

  oc_resource_t *level = oc_new_resource(NULL, switchlevel_rsc_uri, 1, device);
  oc_resource_bind_resource_type(level, switchlevel_rsc_rt);
  oc_resource_bind_resource_interface(level, OC_IF_A);
  oc_resource_set_discoverable(level, g_discoverable);
  oc_resource_set_observable(level, g_observable);
  oc_resource_set_request_handler(level, OC_GET, switchlevel_get_handler, NULL);
  oc_resource_set_request_handler(level, OC_POST, switchlevel_post_handler,
                                  NULL);
  oc_add_resource(level);

  oc_resource_t *temperature = oc_new_resource(NULL, color_temp_rsc_uri, 1, device);
  oc_resource_bind_resource_type(temperature, color_temp_rsc_rt);
  oc_resource_bind_resource_interface(temperature, OC_IF_A);
  oc_resource_bind_resource_interface(temperature, OC_IF_S);
  oc_resource_set_default_interface(temperature, OC_IF_BASELINE);
  oc_resource_set_discoverable(temperature, g_discoverable);
  oc_resource_set_observable(temperature, g_observable);
  oc_resource_set_request_handler(temperature, OC_GET, color_temp_get_handler,
                                  NULL);
  oc_resource_set_request_handler(temperature, OC_POST, color_temp_post_handler,
                                  NULL);
  oc_add_resource(temperature);

  publish_res = oc_new_link(switch_resource);
  oc_link_t *publish_res1 = oc_new_link(level);
  oc_link_t *publish_res2 = oc_new_link(temperature);
  oc_list_add((oc_list_t)publish_res, publish_res1);
  oc_list_add((oc_list_t)publish_res, publish_res2);

  register_sc_provisioning_info_resource();
}

//TODO: remove after publich function change.
oc_link_t *
st_get_publish_resources(void)
{
  return publish_res;
}

void
st_delete_publish_resources(void)
{
  oc_link_t *next = NULL;

  while (publish_res) {
    next = oc_list_item_next(publish_res);
    oc_delete_link(publish_res);
    publish_res = next;
  }
}