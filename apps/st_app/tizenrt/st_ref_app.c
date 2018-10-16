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

#include "st_device_def.h"
#include "st_manager.h"
#include "st_resource_manager.h"

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";

static const char *power_prop_key = "power";
static const char *dimming_prop_key = "dimmingSetting";
static const char *ct_prop_key = "ct";

static char power[10] = "on";

static int dimmingSetting = 50;
static int dimming_range[2] = { 0, 100 };
static int dimming_step = 5;

static int ct = 50;
static int ct_range[2] = { 0, 100 };

static void
switch_resource_construct(void)
{
  oc_rep_set_text_string(root, power, power);
}

static void
switchlevel_resource_construct(void)
{
  oc_rep_set_int(root, dimmingSetting, dimmingSetting);
  oc_rep_set_int_array(root, range, dimming_range, 2);
  oc_rep_set_int(root, step, dimming_step);
}

static void
color_temp_resource_construct(void)
{
  oc_rep_set_int(root, ct, ct);
  oc_rep_set_int_array(root, range, ct_range, 2);
}

static bool
get_resource_handler(st_request_t *request)
{
  if (strncmp(request->uri, switch_rsc_uri, strlen(switch_rsc_uri)) == 0) {
    switch_resource_construct();
  } else if (strncmp(request->uri, switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_construct();
  } else if (strncmp(request->uri, color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", request->uri);
    return false;
  }

  return true;
}
static void
switch_resource_change(oc_rep_t *rep)
{
  size_t len = 0;
  char *m_power = NULL;
  if (oc_rep_get_string(rep, power_prop_key, &m_power, &len)) {
    strncpy(power, m_power, len);
    power[len] = '\0';
    printf("[ST_APP]  %s : %s\n", power_prop_key, power);

    // TODO: device specific behavior.
  }
}

static void
switchlevel_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, dimming_prop_key, &dimmingSetting)) {
    printf("[ST_APP]  %s : %d\n", dimming_prop_key, dimmingSetting);

    // TODO: device specific behavior.
  }
}

static void
color_temp_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, ct_prop_key, &ct)) {
    printf("[ST_APP]  %s : %d\n", ct_prop_key, ct);

    // TODO: device specific behavior.
  }
}

static bool
set_resource_handler(st_request_t *request)
{
  if (strncmp(request->uri, switch_rsc_uri, strlen(switch_rsc_uri)) == 0) {
    switch_resource_change(request->request_payload);
    switch_resource_construct();
  } else if (strncmp(request->uri, switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_change(request->request_payload);
    switchlevel_resource_construct();
  } else if (strncmp(request->uri, color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_change(request->request_payload);
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", request->uri);
    return false;
  }

  return true;
}


int
stapp_main(void)
{
  st_error_t ret = st_manager_initialize();
  if (ret != ST_ERROR_NONE) {
    printf("[ST_APP] st_manager_initialize failed[%d].\n", ret);
    return -1;
  }

  if (st_register_resource_handler(get_resource_handler,
                                   set_resource_handler) != ST_ERROR_NONE) {
    printf("[ST_APP] st_register_resource_handler failed.\n");
    st_manager_deinitialize();
    return -1;
  }

  if (!st_set_device_profile(st_device_def, st_device_def_len)) {
    printf("[ST_APP] st_set_device_profile failed.\n");
    st_manager_deinitialize();
    return -1;
  }

  // TODO: callback registration. (ex. user confirm cb)

#ifndef STATE_MODEL
  do {
    ret = st_manager_start();
    if (ret != ST_ERROR_NONE) {
      printf("[ST_APP] st_manager_start failed[%d].\n", ret);
      st_manager_deinitialize();
      return -1;
    }

    ret = st_manager_run_loop();
    if (ret != ST_ERROR_NONE) {
      printf("[ST_APP] st_manager_run_loop failed[%d].\n", ret);
      sleep(6000);
    }
  } while (ret != ST_ERROR_NONE);
#endif

  st_manager_stop();
  st_manager_deinitialize();
  return 0;
}
