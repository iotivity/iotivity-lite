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

#include "st_fota_manager.h"
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
get_resource_handler(oc_request_t *request)
{
  if (strncmp(oc_string(request->resource->uri), switch_rsc_uri,
              strlen(switch_rsc_uri)) == 0) {
    switch_resource_construct();
  } else if (strncmp(oc_string(request->resource->uri), switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_construct();
  } else if (strncmp(oc_string(request->resource->uri), color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", oc_string(request->resource->uri));
    return false;
  }

  return true;
}
static void
switch_resource_change(oc_rep_t *rep)
{
  int len = 0;
  char *m_power = NULL;
  if (oc_rep_get_string(rep, power_prop_key, &m_power, &len)) {
    strncpy(power, m_power, len);
    power[len] = '\0';
    printf("[ST_APP]  %s : %s\n", oc_string(rep->name), power);

    // TODO: device specific behavior.
  }
}

static void
switchlevel_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, dimming_prop_key, &dimmingSetting)) {
    printf("[ST_APP]  %s : %d\n", oc_string(rep->name), dimmingSetting);

    // TODO: device specific behavior.
  }
}

static void
color_temp_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, ct_prop_key, &ct)) {
    printf("[ST_APP]  %s : %d\n", oc_string(rep->name), ct);

    // TODO: device specific behavior.
  }
}

static bool
set_resource_handler(oc_request_t *request)
{
  if (strncmp(oc_string(request->resource->uri), switch_rsc_uri,
              strlen(switch_rsc_uri)) == 0) {
    switch_resource_change(request->request_payload);
    switch_resource_construct();
  } else if (strncmp(oc_string(request->resource->uri), switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_change(request->request_payload);
    switchlevel_resource_construct();
  } else if (strncmp(oc_string(request->resource->uri), color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_change(request->request_payload);
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", oc_string(request->resource->uri));
    return false;
  }

  return true;
}

static bool
otm_confirm_handler(void)
{
  printf("[ST_APP] OTM request is comming. Will you confirm?[y/n]\n");
  char ret[10];
  if (!scanf("%s", ret))
    printf("[ST_APP] scanf failed.\n");

  if (ret[0] == 'y' || ret[0] == 'Y') {
    printf("[ST_APP] CONFIRMED.\n");
    return true;
  } else {
    printf("[ST_APP] DENIED.\n");
    return false;
  }
}

static void
st_status_handler(st_status_t status)
{
  if (status == ST_STATUS_DONE) {
    printf("[ST_APP] ST connected\n");
  } else {
    printf("[ST_APP] ST connecting(%d)\n", status);
  }
}

static bool
st_fota_cmd_handler(fota_cmd_t cmd)
{
  printf("[ST_APP] FOTA Command: %d\n", cmd);
  switch (cmd) {
  case FOTA_CMD_INIT:
    if (st_fota_set_state(FOTA_STATE_IDLE) != 0) {
      printf("[ST_APP] st_fota_set_state failed.\n");
    }
    break;
  case FOTA_CMD_CHECK: {
    char *ver = "1.0";
    char *uri = "http://www.samsung.com";
    if (st_fota_set_fw_info(ver, uri) != 0) {
      printf("[ST_APP] st_fota_set_fw_info failed.\n");
    }
    break;
  }
  case FOTA_CMD_DOWNLOAD:
    if (st_fota_set_result(FOTA_RESULT_NO_MEMORY) != 0) {
      printf("[ST_APP] st_fota_set_result failed.\n");
    }
    break;
  case FOTA_CMD_UPDATE:
    break;
  case FOTA_CMD_DOWNLOAD_UPDATE:
    break;
  }

  return true;
}

int
main(void)
{
  if (st_manager_initialize() != 0) {
    printf("[ST_APP] st_manager_initialize failed.\n");
    return -1;
  }

  if (st_register_resource_handler(get_resource_handler,
                                   set_resource_handler) != 0) {
    printf("[ST_APP] st_register_resource_handler failed.\n");
  }
  st_register_otm_confirm_handler(otm_confirm_handler);
  st_register_status_handler(st_status_handler);
  st_register_fota_cmd_handler(st_fota_cmd_handler);

  if (st_manager_start() != 0) {
    printf("[ST_APP] st_manager_start failed.\n");
  }

  st_unregister_status_handler();
  st_manager_stop();
  st_manager_deinitialize();
  return 0;
}