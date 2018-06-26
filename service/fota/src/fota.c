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

#include "fota.h"
#include "oc_api.h"

#define OC_RSRVD_FIRMWARE_URI "/firmware"
#define OC_RSRVD_FIRMWARE_RT "x.com.samsung.firmware"

#define FOTA_INIT_STRING "Init"
#define FOTA_CHECK_STRING "Check"
#define FOTA_DOWNLOAD_STRING "Download"
#define FOTA_UPDATE_STRING "Update"
#define FOTA_DOWNLOAD_UPDATE_STRING "DownloadUpdate"

typedef struct
{
  oc_string_t ver;
  oc_string_t uri;
  bool req_notify;
} fw_info_t;

static fota_cmd_cb_t g_fota_cmd_cb;
static fota_state_t g_fota_state;
static fota_result_t g_fota_result;
static fw_info_t g_fw_info;
static oc_resource_t *resource;

static void
get_fota(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    if (g_fota_result != FOTA_RESULT_INIT) {
      oc_rep_set_int(root, result, g_fota_result);
    } else if (g_fw_info.req_notify) {
      oc_rep_set_text_string(root, newversion, oc_string(g_fw_info.ver));
      oc_rep_set_text_string(root, packageuri, oc_string(g_fw_info.uri));
    } else {
      oc_rep_set_text_string(root, version, "version");
      oc_rep_set_text_string(root, vendor, "vendor");
      oc_rep_set_text_string(root, model, "model");
      oc_rep_set_int(root, state, g_fota_state);
      oc_rep_set_int(root, result, g_fota_result);
    }
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

static void
post_fota(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;

  oc_status_t code = OC_STATUS_BAD_REQUEST;
  char *cmd = NULL;
  int size;
  if (oc_rep_get_string(request->request_payload, "update", &cmd, &size)) {
    fota_cmd_t fota_cmd = 0;
    if (strncmp(FOTA_INIT_STRING, cmd, size) == 0) {
      fota_cmd = FOTA_CMD_INIT;
    } else if (strncmp(FOTA_CHECK_STRING, cmd, size) == 0) {
      fota_cmd = FOTA_CMD_CHECK;
    } else if (strncmp(FOTA_DOWNLOAD_STRING, cmd, size) == 0) {
      fota_cmd = FOTA_CMD_DOWNLOAD;
    } else if (strncmp(FOTA_UPDATE_STRING, cmd, size) == 0) {
      fota_cmd = FOTA_CMD_UPDATE;
    } else if (strncmp(FOTA_DOWNLOAD_UPDATE_STRING, cmd, size) == 0) {
      fota_cmd = FOTA_CMD_DOWNLOAD_UPDATE;
    }

    if (fota_cmd != 0 && g_fota_cmd_cb(fota_cmd) == 0)
      code = OC_STATUS_CHANGED;
  }

  oc_send_response(request, code);
}

static void
put_fota(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  post_fota(request, interface, user_data);
}

oc_define_interrupt_handler(notify_fota)
{
  oc_notify_observers(resource);
  g_fota_result = FOTA_RESULT_INIT;
  g_fw_info.req_notify = false;
}

int
fota_init(fota_cmd_cb_t cb)
{
  if (!cb)
    return -1;

  g_fota_cmd_cb = cb;
  g_fota_state = FOTA_STATE_IDLE;
  g_fota_result = FOTA_RESULT_INIT;
  g_fw_info.req_notify = false;

  oc_activate_interrupt_handler(notify_fota);

  resource = oc_new_resource(NULL, OC_RSRVD_FIRMWARE_URI, 1, 0);
  oc_resource_bind_resource_type(resource, OC_RSRVD_FIRMWARE_RT);
  oc_resource_bind_resource_interface(resource, OC_IF_RW);
  oc_resource_set_default_interface(resource, OC_IF_RW);
  oc_resource_set_discoverable(resource, true);
  oc_resource_set_observable(resource, true);
  oc_resource_set_request_handler(resource, OC_GET, get_fota, NULL);
  oc_resource_set_request_handler(resource, OC_PUT, put_fota, NULL);
  oc_resource_set_request_handler(resource, OC_POST, post_fota, NULL);

  return oc_add_resource(resource) ? 0 : -1;
}

void
fota_deinit(void)
{
  g_fota_cmd_cb = NULL;
  g_fota_state = FOTA_STATE_IDLE;
  g_fota_result = FOTA_RESULT_INIT;
  g_fw_info.req_notify = false;

  if (oc_string_len(g_fw_info.ver) > 0)
    oc_free_string(&g_fw_info.ver);
  if (oc_string_len(g_fw_info.uri) > 0)
    oc_free_string(&g_fw_info.uri);
}

int
fota_set_state(fota_state_t state)
{
  if ((g_fota_state == FOTA_STATE_IDLE && state != FOTA_STATE_DOWNLOADING) ||
      (g_fota_state == FOTA_STATE_DOWNLOADING &&
       state == FOTA_STATE_UPDATING) ||
      (g_fota_state == FOTA_STATE_UPDATING && state == FOTA_STATE_DOWNLOADING))
    return -1;

  g_fota_state = state;

  oc_signal_interrupt_handler(notify_fota);
  return 0;
}

int
fota_set_fw_info(const char *ver, const char *uri)
{
  if (!ver || !uri) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  if (oc_string_len(g_fw_info.ver) > 0)
    oc_free_string(&g_fw_info.ver);
  oc_new_string(&g_fw_info.ver, ver, strlen(ver));
  if (oc_string_len(g_fw_info.uri) > 0)
    oc_free_string(&g_fw_info.uri);
  oc_new_string(&g_fw_info.uri, uri, strlen(uri));
  g_fw_info.req_notify = true;

  oc_signal_interrupt_handler(notify_fota);
  return 0;
}

int
fota_set_result(fota_result_t result)
{
  g_fota_result = result;

  oc_signal_interrupt_handler(notify_fota);
  return 0;
}
