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

enum notify_type
{
  FOTA_NOTIFY_DEFAULT,
  FOTA_NOTIFY_STATE,
  FOTA_NOTIFY_INFO,
  FOTA_NOTIFY_RESULT
};

typedef struct
{
  oc_string_t version;
  oc_string_t newversion;
  oc_string_t uri;
  fota_state_t state;
  fota_result_t result;
  enum notify_type type;
} fota_info_t;

static fota_info_t g_fota_info;
static fota_cmd_cb_t g_fota_cmd_cb = NULL;
static enum notify_type g_notify_type;

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
    if (g_fota_info.type == FOTA_NOTIFY_STATE) {
      oc_rep_set_int(root, state, g_fota_info.state);
    } else if (g_fota_info.type == FOTA_NOTIFY_INFO) {
      oc_rep_set_text_string(root, version, oc_string(g_fota_info.version));
      oc_rep_set_text_string(root, newversion,
                             oc_string(g_fota_info.newversion));
      oc_rep_set_text_string(root, packageuri, oc_string(g_fota_info.uri));
    } else if (g_fota_info.type == FOTA_NOTIFY_RESULT) {
      oc_rep_set_int(root, result, g_fota_info.result);
    } else {
      oc_rep_set_text_string(root, version, oc_string(g_fota_info.version));
      oc_rep_set_text_string(root, newversion,
                             oc_string(g_fota_info.newversion));
      oc_rep_set_text_string(root, vendor, "vendor");
      oc_rep_set_text_string(root, model, "model");
      oc_rep_set_int(root, state, g_fota_info.state);
      oc_rep_set_int(root, result, g_fota_info.result);
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

static oc_event_callback_retval_t
notify_fota(void *data)
{
  (void)data;
  g_fota_info.type = g_notify_type;
  oc_resource_t *resource = oc_ri_get_app_resource_by_uri(
    OC_RSRVD_FIRMWARE_URI, strlen(OC_RSRVD_FIRMWARE_URI), 0);
  if (resource)
    oc_notify_observers(resource);
  g_fota_info.type = FOTA_NOTIFY_DEFAULT;

  return OC_EVENT_DONE;
}

static void
fota_info_init(void)
{
  g_fota_info.state = FOTA_STATE_IDLE;
  g_fota_info.result = FOTA_RESULT_INIT;
  g_fota_info.type = FOTA_NOTIFY_DEFAULT;

  if (oc_string_len(g_fota_info.version) > 0)
    oc_free_string(&g_fota_info.version);
  if (oc_string_len(g_fota_info.newversion) > 0)
    oc_free_string(&g_fota_info.newversion);
  if (oc_string_len(g_fota_info.uri) > 0)
    oc_free_string(&g_fota_info.uri);
}

int
fota_init(fota_cmd_cb_t cb)
{
  if (!cb || g_fota_cmd_cb) {
    OC_ERR("Could not fota init");
    return -1;
  }

  g_fota_cmd_cb = cb;
  fota_info_init();

  oc_resource_t *resource = oc_new_resource(NULL, OC_RSRVD_FIRMWARE_URI, 1, 0);
  if (!resource)
    return -1;
  oc_resource_bind_resource_type(resource, OC_RSRVD_FIRMWARE_RT);
  oc_resource_bind_resource_interface(resource, OC_IF_RW);
  oc_resource_set_default_interface(resource, OC_IF_RW);
  oc_resource_set_discoverable(resource, true);
  oc_resource_set_observable(resource, true);
  oc_resource_set_request_handler(resource, OC_GET, get_fota, NULL);
  oc_resource_set_request_handler(resource, OC_POST, post_fota, NULL);

  return oc_add_resource(resource) ? 0 : -1;
}

void
fota_deinit(void)
{
  g_fota_cmd_cb = NULL;
  fota_info_init();
  oc_resource_t *resource = oc_ri_get_app_resource_by_uri(
    OC_RSRVD_FIRMWARE_URI, strlen(OC_RSRVD_FIRMWARE_URI), 0);
  if (resource)
    oc_delete_resource(resource);
}

int
fota_set_state(fota_state_t state)
{
  if ((g_fota_info.state == FOTA_STATE_IDLE &&
       state != FOTA_STATE_DOWNLOADING) ||
      (g_fota_info.state == FOTA_STATE_DOWNLOADING &&
       state == FOTA_STATE_UPDATING) ||
      (g_fota_info.state == FOTA_STATE_UPDATING &&
       state == FOTA_STATE_DOWNLOADING)) {
    OC_ERR("Could not fota set state");
    return -1;
  }

  g_fota_info.state = state;

  g_notify_type = FOTA_NOTIFY_STATE;
  oc_set_delayed_callback(NULL, notify_fota, 0);
  _oc_signal_event_loop();

  return 0;
}

int
fota_set_fw_info(const char *version, const char *new_version, const char *uri)
{
  if (!version || !uri) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  if (oc_string_len(g_fota_info.version) > 0)
    oc_free_string(&g_fota_info.version);
  oc_new_string(&g_fota_info.version, version, strlen(version));
  if (oc_string_len(g_fota_info.uri) > 0)
    oc_free_string(&g_fota_info.uri);
  oc_new_string(&g_fota_info.uri, uri, strlen(uri));
  if (new_version) {
    if (oc_string_len(g_fota_info.newversion) > 0)
      oc_free_string(&g_fota_info.newversion);
    oc_new_string(&g_fota_info.newversion, new_version, strlen(new_version));
  }

  g_notify_type = FOTA_NOTIFY_INFO;
  oc_set_delayed_callback(NULL, notify_fota, 0);
  _oc_signal_event_loop();

  return 0;
}

int
fota_set_result(fota_result_t result)
{
  g_fota_info.result = result;

  g_notify_type = FOTA_NOTIFY_RESULT;
  oc_set_delayed_callback(NULL, notify_fota, 0);
  _oc_signal_event_loop();

  return 0;
}
