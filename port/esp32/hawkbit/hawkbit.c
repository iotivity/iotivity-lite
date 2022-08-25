/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "debug_print.h"
#include "oc_esp.h"
#include "hawkbit_action.h"
#include "hawkbit_context.h"
#include "hawkbit_deployment.h"
#include "hawkbit_feedback.h"
#include "hawkbit_http.h"
#include "hawkbit_internal.h"
#include "hawkbit_json.h"
#include "hawkbit_util.h"

#include "api/oc_swupdate_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_swupdate.h"
#ifdef OC_SECURITY
#include "oc_store.h"
#include "security/oc_doxm_internal.h"
#endif /* OC_SECURITY */

#include <cJSON.h>
#include <esp_chip_info.h>
#include <esp_https_ota.h>
#include <esp_idf_version.h>
#include <esp_image_format.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_system.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

static cJSON *
hawkbit_fetch_by_http_get(const char *url)
{
  char buffer[HAWKBIT_HTTP_MAX_OUTPUT_BUFFER] = { 0 };
  int code = hawkbit_http_perform_get(url, buffer, sizeof(buffer));
  if (code < 0 || code != HAWKBIT_HTTP_CODE_OK) {
    APP_ERR("fetch by HTTP GET: unexpected HTTP code(%d)", code);
    return NULL;
  }

  APP_DBG("Fetch by HTTP GET payload: %s", buffer);
  cJSON *root = cJSON_Parse(buffer);
  if (root == NULL) {
#ifdef APP_DEBUG
    const char *json_error = cJSON_GetErrorPtr();
    APP_ERR("fetch by HTTP GET failed: %s",
            json_error != NULL ? json_error : "failed to parse output");
#endif /* APP_DEBUG */
    return NULL;
  }
  return root;
}

static bool
hawkbit_get_url_server(hawkbit_url_t hurl, char *server_url,
                       size_t server_url_size)
{
  if (hurl.server_url == NULL) {
    APP_ERR("get server URL failed: server url not set");
    return false;
  }
  if (hurl.server_url_length >= server_url_size) {
    APP_ERR("get server URL failed: buffer too small");
    return false;
  }
  memcpy(server_url, hurl.server_url, hurl.server_url_length);
  server_url[hurl.server_url_length] = '\0';
  return true;
}

static bool
hawkbit_get_url_tenant(size_t device, hawkbit_url_t hurl, char *tenant,
                       size_t tenant_size)
{
  if (hurl.tenant != NULL) {
    if (hurl.tenant_length >= tenant_size) {
      APP_ERR("get URL failed: buffer too small");
      return false;
    }
    memcpy(tenant, hurl.tenant, hurl.tenant_length);
    tenant[hurl.tenant_length] = '\0';
    return true;
  }
#ifdef OC_SECURITY
  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  if (doxm->owned && tenant_size >= OC_UUID_LEN) {
    oc_uuid_to_str(&doxm->devowneruuid, tenant, tenant_size);
    return true;
  }
#else  /* !OC_SECURITY */
  (void)device;
#endif /* OC_SECURITY */
  return false;
}

static bool
hawkbit_get_url_controller_id(size_t device, hawkbit_url_t hurl,
                              char *controller_id, size_t controller_id_size)
{
  if (hurl.controller_id != NULL) {
    if (hurl.controller_id_length >= controller_id_size) {
      APP_ERR("get URL failed: buffer too small");
      return false;
    }
    memcpy(controller_id, hurl.controller_id, hurl.controller_id_length);
    controller_id[hurl.controller_id_length] = '\0';
    return true;
  }
  const oc_device_info_t *info = oc_core_get_device_info(device);
  if (info != NULL && controller_id_size >= OC_UUID_LEN) {
    oc_uuid_to_str(&info->piid, controller_id, controller_id_size);
    return true;
  }
  return false;
}

hawkbit_error_t
hawkbit_get_url(const hawkbit_context_t *ctx, char *server_url,
                size_t server_url_size, char *tenant, size_t tenant_size,
                char *controller_id, size_t controller_id_size)
{
  assert(server_url != NULL);
  assert(tenant != NULL);
  assert(controller_id != NULL);

  const char *purl = hawkbit_get_package_url(ctx);
  if (purl == NULL) {
    return HAWKBIT_ERROR_PACKAGE_URL_NOT_SET;
  }
  hawkbit_url_t hurl;
  if (!hawkbit_parse_package_url(purl, &hurl)) {
    APP_ERR("get URL failed: cannot parse package url");
    return HAWKBIT_ERROR_GENERAL;
  }

  if (!hawkbit_get_url_server(hurl, server_url, server_url_size)) {
    APP_ERR("get URL failed: cannot get server url");
    return HAWKBIT_ERROR_GENERAL;
  }

  // TODO: devowneruuid doesn't seem to work for hawkbit, check if the tenant_id
  // must have some format
  if (!hawkbit_get_url_tenant(hawkbit_get_device(ctx), hurl, tenant,
                              tenant_size)) {
    APP_ERR("get URL failed: cannot get tenant");
    return HAWKBIT_ERROR_GENERAL;
  }

  if (!hawkbit_get_url_controller_id(hawkbit_get_device(ctx), hurl,
                                     controller_id, controller_id_size)) {
    APP_ERR("get URL failed: cannot get controller id");
    return HAWKBIT_ERROR_GENERAL;
  }

  APP_DBG("hawkbit server: %s, tenant: %s, controller_id: %s", server_url,
          tenant, controller_id);
  return HAWKBIT_OK;
}

static hawkbit_error_t
hawkbit_base_resource_url(const hawkbit_context_t *ctx, char *buffer,
                          size_t buffer_size)
{
  char base_url[256] = { '\0' };
  char tenant[128] = { '\0' };
  char controller_id[128] = { '\0' };
  hawkbit_error_t err =
    hawkbit_get_url(ctx, base_url, sizeof(base_url), tenant, sizeof(tenant),
                    controller_id, sizeof(controller_id));
  if (err != HAWKBIT_OK) {
    APP_ERR("get resource URL failed: invalid package url");
    return err;
  }
  int len = snprintf(buffer, buffer_size, "%s/%s/controller/v1/%s", base_url,
                     tenant, controller_id);
  if (len < 0 || (size_t)len >= buffer_size) {
    APP_ERR("get resource URL failed: %s", "cannot get url");
    return HAWKBIT_ERROR_GENERAL;
  }
  return HAWKBIT_OK;
}

static bool
hawkbit_fetch_deployment(const char *url, hawkbit_deployment_t *deployment)
{
  assert(url != NULL);
  assert(deployment != NULL);
  cJSON *root = hawkbit_fetch_by_http_get(url);
  if (root == NULL) {
    return false;
  }

  bool result = hawkbit_parse_deployment(root, deployment);
  cJSON_Delete(root);
  return result;
}

static bool
hawkbit_fetch_cancel(const char *url, hawkbit_action_t *action)
{
  assert(url != NULL);
  assert(action != NULL);
  cJSON *root = hawkbit_fetch_by_http_get(url);
  if (root == NULL) {
    return false;
  }

  const char *stopId = hawkbit_json_get_string(root, "cancelAction.stopId");
  if (stopId == NULL) {
    APP_ERR("failed to fetch cancel action: invalid stopId");
    cJSON_Delete(root);
    return false;
  }

  *action = hawkbit_action_cancel(stopId);
  cJSON_Delete(root);
  return true;
}

static bool
hawkbit_parse_integer(const char *text, long *value)
{
  char *endptr;
  errno = 0;
  long result = strtol(text, &endptr, 10);
  if (endptr == text) {
    return false;
  }
  if ((result == LONG_MAX || result == LONG_MIN) && errno == ERANGE) {
    return false;
  }
  *value = result;
  return true;
}

static int64_t
hawkbit_parse_polling_interval(const char *text)
{
  if (strlen(text) != sizeof("HH:MM:SS") - 1) {
    APP_ERR("invalid interval value(%s)", text);
    return -1;
  }

  char hours[3];
  memcpy(hours, text, 2);
  hours[2] = '\0';
  long h;
  if (!hawkbit_parse_integer(hours, &h) || h < 0) {
    return -1;
  }

  char minutes[3];
  memcpy(minutes, text + 3, 2);
  minutes[2] = '\0';
  long m;
  if (!hawkbit_parse_integer(minutes, &m) || m < 0) {
    return -1;
  }

  char seconds[3];
  memcpy(seconds, text + 6, 2);
  seconds[2] = '\0';
  long s;
  if (!hawkbit_parse_integer(seconds, &s) || s < 0) {
    return 0;
  }

  return (h * 3600) + (m * 60) + s;
}

hawkbit_error_t
hawkbit_poll_base_resource(hawkbit_context_t *ctx, hawkbit_action_t *action,
                           hawkbit_configuration_t *cfg)
{
  assert(ctx != NULL);
  assert(action != NULL);

  char url[256];
  hawkbit_error_t err = hawkbit_base_resource_url(ctx, url, sizeof(url));
  if (err != HAWKBIT_OK) {
    return err;
  }
  APP_DBG("Base resource URL: %s", url);
  cJSON *root = hawkbit_fetch_by_http_get(url);
  if (root == NULL) {
    return HAWKBIT_ERROR_GENERAL;
  }

  int64_t polling_interval = 0;
  if (cfg != NULL) {
    const char *polling_interval_str =
      hawkbit_json_get_string(root, "config.polling.sleep");
    if (polling_interval_str != NULL) {
      polling_interval = hawkbit_parse_polling_interval(polling_interval_str);
      if (polling_interval < 0) {
        cJSON_Delete(root);
        return HAWKBIT_ERROR_GENERAL;
      }
    }
    cfg->pollingInterval = (uint64_t)polling_interval;
  }

  const char *href =
    hawkbit_json_get_string(root, "_links.deploymentBase.href");
  if (href != NULL) {
    APP_DBG("Deployment URL: %s", href);
    hawkbit_deployment_t deployment;
    if (!hawkbit_fetch_deployment(href, &deployment)) {
      cJSON_Delete(root);
      return HAWKBIT_ERROR_GENERAL;
    }

    *action = hawkbit_action_deploy(deployment);
    cJSON_Delete(root);
    return HAWKBIT_OK;
  }

  href = hawkbit_json_get_string(root, "_links.configData.href");
  if (href != NULL) {
    APP_DBG("Configuration URL: %s", href);
    *action = hawkbit_action_configure(href);
    cJSON_Delete(root);
    return HAWKBIT_OK;
  }

  href = hawkbit_json_get_string(root, "_links.cancelAction.href");
  if (href != NULL) {
    APP_DBG("Cancel URL: %s", href);
    bool result = hawkbit_fetch_cancel(href, action);
    cJSON_Delete(root);
    return result ? HAWKBIT_OK : HAWKBIT_ERROR_GENERAL;
  }

  cJSON_Delete(root);
  *action = hawkbit_action_none();
  return HAWKBIT_OK;
}

typedef struct
{
  const char *key;
  const char *value;
} hawkbit_data_item_t;

static bool
hawkbit_configure(const hawkbit_context_t *ctx, const char *url)
{
  oc_esp_mac_address_t mac;
  if (!oc_esp_get_mac_address(&mac)) {
    APP_ERR("hawkbit configure error: cannot get MAC address");
    return false;
  }

  esp_chip_info_t info;
  esp_chip_info(&info);
  char revision[6];
  int ret = snprintf(revision, sizeof(revision), "%u", (unsigned)info.revision);
  if (ret < 0 || ret >= sizeof(revision)) {
    APP_ERR("cannot get ESP chip revision: buffer too small");
    return false;
  }

  hawkbit_data_item_t data[] = {
    {
      .key = "mac",
      .value = mac.address,
    },
    {
      .key = "app.version",
      .value = hawkbit_get_version(ctx),
    },
    {
      .key = "esp",
      .value = "esp32",
    },
    {
      .key = "esp32.chipRevision",
      .value = revision,
    },
    {
      .key = "esp32.sdkVersion",
      .value = esp_get_idf_version(),
    },
  };
  const size_t data_size = sizeof(data) / sizeof(data[0]);

  if (url == NULL || url[0] == '\0') {
    APP_ERR("hawkbit configure error: invalid configuration URL");
    return -1;
  }

  APP_DBG("hawkbit configure at href(%s)", url);
  cJSON *root = cJSON_CreateObject();

  // mode
  cJSON_AddItemToObject(root, "mode", cJSON_CreateString("replace"));

  // data
  cJSON *jdata = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "data", jdata);
  for (size_t i = 0; i < data_size; ++i) {
    cJSON_AddItemToObject(jdata, data[i].key,
                          cJSON_CreateString(data[i].value));
  }

  cJSON *status = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "status", status);
  // status.execution
  cJSON_AddItemToObject(status, "execution", cJSON_CreateString("closed"));
  cJSON *status_result = cJSON_CreateObject();
  // status.result
  cJSON_AddItemToObject(status, "result", status_result);
  // status.result.finished
  cJSON_AddItemToObject(status_result, "finished",
                        cJSON_CreateString("success"));

  char *body = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (body == NULL) {
    APP_ERR("hawkbit configure error: cannot render JSON object");
    return false;
  }

  char output[HAWKBIT_HTTP_MAX_OUTPUT_BUFFER] = { 0 };
  int code = hawkbit_http_perform_put(url, body, output, sizeof(output));
  free(body);
  if (code < 0 || code != HAWKBIT_HTTP_CODE_OK) {
    APP_ERR("hawkbit configure error: unexpected HTTP code(%d)", code);
    return false;
  }
  return true;
}

static esp_http_client_config_t
hawkbit_download_get_client_config(hawkbit_download_links_t links)
{
  if (oc_string(links.download) != NULL) {
    // TODO
  }
  if (oc_string(links.downloadHttp) != NULL) {
    esp_http_client_config_t config = {};
    config.url = oc_string(links.downloadHttp);
    config.cert_pem = (char *)"";
    config.skip_cert_common_name_check = true;
    return config;
  }
  esp_http_client_config_t config = {};
  return config;
}

bool
hawkbit_download_from_links(hawkbit_download_links_t links)
{
  if (oc_string(links.download) == NULL &&
      oc_string(links.downloadHttp) == NULL) {
    return false;
  }
  esp_http_client_config_t config = hawkbit_download_get_client_config(links);
  esp_https_ota_config_t ota_config = {
    .http_config = &config,
    .partial_http_download = false,
  };
  esp_https_ota_handle_t https_ota_handle = NULL;
  esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
  if (err != ESP_OK) {
    APP_ERR("OTA update begin failed: %s", esp_err_to_name(err));
    return false;
  }

  while (true) {
    err = esp_https_ota_perform(https_ota_handle);
    if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
      break;
    }
  }

  if (err != ESP_OK) {
    APP_ERR("OTA update perform failed: %s", esp_err_to_name(err));
    err = esp_https_ota_abort(https_ota_handle);
    if (err != ESP_OK) {
      APP_ERR("OTA abort failed: %s", esp_err_to_name(err));
    }
    return false;
  }

  err = esp_https_ota_finish(https_ota_handle);
  if (err != ESP_OK) {
    APP_ERR("OTA update finish failed: %s", esp_err_to_name(err));
    return false;
  }
  return true;
}

static void
hawkbit_send_deploy_feedback_and_log_error(
  const hawkbit_context_t *ctx, const char *id,
  hawkbit_feedback_execution_t execution, hawkbit_feedback_result_t result)
{
  if (!hawkbit_send_deploy_feedback(ctx, id, execution, result)) {
    APP_ERR("hawkbit error: failed to send deploy feedback");
  }
}

static bool
hawkbit_prepare_async_update(hawkbit_context_t *ctx, const char *deployment_id,
                             const char *version,
                             hawkbit_sha256_digest_t digest)
{
  const esp_partition_t *update = esp_ota_get_boot_partition();
  if (update == NULL) {
    APP_ERR("hawkbit deploy error: updated boot partition invalid");
    if (esp_ota_set_boot_partition(esp_ota_get_running_partition()) != 0) {
      APP_ERR("hawkbit deploy error: failed to restore boot partition");
    }
    return false;
  }

  uint8_t psha256[ESP_IMAGE_HASH_LEN] = {};
  esp_err_t err = esp_partition_get_sha256(update, psha256);
  if (err != ESP_OK) {
    APP_ERR("hawkbit deploy error: cannot get sha256 hash of partition(%s)",
            esp_err_to_name(err));
    return false;
  }

  err = esp_ota_set_boot_partition(esp_ota_get_running_partition());
  if (err != ESP_OK) {
    APP_ERR("hawkbit deploy error: set original boot partition failed with "
            "error(%s)",
            esp_err_to_name(err));
    return false;
  }

  hawkbit_set_update(ctx, deployment_id, version, digest.data, sizeof(digest),
                     psha256, sizeof(psha256));
  long ret = hawkbit_store_save(ctx);
  if (ret < 0) {
    APP_ERR(
      "failed to store hawkbit resource of device(%zu) to storage, error(%d)",
      hawkbit_get_device(ctx), (int)ret);
  }
  return true;
}

static bool
hawkbit_download_execute(hawkbit_context_t *ctx)
{
  const hawkbit_download_t *download = hawkbit_get_download(ctx);
  if (download == NULL) {
    APP_ERR("hawkbit download error: download not set");
    return false;
  }
  hawkbit_send_deploy_feedback_and_log_error(
    ctx, hawkbit_download_get_deployment_id(download),
    HAWKBIT_FEEDBACK_EXECUTION_PROCEEDING, HAWKBIT_FEEDBACK_RESULT_NONE);

  if (!hawkbit_download_from_links(hawkbit_download_get_links(download))) {
    APP_ERR("hawkbit download error: failed to download the update");
    hawkbit_send_deploy_feedback_and_log_error(
      ctx, hawkbit_download_get_deployment_id(download),
      HAWKBIT_FEEDBACK_EXECUTION_CLOSED, HAWKBIT_FEEDBACK_RESULT_FAILURE);
    return false;
  }
  if (!hawkbit_prepare_async_update(
        ctx, hawkbit_download_get_deployment_id(download),
        hawkbit_download_get_version(download),
        hawkbit_download_get_hash(download))) {
    hawkbit_send_deploy_feedback_and_log_error(
      ctx, hawkbit_download_get_deployment_id(download),
      HAWKBIT_FEEDBACK_EXECUTION_CLOSED, HAWKBIT_FEEDBACK_RESULT_FAILURE);
    return false;
  }
  return true;
}

static oc_event_callback_retval_t
hawkbit_download_async(void *data)
{
  hawkbit_context_t *ctx = (hawkbit_context_t *)data;
  bool success = hawkbit_download_execute(ctx);
  hawkbit_on_download_done_cb_t on_done = hawkbit_get_on_download_done_cb(ctx);
  if (on_done != NULL) {
    on_done(ctx, success);
  }
  return OC_EVENT_DONE;
}

void
hawkbit_download(hawkbit_context_t *ctx,
                 hawkbit_on_download_done_cb_t download_action)
{
  hawkbit_set_on_download_done_cb(ctx, download_action);
  oc_remove_delayed_callback(ctx, hawkbit_download_async);
  oc_set_delayed_callback(ctx, hawkbit_download_async, 0);
}

static const esp_partition_t *
hawkbit_find_update_partition(const hawkbit_async_update_t *update)
{
  const esp_partition_t *running = esp_ota_get_running_partition();
  if (running == NULL) {
    return NULL;
  }

  esp_partition_iterator_t it =
    esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
  for (; it != NULL; it = esp_partition_next(it)) {
    const esp_partition_t *p = esp_partition_get(it);
    if (p == running) {
      continue;
    }
    APP_DBG("checking partition %s", p->label);
    esp_partition_pos_t pos = {
      .offset = p->address,
      .size = p->size,
    };
    esp_image_metadata_t md;
    if (ESP_OK != esp_image_verify(ESP_IMAGE_VERIFY, &pos, &md)) {
      continue;
    }
    uint8_t sha256[ESP_IMAGE_HASH_LEN] = {};
    if (ESP_OK == esp_partition_get_sha256(p, sha256) &&
        memcmp(sha256, update->partition_sha256, sizeof(sha256)) == 0) {
      APP_DBG("matching checking partition %s found", p->label);
      esp_partition_iterator_release(it);
      return p;
    }
  }
  esp_partition_iterator_release(it);
  return NULL;
}

bool
hawkbit_update(hawkbit_context_t *ctx)
{
  const hawkbit_async_update_t *update = hawkbit_get_update(ctx);
  if (update == NULL) {
    return false;
  }

  // find partition with matching hash
  const esp_partition_t *update_partition =
    hawkbit_find_update_partition(update);
  if (update_partition == NULL) {
    APP_ERR("partition with stored update not found");
    hawkbit_send_deploy_feedback_and_log_error(
      ctx, oc_string(update->deployment_id), HAWKBIT_FEEDBACK_EXECUTION_CLOSED,
      HAWKBIT_FEEDBACK_RESULT_FAILURE);
    hawkbit_clear_update(ctx);
    return false;
  }
  if (esp_ota_set_boot_partition(update_partition) != ESP_OK) {
    APP_ERR("hawkbit update error: failed to set boot partition");
    return false;
  }
  hawkbit_send_deploy_feedback_and_log_error(
    ctx, oc_string(update->deployment_id), HAWKBIT_FEEDBACK_EXECUTION_CLOSED,
    HAWKBIT_FEEDBACK_RESULT_SUCCESS);
  return true;
}

void
hawkbit_restart_device(hawkbit_context_t *ctx)
{
  APP_DBG("saving modified resources");
  size_t device = hawkbit_get_device(ctx);
#ifdef OC_SECURITY
  oc_sec_dump_pstat(device);
#endif /* OC_SECURITY */
  long ret = oc_swupdate_dump(device);
  if (ret < 0) {
    APP_ERR("failed to store software update resource of device(%d) to "
            "storage, error(%d)",
            device, (int)ret);
  }
  ret = hawkbit_store_save(ctx);
  if (ret < 0) {
    APP_ERR(
      "failed to store hawkbit resource of device(%zu) to storage, error(%d)",
      device, (int)ret);
  }
  APP_DBG("device restarting");
  esp_restart();
}

#ifdef APP_DEBUG
static void
print_sha256(const char *label, const uint8_t *sha256)
{
  char hash_print[ESP_IMAGE_HASH_LEN * 2 + 1];
  for (int i = 0; i < ESP_IMAGE_HASH_LEN; ++i) {
    sprintf(&hash_print[i * 2], "%02x", sha256[i]);
  }
  hash_print[ESP_IMAGE_HASH_LEN * 2] = '\0';
  APP_DBG("%s: %s", label, hash_print);
}
#endif /* APP_DEBUG  */

static void
print_partitions_info(void)
{
#ifdef APP_DEBUG
  const esp_partition_t *cur = esp_ota_get_running_partition();
  assert(cur != NULL);
  APP_DBG("running partition(%p) %s", cur, cur->label);

  const esp_partition_t *boot = esp_ota_get_boot_partition();
  assert(boot != NULL);
  APP_DBG("boot partition(%p) %s", boot, boot->label);

  APP_DBG("application partitions:");
  esp_partition_iterator_t it =
    esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
  for (; it != NULL; it = esp_partition_next(it)) {
    const esp_partition_t *p = esp_partition_get(it);
    APP_DBG("\tpartition(%p) %s", p, p->label);
    APP_DBG("\t\taddress %lu", p->address);
    APP_DBG("\t\tsize %lu", p->size);
    APP_DBG("\t\tencrypted %s", p->encrypted ? "true" : "false");

    esp_ota_img_states_t state;
    esp_err_t err = esp_ota_get_state_partition(p, &state);
    if (err == ESP_OK) {
      APP_DBG("\t\tstate: %d", (int)state);
    } else {
      APP_DBG("\t\tcannot get state: %s(%d)", esp_err_to_name(err), (int)err);
    }
    esp_app_desc_t desc = {};
    err = esp_ota_get_partition_description(p, &desc);
    if (ESP_OK == err) {
      APP_DBG("\t\tversion: %s", desc.version);
      APP_DBG("\t\tproject_name: %s", desc.project_name);
      APP_DBG("\t\ttime: %s", desc.time);
      APP_DBG("\t\tdate: %s", desc.date);
      APP_DBG("\t\tidf_ver: %s", desc.idf_ver);
      print_sha256("\t\tsha256", desc.app_elf_sha256);
    } else {
      APP_DBG("\t\tcannot get description: %s(%d)", esp_err_to_name(err),
              (int)err);
    }

    uint8_t sha256[ESP_IMAGE_HASH_LEN] = {};
    err = esp_partition_get_sha256(p, sha256);
    if (ESP_OK == err) {
      print_sha256("\t\tsha256", sha256);
    } else {
      APP_DBG("\t\tcannot get sha256: %s(%d)", esp_err_to_name(err), (int)err);
    }

    const esp_partition_pos_t pos = {
      .offset = p->address,
      .size = p->size,
    };
    esp_image_metadata_t md;
    err = esp_image_verify(ESP_IMAGE_VERIFY, &pos, &md);
    if (ESP_OK == err) {
      APP_DBG("\t\timage start_addr: %lu", md.start_addr);
      APP_DBG("\t\timage len: %lu", md.image_len);
      APP_DBG("\t\thash_appended: %d", (int)md.image.hash_appended);
    } else {
      APP_DBG("\t\timage verification failed: %s(%d)", esp_err_to_name(err),
              (int)err);
    }
  }
  esp_partition_iterator_release(it);
#endif // APP_DEBUG
}

hawkbit_error_t
hawkbit_poll(hawkbit_context_t *ctx, hawkbit_configuration_t *cfg)
{
  APP_DBG("Hawkbit poll");
  print_partitions_info();

  hawkbit_action_t action;
  hawkbit_error_t err = hawkbit_poll_base_resource(ctx, &action, cfg);
  if (err != HAWKBIT_OK) {
    return err;
  }

  APP_DBG("hawkbit action: %s(%d)", hawkbit_action_type_to_string(action.type),
          action.type);
  if (action.type == HAWKBIT_ACTION_CONFIGURE) {
    if (!hawkbit_configure(ctx, oc_string(action.data.configure.url))) {
      APP_ERR("cannot configure device in hawkbit server");
      hawkbit_action_free(&action);
      return HAWKBIT_ERROR_GENERAL;
    }
    hawkbit_action_free(&action);
    if (!hawkbit_poll_base_resource(ctx, &action, NULL)) {
      APP_ERR("cannot poll configured hawkbit resource");
      return HAWKBIT_ERROR_GENERAL;
    }
    if (action.type ==
        HAWKBIT_ACTION_CONFIGURE) { // this shouldn't happen, since it was
                                    // configured above
      APP_ERR("hawkbit server error: internal error");
      return HAWKBIT_ERROR_GENERAL;
    }
  }

  hawkbit_on_polling_action_cb_t action_cb = hawkbit_get_polling_action_cb(ctx);
  if (action_cb != NULL) {
    action_cb(ctx, &action);
  }
  hawkbit_action_free(&action);
  return HAWKBIT_OK;
}
