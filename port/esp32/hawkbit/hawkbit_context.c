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
#include "hawkbit.h"
#include "hawkbit_context.h"
#include "hawkbit_download.h"
#include "hawkbit_internal.h"
#include "hawkbit_update.h"

#include "api/oc_rep_internal.h"
#include "api/oc_swupdate_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_esp.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "port/oc_storage.h"
#include "util/oc_compiler.h"
#include "util/oc_memb.h"

#include <assert.h>
#include <esp_image_format.h>

#ifndef OC_SOFTWARE_UPDATE
#error Preprocessor macro PLGD_HAWKBIT is defined but OC_SOFTWARE_UPDATE is not defined.
#endif

typedef struct
{
  hawkbit_async_update_t update;
} hawkbit_store_t;

typedef struct hawkbit_context_t
{
  size_t device;
  oc_string_t version;
  struct
  {
    bool started;
    uint64_t interval;
    hawkbit_on_polling_action_cb_t action;
  } polling;
  bool execute_all_steps;
  hawkbit_download_t *download;
  hawkbit_on_download_done_cb_t downloadDoneAction;
  hawkbit_store_t store;
} hawkbit_context_t;

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static hawkbit_context_t *g_hawkbit;
#else  /* OC_DYNAMIC_ALLOCATION */
static hawkbit_context_t g_hawkbit[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

#define HAWKBIT_DEFAULT_POLLING_INTERVAL 60
#define HAWKBIT_SVR_TAG_MAX (32)
#define HAWKBIT_STORE_NAME "hb"

static void
hawkbit_store_deinit(hawkbit_store_t *store)
{
  hawkbit_update_free(&store->update);
}

static void
hawkbit_store_init(hawkbit_store_t *store)
{
  hawkbit_store_deinit(store);
}

int
hawkbit_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_hawkbit = (hawkbit_context_t *)calloc(oc_core_get_num_devices(),
                                          sizeof(hawkbit_context_t));
  if (g_hawkbit == NULL) {
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  const char *version = oc_esp_get_application_version();
  size_t version_len = strlen(version);
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    g_hawkbit[i].device = i;
    g_hawkbit[i].polling.interval = HAWKBIT_DEFAULT_POLLING_INTERVAL;
    long ret = hawkbit_store_load(&g_hawkbit[i]);
    if (ret < 0) {
      APP_DBG("failed to load hawkbit resource for device(%zu) from storage, "
              "error(%d)",
              i, (int)ret);
      hawkbit_store_init(&g_hawkbit[i].store);
    }
    oc_esp_mac_address_t mac;
    if (!oc_esp_get_mac_address(&mac)) {
      hawkbit_free();
      return -1;
    }

    oc_new_string(&g_hawkbit[i].version, version, version_len);
    APP_DBG("hawkbit device: %zu, version: %s", g_hawkbit[i].device,
            oc_string(g_hawkbit[i].version));
    hawkbit_start(&g_hawkbit[i]);
  }
  return 0;
}

static void
hawkbit_encode_server(const hawkbit_context_t *ctx)
{
  char server_url[256] = { '\0' };
  char tenant[128] = { '\0' };
  char controller_id[128] = { '\0' };
  if (hawkbit_get_url(ctx, server_url, sizeof(server_url), tenant,
                      sizeof(tenant), controller_id,
                      sizeof(controller_id)) == HAWKBIT_OK) {
    oc_rep_open_object(root, server);
    oc_rep_set_text_string(server, url, server_url);
    oc_rep_set_text_string(server, tenant, tenant);
    oc_rep_set_text_string(server, controller_id, controller_id);
    oc_rep_close_object(root, server);
  }
}

static void
hawkbit_encode_polling(const hawkbit_context_t *ctx)
{
  oc_rep_open_object(root, polling);
  oc_rep_set_int(polling, interval, ctx->polling.interval);
  oc_rep_set_boolean(polling, started, (int64_t)ctx->polling.started);
  oc_rep_close_object(root, polling);
}

static void
hawkbit_encode_download(const hawkbit_download_t *download)
{
  oc_rep_open_object(root, download);
  oc_rep_set_text_string(download, deployment_id,
                         hawkbit_download_get_deployment_id(download));
  oc_rep_set_text_string(download, version,
                         hawkbit_download_get_version(download));
  oc_rep_set_text_string(download, name, hawkbit_download_get_name(download));
  oc_rep_set_text_string(download, filename,
                         hawkbit_download_get_filename(download));
  oc_rep_set_int(download, size, (int64_t)hawkbit_download_get_size(download));
  hawkbit_sha256_hash_t sha256 =
    hawkbit_sha256_digest_to_hash(hawkbit_download_get_hash(download));
  oc_rep_set_text_string(download, sha256, sha256.data);

  hawkbit_download_links_t links = hawkbit_download_get_links(download);
  if (oc_string(links.download) != NULL) {
    oc_rep_set_text_string(download, linkHTTPS, oc_string(links.download));
  }
  if (oc_string(links.downloadHttp) != NULL) {
    oc_rep_set_text_string(download, linkHTTP, oc_string(links.downloadHttp));
  }
  oc_rep_close_object(root, download);
}

void
hawkbit_encode(const hawkbit_context_t *ctx, oc_resource_t *resource,
               oc_interface_mask_t interface, bool to_storage)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
    OC_FALLTHROUGH;
  case OC_IF_R: {
    if (oc_string(ctx->store.update.deployment_id) != NULL &&
        oc_string(ctx->store.update.version) != NULL) {
      oc_rep_set_text_string(root, u_id,
                             oc_string(ctx->store.update.deployment_id));
      oc_rep_set_text_string(root, u_version,
                             oc_string(ctx->store.update.version));

      uint8_t empty[ESP_IMAGE_HASH_LEN] = { 0 };
      if (memcmp(ctx->store.update.sha256, empty, sizeof(empty)) != 0) {
        oc_rep_set_byte_string(root, u_sha256, ctx->store.update.sha256,
                               sizeof(ctx->store.update.sha256));
      }
      if (memcmp(ctx->store.update.partition_sha256, empty, sizeof(empty)) !=
          0) {
        oc_rep_set_byte_string(root, u_psha256,
                               ctx->store.update.partition_sha256,
                               sizeof(ctx->store.update.partition_sha256));
      }
    }
    if (!to_storage) {
      hawkbit_encode_server(ctx);
      hawkbit_encode_polling(ctx);
      if (ctx->download != NULL) {
        hawkbit_encode_download(ctx->download);
      }
    }
  } break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

bool
hawkbit_decode(hawkbit_context_t *ctx, const oc_rep_t *rep, bool from_storage)
{
  const oc_string_t *deployment_id = NULL;
  const oc_string_t *newVersion = NULL;
  const oc_string_t *newVersionSha256 = NULL;
  const oc_string_t *newVersionPartitionSha256 = NULL;
  for (; rep != NULL; rep = rep->next) {
    if (from_storage) {
      if (oc_rep_is_property(rep, "u_id", sizeof("u_id") - 1)) {
        deployment_id = &rep->value.string;
        continue;
      }

      if (oc_rep_is_property(rep, "u_version", sizeof("u_version") - 1)) {
        newVersion = &rep->value.string;
        continue;
      }

      if (oc_rep_is_property(rep, "u_sha256", sizeof("u_sha256") - 1)) {
        if (oc_string_len(rep->value.string) != ESP_IMAGE_HASH_LEN) {
          APP_ERR("invalid sha256 hash of update file: invalid length(%zu)",
                  oc_string_len(rep->value.string));
          return false;
        }
        newVersionSha256 = &rep->value.string;
        continue;
      }
      if (oc_rep_is_property(rep, "u_psha256", sizeof("u_psha256") - 1)) {
        if (oc_string_len(rep->value.string) != ESP_IMAGE_HASH_LEN) {
          APP_ERR("invalid sha256 hash of partition: invalid length(%zu)",
                  oc_string_len(rep->value.string));
          return false;
        }
        newVersionPartitionSha256 = &rep->value.string;
        continue;
      }
    }
    APP_ERR("cannot modify property %s", oc_string(rep->name));
    return false;
  }

  if (deployment_id != NULL && newVersion != NULL &&
      newVersionPartitionSha256 != NULL && newVersionSha256 != NULL) {
    hawkbit_set_update(ctx, oc_string(*deployment_id), oc_string(*newVersion),
                       oc_cast(*newVersionSha256, const uint8_t),
                       oc_string_len(*newVersionSha256),
                       oc_cast(*newVersionPartitionSha256, const uint8_t),
                       oc_string_len(*newVersionPartitionSha256));
  }
  return true;
}

static bool
hawkbit_gen_svr_tag(const char *name, size_t device, char *buffer,
                    size_t buffer_size)
{
  int svr_tag_len = snprintf(buffer, buffer_size, "%s_%zd", name, device);
  if (svr_tag_len < 0) {
    return false;
  }
  svr_tag_len =
    (svr_tag_len < buffer_size - 1) ? svr_tag_len + 1 : buffer_size - 1;
  buffer[svr_tag_len] = '\0';
  return true;
}

long
hawkbit_store_load(hawkbit_context_t *ctx)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (buf == NULL) {
    APP_ERR("cannot allocate storage buffer");
    return -1;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */

  char svr_tag[HAWKBIT_SVR_TAG_MAX];
  if (!hawkbit_gen_svr_tag(HAWKBIT_STORE_NAME, ctx->device, svr_tag,
                           sizeof(svr_tag))) {
    APP_ERR("cannot generate storage tag");
    return -1;
  }

  long ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret <= 0) {
    goto finish;
  }

  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  if (oc_parse_rep(buf, (size_t)ret, &rep) != 0) {
    APP_ERR("cannot parse representation");
    oc_rep_set_pool(prev_rep_objects);
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
    return -1;
  }
  if (!hawkbit_decode(ctx, rep, true)) {
    ret = -1;
  }
  oc_free_rep(rep);
  oc_rep_set_pool(prev_rep_objects);

finish:
#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

long
hawkbit_store_save(const hawkbit_context_t *ctx)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (buf == NULL) {
    return -1;
  }
  oc_rep_new_realloc(&buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MIN_APP_DATA_SIZE];
  oc_rep_new(buf, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */

  hawkbit_encode(ctx, NULL, OC_IF_R, true);
#ifdef OC_DYNAMIC_ALLOCATION
  buf = oc_rep_shrink_encoder_buf(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  int size = oc_rep_get_encoded_payload_size();
  long ret = 0;
  if (size > 0) {
    APP_DBG("encoded hawkbit store size: %d", size);
    char svr_tag[HAWKBIT_SVR_TAG_MAX];
    hawkbit_gen_svr_tag(HAWKBIT_STORE_NAME, ctx->device, svr_tag,
                        sizeof(svr_tag));
    ret = oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

static oc_event_callback_retval_t
hawkbit_poll_async(void *data)
{
  hawkbit_context_t *ctx = (hawkbit_context_t *)data;
  return hawkbit_poll_and_reschedule(ctx, /*forceReschedule*/ false)
           ? OC_EVENT_DONE
           : OC_EVENT_CONTINUE;
}

bool
hawkbit_poll_and_reschedule(hawkbit_context_t *ctx, bool forceReschedule)
{
  hawkbit_configuration_t cfg = { .pollingInterval = 0 };
  hawkbit_error_t err = hawkbit_poll(ctx, &cfg);
  if (err != HAWKBIT_OK) {
    APP_ERR("polling of hawkbit server failed with error(%d)", (int)err);
  }
  bool reschedule = forceReschedule;
  if ((cfg.pollingInterval > 0) &&
      (ctx->polling.interval != cfg.pollingInterval)) {
    APP_DBG("hawkbit polling interval: %llu sec", cfg.pollingInterval);
    ctx->polling.interval = cfg.pollingInterval;
    reschedule = true;
  }
  if (reschedule) {
    oc_remove_delayed_callback(ctx, hawkbit_poll_async);
    oc_ri_add_timed_event_callback_seconds(ctx, hawkbit_poll_async,
                                           ctx->polling.interval);
  }
  return false;
}

void
hawkbit_start_polling(hawkbit_context_t *ctx,
                      hawkbit_on_polling_action_cb_t on_action)
{
  if (ctx->polling.started) {
    return;
  }
  oc_remove_delayed_callback(ctx, hawkbit_poll_async);
  APP_DBG("hawkbit polling started");
  ctx->polling.started = true;
  ctx->polling.action = on_action;
  hawkbit_poll_and_reschedule(ctx, /*forceReschedule*/ true);
}

void
hawkbit_stop_polling(hawkbit_context_t *ctx)
{
  APP_DBG("hawkbit polling stopped");
  ctx->polling.started = false;
  oc_remove_delayed_callback(ctx, hawkbit_poll_async);
}

void
hawkbit_free()
{
  for (size_t i = 0; i < oc_core_get_num_devices(); i++) {
    hawkbit_context_t *hc = &g_hawkbit[i];
    hawkbit_stop_polling(hc);
    long ret = hawkbit_store_save(hc);
    if (ret < 0) {
      APP_ERR(
        "failed to store hawkbit resource of device(%zu) to storage, error(%d)",
        hc->device, (int)ret);
    }
    oc_free_string(&hc->version);
    hawkbit_download_free(hc->download);
    hawkbit_store_deinit(&hc->store);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (g_hawkbit != NULL) {
    free(g_hawkbit);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

hawkbit_context_t *
hawkbit_get_context(size_t device)
{
  assert(device <= oc_core_get_num_devices());
  return &g_hawkbit[device];
}

size_t
hawkbit_get_device(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->device;
}

const char *
hawkbit_get_package_url(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return oc_string(oc_swupdate_get(ctx->device)->purl);
}

void
hawkbit_set_version(hawkbit_context_t *ctx, const char *version, size_t length)
{
  assert(ctx != NULL);
  oc_set_string(&ctx->version, version, length);
}

const char *
hawkbit_get_version(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return oc_string(ctx->version);
}

void
hawkbit_set_polling_interval(hawkbit_context_t *ctx, uint64_t pollingInterval)
{
  assert(ctx != NULL);
  assert(pollingInterval > 0);
  ctx->polling.interval = pollingInterval;
};

hawkbit_on_polling_action_cb_t
hawkbit_get_polling_action_cb(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->polling.action;
}

void
hawkbit_set_download(hawkbit_context_t *ctx, hawkbit_deployment_t deployment)
{
  assert(ctx != NULL);
  if (ctx->download == NULL) {
    ctx->download = hawkbit_download_alloc();
  }
  hawkbit_download_set_from_deployment(ctx->download, &deployment);
}

const hawkbit_download_t *
hawkbit_get_download(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->download;
}

void
hawkbit_clear_download(hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  hawkbit_download_free(ctx->download);
  ctx->download = NULL;
}

void
hawkbit_set_on_download_done_cb(
  hawkbit_context_t *ctx, hawkbit_on_download_done_cb_t on_download_done_cb)
{
  assert(ctx != NULL);
  ctx->downloadDoneAction = on_download_done_cb;
}

hawkbit_on_download_done_cb_t
hawkbit_get_on_download_done_cb(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->downloadDoneAction;
}

void
hawkbit_set_update(hawkbit_context_t *ctx, const char *deployment_id,
                   const char *version, const uint8_t *sha256,
                   size_t sha256_size, const uint8_t *partition_sha256,
                   size_t partition_sha256_size)
{
  assert(ctx != NULL);
  hawkbit_update_free(&ctx->store.update);
  ctx->store.update =
    hawkbit_update_create(deployment_id, version, sha256, sha256_size,
                          partition_sha256, partition_sha256_size);
}

const hawkbit_async_update_t *
hawkbit_get_update(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  if (oc_string(ctx->store.update.version) == NULL) {
    return NULL;
  }
  return &ctx->store.update;
}

void
hawkbit_clear_update(hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  hawkbit_update_free(&ctx->store.update);
}

void
hawkbit_set_execute_all_steps(hawkbit_context_t *ctx, bool execute_all_steps)
{
  assert(ctx != NULL);
  ctx->execute_all_steps = execute_all_steps;
}

bool
hawkbit_execute_all_steps(const hawkbit_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->execute_all_steps;
}
