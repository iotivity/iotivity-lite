/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_resource_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_store_internal.h" // dps_store_init
#include "plgd_dps_verify_certificate_internal.h"

#include "api/oc_tcp_internal.h"
#include "oc_certs.h"
#include "oc_core_res.h"

#ifdef OC_NETWORK_MONITOR
#include "oc_network_monitor.h"
#endif /* OC_NETWORK_MONITOR */

#include <assert.h>
#include <inttypes.h>

static void
dps_manager_status_cb(plgd_dps_context_t *ctx)
{
  DPS_DBG("manager status changed %d", (int)ctx->status);
  if (ctx->callbacks.on_status_change != NULL) {
    ctx->callbacks.on_status_change(ctx, ctx->status,
                                    ctx->callbacks.on_status_change_data);
  }
}

oc_event_callback_retval_t
dps_status_callback_handler(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  dps_manager_status_cb(ctx);
  return OC_EVENT_DONE;
}

#ifdef OC_SESSION_EVENTS

static void
dps_manager_restart(plgd_dps_context_t *ctx)
{
  dps_manager_stop(ctx);
  dps_reset_delayed_callback(ctx, dps_manager_start_async, 0);
}

static void
dps_handle_endpoint_event(plgd_dps_context_t *ctx,
                          const oc_endpoint_t *endpoint,
                          oc_session_state_t state)
{
#if DPS_DBG_IS_ENABLED
// GCOVR_EXCL_START
#define ENDPOINT_STR_LEN 256
  char ep_str[ENDPOINT_STR_LEN] = { 0 };
#undef ENDPOINT_STR_LEN
  dps_endpoint_log_string(endpoint, ep_str, sizeof(ep_str));
// GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
  DPS_DBG("dps_ep_session_event_handler for %s, ep_state: %d", ep_str,
          (int)state);
  if (!ctx->manager_started) {
    DPS_DBG("manager not started yet");
    return;
  }
  if (state == OC_SESSION_CONNECTED && ctx->endpoint->session_id == 0 &&
      (ctx->endpoint->flags & TCP) != 0) {
    ctx->endpoint->session_id = endpoint->session_id;
    DPS_DBG("%s session_id set", ep_str);
  }
  bool changed = ctx->endpoint_state != state;
  if (!changed) {
    DPS_DBG("%s state hasn't changed", ep_str);
    return;
  }
  ctx->endpoint_state = state;
  if (state == OC_SESSION_CONNECTED) {
    DPS_DBG("%s connected", ep_str);
    return;
  }
  if (state == OC_SESSION_DISCONNECTED) {
    DPS_DBG("%s disconnected", ep_str);
    if (ctx->closing_insecure_peer) {
      DPS_DBG("insecure TLS session closed");
      ctx->closing_insecure_peer = false;
      if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) == 0) {
        // keep the endpoint, we only need a new secure session -> set
        // new session_id
        ctx->endpoint->session_id = oc_tcp_get_new_session_id();
        DPS_DBG("continuing provisioning with new session_id=%" PRIu32,
                ctx->endpoint->session_id);
        dps_provisioning_schedule_next_step(ctx);
        return;
      }
      // an error occurred -> clean up the endpoint, retry will reinitialize it
      DPS_DBG("retry provisioning");
      memset(ctx->endpoint, 0, sizeof(oc_endpoint_t));
      dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                    dps_retry_get_delay(&ctx->retry));
      return;
    }
    if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) == 0 &&
        !dps_is_provisioned_with_cloud_started(ctx)) {
      dps_manager_restart(ctx);
    }
    return;
  }
}

static void
dps_ep_session_event_handler(const oc_endpoint_t *endpoint,
                             oc_session_state_t state, void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  if (oc_endpoint_compare(endpoint, ctx->endpoint) == 0) {
    dps_handle_endpoint_event(ctx, endpoint, state);
    return;
  }

  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if ((cloud_ctx != NULL) &&
      oc_endpoint_compare(endpoint, oc_cloud_get_server(cloud_ctx)) == 0) {
    DPS_DBG("dps_ep_session_event_handler cloud_state: %d", (int)state);
    if (state == OC_SESSION_DISCONNECTED &&
        oc_cloud_manager_is_started(cloud_ctx)) {
      dps_cloud_observe_status(ctx);
    }
    return;
  }
}

static bool
dps_restart_initialized(plgd_dps_context_t *ctx, void *data)
{
  (void)data;
  if (ctx->status == PLGD_DPS_INITIALIZED) {
    dps_manager_restart(ctx);
  }
  return true;
}

static void
dps_interface_event_handler(oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP) {
    dps_contexts_iterate(dps_restart_initialized, NULL);
  }
}

#endif /* OC_SESSION_EVENTS */

int
plgd_dps_init(void)
{
  dps_update_list_init();
  for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
    plgd_dps_context_t *ctx = dps_context_alloc();
    if (ctx == NULL) {
      DPS_ERR("insufficient memory to create context");
      return -1;
    }
    dps_context_init(ctx, device);
    if (dps_store_load(&ctx->store, device) == 0) {
      DPS_INFO("DPS data loaded from storage");
    }
    dps_context_list_add(ctx);
  }
  return 0;
}

void
plgd_dps_shutdown(void)
{
  for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
    plgd_dps_context_t *ctx = plgd_dps_get_context(device);
    if (ctx == NULL) {
      continue;
    }
#ifdef OC_SESSION_EVENTS
    oc_remove_session_event_callback_v1(dps_ep_session_event_handler, ctx,
                                        false);
#endif /* OC_SESSION_EVENTS */
    dps_manager_stop(ctx);
    oc_delayed_delete_resource(ctx->conf);
    dps_endpoint_close(ctx->endpoint);
    dps_context_deinit(ctx);
    dps_context_list_remove(ctx);
    dps_context_free(ctx);
    dps_update_list_cleanup();
    DPS_DBG("dps_shutdown for %zu", device);
  }
}

#ifdef OC_SESSION_EVENTS

void
plgd_dps_session_callbacks_init(plgd_dps_context_t *ctx)
{
  oc_add_session_event_callback_v1(dps_ep_session_event_handler, ctx);
}

void
plgd_dps_session_callbacks_deinit(plgd_dps_context_t *ctx)
{
  oc_remove_session_event_callback_v1(dps_ep_session_event_handler, ctx, false);
}

void
plgd_dps_interface_callbacks_init(void)
{
#ifdef OC_NETWORK_MONITOR
  oc_add_network_interface_event_callback(dps_interface_event_handler);
#endif /* OC_NETWORK_MONITOR */
}

void
plgd_dps_interface_callbacks_deinit(void)
{
#ifdef OC_NETWORK_MONITOR
  oc_remove_network_interface_event_callback(dps_interface_event_handler);
#endif /* OC_NETWORK_MONITOR */
}

#endif /* OC_SESSION_EVENTS */

bool
dps_try_set_identity_chain(size_t device)
{
  int dps_id_credid = dps_get_identity_credid(device);
  if (dps_id_credid == -1) {
    DPS_DBG("identity certificate not found");
    return false;
  }
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(device);
  if (cloud_ctx == NULL) {
    return false;
  }
  if (oc_cloud_get_identity_cert_chain(cloud_ctx) == dps_id_credid) {
    // cloud has same cert chain as before.
    return true;
  }
  oc_cloud_set_identity_cert_chain(cloud_ctx, dps_id_credid);
  DPS_DBG("certificate chain updated to credid=%d", dps_id_credid);
  return true;
}

bool
plgd_cloud_manager_start(const plgd_dps_context_t *ctx)
{
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("Cloud context not found");
    return false;
  }
#if DPS_INFO_IS_ENABLED
  // GCOVR_EXCL_START
  const oc_string_t *ep_str = oc_cloud_get_server_uri(cloud_ctx);
  const char *ep_cstr = ep_str != NULL ? oc_string(*ep_str) : "NULL";
  DPS_INFO("Starting cloud registration with endpoint(%s)",
           ep_cstr != NULL ? ep_cstr : "NULL");
  // GCOVR_EXCL_STOP
#endif /* DPS_INFO_IS_ENABLED */
  return oc_cloud_manager_start(
           cloud_ctx, ctx->callbacks.on_cloud_status_change,
           ctx->callbacks.on_cloud_status_change_data) == 0;
}

static bool
dps_set_certificate_fingerprint(plgd_dps_context_t *ctx,
                                mbedtls_md_type_t md_type,
                                const uint8_t *fingerprint, size_t size)
{
  assert(ctx != NULL);
  if (md_type != MBEDTLS_MD_NONE) {
    if (!oc_sec_certs_md_algorithm_is_allowed(md_type)) {
      DPS_ERR("DPS Service certificate fingerprint algorithm not allowed");
      return false;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
      DPS_ERR("DPS Service certificate fingerprint algorithm not found");
      return false;
    }
    if (mbedtls_md_get_size(md_info) != size) {
      DPS_ERR("DPS Service certificate fingerprint size mismatch");
      return false;
    }
  }
  if (ctx->certificate_fingerprint.md_type == md_type &&
      dps_is_equal_string_len(ctx->certificate_fingerprint.data,
                              (const char *)fingerprint, size)) {
    return true;
  }
  oc_set_string(&ctx->certificate_fingerprint.data, (const char *)fingerprint,
                size);
  ctx->certificate_fingerprint.md_type = md_type;
#if DPS_DBG_IS_ENABLED
  dps_print_fingerprint(md_type, fingerprint, size);
#endif /* DPS_DBG_IS_ENABLED */
  return true;
}

bool
plgd_dps_set_certificate_fingerprint(plgd_dps_context_t *ctx,
                                     mbedtls_md_type_t md_type,
                                     const uint8_t *fingerprint, size_t size)
{
  return dps_set_certificate_fingerprint(ctx, md_type, fingerprint, size);
}

int
plgd_dps_get_certificate_fingerprint(const plgd_dps_context_t *ctx,
                                     mbedtls_md_type_t *md_type,
                                     uint8_t *buffer, size_t buffer_size)
{
  assert(ctx != NULL);
  assert(md_type != NULL);
  assert(buffer != NULL);
  if (oc_string(ctx->certificate_fingerprint.data) == NULL) {
    DPS_DBG("No certificate_fingerprint set");
    *md_type = MBEDTLS_MD_NONE;
    return 0;
  }
  size_t len = oc_string_len(ctx->certificate_fingerprint.data);
  if (buffer_size < len) {
    DPS_ERR("cannot copy certificate_fingerprint to buffer: buffer too small "
            "(minimal size=%zu)",
            len);
    return -1;
  }
  if (len > 0) {
    memcpy(buffer, oc_string(ctx->certificate_fingerprint.data), len);
  }
  *md_type = ctx->certificate_fingerprint.md_type;
  return (int)len;
}

static oc_event_callback_retval_t
dps_notify_observers_callback(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  if (ctx->conf) {
    oc_notify_observers(ctx->conf);
  }
  return OC_EVENT_DONE;
}

void
dps_notify_observers(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  if (ctx->conf != NULL) {
    dps_reset_delayed_callback(ctx, dps_notify_observers_callback, 0);
  }
}

const char *
dps_status_flag_to_str(plgd_dps_status_t status)
{
  switch (status) {
  case PLGD_DPS_INITIALIZED:
    return kPlgdDpsStatusInitialized;
  case PLGD_DPS_GET_TIME:
    return kPlgdDpsStatusGetTime;
  case PLGD_DPS_HAS_TIME:
    return kPlgdDpsStatusHasTime;
  case PLGD_DPS_GET_OWNER:
    return kPlgdDpsStatusGetOwner;
  case PLGD_DPS_HAS_OWNER:
    return kPlgdDpsStatusHasOwner;
  case PLGD_DPS_GET_CREDENTIALS:
    return kPlgdDpsStatusGetCredentials;
  case PLGD_DPS_HAS_CREDENTIALS:
    return kPlgdDpsStatusHasCredentials;
  case PLGD_DPS_GET_ACLS:
    return kPlgdDpsStatusGetAcls;
  case PLGD_DPS_HAS_ACLS:
    return kPlgdDpsStatusHasAcls;
  case PLGD_DPS_GET_CLOUD:
    return kPlgdDpsStatusGetCloud;
  case PLGD_DPS_HAS_CLOUD:
    return kPlgdDpsStatusHasCloud;
  case PLGD_DPS_CLOUD_STARTED:
    return kPlgdDpsStatusProvisioned;
  case PLGD_DPS_RENEW_CREDENTIALS:
    return kPlgdDpsStatusRenewCredentials;
  case PLGD_DPS_TRANSIENT_FAILURE:
    return kPlgdDpsStatusTransientFailure;
  case PLGD_DPS_FAILURE:
    return kPlgdDpsStatusFailure;
  }
  return "";
}

typedef struct
{
  char *buffer;
  size_t buffer_size;
  bool add_separator;
} dps_status_buffer_t;

static bool
dps_status_write_flag_to_buffer(dps_status_buffer_t *buffer,
                                plgd_dps_status_t status)
{
  if (buffer->add_separator) {
    int written = snprintf(buffer->buffer, buffer->buffer_size, "|");
    if (written < 0 || (size_t)written >= buffer->buffer_size) {
      return false;
    }
    buffer->buffer_size -= (size_t)written;
    buffer->buffer += (size_t)written;
  }
  int written = snprintf(buffer->buffer, buffer->buffer_size, "%s",
                         dps_status_flag_to_str(status));
  if (written < 0 || (size_t)written >= buffer->buffer_size) {
    return false;
  }
  buffer->buffer_size -= (size_t)written;
  buffer->buffer += (size_t)written;
  buffer->add_separator = true;
  return true;
}

int
dps_status_to_logstr(uint32_t status, char *buffer, size_t buffer_size)
{
  if (status == 0) {
    int written =
      snprintf(buffer, buffer_size, "%s", kPlgdDpsStatusUninitialized);
    return (written < 0 || (size_t)written >= buffer_size) ? -1 : 0;
  }

  dps_status_buffer_t status_buffer = {
    .buffer = buffer,
    .buffer_size = buffer_size,
    .add_separator = false,
  };

  plgd_dps_status_t all_statuses[] = {
    PLGD_DPS_INITIALIZED,       PLGD_DPS_GET_TIME,
    PLGD_DPS_HAS_TIME,          PLGD_DPS_GET_OWNER,
    PLGD_DPS_HAS_OWNER,         PLGD_DPS_GET_CREDENTIALS,
    PLGD_DPS_HAS_CREDENTIALS,   PLGD_DPS_GET_ACLS,
    PLGD_DPS_HAS_ACLS,          PLGD_DPS_GET_CLOUD,
    PLGD_DPS_HAS_CLOUD,         PLGD_DPS_CLOUD_STARTED,
    PLGD_DPS_RENEW_CREDENTIALS, PLGD_DPS_TRANSIENT_FAILURE,
    PLGD_DPS_FAILURE,
  };
  for (size_t i = 0; i < sizeof(all_statuses) / sizeof(all_statuses[0]); i++) {
    if ((status & all_statuses[i]) == 0) {
      continue;
    }
    if (!dps_status_write_flag_to_buffer(&status_buffer, all_statuses[i])) {
      return -1;
    }
  }
  return 0;
}

#if DPS_DBG_IS_ENABLED
void
dps_print_status(const char *prefix, uint32_t status)
{
  // GCOVR_EXCL_START
  char str[256]; // NOLINT
  int ret = dps_status_to_logstr(status, str, sizeof(str));
  if (prefix == NULL) {
    DPS_DBG("status(%u:%s)", status, ret >= 0 ? str : "(NULL)");
    return;
  }
  DPS_DBG("%sstatus(%u:%s)", prefix, status, ret >= 0 ? str : "(NULL)");
  // GCOVR_EXCL_STOP
}
#endif /* DPS_DBG_IS_ENABLED */
