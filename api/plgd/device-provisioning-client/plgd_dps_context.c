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

#include "plgd/plgd_dps.h"
#include "plgd_dps_cloud_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_dhcp_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_resource_internal.h"
#include "plgd_dps_store_internal.h"

#include "api/cloud/oc_cloud_schedule_internal.h"
#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#include <assert.h>

OC_LIST(g_dps_context_list);
OC_MEMB(g_dps_context_pool, plgd_dps_context_t, OC_MAX_NUM_DEVICES);

static void
dps_on_endpoint_change(void *data)
{
  dps_store_dump_async((plgd_dps_context_t *)data);
}

plgd_dps_context_t *
dps_context_alloc(void)
{
  return (plgd_dps_context_t *)oc_memb_alloc(&g_dps_context_pool);
}

void
dps_context_free(plgd_dps_context_t *ctx)
{
  oc_memb_free(&g_dps_context_pool, ctx);
}

void
dps_context_list_add(plgd_dps_context_t *ctx)
{
  oc_list_add(g_dps_context_list, ctx);
}

void
dps_context_list_remove(const plgd_dps_context_t *ctx)
{
  oc_list_remove(g_dps_context_list, ctx);
}

bool
dps_context_list_is_empty(void)
{
  return oc_list_length(g_dps_context_list) == 0;
}

void
dps_contexts_iterate(dps_contexts_iterate_fn_t fn, void *data)
{
  for (plgd_dps_context_t *ctx = oc_list_head(g_dps_context_list); ctx != NULL;
       ctx = ctx->next) {
    if (!fn(ctx, data)) {
      return;
    }
  }
}

void
dps_context_init(plgd_dps_context_t *ctx, size_t device)
{
  ctx->next = NULL;
  ctx->device = device;
  ctx->callbacks.on_status_change = NULL;
  ctx->callbacks.on_status_change_data = NULL;
  ctx->callbacks.on_cloud_status_change = NULL;
  ctx->callbacks.on_cloud_status_change_data = NULL;
  dps_store_init(&ctx->store, dps_on_endpoint_change, ctx);
  ctx->status = 0;
  ctx->transient_retry_count = 0;
  dps_pki_init(&ctx->pki);
  dps_cloud_observer_init(&ctx->cloud_observer);
  ctx->endpoint = oc_new_endpoint();
  memset(ctx->endpoint, 0, sizeof(oc_endpoint_t));
  ctx->endpoint_state = OC_SESSION_DISCONNECTED;
  dps_retry_init(&ctx->retry);
  ctx->last_error = PLGD_DPS_OK;
  ctx->conf = NULL;
  ctx->manager_started = false;
  ctx->force_reprovision = false;
  ctx->skip_verify = false;
  plgd_dps_dhcp_init(&ctx->dhcp);
  memset(&ctx->certificate_fingerprint.data, 0,
         sizeof(ctx->certificate_fingerprint.data));
  ctx->certificate_fingerprint.md_type = MBEDTLS_MD_NONE;
}

void
dps_context_deinit(plgd_dps_context_t *ctx)
{
  oc_remove_delayed_callback(ctx, dps_store_dump_handler);
  dps_cloud_observer_deinit(ctx);
  dps_store_deinit(&ctx->store);
  if (ctx->endpoint != NULL) {
    oc_free_endpoint(ctx->endpoint);
    ctx->endpoint = NULL;
  }
  oc_set_string(&ctx->certificate_fingerprint.data, NULL, 0);
}

void
dps_context_reset(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  dps_cloud_observer_deinit(ctx);
  dps_endpoint_disconnect(ctx);
  dps_manager_stop(ctx);
  dps_store_deinit(&ctx->store);
  dps_store_init(&ctx->store, dps_on_endpoint_change, ctx);
  ctx->last_error = 0;
  ctx->status = 0;
  ctx->transient_retry_count = 0;
  oc_set_string(&ctx->certificate_fingerprint.data, NULL, 0);
  ctx->certificate_fingerprint.md_type = MBEDTLS_MD_NONE;
  dps_store_dump_async(ctx);
}

plgd_dps_context_t *
plgd_dps_get_context(size_t device)
{
  plgd_dps_context_t *ctx = oc_list_head(g_dps_context_list);
  while (ctx != NULL && ctx->device != device) {
    ctx = ctx->next;
  }
  return ctx;
}

int
plgd_dps_on_factory_reset(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
  oc_cloud_set_retry_timeouts(NULL, 0);
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */
  dps_context_reset(ctx);
  return 0;
}

void
plgd_dps_set_skip_verify(plgd_dps_context_t *ctx, bool skip_verify)
{
  DPS_DBG("DPS Service skip_verify=%d", (int)skip_verify);
  assert(ctx != NULL);
  ctx->skip_verify = skip_verify;
}

bool
plgd_dps_get_skip_verify(const plgd_dps_context_t *ctx)
{
  return ctx->skip_verify;
}

void
plgd_dps_set_manager_callbacks(plgd_dps_context_t *ctx,
                               plgd_dps_manager_callbacks_t callbacks)
{
  assert(ctx != NULL);
  ctx->callbacks.on_status_change = callbacks.on_status_change;
  ctx->callbacks.on_status_change_data = callbacks.on_status_change_data;
  ctx->callbacks.on_cloud_status_change = callbacks.on_cloud_status_change;
  ctx->callbacks.on_cloud_status_change_data =
    callbacks.on_cloud_status_change_data;
}

void
plgd_dps_force_reprovision(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  DPS_DBG("DPS force reprovision");
  ctx->force_reprovision = true;
}

bool
plgd_dps_has_forced_reprovision(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->force_reprovision;
}

bool
dps_set_has_been_provisioned_since_reset(plgd_dps_context_t *ctx, bool dump)
{
  assert(ctx != NULL);
  bool has_been_provisioned_since_reset = true;
  bool changed = ctx->store.has_been_provisioned_since_reset !=
                 has_been_provisioned_since_reset;
  if (!changed) {
    return false;
  }
  ctx->store.has_been_provisioned_since_reset =
    has_been_provisioned_since_reset;
  if (dump) {
    dps_store_dump_async(ctx);
  }
  return true;
}

bool
plgd_dps_has_been_provisioned_since_reset(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->store.has_been_provisioned_since_reset;
}

uint32_t
plgd_dps_get_provision_status(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->status;
}

bool
dps_set_last_error(plgd_dps_context_t *ctx, plgd_dps_error_t error)
{
  assert(ctx != NULL);
  bool changed = error != ctx->last_error;
  if (changed) {
    ctx->last_error = error;
    dps_notify_observers(ctx);
  }
  return changed;
}

plgd_dps_error_t
plgd_dps_get_last_error(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->last_error;
}

bool
dps_set_ps_and_last_error(plgd_dps_context_t *ctx, uint32_t add_flags,
                          uint32_t remove_flags, plgd_dps_error_t error)
{
  assert(ctx != NULL);
  uint32_t new_status = ctx->status;
  new_status &= ~remove_flags;
  new_status |= add_flags;
  bool changed = (ctx->status != new_status) || (error != ctx->last_error);
  if (changed) {
    ctx->status = new_status;
    ctx->last_error = error;
    dps_notify_observers(ctx);
  }
  return changed;
}

size_t
plgd_dps_get_device(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->device;
}

void
plgd_dps_set_configuration_resource(plgd_dps_context_t *ctx,
                                    bool create_resource)
{
  assert(ctx != NULL);
  DPS_DBG("DPS Service create_resource=%d", (int)create_resource);
  if (!create_resource) {
    dps_delete_dpsconf_resource(ctx->conf);
    ctx->conf = NULL;
    return;
  }
  if (ctx->conf == NULL) {
    ctx->conf = dps_create_dpsconf_resource(ctx->device);
  }
}
