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
#include "plgd_dps_context_internal.h"
#include "plgd_dps_endpoints_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_resource_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_store_internal.h" // dps_store_dump_async
#include "plgd_dps_internal.h"

#include "api/cloud/oc_cloud_schedule_internal.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_compiler.h"
#include "util/oc_list.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLGD_DPS_RES_TYPE "x.plgd.dps.conf"
#define PLGD_DPS_ENDPOINT "endpoint" /**< endpoint */
#define PLGD_DPS_ENDPOINT_NAME                                                 \
  "endpointName"                       /**< name associated with the endpoint */
#define PLGD_DPS_ENDPOINTS "endpoints" /**< list of endpoints */
#define PLGD_DPS_LAST_ERROR_CODE "lastErrorCode" /**< last error code */
#define PLGD_DPS_FORCE_REPROVISION                                             \
  "forceReprovision" /**< connect to dps service and reprovision time, owner,  \
                        cloud configuration credentials and acls .*/

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES

#define PLGD_DPS_TEST_PROPERTIES "test" /**< test properties */
#define PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER                                    \
  "cloudStatusObserver" /**< cloud status observer configuration */
#define PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER_MAX_COUNT                          \
  "maxCount"                                 /**< max count */
#define PLGD_DPS_TEST_IOTIVITY "iotivity"    /**< iotivity configuration */
#define PLGD_DPS_TEST_IOTIVITY_RETRY "retry" /**< retry configuration */

#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

typedef struct
{
  const oc_string_t *endpoint;
  const oc_string_t *endpointName;
  const oc_rep_t *endpoints;
  bool restart;
} dps_conf_update_t;

typedef struct dps_conf_update_data_t
{
  struct dps_update_conf_data_t *next;

  size_t device;
  bool factory_reset;
} dps_conf_update_data_t;

#ifndef OC_DYNAMIC_ALLOCATION
OC_MEMB(g_dps_conf_update_data_s, dps_conf_update_data_t, 2);
#endif /* !OC_DYNAMIC_ALLOCATION */

OC_LIST(g_dps_update_data_list);

static dps_conf_update_data_t *dps_update_list_insert(size_t device,
                                                      bool factory_reset);

oc_string_view_t
dps_status_to_str(uint32_t status)
{
  if ((status & PLGD_DPS_FAILURE) != 0) {
    return OC_STRING_VIEW(kPlgdDpsStatusFailure);
  }
  if ((status & PLGD_DPS_TRANSIENT_FAILURE) != 0) {
    return OC_STRING_VIEW(kPlgdDpsStatusTransientFailure);
  }
  if (status == 0) {
    return OC_STRING_VIEW(kPlgdDpsStatusUninitialized);
  }
  if (status == PLGD_DPS_INITIALIZED) {
    return OC_STRING_VIEW(kPlgdDpsStatusInitialized);
  }
  if (status == (PLGD_DPS_INITIALIZED | PLGD_DPS_GET_TIME)) {
    return OC_STRING_VIEW(kPlgdDpsStatusGetTime);
  }
  const uint32_t has_time = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME;
  if (status == has_time) {
    return OC_STRING_VIEW(kPlgdDpsStatusHasTime);
  }
  if (status == (has_time | PLGD_DPS_GET_OWNER)) {
    return OC_STRING_VIEW(kPlgdDpsStatusGetOwner);
  }
  const uint32_t has_owner = has_time | PLGD_DPS_HAS_OWNER;
  if (status == has_owner) {
    return OC_STRING_VIEW(kPlgdDpsStatusHasOwner);
  }
  if (status == (has_owner | PLGD_DPS_GET_CLOUD)) {
    return OC_STRING_VIEW(kPlgdDpsStatusGetCloud);
  }
  const uint32_t has_cloud = has_owner | PLGD_DPS_HAS_CLOUD;
  if (status == has_cloud) {
    return OC_STRING_VIEW(kPlgdDpsStatusHasCloud);
  }
  if (status == (has_cloud | PLGD_DPS_GET_CREDENTIALS)) {
    return OC_STRING_VIEW(kPlgdDpsStatusGetCredentials);
  }
  const uint32_t has_creds = has_cloud | PLGD_DPS_HAS_CREDENTIALS;
  if (status == has_creds) {
    return OC_STRING_VIEW(kPlgdDpsStatusHasCredentials);
  }
  if (status == (has_creds | PLGD_DPS_GET_ACLS)) {
    return OC_STRING_VIEW(kPlgdDpsStatusGetAcls);
  }
  const uint32_t has_acls = has_creds | PLGD_DPS_HAS_ACLS;
  if (status == has_acls) {
    return OC_STRING_VIEW(kPlgdDpsStatusHasAcls);
  }
  const uint32_t cloud_started = has_acls | PLGD_DPS_CLOUD_STARTED;
  if (status == cloud_started) {
    return OC_STRING_VIEW(kPlgdDpsStatusProvisioned);
  }
  if (status == (cloud_started | PLGD_DPS_RENEW_CREDENTIALS)) {
    return OC_STRING_VIEW(kPlgdDpsStatusRenewCredentials);
  }
  return OC_STRING_VIEW_NULL;
}

static void
dps_resource_encode_endpoints(CborEncoder *encoder,
                              const oc_endpoint_addresses_t *endpoints)
{
  const oc_endpoint_address_t *selected =
    oc_endpoint_addresses_selected(endpoints);
  oc_string_view_t epname_key = OC_STRING_VIEW(PLGD_DPS_ENDPOINT_NAME);
  oc_endpoint_address_view_t eav;
  if (selected != NULL) {
    eav = oc_endpoint_address_view(selected);
  } else {
    epname_key = OC_STRING_VIEW_NULL; // ignore endpointName
    eav = oc_endpoint_address_make_view_with_name(OC_STRING_VIEW_NULL,
                                                  OC_STRING_VIEW_NULL);
  }
  g_err |=
    oc_endpoint_address_encode(encoder, OC_STRING_VIEW(PLGD_DPS_ENDPOINT),
                               OC_STRING_VIEW_NULL, epname_key, eav);
  g_err |= oc_endpoint_addresses_encode(
    encoder, endpoints, OC_STRING_VIEW(PLGD_DPS_ENDPOINTS), true);
}

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES

static void
dps_resource_encode_cloud_observer(CborEncoder *encoder,
                                   const dps_resource_test_data_t *rtd)
{
  oc_string_view_t key = OC_STRING_VIEW(PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER);
  g_err |= oc_rep_encode_text_string(encoder, key.data, key.length);
  oc_rep_begin_object(encoder, cloudStatusObserver);
  oc_rep_set_int(cloudStatusObserver, maxCount,
                 rtd->cloud_status_observer.max_count);
  oc_rep_set_int(cloudStatusObserver, interval,
                 rtd->cloud_status_observer.interval_s);
  oc_rep_end_object(encoder, cloudStatusObserver);
}

static void
dps_resource_encode_iotivity_retry_timeouts(CborEncoder *encoder,
                                            const dps_resource_test_data_t *rtd)
{
  oc_string_view_t retryKey = OC_STRING_VIEW(PLGD_DPS_TEST_IOTIVITY_RETRY);
  g_err |= oc_rep_encode_text_string(encoder, retryKey.data, retryKey.length);
  oc_rep_begin_array(encoder, retry);
  for (size_t i = 0; i < OC_ARRAY_SIZE(rtd->iotivity.retry_timeout); ++i) {
    if (rtd->iotivity.retry_timeout[i] == 0) {
      break;
    }
    oc_rep_add_int(retry, rtd->iotivity.retry_timeout[i]);
  }
  oc_rep_end_array(encoder, retry);
}

static void
dps_resource_encode_iotivity(CborEncoder *encoder,
                             const dps_resource_test_data_t *rtd)
{
  oc_string_view_t iotKey = OC_STRING_VIEW(PLGD_DPS_TEST_IOTIVITY);
  g_err |= oc_rep_encode_text_string(encoder, iotKey.data, iotKey.length);
  oc_rep_begin_object(encoder, iotivity);
  dps_resource_encode_iotivity_retry_timeouts(oc_rep_object(iotivity), rtd);
  oc_rep_end_object(encoder, iotivity);
}

static void
dps_resource_encode_test_properties(CborEncoder *encoder,
                                    const dps_resource_test_data_t *rtd)
{
  dps_resource_encode_cloud_observer(encoder, rtd);
  dps_resource_encode_iotivity(encoder, rtd);
}

#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

void
dps_resource_encode(oc_interface_mask_t interface,
                    const oc_resource_t *resource,
                    const dps_resource_data_t *data)
{
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
    OC_FALLTHROUGH;
  case OC_IF_R:
    oc_rep_set_int(root, lastErrorCode, (int64_t)data->last_error);
    if (data->provision_status != NULL) {
      oc_rep_set_text_string_v1(root, provisionStatus, data->provision_status,
                                data->provision_status_length);
    }
    OC_FALLTHROUGH;
  case OC_IF_RW: {
    dps_resource_encode_endpoints(oc_rep_object(root), data->endpoints);
    oc_rep_set_boolean(root, forceReprovision, data->forceReprovision);
#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
    oc_rep_open_object(root, test);
    dps_resource_encode_test_properties(oc_rep_object(test), &data->test);
    oc_rep_close_object(root, test);
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */
    OC_FALLTHROUGH;
  }
  default:
    break;
  }
  oc_rep_end_root_object();
}

static void
dps_resource_encode_response(const plgd_dps_context_t *ctx,
                             oc_interface_mask_t interface)
{
  oc_string_view_t status = dps_status_to_str(ctx->status);
  dps_resource_data_t data = {
    .last_error = ctx->last_error,
    .provision_status = status.data,
    .provision_status_length = status.length,
    .endpoints = &ctx->store.endpoints,
    .forceReprovision = false,
  };

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
  data.test.cloud_status_observer = ctx->cloud_observer.cfg;
  oc_cloud_get_retry_timeouts(&data.test.iotivity.retry_timeout[0],
                              OC_ARRAY_SIZE(data.test.iotivity.retry_timeout));
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

  dps_resource_encode(interface, ctx->conf, &data);
}

static void
get_dps(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  (void)interface;
  const plgd_dps_context_t *ctx =
    plgd_dps_get_context(request->resource->device);
  if (ctx == NULL) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }
  DPS_DBG("GET request received");
  dps_resource_encode_response(ctx, interface);
  oc_send_response(request, OC_STATUS_OK);
}

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES

static void
dps_update_iotivity(const oc_rep_t *iot)
{
  DPS_DBG("DPS test properties iotivity update");
  int64_t *retry = NULL;
  size_t retry_size;
  if (oc_rep_get_int_array(iot, PLGD_DPS_TEST_IOTIVITY_RETRY, &retry,
                           &retry_size)) {
    uint16_t retry_timeout[DPS_CLOUD_RETRY_TIMEOUTS_SIZE] = { 0 };
    for (size_t i = 0; i < retry_size && i < OC_ARRAY_SIZE(retry_timeout);
         ++i) {
      retry_timeout[i] = (uint16_t)retry[i];
    }
    if (!oc_cloud_set_retry_timeouts(retry_timeout, (uint8_t)retry_size)) {
      DPS_ERR("failed to set retry timeouts");
    }
  }
}

static void
dps_update_cloud_observer(plgd_dps_context_t *ctx, const oc_rep_t *cso)
{
  DPS_DBG("DPS test properties cloud status observer update");
  int64_t val;
  if (oc_rep_get_int(cso, PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER_MAX_COUNT,
                     &val)) {
    plgd_dps_set_cloud_observer_configuration(
      ctx, (uint8_t)val, ctx->cloud_observer.cfg.interval_s);
  }
}

static bool
dps_update_test_properties(plgd_dps_context_t *ctx, const oc_rep_t *payload)
{
  const oc_rep_t *testProps =
    oc_rep_get_by_type_and_key(payload, OC_REP_OBJECT, PLGD_DPS_TEST_PROPERTIES,
                               OC_CHAR_ARRAY_LEN(PLGD_DPS_TEST_PROPERTIES));
  if (testProps == NULL) {
    return false;
  }
  DPS_DBG("DPS test properties update");

  const oc_rep_t *cso = oc_rep_get_by_type_and_key(
    testProps->value.object, OC_REP_OBJECT, PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER,
    OC_CHAR_ARRAY_LEN(PLGD_DPS_TEST_CLOUD_STATUS_OBSERVER));
  if (cso != NULL) {
    dps_update_cloud_observer(ctx, cso->value.object);
  }

  const oc_rep_t *iot = oc_rep_get_by_type_and_key(
    testProps->value.object, OC_REP_OBJECT, PLGD_DPS_TEST_IOTIVITY,
    OC_CHAR_ARRAY_LEN(PLGD_DPS_TEST_IOTIVITY));
  if (iot != NULL) {
    dps_update_iotivity(iot->value.object);
  }
  return true;
}

#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

static oc_event_callback_retval_t
dps_update_async(void *data)
{
  assert(data != NULL);
  oc_list_remove(g_dps_update_data_list, data);

  dps_conf_update_data_t *update = (dps_conf_update_data_t *)data;
  if (update->factory_reset) {
    if (dps_factory_reset(update->device, false) != 0) {
      DPS_ERR("failed to reset device(%zu) ownership", update->device);
    }
    goto finish;
  }

  const plgd_dps_context_t *ctx = plgd_dps_get_context(update->device);
  if (ctx == NULL) {
    DPS_ERR("failed to get DPS context for device(%zu)", update->device);
    goto finish;
  }
  if (dps_store_dump(&ctx->store, ctx->device) != 0) {
    DPS_ERR("failed to dump storage in async handler");
    goto finish;
  }

finish:
#ifdef OC_DYNAMIC_ALLOCATION
  free(update);
#else  /* !OC_DYNAMIC_ALLOCATION  */
  oc_memb_free(&g_dps_conf_update_data_s, update);
#endif /* OC_DYNAMIC_ALLOCATION */
  return OC_EVENT_DONE;
}

typedef struct
{
  bool success;
  bool asyncUpdate;
} dps_update_endpoint_t;

static dps_update_endpoint_t
dps_update_endpoint_from_request(plgd_dps_context_t *ctx,
                                 const oc_rep_t *payload,
                                 dps_conf_update_t *data)
{
  dps_update_endpoint_t res = {
    .success = false,
    .asyncUpdate = false,
  };

  const oc_rep_t *prop =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, PLGD_DPS_ENDPOINT,
                               OC_CHAR_ARRAY_LEN(PLGD_DPS_ENDPOINT));
  if (prop == NULL) {
    return res;
  }
  data->endpoint = &prop->value.string;
  if (oc_string_len_unsafe(*data->endpoint) == 0) {
    DPS_DBG("got forced deregister via provisioning of empty endpoint");
    dps_context_reset(ctx);
    res.asyncUpdate = true;
    dps_conf_update_data_t *update = dps_update_list_insert(ctx->device, true);
    if (update == NULL) {
      return res;
    }
    oc_set_delayed_callback(update, dps_update_async, 0);
    res.success = true;
    return res;
  }
  prop =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, PLGD_DPS_ENDPOINT_NAME,
                               OC_CHAR_ARRAY_LEN(PLGD_DPS_ENDPOINT_NAME));
  if (prop != NULL) {
    data->endpointName = &prop->value.string;
  }
  prop =
    oc_rep_get_by_type_and_key(payload, OC_REP_OBJECT_ARRAY, PLGD_DPS_ENDPOINTS,
                               OC_CHAR_ARRAY_LEN(PLGD_DPS_ENDPOINTS));
  if (prop != NULL) {
    data->endpoints = prop->value.object_array;
  }
  res.success =
    dps_set_endpoints(ctx, data->endpoint, data->endpointName, data->endpoints);
  return res;
}

static bool
dps_update_reprovision_from_request(const oc_rep_t *payload,
                                    dps_conf_update_t *data)
{
  if (oc_rep_get_bool(payload, PLGD_DPS_FORCE_REPROVISION, &data->restart) &&
      data->restart) {
    DPS_DBG("DPS property(%s) was set", PLGD_DPS_FORCE_REPROVISION);
    return true;
  }
  return false;
}

static oc_event_callback_retval_t
dps_update_manager_restart(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  if (plgd_dps_manager_restart(ctx) != 0) {
    DPS_ERR("failed to restart DPS");
  }
  return OC_EVENT_DONE;
}

static bool
dps_update_from_request(plgd_dps_context_t *ctx, const oc_request_t *request)
{
#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
  if (dps_update_test_properties(ctx, request->request_payload)) {
    return true;
  }
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

  dps_conf_update_t data;
  memset(&data, 0, sizeof(data));

  dps_update_endpoint_t res =
    dps_update_endpoint_from_request(ctx, request->request_payload, &data);
  if (res.asyncUpdate) {
    return res.success;
  }

  bool changed =
    dps_update_reprovision_from_request(request->request_payload, &data) ||
    res.success;

  if (changed) {
    dps_conf_update_data_t *update = dps_update_list_insert(ctx->device, false);
    if (update == NULL) {
      return false;
    }
    dps_reset_delayed_callback(update, dps_update_async, 0);

    plgd_dps_force_reprovision(ctx);
    dps_reset_delayed_callback(ctx, dps_update_manager_restart, 0);
  }
  return changed;
}

static void
post_dps(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  plgd_dps_context_t *ctx = plgd_dps_get_context(request->resource->device);
  if (ctx == NULL) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }
  DPS_DBG("POST request received");
  bool changed = dps_update_from_request(ctx, request);
  dps_resource_encode_response(ctx, interface);
  oc_send_response(request,
                   changed ? OC_STATUS_CHANGED : OC_STATUS_BAD_REQUEST);
}

oc_resource_t *
dps_create_dpsconf_resource(size_t device)
{
  DPS_DBG("plgd_dps_resource: initializing DPS resource");
  oc_resource_t *res = oc_new_resource(NULL, PLGD_DPS_URI, 1, device);
  if (!res) {
    DPS_ERR("plgd_dps_resource: cannot create resource");
    return NULL;
  }
  oc_resource_bind_resource_type(res, PLGD_DPS_RES_TYPE);
  oc_resource_bind_resource_interface(res, OC_IF_BASELINE | OC_IF_R | OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_BASELINE);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_dps, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_dps, NULL);
  oc_add_resource(res);
  oc_cloud_add_resource(res);
  return res;
}

void
dps_delete_dpsconf_resource(oc_resource_t *res)
{
  if (res == NULL) {
    return;
  }
  DPS_DBG("plgd_dps_resource: destroying DPS resource");
  oc_cloud_delete_resource(res);
  oc_delete_resource(res);
}

void
dps_update_list_init(void)
{
  oc_list_init(g_dps_update_data_list);
}

void
dps_update_list_cleanup(void)
{
  dps_conf_update_data_t *upd;
  while ((upd = oc_list_pop(g_dps_update_data_list)) != NULL) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(upd);
#else  /* !OC_DYNAMIC_ALLOCATION  */
    oc_memb_free(&g_dps_conf_update_data_s, upd);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
}

static dps_conf_update_data_t *
dps_update_list_insert(size_t device, bool factory_reset)
{
#ifdef OC_DYNAMIC_ALLOCATION
  dps_conf_update_data_t *update =
    (dps_conf_update_data_t *)calloc(1, sizeof(dps_conf_update_data_t));
#else  /* !OC_DYNAMIC_ALLOCATION  */
  dps_conf_update_data_t *update =
    (dps_conf_update_data_t *)oc_memb_alloc(&g_dps_conf_update_data_s);
#endif /* OC_DYNAMIC_ALLOCATION */
  if (update == NULL) {
    DPS_ERR("failed to allocate update item");
    return NULL;
  }
  update->device = device;
  update->factory_reset = factory_reset;
  oc_list_add(g_dps_update_data_list, update);
  return update;
}
