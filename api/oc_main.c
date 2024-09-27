/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_config.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include "oc_main_internal.h"
#include "oc_signal_event_loop.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#if defined(OC_COLLECTIONS) && defined(OC_SERVER) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

#ifdef OC_SECURITY
#include "oc_storage_internal.h"
#include "oc_store.h"
#include "security/oc_acl_internal.h"
#include "security/oc_ael_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_sp_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#ifdef OC_PKI
#include "security/oc_keypair_internal.h"
#include "security/oc_roles_internal.h"
#endif /* OC_PKI */
#include "security/oc_sdi_internal.h"
#include "security/oc_u_ids_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_CLOUD
#include "api/cloud/oc_cloud_internal.h"
#endif /* OC_CLOUD */

#ifdef OC_SOFTWARE_UPDATE
#include "api/oc_swupdate_internal.h"
#include "oc_swupdate.h"
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_MEMORY_TRACE
#include "util/oc_mem_trace_internal.h"
#endif /* OC_MEMORY_TRACE */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static bool g_initialized = false;
static void (*g_signal_event_loop)(void) = NULL;
static oc_factory_presets_t g_factory_presets;

void
oc_set_factory_presets_cb(oc_factory_presets_cb_t cb, void *data)
{
  g_factory_presets.cb = cb;
  g_factory_presets.data = data;
}

oc_factory_presets_t *
oc_get_factory_presets_cb(void)
{
  return &g_factory_presets;
}

static void
oc_shutdown_all_devices(void)
{
  for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
    oc_connectivity_shutdown(device);
  }

  oc_network_event_handler_mutex_destroy();
  oc_core_shutdown();
}

static void
main_init_resources(void)
{
#ifdef OC_HAS_FEATURE_PLGD_TIME
  plgd_time_create_resource();
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_SECURITY
  oc_sec_svr_create();
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_create();
#endif /* OC_SOFTWARE_UPDATE */
}

#ifdef OC_SECURITY
/**
 * @brief Clear the security-related resources for a device.
 *
 * The function clears the device's security-related data from storage.
 * It is called when the ownership of the device cannot be established.
 *
 * @param device The index of the device for which to clear the resources.
 */
static void
main_sec_clear_resources(size_t device)
{
  oc_storage_data_clear(OCF_SEC_U_IDS_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_PSTAT_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_CRED_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_ACL_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_SP_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_AEL_STORE_NAME, device);
  oc_storage_data_clear(OCF_SEC_SDI_STORE_NAME, device);
#ifdef OC_SOFTWARE_UPDATE
  oc_storage_data_clear(OCF_SW_UPDATE_STORE_NAME, device);
#endif /* OC_SOFTWARE_UPDATE */
}
#endif /* OC_SECURITY */

static void
main_load_resources(void)
{
#ifdef OC_HAS_FEATURE_PLGD_TIME
  OC_DBG("oc_main_init(): loading plgd time");
  plgd_time_load();
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#if defined(OC_SECURITY) || defined(OC_SOFTWARE_UPDATE)
  for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
#ifdef OC_SECURITY
    OC_DBG("oc_main_init(): loading doxm(%zu)", device);
    oc_sec_load_doxm(device);
    const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
    if (!doxm->owned) {
      OC_DBG("oc_main_init(): clearing sec resource storages(%zu)", device);
      main_sec_clear_resources(device);
    }
    oc_sec_load_unique_ids(device);
    OC_DBG("oc_main_init(): loading pstat(%zu)", device);
    oc_sec_load_pstat(device);
    OC_DBG("oc_main_init(): loading cred(%zu)", device);
    oc_sec_load_cred(device);
    OC_DBG("oc_main_init(): loading acl(%zu)", device);
    oc_sec_load_acl(device);
    OC_DBG("oc_main_init(): loading sp(%zu)", device);
    oc_sec_load_sp(device);
    OC_DBG("oc_main_init(): loading ael(%zu)", device);
    oc_sec_load_ael(device);
#ifdef OC_PKI
    OC_DBG("oc_main_init(): loading ECDSA keypair(%zu)", device);
    oc_sec_load_ecdsa_keypair(device);
#endif /* OC_PKI */
    OC_DBG("oc_main_init(): loading sdi(%zu)", device);
    oc_sec_load_sdi(device);
#endif /* OC_SECURITY */
#ifdef OC_SOFTWARE_UPDATE
    OC_DBG("oc_main_init(): loading swupdate(%zu)", device);
    oc_swupdate_load(device);
#endif /* OC_SOFTWARE_UPDATE */
  }
#endif /* OC_SECURITY || OC_SOFTWARE_UPDATE */
}

static void
main_free_resources(void)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_free();
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_SECURITY
  oc_sec_svr_free();
#ifdef OC_PKI
#ifdef OC_CLIENT
  oc_sec_role_creds_free();
#endif /* OC_CLIENT */
  oc_sec_ecdsa_free_keypairs();
#endif /* OC_PKI */
#endif /* OC_SECURITY */
}

int
oc_main_init(const oc_handler_t *handler)
{
  if (g_initialized) {
    return 0;
  }

  g_signal_event_loop = handler->signal_event_loop;

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_init();
#endif /* OC_MEMORY_TRACE */

  oc_runtime_init();
  oc_ri_init();
  oc_core_init();
#ifdef OC_REQUEST_HISTORY
  oc_request_history_init();
#endif /* OC_REQUEST_HISTORY */

  oc_network_event_handler_mutex_init();

  int ret = handler->init();
  if (ret < 0) {
    goto err;
  }

#ifdef OC_SECURITY
  ret = oc_tls_init_context();
  if (ret < 0) {
    goto err;
  }
#endif /* OC_SECURITY */

  main_init_resources();
  main_load_resources();

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  // initialize cloud after load of pstat
  if (!oc_cloud_init()) {
    main_free_resources();
#ifdef OC_SECURITY
    oc_tls_shutdown();
#endif /* OC_SECURITY */
    goto err;
  }
  OC_DBG("oc_main_init(): loading cloud");
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SERVER
  // initialize after cloud because their can be registered to cloud.
  if (handler->register_resources) {
    handler->register_resources();
  }
#endif /* OC_SERVER */

  OC_DBG("oc_main: stack initialized");
  g_initialized = true;

#ifdef OC_CLIENT
  if (handler->requests_entry) {
    handler->requests_entry();
  }
#endif /* OC_CLIENT */

  return 0;

err:
  OC_ERR("oc_main: error in stack initialization");
  oc_ri_shutdown();
  oc_shutdown_all_devices();
  oc_runtime_shutdown();
  return ret;
}

oc_clock_time_t
oc_main_poll_v1(void)
{
  oc_clock_time_t next_event_mt = oc_etimer_request_poll();
  while (oc_process_run() != 0) {
    next_event_mt = oc_etimer_request_poll();
  }
  return next_event_mt;
}

oc_clock_time_t
oc_main_poll(void)
{
  oc_clock_time_t next_event_mt = oc_main_poll_v1();
  if (next_event_mt == 0) {
    return 0;
  }
  // if the platform does not have a monotonic clock, then the ticks are already
  // in absolute time
  if (!oc_clock_time_has_monotonic_clock()) {
    return next_event_mt;
  }
  // translate monotononic time to system time
  oc_clock_time_t now_mt = oc_clock_time_monotonic();
  oc_clock_time_t now = oc_clock_time();
  return (oc_clock_time_t)((int64_t)(next_event_mt - now_mt) + (int64_t)now);
}

bool
oc_main_needs_poll(void)
{
  return oc_process_needs_poll();
}

void
oc_main_shutdown(void)
{
  if (!g_initialized) {
    return;
  }
  g_initialized = false;

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  oc_cloud_shutdown();
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */
#if defined(OC_COLLECTIONS) && defined(OC_SERVER) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
  oc_collections_free_rt_factories();
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

#ifdef OC_HAS_FEATURE_PUSH
  oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */

  oc_ri_shutdown();

#ifdef OC_SECURITY
  oc_tls_shutdown();

  // In case that the device is still in onboarding state(RFOTM), it will be
  // reset to allow re-onboarding.
  oc_reset_devices_in_RFOTM();
#endif /* OC_SECURITY */

  main_free_resources();
  oc_shutdown_all_devices();

  g_signal_event_loop = NULL;

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_shutdown();
#endif /* OC_MEMORY_TRACE */

  oc_runtime_shutdown();
}

bool
oc_main_initialized(void)
{
  return g_initialized;
}

void
_oc_signal_event_loop(void)
{
  if (g_signal_event_loop != NULL) {
    g_signal_event_loop();
  }
}
