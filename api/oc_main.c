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
#include "oc_store.h"
#include "security/oc_acl_internal.h"
#include "security/oc_ael.h"
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
static const oc_handler_t *g_app_callbacks;
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

#ifdef OC_DYNAMIC_ALLOCATION
#include "oc_buffer_settings.h"
#ifdef OC_INOUT_BUFFER_SIZE
static size_t _OC_MTU_SIZE = OC_INOUT_BUFFER_SIZE;
#else  /* OC_INOUT_BUFFER_SIZE */
static size_t _OC_MTU_SIZE = 2048 + COAP_MAX_HEADER_SIZE;
#endif /* !OC_INOUT_BUFFER_SIZE */
#ifdef OC_APP_DATA_BUFFER_SIZE
static size_t _OC_MAX_APP_DATA_SIZE = 7168;
static size_t _OC_MIN_APP_DATA_SIZE = 7168;
#else /* OC_APP_DATA_BUFFER_SIZE */
static size_t _OC_MAX_APP_DATA_SIZE = 7168;
#ifdef OC_REP_ENCODING_REALLOC
static size_t _OC_MIN_APP_DATA_SIZE = 256;
#else                                /* OC_REP_ENCODING_REALLOC */
static size_t _OC_MIN_APP_DATA_SIZE = 7168;
#endif                               /* !OC_REP_ENCODING_REALLOC */
#endif                               /* !OC_APP_DATA_BUFFER_SIZE */
static size_t _OC_BLOCK_SIZE = 1024; // FIX

int
oc_set_mtu_size(size_t mtu_size)
{
  (void)mtu_size;
#ifdef OC_INOUT_BUFFER_SIZE
  return -1;
#else /* !OC_INOUT_BUFFER_SIZE */
#ifdef OC_BLOCK_WISE
  if (mtu_size < (COAP_MAX_HEADER_SIZE + 16)) {
    return -1;
  }
#ifdef OC_OSCORE
  _OC_MTU_SIZE = mtu_size + COAP_MAX_HEADER_SIZE;
#else  /* OC_OSCORE */
  _OC_MTU_SIZE = mtu_size;
#endif /* !OC_OSCORE */
  mtu_size -= COAP_MAX_HEADER_SIZE;
  size_t i;
  for (i = 10; i >= 4 && (mtu_size >> i) == 0; i--)
    ;
  _OC_BLOCK_SIZE = ((size_t)1) << i;
#endif /* OC_BLOCK_WISE */
  return 0;
#endif /* OC_INOUT_BUFFER_SIZE */
}

long
oc_get_mtu_size(void)
{
  return (long)_OC_MTU_SIZE;
}

void
oc_set_max_app_data_size(size_t size)
{
#ifdef OC_APP_DATA_BUFFER_SIZE
  (void)size;
#else /* !OC_APP_DATA_BUFFER_SIZE */
  _OC_MAX_APP_DATA_SIZE = size;
#ifndef OC_REP_ENCODING_REALLOC
  _OC_MIN_APP_DATA_SIZE = size;
#endif /* !OC_REP_ENCODING_REALLOC */
#ifndef OC_BLOCK_WISE
  _OC_BLOCK_SIZE = size;
  _OC_MTU_SIZE = size + COAP_MAX_HEADER_SIZE;
#endif /* !OC_BLOCK_WISE */
#endif /* OC_APP_DATA_BUFFER_SIZE */
}

long
oc_get_max_app_data_size(void)
{
  return (long)_OC_MAX_APP_DATA_SIZE;
}

void
oc_set_min_app_data_size(size_t size)
{
#if defined(OC_APP_DATA_BUFFER_SIZE) || !defined(OC_REP_ENCODING_REALLOC)
  (void)size;
#else  /* !OC_APP_DATA_BUFFER_SIZE && !OC_REP_ENCODING_REALLOC */
  _OC_MIN_APP_DATA_SIZE = size;
#endif /* OC_APP_DATA_BUFFER_SIZE || !OC_REP_ENCODING_REALLOC */
}

long
oc_get_min_app_data_size(void)
{
  return (long)_OC_MIN_APP_DATA_SIZE;
}

long
oc_get_block_size(void)
{
  return (long)_OC_BLOCK_SIZE;
}
#else  /* !OC_DYNAMIC_ALLOCATION  */
int
oc_set_mtu_size(size_t mtu_size)
{
  (void)mtu_size;
  OC_WRN("Dynamic memory not available");
  return -1;
}

long
oc_get_mtu_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

void
oc_set_max_app_data_size(size_t size)
{
  (void)size;
  OC_WRN("Dynamic memory not available");
}

long
oc_get_max_app_data_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

void
oc_set_min_app_data_size(size_t size)
{
  (void)size;
  OC_WRN("Dynamic memory not available");
}

long
oc_get_min_app_data_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

long
oc_get_block_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}
#endif /* OC_DYNAMIC_ALLOCATION */

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
    oc_sec_load_unique_ids(device);
    OC_DBG("oc_main_init(): loading pstat(%zu)", device);
    oc_sec_load_pstat(device);
    OC_DBG("oc_main_init(): loading doxm(%zu)", device);
    oc_sec_load_doxm(device);
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

int
oc_main_init(const oc_handler_t *handler)
{
  if (g_initialized) {
    return 0;
  }

  g_app_callbacks = handler;

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

  int ret = g_app_callbacks->init();
  if (ret < 0) {
    oc_ri_shutdown();
    oc_shutdown_all_devices();
    oc_runtime_shutdown();
    goto err;
  }

#ifdef OC_SECURITY
  ret = oc_tls_init_context();
  if (ret < 0) {
    oc_ri_shutdown();
    oc_shutdown_all_devices();
    oc_runtime_shutdown();
    goto err;
  }
#endif /* OC_SECURITY */

  main_init_resources();
  main_load_resources();

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  // initialize cloud after load pstat
  oc_cloud_init();
  OC_DBG("oc_main_init(): loading cloud");
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SERVER
  // initialize after cloud because their can be registered to cloud.
  if (g_app_callbacks->register_resources) {
    g_app_callbacks->register_resources();
  }
#endif /* OC_SERVER */

  OC_DBG("oc_main: stack initialized");
  g_initialized = true;

#ifdef OC_CLIENT
  if (g_app_callbacks->requests_entry) {
    g_app_callbacks->requests_entry();
  }
#endif /* OC_CLIENT */

  return 0;

err:
  OC_ERR("oc_main: error in stack initialization");
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

  oc_sec_svr_free();
#ifdef OC_PKI
#ifdef OC_CLIENT
  oc_sec_role_creds_free();
#endif /* OC_CLIENT */
  oc_sec_ecdsa_free_keypairs();
#endif /* OC_PKI */
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_free();
#endif /* OC_SOFTWARE_UPDATE */

  oc_shutdown_all_devices();

  g_app_callbacks = NULL;

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
  if (g_app_callbacks != NULL) {
    g_app_callbacks->signal_event_loop();
  }
}
