/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <stdint.h>
#include <stdio.h>

#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"

#include "util/oc_etimer.h"
#include "util/oc_process.h"

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_introspection_internal.h"
#include "oc_signal_event_loop.h"

#if defined(OC_COLLECTIONS) && defined(OC_SERVER) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
#include "oc_collection.h"
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm.h"
#include "security/oc_pstat.h"
#include "security/oc_store.h"
#include "security/oc_svr.h"
#include "security/oc_tls.h"
#include "security/oc_ael.h"
#ifdef OC_PKI
#include "security/oc_keypair.h"
#include "security/oc_sp.h"
#endif /* OC_PKI */
#endif /* OC_SECURITY */

#ifdef OC_CLOUD
#include "api/cloud/oc_cloud_internal.h"
#endif /* OC_CLOUD */

#ifdef OC_SOFTWARE_UPDATE
#include "oc_swupdate_internal.h"
#endif /* OC_SOFTWARE_UPDATE */
#ifdef OC_MEMORY_TRACE
#include "util/oc_mem_trace.h"
#endif /* OC_MEMORY_TRACE */

#include "oc_main.h"

static bool initialized = false;
static const oc_handler_t *app_callbacks;
static oc_factory_presets_t factory_presets;

void
oc_set_factory_presets_cb(oc_factory_presets_cb_t cb, void *data)
{
  factory_presets.cb = cb;
  factory_presets.data = data;
}

oc_factory_presets_t *
oc_get_factory_presets_cb(void)
{
  return &factory_presets;
}

#ifdef OC_DYNAMIC_ALLOCATION
#include "oc_buffer_settings.h"
static size_t _OC_MTU_SIZE = 2048 + COAP_MAX_HEADER_SIZE;
static size_t _OC_MAX_APP_DATA_SIZE = 8192;
static size_t _OC_BLOCK_SIZE = 1024;

int
oc_set_mtu_size(size_t mtu_size)
{
  (void)mtu_size;
#ifdef OC_BLOCK_WISE
  if (mtu_size < (COAP_MAX_HEADER_SIZE + 16))
    return -1;
  _OC_MTU_SIZE = mtu_size;
  mtu_size -= COAP_MAX_HEADER_SIZE;
  size_t i;
  for (i = 10; i >= 4 && (mtu_size >> i) == 0; i--)
    ;
  _OC_BLOCK_SIZE = ((size_t)1) << i;
#endif /* OC_BLOCK_WISE */
  return 0;
}

long
oc_get_mtu_size(void)
{
  return (long)_OC_MTU_SIZE;
}

void
oc_set_max_app_data_size(size_t size)
{
  _OC_MAX_APP_DATA_SIZE = size;
#ifndef OC_BLOCK_WISE
  _OC_BLOCK_SIZE = size;
  _OC_MTU_SIZE = size + COAP_MAX_HEADER_SIZE;
#endif /* !OC_BLOCK_WISE */
}

long
oc_get_max_app_data_size(void)
{
  return (long)_OC_MAX_APP_DATA_SIZE;
}

long
oc_get_block_size(void)
{
  return (long)_OC_BLOCK_SIZE;
}
#else
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
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_connectivity_shutdown(device);
  }

  oc_network_event_handler_mutex_destroy();
  oc_core_shutdown();
}

int
oc_main_init(const oc_handler_t *handler)
{
  int ret;

  if (initialized == true)
    return 0;

  app_callbacks = handler;

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_init();
#endif /* OC_MEMORY_TRACE */

  oc_ri_init();
  oc_core_init();
  oc_network_event_handler_mutex_init();

  ret = app_callbacks->init();
  if (ret < 0) {
    oc_ri_shutdown();
    oc_shutdown_all_devices();
    goto err;
  }

#ifdef OC_SECURITY
  ret = oc_tls_init_context();
  if (ret < 0) {
    oc_ri_shutdown();
    oc_shutdown_all_devices();
    goto err;
  }
#endif /* OC_SECURITY */

#ifdef OC_SECURITY
  oc_sec_create_svr();
#endif

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  oc_cloud_init();
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_init();
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_SERVER
  if (app_callbacks->register_resources)
    app_callbacks->register_resources();
#endif

#ifdef OC_SECURITY
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_load_unique_ids(device);
    oc_sec_load_pstat(device);
    oc_sec_load_doxm(device);
    oc_sec_load_cred(device);
    oc_sec_load_acl(device);
    oc_sec_load_ael(device);
#ifdef OC_PKI
    oc_sec_load_sp(device);
    oc_sec_load_ecdsa_keypair(device);
#endif /* OC_PKI */
  }
#endif

  OC_DBG("oc_main: stack initialized");

  initialized = true;

#ifdef OC_CLIENT
  if (app_callbacks->requests_entry)
    app_callbacks->requests_entry();
#endif

  return 0;

err:
  OC_ERR("oc_main: error in stack initialization");
  return ret;
}

oc_clock_time_t
oc_main_poll(void)
{
  oc_clock_time_t ticks_until_next_event = oc_etimer_request_poll();
  while (oc_process_run()) {
    ticks_until_next_event = oc_etimer_request_poll();
  }
  return ticks_until_next_event;
}

void
oc_main_shutdown(void)
{
  if (initialized == false)
    return;

  initialized = false;

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  oc_cloud_shutdown();
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */
#if defined(OC_COLLECTIONS) && defined(OC_SERVER) &&                           \
  defined(OC_COLLECTIONS_IF_CREATE)
  oc_collections_free_rt_factories();
#endif /* OC_COLLECTIONS && OC_SERVER && OC_COLLECTIONS_IF_CREATE */

  oc_ri_shutdown();

#ifdef OC_SECURITY
  oc_sec_acl_free();
  oc_sec_cred_free();
  oc_sec_doxm_free();
  oc_sec_pstat_free();
  oc_sec_ael_free();
#ifdef OC_PKI
  oc_sec_sp_free();
  oc_free_ecdsa_keypairs();
#endif /* OC_PKI */
  oc_tls_shutdown();
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_free();
#endif /* OC_SOFTWARE_UPDATE */

  oc_shutdown_all_devices();

  app_callbacks = NULL;

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_shutdown();
#endif /* OC_MEMORY_TRACE */
}

bool
oc_main_initialized(void)
{
  return initialized;
}

void
_oc_signal_event_loop(void)
{
  if (app_callbacks) {
    app_callbacks->signal_event_loop();
  }
}
