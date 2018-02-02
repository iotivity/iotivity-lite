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

#ifdef OC_SECURITY
#include "security/oc_dtls.h"
#include "security/oc_store.h"
#include "security/oc_svr.h"
#endif /* OC_SECURITY */

static bool initialized = false;
static const oc_handler_t *app_callbacks;

#ifdef OC_DYNAMIC_ALLOCATION
#include "oc_buffer_settings.h"
static long _OC_MTU_SIZE = 2048 + COAP_MAX_HEADER_SIZE;
static long _OC_MAX_APP_DATA_SIZE = 8192;
static long _OC_BLOCK_SIZE = 1024;

int
oc_set_mtu_size(long mtu_size)
{
#ifdef OC_BLOCK_WISE
  if (mtu_size < (COAP_MAX_HEADER_SIZE + 16))
    return -1;
  _OC_MTU_SIZE = mtu_size;
  mtu_size -= COAP_MAX_HEADER_SIZE;
  int i;
  for (i = 10; i >= 4 && (mtu_size >> i) == 0; i--)
    ;
  _OC_BLOCK_SIZE = 1 << i;
#endif /* OC_BLOCK_WISE */
  return 0;
}

long
oc_get_mtu_size(void)
{
  return _OC_MTU_SIZE;
}

void
oc_set_max_app_data_size(long size)
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
  return _OC_MAX_APP_DATA_SIZE;
}

long
oc_get_block_size(void)
{
  return _OC_BLOCK_SIZE;
}
#else
int
oc_set_mtu_size(long mtu_size)
{
  (void)mtu_size;
  OC_WRN("Dynamic memory not available\n");
  return -1;
}

long
oc_get_mtu_size(void)
{
  OC_WRN("Dynamic memory not available\n");
  return -1;
}

void
oc_set_max_app_data_size(long size)
{
  (void)size;
  OC_WRN("Dynamic memory not available\n");
}

long
oc_get_max_app_data_size(void)
{
  OC_WRN("Dynamic memory not available\n");
  return -1;
}

long
oc_get_block_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}
#endif /* OC_DYNAMIC_ALLOCATION */

int
oc_main_init(const oc_handler_t *handler)
{
  int ret;

  if (initialized == true)
    return 0;

  app_callbacks = handler;

  oc_ri_init();

  oc_network_event_handler_mutex_init();

  ret = app_callbacks->init();
  if (ret < 0)
    goto err;

#ifdef OC_SECURITY
  oc_sec_create_svr();
#endif

#ifdef OC_SERVER
  if (app_callbacks->register_resources)
    app_callbacks->register_resources();
#endif

#ifdef OC_SECURITY
  oc_sec_dtls_init_context();
  int device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_load_pstat(device);
    oc_sec_load_doxm(device);
    oc_sec_load_cred(device);
    oc_sec_load_acl(device);
    oc_sec_load_unique_ids(device);
  }
#endif

  OC_DBG("oc_main: stack initialized\n");

#ifdef OC_CLIENT
  if (app_callbacks->requests_entry)
    app_callbacks->requests_entry();
#endif

  initialized = true;
  return 0;

err:
  oc_abort("oc_main: error in stack initialization\n");
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
  if (initialized == false) {
    return;
  }

  int device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_connectivity_shutdown(device);
  }

  oc_network_event_handler_mutex_destroy();

  oc_ri_shutdown();

  app_callbacks = NULL;
  initialized = false;
}

void
_oc_signal_event_loop(void)
{
  if (app_callbacks)
    app_callbacks->signal_event_loop();
}
