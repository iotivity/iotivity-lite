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

#include <stdio.h>
#include <stdint.h>

#include "port/oc_connectivity.h"
#include "port/oc_clock.h"
#include "port/oc_assert.h"

#include "util/oc_process.h"
#include "util/oc_etimer.h"

#include "oc_api.h"

#ifdef OC_SECURITY
#include "security/oc_store.h"
#include "security/oc_svr.h"
#include "security/oc_dtls.h"
#endif /* OC_SECURITY */

static int initialized, terminate;

int
oc_main_init(oc_handler_t *handler)
{
  extern int oc_stack_errno;

  oc_ri_init();

#ifdef OC_SECURITY
  handler->get_credentials();

  oc_sec_load_pstat();
  oc_sec_load_doxm();
  oc_sec_load_cred();

  oc_sec_dtls_init_context();
#endif

  oc_network_event_handler_mutex_init();
  initialized = oc_connectivity_init();

  handler->init();

#ifdef OC_SERVER
  handler->register_resources();
#endif

#ifdef OC_SECURITY
  oc_sec_create_svr();
  oc_sec_load_acl();
#endif

  initialized = (initialized && !oc_stack_errno)?1:0;

  if (initialized)
    PRINT("oc_main: Stack successfully initialized\n");
  else
    oc_abort("oc_main: Error in stack initialization\n");

#ifdef OC_CLIENT
  if (initialized)
    handler->requests_entry();
#endif

  return initialized;
}

oc_clock_time_t
oc_main_poll()
{
  oc_clock_time_t ticks_until_next_event = oc_etimer_request_poll();
  while (oc_process_run()) {
    ticks_until_next_event = oc_etimer_request_poll();
  }
  return ticks_until_next_event;
}

void
oc_main_shutdown()
{
  oc_connectivity_shutdown();
  oc_ri_shutdown();

#ifdef OC_SECURITY /* fix ensure this gets executed on constraied platforms */
  oc_sec_dump_state();
#endif

  terminate = 1;
  initialized = 0;
}
