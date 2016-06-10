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
#include "security/oc_store.h"
#include "security/oc_svr.h"
#include "oc_ri.h"
#include "oc_main.h"

#ifdef OC_SERVER
#include "oc_server.h"
#endif /* OC_SERVER */

#ifdef OC_CLIENT
#include "oc_client.h"
#endif /* OC_CLIENT */

#ifdef OC_SECURITY
#include "security/oc_dtls.h"
#endif /* OC_SECURITY */

static int initialized, terminate;

int
oc_main_init()
{
  extern int oc_stack_errno;
  oc_ri_init();

#ifdef OC_SECURITY  
  fetch_credentials();//Sets device id
  oc_sec_load_pstat();
  oc_sec_load_doxm();
  oc_sec_load_cred();
  oc_sec_dtls_init_context();  
#endif

  initialized = oc_connectivity_init();
    
  app_init();

#ifdef OC_SERVER    
  register_resources();
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
    issue_requests();
#endif      
  
  return initialized;
}

void
oc_main_loop()
{
  if(!initialized)
    oc_main_init();
  while(initialized && !terminate) {
    oc_etimer_request_poll();
    while(oc_process_run()) {
#if POLL_NETWORK
      oc_poll_network();
#endif
      oc_etimer_request_poll();
    }
  }
}

void
oc_main_poll()
{
#if POLL_NETWORK
  oc_poll_network();
#endif
  oc_etimer_request_poll();
  oc_process_run();
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

