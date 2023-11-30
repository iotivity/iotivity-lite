/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_SIMPLE_MAIN_LOOP

#include "oc_api.h"
#include "port/oc_loop_event_internal.h"
#include "port/oc_poll_loop.h"
#include "util/oc_atomic.h"
#include "util/oc_macros_internal.h"

static OC_ATOMIC_INT8_T g_terminated = 0;
static oc_loop_event_t g_signal_event = OC_LOOP_EVENT_INIT;

bool
oc_poll_loop_init(void)
{
  return oc_loop_event_init(&g_signal_event);
}

void
oc_poll_loop_shutdown(void)
{
  oc_loop_event_deinit(&g_signal_event);
}

void
oc_poll_loop_run(void)
{
  OC_ATOMIC_STORE8(g_terminated, 0);

  while (!oc_poll_loop_is_terminated()) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    if (next_event_mt == 0) {
      oc_loop_event_wait(&g_signal_event);
      continue;
    }
    oc_clock_time_t now_mt = oc_clock_time_monotonic();
    if (now_mt >= next_event_mt) {
      continue;
    }
    oc_loop_event_timedwait(&g_signal_event, next_event_mt - now_mt);
  }
}

void
oc_poll_loop_signal(void)
{
  oc_loop_event_signal(&g_signal_event);
}

void
oc_poll_loop_terminate(void)
{
  OC_ATOMIC_STORE8(g_terminated, 1);
  oc_poll_loop_signal();
}

bool
oc_poll_loop_is_terminated(void)
{
  return OC_ATOMIC_LOAD8(g_terminated) == 1;
}

#endif /* OC_HAS_FEATURE_SIMPLE_MAIN_LOOP */
