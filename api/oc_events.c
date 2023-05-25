/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "oc_events_internal.h"

#include <assert.h>

/** Translation array of oc_events_t to oc_process_event_t */
static oc_process_event_t oc_events[__NUM_OC_EVENT_TYPES__] = { 0 };

void
oc_event_assign_oc_process_events(void)
{
  for (int i = 0; i < __NUM_OC_EVENT_TYPES__; ++i) {
    oc_events[i] = oc_process_alloc_event();
  }
}

oc_process_event_t
oc_event_to_oc_process_event(oc_events_t event)
{
  assert(event < __NUM_OC_EVENT_TYPES__);
  return oc_events[event];
}
