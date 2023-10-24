/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.

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

#include "oc_event_callback_internal.h"

#include "api/oc_ri_internal.h"
#include "oc_config.h"
#include "port/oc_log_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"

#ifdef OC_SERVER
#include "messaging/coap/observe_internal.h"
#endif /* OC_SERVER */

#include <assert.h>
#include <stdbool.h>

OC_LIST(g_timed_callbacks);
OC_MEMB(g_event_callbacks_s, oc_event_callback_t, OC_MAX_EVENT_CALLBACKS);
static oc_event_callback_t *g_currently_processed_event_cb = NULL;
static bool g_currently_processed_event_cb_delete = false;
static oc_ri_timed_event_on_delete_t g_currently_processed_event_on_delete =
  NULL;

OC_PROCESS(oc_timed_callback_events, "OC timed callbacks");

#ifdef OC_SERVER
OC_LIST(g_observe_callbacks);
#endif /* OC_SERVER */

void
oc_event_callbacks_init(void)
{
  oc_list_init(g_timed_callbacks);
#ifdef OC_SERVER
  oc_list_init(g_observe_callbacks);
#endif /* OC_SERVER */
}

static void
event_callbacks_free_event_timers(oc_list_t timers)
{
  oc_event_callback_t *event_cb = (oc_event_callback_t *)oc_list_pop(timers);
  while (event_cb != NULL) {
    oc_etimer_stop(&event_cb->timer);
    oc_memb_free(&g_event_callbacks_s, event_cb);
    event_cb = (oc_event_callback_t *)oc_list_pop(timers);
  }
}

void
oc_event_callbacks_shutdown(void)
{
#ifdef OC_SERVER
  event_callbacks_free_event_timers(g_observe_callbacks);
#endif /* OC_SERVER */
  event_callbacks_free_event_timers(g_timed_callbacks);
}

void
oc_event_callbacks_process_start(void)
{
  oc_process_start(&oc_timed_callback_events, NULL);
}

void
oc_event_callbacks_process_exit(void)
{
  oc_process_exit(&oc_timed_callback_events);
}

bool
oc_ri_has_timed_event_callback(const void *cb_data, oc_trigger_t event_callback,
                               bool ignore_cb_data)
{
  const oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_list_head(g_timed_callbacks);
  while (event_cb != NULL) {
    if (event_cb->callback == event_callback &&
        (ignore_cb_data || event_cb->data == cb_data)) {
      return true;
    }
    event_cb = event_cb->next;
  }
  return false;
}

bool
oc_timed_event_callback_is_currently_processed(const void *cb_data,
                                               oc_trigger_t event_callback)
{
  if (g_currently_processed_event_cb == NULL) {
    return false;
  }
  return g_currently_processed_event_cb->callback == event_callback &&
         g_currently_processed_event_cb->data == cb_data;
}

void
oc_ri_remove_timed_event_callback_by_filter(
  oc_trigger_t cb, oc_ri_timed_event_filter_t filter, const void *filter_data,
  bool match_all, oc_ri_timed_event_on_delete_t on_delete)
{
  bool want_to_delete_currently_processed_event_cb = false;
  oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_list_head(g_timed_callbacks);
  while (event_cb != NULL) {
    if (event_cb->callback != cb || !filter(event_cb->data, filter_data)) {
      event_cb = event_cb->next;
      continue;
    }

    oc_event_callback_t *next = event_cb->next;
    if (g_currently_processed_event_cb == event_cb) {
      want_to_delete_currently_processed_event_cb = true;
    } else {
      OC_PROCESS_CONTEXT_BEGIN(&oc_timed_callback_events)
      oc_etimer_stop(&event_cb->timer);
      OC_PROCESS_CONTEXT_END(&oc_timed_callback_events)
      oc_list_remove(g_timed_callbacks, event_cb);
      if (on_delete != NULL) {
        on_delete(event_cb->data);
      }
      OC_DBG("oc_event_callback: timed callback(%p) removed", (void *)event_cb);
      oc_memb_free(&g_event_callbacks_s, event_cb);
      want_to_delete_currently_processed_event_cb = false;
    }
    if (!match_all) {
      break;
    }
    event_cb = next;
  }
  if (want_to_delete_currently_processed_event_cb) {
    // We can't remove the currently processed delayed callback because when
    // the callback returns OC_EVENT_DONE, a double release occurs. So we
    // set up the flag to remove it, and when it's over, we've removed it.
    g_currently_processed_event_cb_delete = true;
    g_currently_processed_event_on_delete = on_delete;
  }
}

static bool
timed_event_is_identical_filter(const void *cb_data, const void *filter_data)
{
  return cb_data == filter_data;
}

void
oc_ri_remove_timed_event_callback(const void *cb_data,
                                  oc_trigger_t event_callback)
{
  oc_ri_remove_timed_event_callback_by_filter(
    event_callback, timed_event_is_identical_filter, cb_data, false, NULL);
}

void
oc_ri_add_timed_event_callback_ticks(void *cb_data, oc_trigger_t event_callback,
                                     oc_clock_time_t ticks)
{
  oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_memb_alloc(&g_event_callbacks_s);
  if (event_cb == NULL) {
    OC_WRN("insufficient memory to add timed event callback");
    return;
  }

  OC_DBG("oc_event_callback: timed callback(%p) added", (void *)event_cb);
  event_cb->data = cb_data;
  event_cb->callback = event_callback;
  OC_PROCESS_CONTEXT_BEGIN(&oc_timed_callback_events)
  oc_etimer_set(&event_cb->timer, ticks);
  OC_PROCESS_CONTEXT_END(&oc_timed_callback_events)
  oc_list_add(g_timed_callbacks, event_cb);
}

static void
event_callbacks_poll_timers(oc_list_t list, struct oc_memb *cb_pool)
{
  oc_event_callback_t *event_cb = (oc_event_callback_t *)oc_list_head(list);
  while (event_cb != NULL) {
    oc_event_callback_t *next = event_cb->next;
    if (!oc_etimer_expired(&event_cb->timer)) {
      event_cb = next;
      continue;
    }
    g_currently_processed_event_cb = event_cb;
    g_currently_processed_event_cb_delete = false;
    if ((event_cb->callback(event_cb->data) == OC_EVENT_DONE) ||
        g_currently_processed_event_cb_delete) {
      oc_list_remove(list, event_cb);
      if (g_currently_processed_event_on_delete != NULL) {
        g_currently_processed_event_on_delete(event_cb->data);
      }
      OC_DBG("oc_event_callback: callback(%p) done", (void *)event_cb);
      oc_memb_free(cb_pool, event_cb);
      event_cb = (oc_event_callback_t *)oc_list_head(list);
      continue;
    }
    OC_PROCESS_CONTEXT_BEGIN(&oc_timed_callback_events)
    oc_etimer_restart(&event_cb->timer);
    OC_PROCESS_CONTEXT_END(&oc_timed_callback_events)
    event_cb = (oc_event_callback_t *)oc_list_head(list);
    continue;
  }

  g_currently_processed_event_cb = NULL;
  g_currently_processed_event_cb_delete = false;
  g_currently_processed_event_on_delete = NULL;
}

#ifdef OC_SERVER

static oc_event_callback_retval_t
periodic_observe_callback_handler(void *data)
{
  oc_resource_t *resource = (oc_resource_t *)data;
  if (coap_notify_observers(resource, NULL, NULL)) {
    return OC_EVENT_CONTINUE;
  }
  return OC_EVENT_DONE;
}

bool
oc_periodic_observe_callback_add(oc_resource_t *resource)
{
  assert(resource != NULL);
  oc_event_callback_t *event_cb = oc_periodic_observe_callback_get(resource);
  if (event_cb != NULL) {
    OC_DBG(
      "oc_event_callback: observe callback(%p) for resource(%s) already exists",
      (void *)event_cb, oc_string(resource->uri));
    return true;
  }

  event_cb = (oc_event_callback_t *)oc_memb_alloc(&g_event_callbacks_s);
  if (event_cb == NULL) {
    OC_WRN("insufficient memory to add periodic observe callback");
    return false;
  }

  OC_DBG("oc_event_callback: observe callback(%p) for resource(%s) added",
         (void *)event_cb, oc_string(resource->uri));
  event_cb->data = resource;
  event_cb->callback = periodic_observe_callback_handler;
  OC_PROCESS_CONTEXT_BEGIN(&oc_timed_callback_events)
  oc_etimer_set(&event_cb->timer,
                resource->observe_period_seconds * OC_CLOCK_SECOND);
  OC_PROCESS_CONTEXT_END(&oc_timed_callback_events)
  oc_list_add(g_observe_callbacks, event_cb);
  return true;
}

bool
oc_periodic_observe_callback_remove(const oc_resource_t *resource)
{
  assert(resource != NULL);
  oc_event_callback_t *event_cb = oc_periodic_observe_callback_get(resource);
  if (event_cb == NULL) {
    return false;
  }
  oc_etimer_stop(&event_cb->timer);
  oc_list_remove(g_observe_callbacks, event_cb);
  OC_DBG("oc_event_callback: observe callback(%p) for resource(%s) removed",
         (void *)event_cb, oc_string(resource->uri));
  oc_memb_free(&g_event_callbacks_s, event_cb);
  return true;
}

oc_event_callback_t *
oc_periodic_observe_callback_get(const oc_resource_t *resource)
{
  for (oc_event_callback_t *event_cb =
         (oc_event_callback_t *)oc_list_head(g_observe_callbacks);
       event_cb != NULL; event_cb = event_cb->next) {
    if (resource == event_cb->data) {
      return event_cb;
    }
  }
  return NULL;
}

size_t
oc_periodic_observe_callback_count(void)
{
  return (size_t)oc_list_length(g_observe_callbacks);
}

#endif /* OC_SERVER */

static void
event_callbacks_check(void)
{
#ifdef OC_SERVER
  event_callbacks_poll_timers(g_observe_callbacks, &g_event_callbacks_s);
#endif /* OC_SERVER */
  event_callbacks_poll_timers(g_timed_callbacks, &g_event_callbacks_s);
}

OC_PROCESS_THREAD(oc_timed_callback_events, ev, data)
{
  (void)data;
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_timed_callback_events)) {
    OC_PROCESS_YIELD();
    if (ev == OC_PROCESS_EVENT_TIMER) {
      event_callbacks_check();
    }
  }
  OC_PROCESS_END();
}
