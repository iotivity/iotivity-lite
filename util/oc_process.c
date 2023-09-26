/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Copyright (c) 2005, Swedish Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "oc_process.h"
#include "oc_process_internal.h"
#include "oc_buffer.h"
#include "util/oc_atomic.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_SECURITY
#include "api/oc_events_internal.h" // oc_event_to_oc_process_event
#include "messaging/coap/coap_internal.h"
#endif /* OC_SECURITY */

#include <stdio.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#include <string.h>
#endif /* OC_DYNAMIC_ALLOCATION */

/*
 * Pointer to the currently running process structure.
 */
struct oc_process *oc_process_list = NULL;
struct oc_process *oc_process_current = NULL;

static oc_process_event_t oc_lastevent = OC_PROCESS_EVENT_MAX;

/*
 * Structure used for keeping the queue of active events.
 */
struct event_data
{
  oc_process_event_t ev;
  oc_process_data_t data;
  struct oc_process *p;
};

#ifdef OC_DYNAMIC_ALLOCATION
static oc_process_num_events_t OC_PROCESS_NUMEVENTS = 10;
#else /* OC_DYNAMIC_ALLOCATION */
#define OC_PROCESS_NUMEVENTS 10
#endif /* !OC_DYNAMIC_ALLOCATION */

static oc_process_num_events_t g_nevents;
static oc_process_num_events_t g_fevent;
#ifdef OC_DYNAMIC_ALLOCATION
static struct event_data *g_events;
#else  /* OC_DYNAMIC_ALLOCATION */
static struct event_data g_events[OC_PROCESS_NUMEVENTS];
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_TEST
#define OC_PROCESS_QUEUED_NUMEVENTS 128
static struct event_data g_queued_events[OC_PROCESS_QUEUED_NUMEVENTS] = { 0 };
static oc_process_num_events_t g_queued_nevents = 0;
static oc_process_num_events_t g_queued_fevent = 0;
#endif /* OC_TEST */

static OC_ATOMIC_INT8_T g_poll_requested;

#define OC_PROCESS_STATE_NONE 0
#define OC_PROCESS_STATE_RUNNING 1
#define OC_PROCESS_STATE_CALLED 2

#ifdef OC_TEST
#define OC_PROCESS_STATE_SUSPENDED 64
#endif /* OC_TEST */

static void call_process(struct oc_process *p, oc_process_event_t ev,
                         oc_process_data_t data);

oc_process_event_t
oc_process_alloc_event(void)
{
  return oc_lastevent++;
}

void
oc_process_start(struct oc_process *p, oc_process_data_t data)
{
  struct oc_process *q;

  /* First make sure that we don't try to start a process that is
     already running. */
  for (q = oc_process_list; q != p && q != NULL; q = q->next)
    ;

  /* If we found the process on the process list, we bail out. */
  if (q == p) {
    return;
  }
  /* Put on the procs list.*/
  p->next = oc_process_list;
  oc_process_list = p;
  p->state = OC_PROCESS_STATE_RUNNING;
  PT_INIT(&p->pt);

  /* Post a synchronous initialization event to the process. */
  oc_process_post_synch(p, OC_PROCESS_EVENT_INIT, data);
}

static void
exit_process(struct oc_process *p, const struct oc_process *fromprocess)
{
  register struct oc_process *q;
  struct oc_process *old_current = oc_process_current;

  /* Make sure the process is in the process list before we try to
     exit it. */
  for (q = oc_process_list; q != p && q != NULL; q = q->next)
    ;
  if (q == NULL) {
    return;
  }

#ifdef OC_TEST
  oc_process_resume(p);
#endif /* OC_TEST */

  int8_t state = OC_ATOMIC_LOAD8(p->state);
  while (state != OC_PROCESS_STATE_NONE) {
    /* Process was running */
    bool swapped;
    OC_ATOMIC_COMPARE_AND_SWAP8(p->state, state, OC_PROCESS_STATE_NONE,
                                swapped);
    if (!swapped) {
      continue;
    }
    state = OC_PROCESS_STATE_NONE;

    /*
     * Post a synchronous event to all processes to inform them that
     * this process is about to exit. This will allow services to
     * deallocate state associated with this process.
     */
    for (q = oc_process_list; q != NULL; q = q->next) {
      if (p != q) {
        call_process(q, OC_PROCESS_EVENT_EXITED, (oc_process_data_t)p);
      }
    }

    if (p->thread != NULL && p != fromprocess) {
      /* Post the exit event to the process that is about to exit. */
      oc_process_current = p;
      p->thread(&p->pt, OC_PROCESS_EVENT_EXIT, NULL);
    }

    break;
  }

  if (p == oc_process_list) {
    oc_process_list = oc_process_list->next;
  } else {
    for (q = oc_process_list; q != NULL; q = q->next) {
      if (q->next == p) {
        q->next = p->next;
        break;
      }
    }
  }

  oc_process_current = old_current;
}

static void
call_process(struct oc_process *p, oc_process_event_t ev,
             oc_process_data_t data)
{
  if (p->thread == NULL) {
    return;
  }

  int8_t state = OC_ATOMIC_LOAD8(p->state);
#ifdef OC_TEST
  if ((state & OC_PROCESS_STATE_SUSPENDED) != 0) {
    oc_process_queue_event(p, ev, data);
    return;
  }
#endif /* OC_TEST */

  while ((state & OC_PROCESS_STATE_RUNNING) != 0) {
    bool swapped;
    OC_ATOMIC_COMPARE_AND_SWAP8(p->state, state, OC_PROCESS_STATE_CALLED,
                                swapped);
    if (!swapped) {
      continue;
    }
    oc_process_current = p;
    char ret = p->thread(&p->pt, ev, data);
    if (ret == PT_EXITED || ret == PT_ENDED || ev == OC_PROCESS_EVENT_EXIT) {
      exit_process(p, p);
      break;
    }
    OC_ATOMIC_STORE8(p->state, OC_PROCESS_STATE_RUNNING);
    break;
  }
}

void
oc_process_exit(struct oc_process *p)
{
  exit_process(p, OC_PROCESS_CURRENT());
}

void
oc_process_shutdown(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  free(g_events);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_process_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  g_events = (struct event_data *)calloc(OC_PROCESS_NUMEVENTS,
                                         sizeof(struct event_data));
  if (!g_events) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_lastevent = OC_PROCESS_EVENT_MAX;

  g_nevents = g_fevent = 0;
  oc_process_current = oc_process_list = NULL;
}

/*
 * Call each process' poll handler.
 */

static void
do_poll(void)
{
  OC_ATOMIC_STORE8(g_poll_requested, 0);
  /* Call the processes that needs to be polled. */
  for (struct oc_process *p = oc_process_list; p != NULL; p = p->next) {
    bool exchanged;
    int8_t expected = 1;
    OC_ATOMIC_COMPARE_AND_SWAP8(p->needspoll, expected, 0, exchanged);
    if (exchanged) {
      OC_ATOMIC_STORE8(p->state, OC_PROCESS_STATE_RUNNING);
      call_process(p, OC_PROCESS_EVENT_POLL, NULL);
    }
  }
}

/*
 * Process the next event in the event queue and deliver it to
 * listening processes.
 */
static void
do_event(void)
{
  static oc_process_event_t ev;
  static oc_process_data_t data;
  static struct oc_process *receiver;
  static struct oc_process *p;

  /*
   * If there are any events in the queue, take the first one and walk
   * through the list of processes to see if the event should be
   * delivered to any of them. If so, we call the event handler
   * function for the process. We only process one event at a time and
   * call the poll handlers inbetween.
   */

  if (g_nevents <= 0) {
    return;
  }

  /* There are events that we should deliver. */
  ev = g_events[g_fevent].ev;
  data = g_events[g_fevent].data;
  receiver = g_events[g_fevent].p;

  /* Since we have seen the new event, we move pointer upwards
     and decrease the number of events. */
  g_fevent = (g_fevent + 1) % OC_PROCESS_NUMEVENTS;
  --g_nevents;

  /* If this is a broadcast event, we deliver it to all events, in
     order of their priority. */
  if (receiver == OC_PROCESS_BROADCAST) {
    for (p = oc_process_list; p != NULL; p = p->next) {

      /* If we have been requested to poll a process, we do this in
         between processing the broadcast event. */
      if (OC_ATOMIC_LOAD8(g_poll_requested)) {
        do_poll();
      }
      call_process(p, ev, data);
    }
  } else {
    /* This is not a broadcast event, so we deliver it to the
 specified process. */
    /* If the event was an INIT event, we should also update the
 state of the process. */
    if (ev == OC_PROCESS_EVENT_INIT) {
      OC_ATOMIC_STORE8(receiver->state, OC_PROCESS_STATE_RUNNING);
    }

    /* Make sure that the process actually is running. */
    call_process(receiver, ev, data);
  }
}

int
oc_process_run(void)
{
  /* Process poll events. */
  if (OC_ATOMIC_LOAD8(g_poll_requested)) {
    do_poll();
  }

  /* Process one event from the queue */
  do_event();

  return (int)g_nevents + OC_ATOMIC_LOAD8(g_poll_requested);
}

int
oc_process_nevents(void)
{
  return (int)g_nevents + OC_ATOMIC_LOAD8(g_poll_requested);
}

bool
oc_process_needs_poll(void)
{
  return OC_ATOMIC_LOAD8(g_poll_requested) != 0;
}

#ifdef OC_SECURITY
bool
oc_process_is_closing_all_tls_sessions(void)
{
  const oc_process_event_t tls_close =
    oc_event_to_oc_process_event(TLS_CLOSE_ALL_SESSIONS);
  for (oc_process_num_events_t i = 0; i < g_nevents; ++i) {
    oc_process_num_events_t index = (g_fevent + i) % OC_PROCESS_NUMEVENTS;
    if (g_events[index].ev == tls_close) {
      return true;
    }
  }
  return false;
}
#endif /* OC_SECURITY */

void
oc_process_iterate_events(oc_process_iterate_event_fn_t fn, void *fn_data)
{
  for (oc_process_num_events_t i = 0; i < g_nevents; ++i) {
    oc_process_num_events_t index = (g_fevent + i) % OC_PROCESS_NUMEVENTS;
    struct event_data *event = &g_events[index];
    if (!fn(event->p, event->ev, event->data, fn_data)) {
      return;
    }
  }
}

int
oc_process_drop(const struct oc_process *p, oc_process_drop_event_t drop_event,
                const void *user_data)
{
  int dropped = 0;

  if (!p || !drop_event) {
    return dropped;
  }

  oc_process_num_events_t i = 0;
  while (i < g_nevents) {
    oc_process_num_events_t index = (g_fevent + i) % OC_PROCESS_NUMEVENTS;
    struct event_data *event = &g_events[index];
    if (event->p != p || !drop_event(event->ev, event->data, user_data)) {
      // move to the next event
      ++i;
      continue;
    }
    // we have a match, drop the event and move the last event to its position
    if (g_nevents > 1) {
      oc_process_num_events_t last_index =
        (g_fevent + g_nevents - 1) % OC_PROCESS_NUMEVENTS;

      if (last_index >= index) {
        memmove(event, event + 1,
                (last_index - index) * sizeof(struct event_data));
      } else {
        // Handle rotation when last_index is wrapped around to the beginning of
        // the array
        memmove(event, event + 1,
                (OC_PROCESS_NUMEVENTS - 1 - index) * sizeof(struct event_data));
        g_events[OC_PROCESS_NUMEVENTS - 1] = g_events[0];
        memmove(g_events, g_events + 1, last_index * sizeof(struct event_data));
      }
    }
    --g_nevents;
    ++dropped;
  }
  return dropped;
}

int
oc_process_post(struct oc_process *p, oc_process_event_t ev,
                oc_process_data_t data)
{
  static oc_process_num_events_t snum;

  if (g_nevents == OC_PROCESS_NUMEVENTS) {
#ifdef OC_DYNAMIC_ALLOCATION
    OC_PROCESS_NUMEVENTS <<= 1;
    g_events = (struct event_data *)realloc(
      g_events, OC_PROCESS_NUMEVENTS * sizeof(struct event_data));
    if (!g_events) {
      oc_abort("Insufficient memory");
    }
    oc_process_num_events_t i = g_fevent;
    oc_process_num_events_t n = g_nevents - g_fevent;
    oc_process_num_events_t j = 0;
    while (i < (OC_PROCESS_NUMEVENTS - n)) {
      if (i < g_nevents) {
        memcpy(&g_events[OC_PROCESS_NUMEVENTS - n + j], &g_events[i],
               sizeof(struct event_data));
        j++;
      }
      memset(&g_events[i], 0, sizeof(struct event_data));
      i++;
    }
    g_fevent = OC_PROCESS_NUMEVENTS - n;
#else  /* OC_DYNAMIC_ALLOCATION */
    return OC_PROCESS_ERR_FULL;
#endif /* !OC_DYNAMIC_ALLOCATION */
  }

  snum = (g_fevent + g_nevents) % OC_PROCESS_NUMEVENTS;
  g_events[snum].ev = ev;
  g_events[snum].data = data;
  g_events[snum].p = p;
  ++g_nevents;

  return OC_PROCESS_ERR_OK;
}

void
oc_process_post_synch(struct oc_process *p, oc_process_event_t ev,
                      oc_process_data_t data)
{
  struct oc_process *caller = oc_process_current;

  call_process(p, ev, data);
  oc_process_current = caller;
}

void
oc_process_poll(struct oc_process *p)
{
  if (p != NULL) {
    unsigned char state = OC_ATOMIC_LOAD8(p->state);
    if (state == OC_PROCESS_STATE_RUNNING || state == OC_PROCESS_STATE_CALLED) {
      OC_ATOMIC_STORE8(p->needspoll, 1);
      OC_ATOMIC_STORE8(g_poll_requested, 1);
    }
  }
}

int
oc_process_is_running(const struct oc_process *p)
{
  return OC_ATOMIC_LOAD8(p->state) != OC_PROCESS_STATE_NONE ? 1 : 0;
}

#ifdef OC_TEST

oc_process_num_events_t
oc_process_num_events(void)
{
  return OC_PROCESS_NUMEVENTS;
}

void
oc_process_suspend(struct oc_process *p)
{
  int8_t state = OC_ATOMIC_LOAD8(p->state);
  while ((state & OC_PROCESS_STATE_SUSPENDED) == 0) {
    bool swapped;
    OC_ATOMIC_COMPARE_AND_SWAP8(p->state, state,
                                state | OC_PROCESS_STATE_SUSPENDED, swapped);
    if (!swapped) {
      continue;
    }
    return;
  }
}

void
oc_process_resume(struct oc_process *p)
{
  int8_t state = OC_ATOMIC_LOAD8(p->state);
  while ((state & OC_PROCESS_STATE_SUSPENDED) != 0) {
    bool swapped;
    OC_ATOMIC_COMPARE_AND_SWAP8(p->state, state,
                                state & ~OC_PROCESS_STATE_SUSPENDED, swapped);
    if (!swapped) {
      continue;
    }
    oc_process_unqueue_events();
    return;
  }
}

int
oc_process_queue_event(struct oc_process *p, oc_process_event_t ev,
                       oc_process_data_t data)
{
  if (g_queued_nevents == OC_PROCESS_QUEUED_NUMEVENTS) {
    return OC_PROCESS_ERR_FULL;
  }
  oc_process_num_events_t snum =
    (g_queued_fevent + g_queued_nevents) % OC_PROCESS_QUEUED_NUMEVENTS;
  g_queued_events[snum].ev = ev;
  g_queued_events[snum].data = data;
  g_queued_events[snum].p = p;
  ++g_queued_nevents;

  return OC_PROCESS_ERR_OK;
}

void
oc_process_unqueue_events(void)
{
  while (g_queued_nevents > 0) {
    oc_process_event_t event = g_queued_events[g_queued_fevent].ev;
    oc_process_data_t data = g_queued_events[g_queued_fevent].data;
    struct oc_process *process = g_queued_events[g_queued_fevent].p;

    oc_process_post(process, event, data);

    g_queued_fevent = (g_queued_fevent + 1) % OC_PROCESS_QUEUED_NUMEVENTS;
    --g_queued_nevents;
  }
}

#endif /* OC_TEST */
