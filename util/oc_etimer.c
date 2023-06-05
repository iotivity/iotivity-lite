/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "oc_etimer_internal.h"

#include "oc_process.h"
#include "port/oc_log_internal.h"
#include "util/oc_timer_internal.h"

static struct oc_etimer *g_timerlist;
static oc_clock_time_t
  g_next_expiration; ///< next expiration time in monotonic clock ticks

OC_PROCESS(oc_etimer_process, "Event timer");

static void
etimer_update_time(void)
{
  if (g_timerlist == NULL) {
    OC_DBG("etimer: no expiring timers");
    g_next_expiration = 0;
    return;
  }

  oc_clock_time_t now = oc_timer_now();
  struct oc_etimer *t = g_timerlist;
  /* Must calculate distance to next time into account due to wraps */
  oc_clock_time_t tdist = oc_timer_until(&t->timer, now);
  for (t = t->next; t != NULL; t = t->next) {
    oc_clock_time_t tdist2 = oc_timer_until(&t->timer, now);
    if (tdist2 < tdist) {
      tdist = tdist2;
    }
  }
  g_next_expiration = now + tdist;
  OC_DBG("etimer: next expiration=%ld", (long)g_next_expiration);
}

static bool
etimer_process_poll(void)
{
  struct oc_etimer *prev = NULL;
  for (struct oc_etimer *t = g_timerlist; t != NULL; prev = t, t = t->next) {
    if (!oc_timer_expired(&t->timer)) {
      continue;
    }
    if (oc_process_post(t->p, OC_PROCESS_EVENT_TIMER, t) != OC_PROCESS_ERR_OK) {
      OC_DBG("cannot send timer event to process, scheduling retry by polling");
      oc_process_poll(&oc_etimer_process);
      continue;
    }

    /* Reset the process ID of the event timer, to signal that the
       etimer has expired. This is later checked in the
       oc_etimer_expired() function. */
    t->p = OC_PROCESS_NONE;
    if (prev != NULL) {
      prev->next = t->next;
    } else {
      g_timerlist = t->next;
    }
    t->next = NULL;
    etimer_update_time();
    return true;
  }
  return false;
}

static void
etimer_remove_process_pending_timers(const struct oc_process *p)
{
  while (g_timerlist != NULL && g_timerlist->p == p) {
    OC_DBG("etimer(%p) removed from pending list", (void *)g_timerlist);
    g_timerlist = g_timerlist->next;
  }

  if (g_timerlist == NULL) {
    return;
  }
  struct oc_etimer *t = g_timerlist;
  while (t->next != NULL) {
    if (t->next->p == p) {
      OC_DBG("etimer(%p) removed from pending list", (void *)t->next);
      t->next = t->next->next;
    } else
      t = t->next;
  }
}

OC_PROCESS_THREAD(oc_etimer_process, ev, data)
{
  OC_PROCESS_BEGIN();
  g_timerlist = NULL;

  while (oc_process_is_running(&oc_etimer_process)) {
    OC_PROCESS_YIELD();
    if (ev == OC_PROCESS_EVENT_EXITED) {
      etimer_remove_process_pending_timers((struct oc_process *)data);
      continue;
    }
    if (ev != OC_PROCESS_EVENT_POLL) {
      continue;
    }

    while (etimer_process_poll()) {
      // keep polling until all timers are updated
    }
  }

  OC_PROCESS_END();
}

oc_clock_time_t
oc_etimer_request_poll(void)
{
  oc_process_poll(&oc_etimer_process);
  return oc_etimer_next_expiration_time();
}

static void
etimer_add_timer(struct oc_etimer *timer)
{
  oc_process_poll(&oc_etimer_process);

  bool is_in_list = false;
  if (timer->p != OC_PROCESS_NONE) {
    for (const struct oc_etimer *t = g_timerlist; t != NULL; t = t->next) {
      if (t == timer) {
        /* Timer already in list. */
        is_in_list = true;
        break;
      }
    }
  }

  if (!is_in_list) {
    /* Timer not in list -> add it to front. */
    timer->next = g_timerlist;
    g_timerlist = timer;
  }
  timer->p = OC_PROCESS_CURRENT();
  etimer_update_time();
}

void
oc_etimer_set(struct oc_etimer *et, oc_clock_time_t interval)
{
  OC_DBG("etimer(%p) set", (void *)et);
  oc_timer_set(&et->timer, interval);
  etimer_add_timer(et);
}

void
oc_etimer_reset_with_new_interval(struct oc_etimer *et,
                                  oc_clock_time_t interval)
{
  oc_timer_reset(&et->timer);
  et->timer.interval = interval;
  etimer_add_timer(et);
}

void
oc_etimer_reset(struct oc_etimer *et)
{
  oc_timer_reset(&et->timer);
  etimer_add_timer(et);
}

void
oc_etimer_restart(struct oc_etimer *et)
{
  oc_timer_restart(&et->timer);
  etimer_add_timer(et);
}

void
oc_etimer_adjust(struct oc_etimer *et, int timediff)
{
  et->timer.start += timediff;
  etimer_update_time();
}

bool
oc_etimer_expired(const struct oc_etimer *et)
{
  return et->p == OC_PROCESS_NONE;
}

oc_clock_time_t
oc_etimer_expiration_time(const struct oc_etimer *et)
{
  return oc_timer_expiration_time(&et->timer);
}

oc_clock_time_t
oc_etimer_start_time(const struct oc_etimer *et)
{
  return et->timer.start;
}

bool
oc_etimer_pending(void)
{
  return g_timerlist != NULL;
}

oc_clock_time_t
oc_etimer_next_expiration_time(void)
{
  return oc_etimer_pending() ? g_next_expiration : 0;
}

void
oc_etimer_stop(struct oc_etimer *et)
{
  /* First check if et is the first event timer on the list. */
  if (et == g_timerlist) {
    g_timerlist = g_timerlist->next;

    etimer_update_time();
  } else {
    /* Else walk through the list and try to find the item before the
       et timer. */
    struct oc_etimer *t;
    for (t = g_timerlist; t != NULL && t->next != et; t = t->next)
      ;

    if (t != NULL) {
      /* We've found the item before the event timer that we are about
   to remove. We point the items next pointer to the event after
   the removed item. */
      t->next = et->next;

      etimer_update_time();
    }
  }

  /* Remove the next pointer from the item to be removed. */
  et->next = NULL;
  /* Set the timer as expired */
  et->p = OC_PROCESS_NONE;
}

/** @} */
