/*
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

#include "oc_timer_internal.h"
#include "port/oc_clock.h"

oc_clock_time_t
oc_timer_now(void)
{
  return oc_clock_time_monotonic();
}

void
oc_timer_set(struct oc_timer *t, oc_clock_time_t interval)
{
  t->interval = interval;
  t->start = oc_timer_now();
}

void
oc_timer_reset(struct oc_timer *t)
{
  t->start += t->interval;
}

void
oc_timer_restart(struct oc_timer *t)
{
  t->start = oc_timer_now();
}

static bool
timer_expired(const struct oc_timer *t, oc_clock_time_t now)
{
  if (t->start > now) {
    return false;
  }
  /* Note: Cannot return diff >= t->interval so we add 1 to diff and return
   t->interval < diff - required to avoid an internal error in mspgcc. */
  oc_clock_time_t diff = (now - t->start) + 1;
  return t->interval < diff;
}

bool
oc_timer_expired(const struct oc_timer *t)
{
  return timer_expired(t, oc_timer_now());
}

oc_clock_time_t
oc_timer_until(const struct oc_timer *t, oc_clock_time_t time)
{
  if (timer_expired(t, time)) {
    return 0;
  }
  return t->start + t->interval - time;
}

oc_clock_time_t
oc_timer_remaining(const struct oc_timer *t)
{
  return oc_timer_until(t, oc_timer_now());
}

oc_clock_time_t
oc_timer_expiration_time(const struct oc_timer *t)
{
  return t->start + t->interval;
}
