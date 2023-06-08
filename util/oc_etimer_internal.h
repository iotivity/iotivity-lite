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

/**
 * \defgroup etimer Event timers
 *
 * Event timers provides a way to generate timed events. An event
 * timer will post an event to the process that set the timer when the
 * event timer expires.
 *
 * An event timer is declared as a \c struct \c etimer and all access
 * to the event timer is made by a pointer to the declared event
 * timer.
 *
 * \sa \ref timer "Simple timer library"
 * \sa \ref clock "Clock library" (used by the timer library)
 *
 * @{
 */

#ifndef OC_ETIMER_INTERNAL_H
#define OC_ETIMER_INTERNAL_H

#include "oc_config.h"
#include "oc_process.h"
#include "oc_timer_internal.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A timer.
 *
 * This structure is used for declaring a timer. The timer must be set
 * with oc_etimer_set() before it can be used.
 *
 * \hideinitializer
 */
struct oc_etimer
{
  struct oc_timer timer;
  struct oc_etimer *next;
  struct oc_process *p; // oc_process associated with the timer
};

/**
 * \name Functions called from application programs
 * @{
 */

/**
 * \brief      Set an event timer.
 * \param et   A pointer to the event timer
 * \param interval The interval before the timer expires.
 *
 *             This function is used to set an event timer for a time
 *             sometime in the future. When the event timer expires,
 *             the event PROCESS_EVENT_TIMER will be posted to the
 *             process that called the oc_etimer_set() function.
 *
 *             The oc_process of the event timer will be set to the value
 *             returned by OC_PROCESS_CURRENT()
 *
 * \sa OC_PROCESS_CURRENT
 */
void oc_etimer_set(struct oc_etimer *et, oc_clock_time_t interval) OC_NONNULL();

/**
 * \brief      Reset an event timer with the same interval as was
 *             previously set.
 * \param et   A pointer to the event timer.
 *
 *             This function resets the event timer with the same
 *             interval that was given to the event timer with the
 *             oc_etimer_set() function. The start point of the interval
 *             is the exact time that the event timer last
 *             expired. Therefore, this function will cause the timer
 *             to be stable over time, unlike the oc_etimer_restart()
 *             function.
 *
 * \sa oc_etimer_restart()
 */
void oc_etimer_reset(struct oc_etimer *et) OC_NONNULL();

/**
 * \brief      Reset an event timer with a new interval.
 * \param et   A pointer to the event timer.
 * \param interval The interval before the timer expires.
 *
 *             This function very similar to oc_etimer_reset. Opposed to
 *             oc_etimer_reset it is possible to change the timout.
 *             This allows accurate, non-periodic timers without drift.
 *
 * \sa oc_etimer_reset()
 */
void oc_etimer_reset_with_new_interval(struct oc_etimer *et,
                                       oc_clock_time_t interval) OC_NONNULL();

/**
 * \brief      Restart an event timer from the current point in time
 * \param et   A pointer to the event timer.
 *
 *             This function restarts the event timer with the same
 *             interval that was given to the oc_etimer_set()
 *             function. The event timer will start at the current
 *             time.
 *
 *             \note A periodic timer will drift if this function is
 *             used to reset it. For periodic timers, use the
 *             oc_etimer_reset() function instead.
 *
 * \sa oc_etimer_reset()
 */
void oc_etimer_restart(struct oc_etimer *et) OC_NONNULL();

/**
 * \brief      Adjust the expiration time for an event timer
 * \param et   A pointer to the event timer.
 * \param td   The time difference to adjust the expiration time with.
 *
 *             This function is used to adjust the time the event
 *             timer will expire. It can be used to synchronize
 *             periodic timers without the need to restart the timer
 *             or change the timer interval.
 *
 *             \note This function should only be used for small
 *             adjustments. For large adjustments use oc_etimer_set()
 *             instead.
 *
 *             \note A periodic timer will drift unless the
 *             oc_etimer_reset() function is used.
 *
 * \sa oc_etimer_set()
 * \sa oc_etimer_reset()
 */
void oc_etimer_adjust(struct oc_etimer *et, int td) OC_NONNULL();

/**
 * \brief      Get the expiration time for the event timer.
 *
 * \param et   A pointer to the event timer (cannot be NULL)
 * \return     The expiration time for the event timer.
 */
oc_clock_time_t oc_etimer_expiration_time(const struct oc_etimer *et)
  OC_NONNULL();

/**
 * \brief      Get the start time (when the timer was last set) for the event
 * timer.
 *
 * \param et   A pointer to the event timer
 * \return     The start time for the event timer.
 */
oc_clock_time_t oc_etimer_start_time(const struct oc_etimer *et) OC_NONNULL();

/**
 * \brief      Check if an event timer has expired.
 * \param et   A pointer to the event timer
 * \return     Non-zero if the timer has expired, zero otherwise.
 *
 *             This function tests if an event timer has expired and
 *             returns true or false depending on its status.
 */
bool oc_etimer_expired(const struct oc_etimer *et) OC_NONNULL();

/**
 * \brief      Stop a pending event timer.
 * \param et   A pointer to the pending event timer.
 *
 *             This function stops an event timer that has previously
 *             been set with oc_etimer_set() or oc_etimer_reset(). After
 *             this function has been called, the event timer will not
 *             emit any event when it expires.
 */
void oc_etimer_stop(struct oc_etimer *et) OC_NONNULL();

/** @} */

/**
 * \name Functions called from timer interrupts, by the system
 * @{
 */

/**
 * \brief      Make the event timer aware that the clock has changed
 *
 *             This function is used to inform the event timer module
 *             that the system clock has been updated. Typically, this
 *             function would be called from the timer interrupt
 *             handler when the clock has ticked.
 *
 * \note       Internally, monotonic clock is used for event timers.
 *
 * \return     Next timer expiration time.
 */
oc_clock_time_t oc_etimer_request_poll(void);

/**
 * \brief      Check if there are any non-expired event timers.
 * \return     True if there are active event timers, false if there are
 *             no active timers.
 *
 *             This function checks if there are any active event
 *             timers that have not expired.
 */
bool oc_etimer_pending(void);

/**
 * \brief      Get next event timer expiration time.
 * \return     Next expiration time of all pending event timers.
 *             If there are no pending event timers this function
 *	           returns 0.
 *
 *             This functions returns next expiration time of all
 *             pending event timers.
 */
oc_clock_time_t oc_etimer_next_expiration_time(void);

OC_PROCESS_NAME(oc_etimer_process);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* OC_ETIMER_INTERNAL_H  */

/** @} */
