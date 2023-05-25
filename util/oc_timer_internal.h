/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ******************************************************************/

/**
 * \defgroup timer Timer library
 *
 * The Contiki kernel does not provide support for timed
 * events. Rather, an application that wants to use timers needs to
 * explicitly use the timer library.
 *
 * The timer library provides functions for setting, resetting and
 * restarting timers, and for checking if a timer has expired. An
 * application must "manually" check if its timers have expired; this
 * is not done automatically.
 *
 * A timer is declared as a \c struct \c timer and all access to the
 * timer is made by a pointer to the declared timer.
 *
 * \note The timer library is not able to post events when a timer
 * expires. The \ref etimer "Event timers" should be used for this
 * purpose.
 *
 * \note The timer library uses the \ref clock "Clock library" to
 * measure time. Intervals should be specified in the format used by
 * the clock library.
 *
 * \sa \ref etimer "Event timers"
 *
 * @{
 */

#ifndef OC_TIMER_INTERNAL_H
#define OC_TIMER_INTERNAL_H

#include "port/oc_clock.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A timer.
 *
 * This structure is used for declaring a timer. The timer must be set
 * with timer_set() before it can be used.
 *
 * \hideinitializer
 */
struct oc_timer
{
  oc_clock_time_t start;
  oc_clock_time_t interval;
};

/**
 * Set a timer.
 *
 * This function is used to set a timer for a time sometime in the
 * future. The function oc_timer_expired() will evaluate to true after
 * the timer has expired.
 *
 * \param t A pointer to the timer (cannot be NULL).
 * \param interval The interval before the timer expires.
 */
void oc_timer_set(struct oc_timer *t, oc_clock_time_t interval) OC_NONNULL();

/**
 * Reset the timer with the same interval.
 *
 * This function resets the timer with the same interval that was
 * given to the oc_timer_set() function. The start point of the interval
 * is the exact time that the timer last expired. Therefore, this
 * function will cause the timer to be stable over time, unlike the
 * oc_timer_restart() function.
 *
 * \note Must not be executed before timer expired
 *
 * \param t A pointer to the timer (cannot be NULL).
 * \sa oc_timer_restart()
 */
void oc_timer_reset(struct oc_timer *t) OC_NONNULL();

/**
 * Restart the timer from the current point in time
 *
 * This function restarts a timer with the same interval that was
 * given to the oc_timer_set() function. The timer will start at the
 * current time.
 *
 * \note A periodic timer will drift if this function is used to reset
 * it. For preioric timers, use the oc_timer_reset() function instead.
 *
 * \param t A pointer to the timer (cannot be NULL)
 *
 * \sa oc_timer_reset()
 */
void oc_timer_restart(struct oc_timer *t) OC_NONNULL();

/**
 * Check if a timer has expired.
 *
 * This function tests if a timer has expired and returns true or
 * false depending on its status.
 *
 * \param t A pointer to the timer (cannot be NULL)
 *
 * \return True if the timer has expired, false otherwise.
 */
bool oc_timer_expired(const struct oc_timer *t) OC_NONNULL();

/**
 * \brief Calculate remaining time until deadline.
 *
 * \param t A pointer to the timer (cannot be NULL).
 * \param time Deadline
 * \return oc_clock_time_t
 */
oc_clock_time_t oc_timer_until(const struct oc_timer *t, oc_clock_time_t time)
  OC_NONNULL();

/**
 * The time until the timer expires
 *
 * This function returns the time until the timer expires.
 *
 * \param t A pointer to the timer (cannot be NULL)
 *
 * \return (oc_clock_time_t)-1 if the timer is expired
 * \return The time until the timer expires
 */
oc_clock_time_t oc_timer_remaining(const struct oc_timer *t) OC_NONNULL();

/**
 * \brief      Get the expiration time for the timer
 * \param t    A pointer to the timer (cannot be NULL)
 * \return     The expiration time for the timer
 */
oc_clock_time_t oc_timer_expiration_time(const struct oc_timer *t) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_TIMER_INTERNAL_H */

/** @} */
