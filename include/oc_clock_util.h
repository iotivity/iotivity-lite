/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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
/**
 * @file
 */
#ifndef OC_CLOCK_UTIL_H
#define OC_CLOCK_UTIL_H

#include "oc_config.h"
#include "oc_export.h"
#include "util/oc_compiler.h"
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef OC_HAVE_TIME_H
#include <time.h>
#endif /* OC_HAVE_TIME_H */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief retrieve time as rfc3339 time (e.g. string)
 *
 * @param[out] out_buf allocated buffer (cannot be NULL)
 * @param out_buf_len buffer lenght of the allocated buffer
 * @return size_t used buffer size
 */
OC_API
size_t oc_clock_time_rfc3339(char *out_buf, size_t out_buf_len) OC_NONNULL();

/**
 * @brief encode time as rfc3339 time
 *
 * @param time time from the oc clock
 * @param[out] out_buf allocated buffer to store time in rfc3339 format (cannot
 * be NULL)
 * @param out_buf_len the allocated buffer size
 * @return size_t the used buffer size
 */
OC_API
size_t oc_clock_encode_time_rfc3339(oc_clock_time_t time, char *out_buf,
                                    size_t out_buf_len) OC_NONNULL();

/**
 * @brief parse rfc3339 time into oc_clock format
 *
 * @param in_buf buffer with rfc3339 time (cannot be NULL)
 * @param in_buf_len the lenght of the buffer
 * @param[out] time the parsed time (cannot be NULL)
 *
 * @return true if parsing was successful
 * @return false otherwise
 */
OC_API
bool oc_clock_parse_time_rfc3339_v1(const char *in_buf, size_t in_buf_len,
                                    oc_clock_time_t *time) OC_NONNULL();

/**
 * @brief parse rfc3339 time into oc_clock format
 *
 * @warning this implementation cannot distinguish between parsing errors and
 * the start of UNIX epoch (1970-01-01T00:00:00Z) and returns 0 in both cases.
 *
 * @deprecated replaced by oc_clock_parse_time_rfc3339_v1 in 2.2.5.6
 */
OC_API
oc_clock_time_t oc_clock_parse_time_rfc3339(const char *in_buf,
                                            size_t in_buf_len)
  OC_DEPRECATED("replaced by oc_clock_parse_time_rfc3339_v1 in v2.2.5.6");

#ifdef OC_HAVE_TIME_H

/**
 * @brief Convert oc_clock_time_t into a C struct timespec.
 */
OC_API
struct timespec oc_clock_time_to_timespec(oc_clock_time_t time);

/**
 * @brief Convert a C struct timespec into oc_clock_time_t.
 */
OC_API
oc_clock_time_t oc_clock_time_from_timespec(struct timespec ts);

#ifdef OC_HAVE_CLOCKID_T

/**
 * @brief Convert monotonic oc_clock time into a clock time with an offset of
 * the defined POSIX clock.
 *
 * @param time_mt clock time retrieved by oc_clock_time_monotonic()
 * @param clock_id POSIX clock ID
 * @param[out] time clock time with an offset of the defined POSIX clock (cannot
 * be NULL)
 * @return true on success
 * @return false on failure
 */
OC_API
bool oc_clock_monotonic_time_to_posix(oc_clock_time_t time_mt,
                                      clockid_t clock_id, oc_clock_time_t *time)
  OC_NONNULL();

#endif /* OC_HAVE_CLOCKID_T */

#endif /* OC_HAVE_TIME_H */

/**
 * @brief Convert clock time into a C struct timespec
 */
struct timespec oc_clock_time_to_timespec(oc_clock_time_t time);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOCK_UTIL_H */
