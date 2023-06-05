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

#include "c-timestamp/timestamp.h"
#include "oc_clock_util.h"
#include "oc_config.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "c-timestamp/timestamp.h"

#include <assert.h>

#define OC_NSEC_PER_SEC (1000000000)

size_t
oc_clock_time_rfc3339(char *out_buf, size_t out_buf_len)
{
  return oc_clock_encode_time_rfc3339(oc_clock_time(), out_buf, out_buf_len);
}

size_t
oc_clock_encode_time_rfc3339(oc_clock_time_t time, char *out_buf,
                             size_t out_buf_len)
{
  timestamp_t now_t = { 0 };
  now_t.sec = (int64_t)(time / OC_CLOCK_SECOND);
  now_t.nsec =
    (int32_t)((time % OC_CLOCK_SECOND) * (OC_NSEC_PER_SEC / OC_CLOCK_SECOND));

  return timestamp_format(out_buf, out_buf_len, &now_t);
}

oc_clock_time_t
oc_clock_parse_time_rfc3339(const char *in_buf, size_t in_buf_len)
{
  oc_clock_time_t ct;
  if (!oc_clock_parse_time_rfc3339_v1(in_buf, in_buf_len, &ct)) {
    return 0;
  }
  return ct;
}

bool
oc_clock_parse_time_rfc3339_v1(const char *in_buf, size_t in_buf_len,
                               oc_clock_time_t *time)
{
  assert(time != NULL);
  timestamp_t in_time = { 0 };
  int ret = timestamp_parse(in_buf, in_buf_len, &in_time);
  if (ret != 0) {
    OC_ERR("error parsing time in RFC3339 formatted string");
    return false;
  }
  *time = in_time.sec * OC_CLOCK_SECOND +
          (in_time.nsec * OC_CLOCK_SECOND) / OC_NSEC_PER_SEC;
  return true;
}

#ifdef OC_HAVE_TIME_H

struct timespec
oc_clock_time_to_timespec(oc_clock_time_t time)
{
  struct timespec ts = {
    .tv_sec = (time_t)(time / OC_CLOCK_SECOND),
    .tv_nsec =
      (long)((double)(time % OC_CLOCK_SECOND) * (1.e09 / OC_CLOCK_SECOND)),
  };
  return ts;
}

#ifdef OC_HAVE_CLOCKID_T

bool
oc_clock_monotonic_time_to_posix(oc_clock_time_t time, clockid_t clock_id,
                                 oc_clock_time_t *clock_time)
{
  oc_clock_time_t clock_mt = oc_clock_time_monotonic();
  if (clock_mt == (oc_clock_time_t)-1) {
    return false;
  }

  struct timespec ts;
  if (clock_gettime(clock_id, &ts) != 0) {
    return false;
  }
  oc_clock_time_t posix_time = ts.tv_sec * OC_CLOCK_SECOND +
                               (ts.tv_nsec * OC_CLOCK_SECOND) / OC_NSEC_PER_SEC;

  *clock_time = posix_time + ((int64_t)time - clock_mt);
  return true;
}

#endif /* OC_HAVE_CLOCKID_T */

#endif /* OC_HAVE_TIME_H */
