/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "port/oc_clock.h"
#include "c-timestamp/timestamp.h"
#include "port/oc_log.h"

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
  now_t.nsec = (int32_t)((time % OC_CLOCK_SECOND) * (1.e09 / OC_CLOCK_SECOND));

  return timestamp_format(out_buf, out_buf_len, &now_t);
}

oc_clock_time_t
oc_clock_parse_time_rfc3339(const char *in_buf, size_t in_buf_len)
{
  timestamp_t in_time = { 0 };

  int ret = timestamp_parse(in_buf, in_buf_len, &in_time);

  if (ret != 0) {
    OC_ERR("error parsing time in RFC3339 formatted string");
    return 0;
  }

  oc_clock_time_t t =
    ((in_time.sec * 1.e09) + in_time.nsec) * OC_CLOCK_SECOND / 1.e09;

  return t;
}
