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
/**
 * @file
 */
#ifndef OC_CLOCK_UTIL_H
#define OC_CLOCK_UTIL_H

#include "oc_config.h"
#include <stddef.h>

size_t oc_clock_time_rfc3339(char *out_buf, size_t out_buf_len);

size_t oc_clock_encode_time_rfc3339(oc_clock_time_t time, char *out_buf,
                                    size_t out_buf_len);

oc_clock_time_t oc_clock_parse_time_rfc3339(const char *in_buf,
                                            size_t in_buf_len);

#endif /* OC_CLOCK_UTIL_H */
