/*
// Copyright (c) 2018 Intel Corporation
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

#ifndef OC_LOG_ANDROID_H
#define OC_LOG_ANDROID_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <android/log.h>
#include "oc_endpoint.h"

#ifdef __cplusplus
extern "C"
{
#endif

void android_log(const char *level, const char *file, const char *func, int line, ...);
void android_log_ipaddr(const char *level, const char *file, const char *func, int line, oc_endpoint_t endpoint);
void android_log_bytes(const char *level, const char *file, const char *func, int line, uint8_t *bytes, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* OC_LOG_ANDROID_H */
