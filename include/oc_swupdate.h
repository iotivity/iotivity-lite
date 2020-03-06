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
  @file
*/
#ifndef OC_SWUPDATE_H
#define OC_SWUPDATE_H

#include "oc_ri.h"
#include "port/oc_clock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_SWUPDATE_RESULT_IDLE = 0,
  OC_SWUPDATE_RESULT_SUCCESS,
  OC_SWUPDATE_RESULT_LESS_RAM,
  OC_SWUPDATE_RESULT_LESS_FLASH,
  OC_SWUPDATE_RESULT_CONN_FAIL,
  OC_SWUPDATE_RESULT_SVV_FAIL,
  OC_SWUPDATE_RESULT_INVALID_URL,
  OC_SWUPDATE_RESULT_UPGRADE_FAIL,
} oc_swupdate_result_t;

void oc_swupdate_notify_new_version_available(size_t device,
                                              const char *version,
                                              oc_swupdate_result_t result);
void oc_swupdate_notify_downloaded(size_t device, const char *version,
                                   oc_swupdate_result_t result);
void oc_swupdate_notify_upgrading(size_t device, const char *version,
                                  oc_clock_time_t timestamp,
                                  oc_swupdate_result_t result);
void oc_swupdate_notify_done(size_t device, oc_swupdate_result_t result);

typedef struct
{
  int (*validate_purl)(const char *url);
  int (*check_new_version)(size_t device, const char *url, const char *version);
  int (*download_update)(size_t device, const char *url);
  int (*perform_upgrade)(size_t device, const char *url);
} oc_swupdate_cb_t;

void oc_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl);

#ifdef __cplusplus
}
#endif

#endif /* OC_SWUPDATE_H */
