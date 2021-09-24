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

#ifndef OC_SWUPDATE_INTERNAL_H
#define OC_SWUPDATE_INTERNAL_H

#include "oc_ri.h"
#include "port/oc_clock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_SWUPDATE_STATE_IDLE,
  OC_SWUPDATE_STATE_NSA,
  OC_SWUPDATE_STATE_SVV,
  OC_SWUPDATE_STATE_SVA,
  OC_SWUPDATE_STATE_UPGRADING
} oc_swupdate_state_t;

typedef enum {
  OC_SWUPDATE_IDLE,
  OC_SWUPDATE_ISAC,
  OC_SWUPDATE_ISVV,
  OC_SWUPDATE_UPGRADE
} oc_swupdate_action_t;

typedef struct
{
  oc_string_t purl;
  oc_string_t nv;
  oc_string_t signage;
  oc_swupdate_action_t swupdateaction;
  oc_swupdate_state_t swupdatestate;
  int swupdateresult;
  oc_clock_time_t lastupdate;
  oc_clock_time_t updatetime;
} oc_swupdate_t;

void oc_swupdate_free(void);
void oc_swupdate_init(void);

/* Internal interface to swupdate resource used for handling sw update requests
 * via pstat */
void oc_swupdate_perform_action(oc_swupdate_action_t action, size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_SWUPDATE_INTERNAL_H */
