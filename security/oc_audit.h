/*
// Copyright (c) 2016-2019 Intel Corporation
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

#ifndef OC_AUDIT_H
#define OC_AUDIT_H

#include "oc_uuid.h"
#include "port/oc_log.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

void oc_audit_log(char *message, uint8_t category, uint8_t priority, char **aux, size_t aux_len) {
  OC_ERR("audit_log: %s %u %u", message, category, priority);
  size_t i;
  for (i = 0; i < aux_len; ++i) {
    OC_ERR("audit_log: %s", aux[i]);
  }
}

#ifdef __cplusplus
}
#endif

#endif /* OC_AUDIT_H */
