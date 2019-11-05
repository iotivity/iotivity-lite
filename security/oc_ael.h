/*
// Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef OC_AEL_H
#define OC_AEL_H

#include <stdbool.h>

#include "oc_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  char *dev_type;
  oc_uuid_t di;
  uint8_t category;
  uint8_t priority;
  uint32_t timestamp;
  char *message;
  char **aux_info;
  size_t aux_size;
} oc_sec_ael_event_t;

typedef enum {
  OC_SEC_AEL_LOGCATEGORY_ACCESS_CONTROL = 0x01,
  OC_SEC_AEL_LOGCATEGORY_ONBOARDING = 0x02,
  OC_SEC_AEL_LOGCATEGORY_DEVICE = 0x04,
  OC_SEC_AEL_LOGCATEGORY_AUTHENTICATION = 0x08,
  OC_SEC_AEL_LOGCATEGORY_SVR_MODIFICATION = 0x10,
  OC_SEC_AEL_LOGCATEGORY_CLOUD = 0x20,
  OC_SEC_AEL_LOGCATEGORY_COMMUNICATION = 0x40,
  OC_SEC_AEL_LOGCATEGORY_ALL = 0xFF,
  OC_SEC_AEL_LOGCATEGORY_DEFAULT = OC_SEC_AEL_LOGCATEGORY_ALL,
} oc_sec_ael_logcategory_t;

typedef enum {
  OC_SEC_AEL_LOGLEVEL_CRIT = 0,
  OC_SEC_AEL_LOGLEVEL_ERR,
  OC_SEC_AEL_LOGLEVEL_WARN,
  OC_SEC_AEL_LOGLEVEL_INFO,
  OC_SEC_AEL_LOGLEVEL_DEBUG,
  OC_SEC_AEL_LOGLEVEL_DEFAULT = OC_SEC_AEL_LOGLEVEL_DEBUG,
} oc_sec_ael_loglevel_t;

typedef enum {
  OC_SEC_AEL_UNIT_EVENT = 0,
  OC_SEC_AEL_UNIT_BYTE,
  OC_SEC_AEL_UNIT_KBYTE,
  OC_SEC_AEL_UNIT_DEFAULT = OC_SEC_AEL_UNIT_KBYTE,
} oc_sec_ael_unit_t;

typedef struct
{
  uint8_t logcategory;
  uint8_t loglevel;
  oc_uuid_t rowneruuid;
  size_t event_max;
  oc_sec_ael_event_t *events;
  uint32_t head_idx;
  uint32_t tail_idx;
  oc_sec_ael_unit_t unit;
} oc_sec_ael_t;

void oc_sec_ael_init(void);
void oc_sec_ael_free(void);

void oc_sec_ael_default(void);

void oc_sec_ael_add(const char *dev_type, const oc_uuid_t *di,
                    uint8_t category, uint8_t priority, uint32_t timestamp,
                    const char *message, const char **aux, size_t aux_len);

void get_ael(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_ael(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);

bool oc_sec_ael_encode(size_t device, bool to_storage);
bool oc_sec_ael_decode(oc_rep_t *rep);

#ifdef __cplusplus
}
#endif

#endif /* OC_AEL_H */
