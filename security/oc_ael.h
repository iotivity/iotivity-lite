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

#include "oc_config.h"
#include "oc_core_res.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_sec_ael_aux_info_t
{
  struct oc_sec_ael_aux_info_t *next;
  oc_string_t aux_info;
} oc_sec_ael_aux_info_t;

typedef struct oc_sec_ael_event_t
{
  struct oc_sec_ael_event_t *next;
  size_t size;
  uint8_t category;
  uint8_t priority;
  oc_clock_time_t timestamp;
  oc_string_t aeid;
  oc_string_t message;
  OC_LIST_STRUCT(aux_info);
} oc_sec_ael_event_t;

typedef enum {
  OC_SEC_AEL_CATEGORYFILTER_ACCESS_CONTROL = 0x01,
  OC_SEC_AEL_CATEGORYFILTER_ONBOARDING = 0x02,
  OC_SEC_AEL_CATEGORYFILTER_DEVICE = 0x04,
  OC_SEC_AEL_CATEGORYFILTER_AUTHENTICATION = 0x08,
  OC_SEC_AEL_CATEGORYFILTER_SVR_MODIFICATION = 0x10,
  OC_SEC_AEL_CATEGORYFILTER_CLOUD = 0x20,
  OC_SEC_AEL_CATEGORYFILTER_COMMUNICATION = 0x40,
  OC_SEC_AEL_CATEGORYFILTER_ALL = 0xFF,
  OC_SEC_AEL_CATEGORYFILTER_DEFAULT = OC_SEC_AEL_CATEGORYFILTER_ALL,
} oc_sec_ael_categoryfilter_t;

typedef enum {
  OC_SEC_AEL_PRIORITYFILTER_CRIT = 0,
  OC_SEC_AEL_PRIORITYFILTER_ERR,
  OC_SEC_AEL_PRIORITYFILTER_WARN,
  OC_SEC_AEL_PRIORITYFILTER_INFO,
  OC_SEC_AEL_PRIORITYFILTER_DEBUG,
  OC_SEC_AEL_PRIORITYFILTER_DEFAULT = OC_SEC_AEL_PRIORITYFILTER_DEBUG,
} oc_sec_ael_priorityfilter_t;

#define OC_SEC_AEL_MAX_SIZE                                                    \
  (1024 * 2) // 2K
             // (due to buffer limitations used in file I/O operations (8K)
             // and CBOR format redundancy)

typedef enum {
  OC_SEC_AEL_UNIT_BYTE = 0,
  OC_SEC_AEL_UNIT_KBYTE,
  OC_SEC_AEL_UNIT_DEFAULT = OC_SEC_AEL_UNIT_BYTE,
} oc_sec_ael_unit_t;

typedef struct oc_sec_ael_t
{
  uint8_t categoryfilter;
  uint8_t priorityfilter;
  size_t maxsize;
  oc_sec_ael_unit_t unit;
  size_t events_size;
  OC_LIST_STRUCT(events);
} oc_sec_ael_t;

void oc_sec_ael_init(void);
void oc_sec_ael_free(void);

void oc_sec_ael_default(size_t device);

bool oc_sec_ael_add(size_t device, uint8_t category, uint8_t priority,
                    const char *aeid, const char *message, const char **aux,
                    size_t aux_len);

void get_ael(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_ael(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *data);

bool oc_sec_ael_encode(size_t device, oc_interface_mask_t iface_mask,
                       bool to_storage);
bool oc_sec_ael_decode(size_t device, oc_rep_t *rep, bool from_storage);

#ifdef __cplusplus
}
#endif

#endif /* OC_AEL_H */
