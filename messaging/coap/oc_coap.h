/*
// Copyright (c) 2016 Intel Corporation
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

#ifndef OC_COAP_H
#define OC_COAP_H

#include "separate.h"
#include "util/oc_list.h"

struct oc_separate_response_s
{
  OC_LIST_STRUCT(requests);
  int active;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
};

struct oc_response_buffer_s
{
  uint8_t *buffer;
  uint16_t buffer_size;
  uint16_t response_length;
  int code;
};

#endif /* OC_COAP_H */
