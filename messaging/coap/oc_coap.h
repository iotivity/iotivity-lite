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

#ifndef OCCOAP_H_
#define OCCOAP_H_

#include "util/oc_list.h"
#include "separate.h"

typedef struct oc_slow_response_s {
  OC_LIST_STRUCT(requests);
  int in_process;
  uint8_t buffer[COAP_MAX_BLOCK_SIZE];
} oc_slow_response_t;

typedef struct oc_response_buffer_s {
  uint8_t *buffer;
  uint16_t buffer_size;
  int32_t *block_offset;
  uint16_t response_length;
  int code;
} oc_response_buffer_t;

#endif /* OCCOAP_H_ */
