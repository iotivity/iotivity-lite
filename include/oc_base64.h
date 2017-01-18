/*
// Copyright (c) 2017 Intel Corporation
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

#ifndef OC_BASE64_H
#define OC_BASE64_H

#include <stdint.h>

int oc_base64_encode(const uint8_t *input, int input_len,
                     uint8_t *output_buffer, int output_buffer_len);
int oc_base64_decode(uint8_t *str, int len);

#endif /* OC_BASE64_H */
