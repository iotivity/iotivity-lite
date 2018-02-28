/*
// Copyright 2018 Oleksandr Grytsov
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

#ifndef OC_INSTANCE_H_
#define OC_INSTANCE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "oc_api.h"

void ocInstanceInit(const oc_handler_t *handler);

void ocInstanceSignal();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
