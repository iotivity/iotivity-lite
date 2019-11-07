/*
// Copyright (c) 2017 Lynx Technology
// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2019 Kistler Instrumente AG
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

#ifndef MUTEX_H
#define MUTEX_H

#define WIN32_LEAN_AND_MEAN
#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

HANDLE mutex_new(void);
void mutex_lock(HANDLE m);
void mutex_unlock(HANDLE m);
void mutex_free(HANDLE m);

#ifdef __cplusplus
}
#endif

#endif /* MUTEX_H */
