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

#include "oc_config.h"
#include "port/oc_storage.h"

#ifdef OC_STORAGE
// TODO:

int
oc_storage_config(const char *store)
{
  (void)store;
  return 0;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  (void)store;
  (void)buf;
  (void)size;
  return size;
}

long
oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
  (void)store;
  (void)buf;
  (void)size;
  return size;
}
#endif /* OC_STORAGE */
