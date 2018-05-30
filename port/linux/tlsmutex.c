/*
// Copyright (c) 2018
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

//#define __USE_GNU

#include "oc_assert.h"
#include <pthread.h>

static pthread_mutex_t mutex;

void
oc_tls_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
  }
}

void
oc_tls_mutex_lock(void)
{
  pthread_mutex_lock(&mutex);
}

void
oc_tls_mutex_unlock(void)
{
  pthread_mutex_unlock(&mutex);
}

void
oc_tls_mutex_destroy(void)
{
  pthread_mutex_destroy(&mutex);
}
