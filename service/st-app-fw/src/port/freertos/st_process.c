/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "st_process.h"
#include "oc_api.h"
#include "oc_assert.h"

typedef struct
{
  st_mutex_t mutex;
  st_mutex_t app_mutex;
  st_cond_t cv;
  st_thread_t thread;
  int quit;
} st_process_data_t;

static st_process_data_t g_process_data;

static void *st_process_func(void *data);

int
st_process_init(void)
{
  oc_abort(__func__);
  return 0;
}

int
st_process_start(void)
{
  oc_abort(__func__);
  return 0;
}

int
st_process_stop(void)
{
  oc_abort(__func__);
  return 0;
}

static void *
st_process_func(void *data)
{
  oc_abort(__func__);
  return NULL;
}

void
st_process_signal(void)
{
  oc_abort(__func__);
}

void
st_process_app_sync_lock(void)
{
  oc_abort(__func__);
}

void
st_process_app_sync_unlock(void)
{
  oc_abort(__func__);
}
