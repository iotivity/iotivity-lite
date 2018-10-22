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

typedef struct
{
  st_mutex_t mutex;
  st_mutex_t app_mutex;
  st_cond_t cv;
  st_thread_t thread;
  bool quit;
} st_process_data_t;

static st_process_data_t g_process_data;

static void *st_process_func(void *data);

int
st_process_init(void)
{
  g_process_data.mutex = st_mutex_init();
  if (!g_process_data.mutex) {
    st_print_log("[ST_PROC] st_mutex_init failed!\n");
    return -1;
  }

  g_process_data.app_mutex = st_mutex_init();
  if (!g_process_data.app_mutex) {
    st_print_log("[ST_PROC] st_mutex_init failed!\n");
    st_mutex_destroy(g_process_data.mutex);
    return -1;
  }

  g_process_data.cv = st_cond_init();
  if (!g_process_data.cv) {
    st_print_log("[ST_PROC] st_cond_init failed!\n");
    st_mutex_destroy(g_process_data.mutex);
    st_mutex_destroy(g_process_data.app_mutex);
    return -1;
  }

  g_process_data.quit = true;
  return 0;
}

int
st_process_start(void)
{
  st_print_log("[ST_PROC] st_process_start IN\n");
  g_process_data.quit = false;
#ifdef STATE_MODEL
  g_process_data.thread =
    st_thread_create(st_process_func, "MAIN", 0, &g_process_data);
  if (!g_process_data.thread) {
    st_print_log("[ST_PROC] Failed to create main thread\n");
    return -1;
  }
#else  /* STATE_MODEL */
  st_process_func(&g_process_data);
#endif /* !STATE_MODEL */
  st_print_log("[ST_PROC] st_process_start OUT\n");
  return 0;
}

int
st_process_stop(void)
{
  if (g_process_data.quit) {
    st_print_log("[ST_PROC] st_process already stops.\n");
    return 0;
  }

  g_process_data.quit = true;
  st_process_signal();

#ifdef STATE_MODEL
  if (st_thread_destroy(g_process_data.thread) != 0) {
    st_print_log("[ST_PROC] st_thread_destroy failed!\n");
    return -1;
  }
  g_process_data.thread = NULL;
  st_print_log("[ST_PROC] st_thread_destroy finish!\n");
#endif /* STATE_MODEL */
  return 0;
}

int
st_process_destroy(void)
{
  if (g_process_data.quit != true) {
    st_print_log("[ST_PROC] please stop process first.\n");
    return -1;
  }

  if (g_process_data.cv) {
    st_cond_destroy(g_process_data.cv);
    g_process_data.cv = NULL;
  }

  if (g_process_data.app_mutex) {
    st_mutex_destroy(g_process_data.app_mutex);
    g_process_data.app_mutex = NULL;
  }
  if (g_process_data.mutex) {
    st_mutex_destroy(g_process_data.mutex);
    g_process_data.mutex = NULL;
  }
  return 0;
}

static void *
st_process_func(void *data)
{
  st_process_data_t *process_data = (st_process_data_t *)data;
  oc_clock_time_t next_event;

  if (process_data->quit) {
    st_print_log("[ST_PROC] st_process_func stops in starting itself.\n");
    return NULL;
  }

  while (process_data->quit != true) {

    st_mutex_lock(process_data->app_mutex);
    next_event = oc_main_poll();
    st_mutex_unlock(process_data->app_mutex);

    if (process_data->quit)
      break;

    st_mutex_lock(process_data->mutex);
    if (next_event == 0) {
      st_cond_wait(process_data->cv, process_data->mutex);
    } else {
      st_cond_timedwait(process_data->cv, process_data->mutex, next_event);
    }
    st_mutex_unlock(process_data->mutex);
  }

#ifdef STATE_MODEL
  st_thread_exit(NULL);
#endif
  return NULL;
}

void
st_process_signal(void)
{
  st_mutex_lock(g_process_data.mutex);
  st_cond_signal(g_process_data.cv);
  st_mutex_unlock(g_process_data.mutex);
}

void
st_process_app_sync_lock(void)
{
  st_mutex_lock(g_process_data.app_mutex);
}

void
st_process_app_sync_unlock(void)
{
  st_mutex_unlock(g_process_data.app_mutex);
}
