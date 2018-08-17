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

#include "st_status_queue.h"
#include "oc_clock.h"
#include "oc_helpers.h"
#include "st_port.h"
#include "util/oc_memb.h"

#define MAX_WAIT_WIME (1)

// signaling is disabled due to some environment doesn't work.
#define STATUS_Q_SIGNAL_DISABLE

OC_LIST(g_main_status_queue);
OC_MEMB(st_status_item_s, st_status_item_t, MAX_STATUS_COUNT);

static st_mutex_t status_queue_mutex = NULL;
#ifndef STATUS_Q_SIGNAL_DISABLE
static st_cond_t status_queue_cv = NULL;
#endif /* STATUS_Q_SIGNAL_DISABLE */

int
st_status_queue_initialize(void)
{
  if (status_queue_mutex) {
    st_print_log("[ST_Q] status_queue_mutex already initialized!\n");
    return -1;
  }

#ifndef STATUS_Q_SIGNAL_DISABLE
  if (status_queue_cv) {
    st_print_log("[ST_Q] status_queue_cv already initialized!\n");
    return -1;
  }
#endif /* STATUS_Q_SIGNAL_DISABLE */

  status_queue_mutex = st_mutex_init();
  if (!status_queue_mutex) {
    st_print_log("[ST_Q] st_mutex_init failed!\n");
    return -1;
  }
#ifndef STATUS_Q_SIGNAL_DISABLE
  status_queue_cv = st_cond_init();
  if (!status_queue_cv) {
    st_print_log("[ST_Q] st_cond_init failed!\n");
    st_mutex_destroy(status_queue_mutex);
    return -1;
  }
#endif /* STATUS_Q_SIGNAL_DISABLE */

  return 0;
}

static bool
is_initialized(void)
{
  if (!status_queue_mutex) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return false;
  }
#ifndef STATUS_Q_SIGNAL_DISABLE
  if (!status_queue_mutex) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return false;
  }
#endif /* STATUS_Q_SIGNAL_DISABLE */
  return true;
}

#ifndef STATUS_Q_SIGNAL_DISABLE
static void
status_queue_send_signal(void)
{
  if (!is_initialized()) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return;
  }

  st_mutex_lock(status_queue_mutex);
  st_cond_signal(status_queue_cv);
  st_mutex_unlock(status_queue_mutex);
}
#endif /* STATUS_Q_SIGNAL_DISABLE */

int
st_status_queue_wait_signal(void)
{
  int ret = 0;
#ifdef STATUS_Q_SIGNAL_DISABLE
  st_sleep(MAX_WAIT_WIME);
#else  /* STATUS_Q_SIGNAL_DISABLE */
  st_mutex_lock(status_queue_mutex);
  oc_clock_time_t wait_time = oc_clock_time() + MAX_WAIT_WIME * OC_CLOCK_SECOND;
  ret = st_cond_timedwait(status_queue_cv, status_queue_mutex, wait_time);
  st_mutex_unlock(status_queue_mutex);
#endif /* !STATUS_Q_SIGNAL_DISABLE */

  return ret;
}

int
st_status_queue_add(st_status_t status)
{
  if (!is_initialized()) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return -1;
  }

  st_status_item_t *queue_item = oc_memb_alloc(&st_status_item_s);
  if (!queue_item) {
    st_print_log("[ST_Q] oc_memb_alloc failed!\n");
    return -1;
  }

  queue_item->status = status;
  st_mutex_lock(status_queue_mutex);
  oc_list_add(g_main_status_queue, queue_item);
  st_mutex_unlock(status_queue_mutex);
#ifndef STATUS_Q_SIGNAL_DISABLE
  status_queue_send_signal();
#endif /* STATUS_Q_SIGNAL_DISABLE */

  return 0;
}

st_status_item_t *
st_status_queue_pop(void)
{
  if (!is_initialized()) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return NULL;
  }

  st_mutex_lock(status_queue_mutex);
  st_status_item_t *item = (st_status_item_t *)oc_list_pop(g_main_status_queue);
  st_mutex_unlock(status_queue_mutex);

  return item;
}

st_status_item_t *
st_status_queue_get_head(void)
{
  return (st_status_item_t *)oc_list_head(g_main_status_queue);
}

int
st_status_queue_free_item(st_status_item_t *item)
{
  if (!item)
    return -1;

  oc_memb_free(&st_status_item_s, item);
  return 0;
}

void
st_status_queue_remove_all_items(void)
{
  st_status_item_t *item = NULL;
  while ((item = (st_status_item_t *)st_status_queue_pop()) != NULL) {
    st_status_queue_free_item(item);
  }
}

void
st_status_queue_remove_all_items_without_stop(void)
{
  st_status_item_t *item = NULL;
  bool stop_flag = false;

  while ((item = (st_status_item_t *)st_status_queue_pop()) != NULL) {
    if (!stop_flag && item->status == ST_STATUS_STOP) {
      stop_flag = true;
    }
    st_status_queue_free_item(item);
  }
  if (stop_flag) {
    st_status_queue_add(ST_STATUS_STOP);
  }
}

void
st_status_queue_deinitialize(void)
{
  if (!is_initialized()) {
    st_print_log("[ST_Q] status queue not initialized!\n");
    return;
  }

#ifndef STATUS_Q_SIGNAL_DISABLE
  status_queue_send_signal();
#endif /* STATUS_Q_SIGNAL_DISABLE */
  st_mutex_destroy(status_queue_mutex);
  status_queue_mutex = NULL;
#ifndef STATUS_Q_SIGNAL_DISABLE
  st_cond_destroy(status_queue_cv);
  status_queue_cv = NULL;
#endif /* STATUS_Q_SIGNAL_DISABLE */
}