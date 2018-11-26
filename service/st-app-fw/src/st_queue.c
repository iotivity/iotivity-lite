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

#include "st_queue.h"
#include "oc_clock.h"
#include "util/oc_memb.h"

#define MAX_WAIT_TIME (1)
#define MAX_QUEUE_COUNT (2)

OC_MEMB(st_queue_s, st_queue_t, MAX_QUEUE_COUNT);

st_queue_t *
st_queue_initialize(st_queue_add_handler_t add_handler,
                    st_queue_free_handler_t free_handler)
{
  if (!add_handler || !free_handler) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return NULL;
  }

  st_queue_t *queue = (st_queue_t *)oc_memb_alloc(&st_queue_s);
  if (!queue) {
    st_print_log("[ST_Q] queue alloc failed\n");
    return NULL;
  }

  queue->mutex = st_mutex_init();
  if (!queue->mutex) {
    st_print_log("[ST_Q] queue->mutex initialize failed!\n");
    oc_memb_free(&st_queue_s, queue);
    return NULL;
  }

#ifndef Q_SIGNAL_DISABLE
  queue->cv = st_cond_init();
  if (!queue->cv) {
    st_print_log("[ST_Q] queue->cv initialize failed!\n");
    st_mutex_destroy(queue->mutex);
    oc_memb_free(&st_queue_s, queue);
    return NULL;
  }
#endif /* Q_SIGNAL_DISABLE */

  OC_LIST_STRUCT_INIT(queue, queue);
  queue->add_handler = add_handler;
  queue->free_handler = free_handler;
  return queue;
}

static bool
queue_is_initialized(st_queue_t *queue)
{
  if (!queue->mutex) {
    return false;
  }
#ifndef Q_SIGNAL_DISABLE
  if (!queue->cv) {
    return false;
  }
#endif /* Q_SIGNAL_DISABLE */
  return true;
}

#ifndef Q_SIGNAL_DISABLE
static void
st_queue_send_signal(st_queue_t *queue)
{
  if (!queue_is_initialized(queue)) {
    st_print_log("[ST_Q] Queue is not initialized!\n");
    return;
  }

  st_mutex_lock(queue->mutex);
  st_cond_signal(queue->cv);
  st_mutex_unlock(queue->mutex);
}
#endif /* Q_SIGNAL_DISABLE */

int
st_queue_deinitialize(st_queue_t *queue)
{
  if (!queue) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return -1;
  }

#ifndef Q_SIGNAL_DISABLE
  st_queue_send_signal(queue);
#endif /* Q_SIGNAL_DISABLE */

  st_queue_free_all_items(queue);

  if (queue->mutex) {
    st_mutex_destroy(queue->mutex);
    queue->mutex = NULL;
  }
#ifndef Q_SIGNAL_DISABLE
  if (queue->cv) {
    st_cond_destroy(queue->cv);
    queue->cv = NULL;
  }
#endif /* Q_SIGNAL_DISABLE */
  oc_memb_free(&st_queue_s, queue);

  return 0;
}

int
st_queue_push(st_queue_t *queue, void *value)
{
  if (!queue || !value) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return -1;
  }

  if (!queue_is_initialized(queue)) {
    st_print_log("[ST_Q] Queue is not initialized!\n");
    return -1;
  }

  void *item = queue->add_handler(value);
  if (!item) {
    st_print_log("[ST_Q] Queue item is NULL\n");
    return -1;
  }

  st_mutex_lock(queue->mutex);
  oc_list_add(queue->queue, item);
  st_mutex_unlock(queue->mutex);
#ifndef Q_SIGNAL_DISABLE
  st_queue_send_signal(queue);
#endif /* Q_SIGNAL_DISABLE */

  return 0;
}

void *
st_queue_pop(st_queue_t *queue)
{
  if (!queue) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return NULL;
  }

  if (!queue_is_initialized(queue)) {
    st_print_log("[ST_Q] Queue is not initialized!\n");
    return NULL;
  }

  void *item = NULL;
  st_mutex_lock(queue->mutex);
  item = oc_list_pop(queue->queue);
  st_mutex_unlock(queue->mutex);

  return item;
}

void *
st_queue_get_head(st_queue_t *queue)
{
  if (!queue) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return NULL;
  }

  if (!queue_is_initialized(queue)) {
    st_print_log("[ST_Q] Queue is not initialized!\n");
    return NULL;
  }

  return oc_list_head(queue->queue);
}

int
st_queue_wait(st_queue_t *queue)
{
  if (!queue) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return -1;
  }

  int ret = 0;
#ifdef Q_SIGNAL_DISABLE
  (void)queue;
  st_sleep(MAX_WAIT_TIME);
#else  /* Q_SIGNAL_DISABLE */
  st_mutex_lock(queue->mutex);
  oc_clock_time_t wait_time = oc_clock_time() + MAX_WAIT_TIME * OC_CLOCK_SECOND;
  ret = st_cond_timedwait(queue->cv, queue->mutex, wait_time);
  st_mutex_unlock(queue->mutex);
#endif /* !Q_SIGNAL_DISABLE */
  return ret;
}

int
st_queue_free_item(st_queue_t *queue, void *item)
{
  if (!queue || !item) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return -1;
  }

  queue->free_handler(item);
  return 0;
}

int
st_queue_free_all_items(st_queue_t *queue)
{
  if (!queue) {
    st_print_log("[ST_Q] Invalid parameter\n");
    return -1;
  }

  void *item = NULL;
  while ((item = st_queue_pop(queue)) != NULL) {
    st_queue_free_item(queue, item);
  }
  return 0;
}