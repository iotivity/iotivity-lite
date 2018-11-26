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
#ifndef STATE_MODEL

#include "st_status_queue.h"
#include "st_queue.h"
#include "util/oc_memb.h"

#define MAX_STATUS_COUNT 10

static st_queue_t *g_status_queue = NULL;
OC_MEMB(st_status_item_s, st_status_item_t, MAX_STATUS_COUNT);

int
st_status_queue_initialize(void)
{
  g_status_queue = st_queue_initialize();
  if (!g_status_queue) {
    st_print_log("[ST_SQ] st_queue_initialize failed\n");
    return -1;
  }

  return 0;
}

int
st_status_queue_wait_signal(void)
{
  return st_queue_wait(g_status_queue);
}

int
st_status_queue_add(st_status_t status)
{
  st_status_item_t *queue_item = oc_memb_alloc(&st_status_item_s);
  if (!queue_item) {
    st_print_log("[ST_Q] oc_memb_alloc failed!\n");
    return -1;
  }

  queue_item->status = status;

  if (st_queue_push(g_status_queue, queue_item) == -1) {
    st_print_log("[ST_SQ] st_queue_push failed!\n");
    oc_memb_free(&st_status_item_s, queue_item);
    return -1;
  }

  return 0;
}

st_status_item_t *
st_status_queue_pop(void)
{
  return st_queue_pop(g_status_queue);
}

st_status_item_t *
st_status_queue_get_head(void)
{
  return (st_status_item_t *)st_queue_get_head(g_status_queue);
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
  st_queue_deinitialize(g_status_queue);
  g_status_queue = NULL;
}
#endif /* !STATE_MODEL */