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

/**
  @brief Status queue managing APIs.
  @file
*/

#ifndef ST_STATUS_QUEUE_H
#define ST_STATUS_QUEUE_H

#include "st_manager.h"

#define MAX_STATUS_COUNT 10

/**
 * Structure to manage st_status_t queue.
 */
typedef struct st_status_item
{
  struct st_status_item *next;
  st_status_t status;
} st_status_item_t;

int st_status_queue_initialize(void);
int st_status_queue_wait_signal(void);
int st_status_queue_add(st_status_t status);
st_status_item_t *st_status_queue_pop(void);
st_status_item_t *st_status_queue_get_head(void);
int st_status_queue_free_item(st_status_item_t *item);
void st_status_queue_remove_all_items(void);
void st_status_queue_deinitialize(void);

#endif /* ST_STATUS_QUEUE_H */