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

#ifndef ST_QUEUE_H
#define ST_QUEUE_H

#include "st_port.h"
#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

// signaling is disabled due to some environment doesn't work.
#ifndef Q_SIGNAL_DISABLE
#define Q_SIGNAL_DISABLE
#endif /* Q_SIGNAL_DISABLE */

typedef struct st_queue
{
  OC_LIST_STRUCT(queue);
  st_mutex_t mutex;
#ifndef Q_SIGNAL_DISABLE
  st_cond_t cv;
#endif /* Q_SIGNAL_DISABLE */
} st_queue_t;

st_queue_t *st_queue_initialize(void);
int st_queue_deinitialize(st_queue_t *queue);
int st_queue_push(st_queue_t *queue, void *item);
void *st_queue_pop(st_queue_t *queue);
void *st_queue_get_head(st_queue_t *queue);
int st_queue_wait(st_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* ST_QUEUE_H */
