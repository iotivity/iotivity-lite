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
#ifdef STATE_MODEL
#include "st_state_util.h"
#include "st_port.h"

#define ST_EVT_LEN 10

st_evt st_evt_queue[ST_EVT_LEN];
int st_evt_head, st_evt_tail;

void
st_evt_init(void)
{
  st_evt_head = st_evt_tail = 0;
}

void
st_evt_deinit(void)
{
  st_evt_head = st_evt_tail = 0;
}

bool
st_evt_is_in_queue(void)
{
  if (st_evt_head == st_evt_tail)
    return false;
  return true;
}

st_evt
st_evt_pop(void)
{

  if (!st_evt_is_in_queue()) {
    st_print_log("[ST_STATE_UTIL] st_evt_push is empty\n");
    return ST_EVT_MAX;
  }

  st_evt ret = st_evt_queue[st_evt_head];

  st_evt_head = (st_evt_head + 1) % ST_EVT_LEN;

  return ret;
}

void
st_evt_push(st_evt evt)
{
  if (st_evt_head == (st_evt_tail + 1)) {
    st_print_log("[ST_STATE_UTIL] st_evt_push is full\n");
    return;
  }

  st_evt_queue[st_evt_tail] = evt;
  st_evt_tail = (st_evt_tail + 1) % ST_EVT_LEN;
}
#endif /* STATE_MODEL */