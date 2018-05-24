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

#ifndef ST_PORT_H
#define ST_PORT_H

#include "config.h"

typedef void *st_mutex_t;
typedef void *st_cond_t;
typedef void *st_thread_t;
typedef void *(*st_thread_process_t)(void *);
typedef void (*st_sig_handler_t)(int);

typedef struct
{
  st_thread_t thread;
  st_mutex_t mutex;
  st_cond_t cv;
  int is_soft_ap_on;
} st_soft_ap_t;

void st_print_log(const char *log, ...);

st_mutex_t st_mutex_init(void);
int st_mutex_destroy(st_mutex_t mutex);
int st_mutex_lock(st_mutex_t mutex);
int st_mutex_unlock(st_mutex_t mutex);

st_cond_t st_cond_init(void);
int st_cond_destroy(st_cond_t cv);
int st_cond_wait(st_cond_t cv, st_mutex_t mutex);
int st_cond_timedwait(st_cond_t cv, st_mutex_t mutex, oc_clock_time_t time);
int st_cond_signal(st_cond_t cv);
int st_set_sigint_handler(st_sig_handler_t handler);

st_thread_t st_thread_create(st_thread_process_t handler, const char *name,
                             void *user_data);
int st_thread_destroy(st_thread_t thread);
int st_thread_join(st_thread_t thread);
int st_thread_cancel(st_thread_t thread);
void st_thread_exit(void *retval);

void st_sleep(int seconds);
void st_turn_on_soft_AP(st_soft_ap_t *data);
void st_turn_off_soft_AP(st_soft_ap_t *data);
void st_connect_wifi(const char *ssid, const char *pwd);

#endif /* ST_PORT_H */