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

#define _GNU_SOURCE
#include "st_port.h"
#include "oc_assert.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "st_process.h"
#include "util/oc_memb.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

typedef struct
{
  st_thread_t thread;
  st_mutex_t mutex;
  st_cond_t cv;
  int is_soft_ap_on;
  oc_string_t ssid;
  oc_string_t pwd;
  int channel;
} st_soft_ap_t;

static st_soft_ap_t g_soft_ap;

OC_MEMB(st_mutex_s, pthread_mutex_t, 10);
OC_MEMB(st_cond_s, pthread_cond_t, 10);
OC_MEMB(st_thread_s, pthread_t, 10);

extern int quit;

static void *soft_ap_process_routine(void *data);

int
st_port_specific_init(void)
{
  oc_abort(__func__);
  return 0;
}

void
st_port_specific_destroy(void)
{
  oc_abort(__func__);
  return;
}

static void
print_menu(void)
{
  oc_abort(__func__);
}

void
st_print_log(const char *fmt, ...)
{
  oc_abort(__func__);
}

st_mutex_t
st_mutex_init(void)
{
  st_mutex_t mutex;
  oc_abort(__func__);

  return mutex;
}

int
st_mutex_destroy(st_mutex_t mutex)
{
  oc_abort(__func__);
  return 0;
}

int
st_mutex_lock(st_mutex_t mutex)
{
  oc_abort(__func__);
  return 0;
}

int
st_mutex_unlock(st_mutex_t mutex)
{
  oc_abort(__func__);
  return 0;
}

st_cond_t
st_cond_init(void)
{
  oc_abort(__func__);
}

int
st_cond_destroy(st_cond_t cv)
{
  oc_abort(__func__);
  return 0;
}

int
st_cond_wait(st_cond_t cv, st_mutex_t mutex)
{
  oc_abort(__func__);
}

int
st_cond_timedwait(st_cond_t cv, st_mutex_t mutex, oc_clock_time_t time)
{
  oc_abort(__func__);
}

int
st_cond_signal(st_cond_t cv)
{
  oc_abort(__func__);
}

st_thread_t
st_thread_create(st_thread_process_t handler, const char *name, int stack_size,
                 void *user_data)
{
  oc_abort(__func__);
  return NULL;
}

int
st_thread_destroy(st_thread_t thread)
{
  oc_abort(__func__);
}

int
st_thread_cancel(st_thread_t thread)
{
  oc_abort(__func__);
}

void
st_thread_exit(void *retval)
{
  oc_abort(__func__);
}

void
st_sleep(int seconds)
{
  oc_abort(__func__);
}

void
st_turn_on_soft_AP(const char *ssid, const char *pwd, int channel)
{
  oc_abort(__func__);
}

static int
system_ret_check(int ret)
{
  oc_abort(__func__);
  return 0;
}

void
st_turn_off_soft_AP(void)
{
  oc_abort(__func__);
}

int
st_connect_wifi(const char *ssid, const char *pwd)
{
  oc_abort(__func__);
  return 0;
}

void
st_wifi_scan(st_wifi_ap_t **ap_list)
{
  oc_abort(__func__);
}

void
st_wifi_set_cache(st_wifi_ap_t *scanlist)
{
  oc_abort(__func__);
}

st_wifi_ap_t*
st_wifi_get_cache(void)
{
  oc_abort(__func__);
}

static void *
soft_ap_process_routine(void *data)
{
  oc_abort(__func__);
}
