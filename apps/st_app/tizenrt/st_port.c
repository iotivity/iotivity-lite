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

#include "st_port.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "util/oc_memb.h"
#include "wifi_soft_ap_util.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#define SYSTEM_RET_CHECK(ret)                                                  \
  do {                                                                         \
    if (system_ret_chcek(ret) != 0) {                                          \
      goto exit;                                                               \
    }                                                                          \
  } while (0);

OC_MEMB(st_mutex_s, pthread_mutex_t, 10);
OC_MEMB(st_cond_s, pthread_cond_t, 10);
OC_MEMB(st_thread_s, pthread_t, 10);

static void *soft_ap_process_routine(void *data);

void
st_print_log(const char *fmt, ...)
{
  va_list arg;

  va_start(arg, fmt);
  vprintf(fmt, arg);
  va_end(arg);
}

st_mutex_t
st_mutex_init(void)
{
  st_mutex_t mutex = (st_mutex_t)oc_memb_alloc(&st_mutex_s);
  if (!mutex)
    oc_abort("alloc failed");

  pthread_mutex_init((pthread_mutex_t *)mutex, NULL);

  return mutex;
}

int
st_mutex_destroy(st_mutex_t mutex)
{
  if (!mutex)
    return -1;

  pthread_mutex_destroy((pthread_mutex_t *)mutex);

  oc_memb_free(&st_mutex_s, mutex);

  return 0;
}

int
st_mutex_lock(st_mutex_t mutex)
{
  if (!mutex)
    return -1;

  pthread_mutex_lock((pthread_mutex_t *)mutex);

  return 0;
}

int
st_mutex_unlock(st_mutex_t mutex)
{
  if (!mutex)
    return -1;

  pthread_mutex_unlock((pthread_mutex_t *)mutex);

  return 0;
}

st_cond_t
st_cond_init(void)
{
  st_cond_t cv = (st_cond_t)oc_memb_alloc(&st_cond_s);
  if (!cv)
    oc_abort("alloc failed");

  pthread_cond_init((pthread_cond_t *)cv, NULL);

  return cv;
}

int
st_cond_destroy(st_cond_t cv)
{
  if (!cv)
    return -1;

  pthread_cond_destroy((pthread_cond_t *)cv);

  oc_memb_free(&st_cond_s, cv);

  return 0;
}

int
st_cond_wait(st_cond_t cv, st_mutex_t mutex)
{
  if (!cv || !mutex)
    return -1;

  return pthread_cond_wait((pthread_cond_t *)cv, (pthread_mutex_t *)mutex);
}

int
st_cond_timedwait(st_cond_t cv, st_mutex_t mutex, oc_clock_time_t time)
{
  if (!cv || !mutex)
    return -1;

  struct timespec ts;
  ts.tv_sec = (time / OC_CLOCK_SECOND);
  ts.tv_nsec = (time % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
  return pthread_cond_timedwait((pthread_cond_t *)cv, (pthread_mutex_t *)mutex,
                                &ts);
}

int
st_cond_signal(st_cond_t cv)
{
  if (!cv)
    return -1;

  return pthread_cond_signal((pthread_cond_t *)cv);
}

#if 0
int
st_set_sigint_handler(st_sig_handler_t handler)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handler;
  return sigaction(SIGINT, &sa, NULL);
}
#endif

st_thread_t
st_thread_create(st_thread_process_t handler, void *user_data)
{
  if (!handler)
    return NULL;

  st_thread_t thread = (st_thread_t)oc_memb_alloc(&st_thread_s);
  if (!thread)
    oc_abort("alloc failed");

  pthread_create((pthread_t *)thread, NULL, handler, user_data);

  return thread;
}

int
st_thread_destroy(st_thread_t thread)
{
  if (!thread)
    return -1;

  pthread_join(*(pthread_t *)(thread), NULL);

  oc_memb_free(&st_thread_s, thread);

  return 0;
}

int
st_thread_cancel(st_thread_t thread)
{
  if (!thread)
    return -1;

  return pthread_cancel(*(pthread_t *)thread);
}

void
st_thread_exit(void *retval)
{
  pthread_exit(retval);
}

void
st_sleep(int seconds)
{
  sleep(seconds);
}

void
st_turn_on_soft_AP(st_soft_ap_t *data)
{
  if (!data)
    return;

  st_print_log("st_turn_on_soft_AP\n");

  data->mutex = st_mutex_init();
  data->thread = st_thread_create(soft_ap_process_routine, data);

  st_mutex_lock(data->mutex);
  data->is_soft_ap_on = 1;
  st_mutex_unlock(data->mutex);
}

static int
system_ret_chcek(int ret)
{
  if (ret == -1 || ret == 127) {
    st_print_log("[Easy_Setup] system() invoke error(%d).", ret);
    return -1;
  }
  return 0;
}

void
st_turn_off_soft_AP(st_soft_ap_t *data)
{
  if (!data)
    return;

  st_print_log("st_turn_off_soft_AP\n");
  st_mutex_lock(data->mutex);
  if (data->is_soft_ap_on) {
    stop_dhcp(SLSI_WIFI_SOFT_AP_IF);
    st_thread_cancel(data->thread);
    data->is_soft_ap_on = 0;
  }
  st_print_log("st_turn_off_soft_AP success.\n");
#if 0
exit:
  st_thread_destroy(data->thread);
  st_mutex_unlock(data->mutex);
#endif

  st_mutex_destroy(data->mutex);
  data->thread = NULL;
  data->mutex = NULL;
}

void
st_connect_wifi(const char *ssid, const char *pwd)
{
  st_print_log("[Easy_Setup] st_connect_wifi in\n");

  stop_dhcp(SLSI_WIFI_SOFT_AP_IF);

  if (wifi_start_station() < 0) {
    st_print_log("start station error! \n");
    return;
  }

  char auth_type[20] = "wpa2_psk";

  while (wifi_join(ssid, auth_type, pwd) != 0) {
    printf("Retry to Join\n");
    sleep(1);
  }

  st_print_log("AP join :\n");
  while (dhcpc_start() != 0) {
      printf("Get IP address Fail\n");
  }

  st_print_log("DHCP Client Start :\n");
  return;

}

static void *
soft_ap_process_routine(void *data)
{
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  st_print_log("[Easy_Setup] soft_ap_handler in\n");

  if(es_create_softap() == -1){
    st_print_log("Soft AP mode failed!!\n");
    return 0;
  }

  dhcpserver_start();

  st_thread_exit(NULL);
  return NULL;
}
