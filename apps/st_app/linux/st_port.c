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
#include "../st_port.h"
#include "../st_manager.h"
#include "../st_process.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "util/oc_memb.h"
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

static st_thread_t g_user_input_thread = NULL;

OC_MEMB(st_mutex_s, pthread_mutex_t, 10);
OC_MEMB(st_cond_s, pthread_cond_t, 10);
OC_MEMB(st_thread_s, pthread_t, 10);

extern void st_manager_quit(void);

static void *st_port_user_input_loop(void *data);
static void *soft_ap_process_routine(void *data);

int
st_port_specific_init(void)
{
  /* set port specific logics. in here */
  g_user_input_thread =
    st_thread_create(st_port_user_input_loop, "INPUT", NULL);
  return 0;
}

void
st_port_specific_destroy(void)
{
  /* set initialized port specific logics destroyer. in here */
  st_thread_destroy(g_user_input_thread);
  g_user_input_thread = NULL;
  return;
}

static void
print_menu(void)
{
  st_process_app_sync_lock();
  st_print_log("=====================================\n");
  st_print_log("1. Reset device\n");
  st_print_log("0. Quit\n");
  st_print_log("=====================================\n");
  st_process_app_sync_unlock();
}

static void *
st_port_user_input_loop(void *data)
{
  (void)data;
  char key[10];

  while (1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%s", &key)) {
      st_print_log("scanf failed!!!!\n");
      st_manager_quit();
      st_process_signal();
      goto exit;
    }

    switch (key[0]) {
    case '1':
      st_manager_reset();
      goto exit;
    case '0':
      st_manager_quit();
      st_process_signal();
      goto exit;
    default:
      st_print_log("unsupported command.\n");
      break;
    }
  }
exit:
  st_thread_exit(NULL);
  return NULL;
}

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

st_thread_t
st_thread_create(st_thread_process_t handler, const char *name, void *user_data)
{
  if (!handler)
    return NULL;

  st_thread_t thread = (st_thread_t)oc_memb_alloc(&st_thread_s);
  if (!thread)
    oc_abort("alloc failed");

  pthread_create((pthread_t *)thread, NULL, handler, user_data);
  pthread_setname_np(*(pthread_t *)thread, name);

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
st_turn_on_soft_AP(const char *ssid, const char *pwd, int channel)
{
  if (g_soft_ap.is_soft_ap_on) {
    st_print_log("[St_Port] Soft AP is already turned on\n");
    return;
  }

  st_print_log("[St_Port] st_turn_on_soft_AP\n");

  if (oc_string(g_soft_ap.ssid)) {
    oc_free_string(&g_soft_ap.ssid);
  }
  if (oc_string(g_soft_ap.pwd)) {
    oc_free_string(&g_soft_ap.pwd);
  }

  oc_new_string(&g_soft_ap.ssid, ssid, strlen(ssid));
  oc_new_string(&g_soft_ap.pwd, pwd, strlen(pwd));
  g_soft_ap.channel = channel;

  g_soft_ap.mutex = st_mutex_init();
  g_soft_ap.cv = st_cond_init();
  g_soft_ap.is_soft_ap_on = 1;
  g_soft_ap.thread =
    st_thread_create(soft_ap_process_routine, "SOFT_AP", &g_soft_ap);

  st_mutex_lock(g_soft_ap.mutex);
  st_cond_wait(g_soft_ap.cv, g_soft_ap.mutex);
  st_mutex_unlock(g_soft_ap.mutex);

  st_print_log("[St_Port] st_turn_on_soft_AP success\n");
}

static int
system_ret_chcek(int ret)
{
  if (ret == -1 || ret == 127) {
    st_print_log("[St_Port] system() invoke error(%d).\n", ret);
    return -1;
  }
  return 0;
}

void
st_turn_off_soft_AP(void)
{
  if (!g_soft_ap.is_soft_ap_on) {
    st_print_log("[St_Port] soft AP is already turned off\n");
  }

  st_print_log("[St_Port] st_turn_off_soft_AP\n");
  st_mutex_lock(g_soft_ap.mutex);
  if (g_soft_ap.is_soft_ap_on) {
    SYSTEM_RET_CHECK(system("sudo pkill hostapd"));
    st_thread_cancel(g_soft_ap.thread);
    g_soft_ap.is_soft_ap_on = 0;
  }
  st_print_log("[St_Port] st_turn_off_soft_AP success.\n");

exit:
  st_thread_destroy(g_soft_ap.thread);

  if (oc_string(g_soft_ap.ssid)) {
    oc_free_string(&g_soft_ap.ssid);
  }
  if (oc_string(g_soft_ap.pwd)) {
    oc_free_string(&g_soft_ap.pwd);
  }
  st_mutex_unlock(g_soft_ap.mutex);

  st_cond_destroy(g_soft_ap.cv);
  st_mutex_destroy(g_soft_ap.mutex);
  g_soft_ap.thread = NULL;
  g_soft_ap.mutex = NULL;
  g_soft_ap.cv = NULL;
}

void
st_connect_wifi(const char *ssid, const char *pwd)
{
  st_print_log("[St_Port] st_connect_wifi in\n");

  /** sleep to allow response sending from post_callback thread before turning
   * Off Soft AP. */
  st_sleep(1);

  st_print_log("[St_Port] target ap ssid: %s\n", ssid);
  st_print_log("[St_Port] password: %s\n", pwd);

  /** Stop Soft AP */
  st_print_log("[St_Port] Stopping Soft AP\n");
  SYSTEM_RET_CHECK(system("sudo service hostapd stop"));

  /** Turn On Wi-Fi */
  st_print_log("[St_Port] Turn on the AP\n");
  SYSTEM_RET_CHECK(system("sudo nmcli radio wifi on"));

  /** On some systems it may take time for Wi-Fi to turn ON. */
  st_sleep(1);

  /** Connect to Target Wi-Fi AP */
  st_print_log("[St_Port] connect to %s AP.\n", ssid);
  char nmcli_command[200];
  sprintf(nmcli_command, "nmcli d wifi connect %s password %s", ssid, pwd);
  st_print_log("[St_Port] $ %s\n", nmcli_command);
  SYSTEM_RET_CHECK(system(nmcli_command));

  st_print_log("[St_Port] st_connect_wifi out\n");
  return;

exit:
  st_print_log("[St_Port] st_connect_wifi error occur\n");
}

static void *
soft_ap_process_routine(void *data)
{
  st_soft_ap_t *soft_ap = (st_soft_ap_t *)data;

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  st_print_log("[St_Port] soft_ap_handler in\n");

  /** Stop AP */
  st_print_log("[St_Port] Stopping AP\n");
  SYSTEM_RET_CHECK(system("sudo nmcli radio wifi off"));
  SYSTEM_RET_CHECK(system("sudo rfkill unblock wlan"));

  /** Turn On Wi-Fi interface */
  st_print_log("[St_Port] Turn on the wifi interface\n");
  SYSTEM_RET_CHECK(system("sudo ifconfig wlx00259ce05a49 10.0.0.2/24 up"));

  /** On some systems it may take time for Wi-Fi to turn ON. */
  st_print_log("[St_Port] $ sudo service dnsmasq restart\n");
  SYSTEM_RET_CHECK(system("sudo service dnsmasq restart"));

  st_print_log("[St_Port] $ sudo service radvd restart\n");
  SYSTEM_RET_CHECK(system("sudo service radvd restart"));

  st_print_log("[St_Port] $ sudo service hostapd start\n");
  SYSTEM_RET_CHECK(system("sudo service hostapd start"));

  st_mutex_lock(soft_ap->mutex);
  st_cond_signal(soft_ap->cv);
  st_mutex_unlock(soft_ap->mutex);

  st_print_log("[St_Port] $ sudo hostapd /etc/hostapd/hostapd.conf\n");
  SYSTEM_RET_CHECK(system("sudo hostapd /etc/hostapd/hostapd.conf"));

  st_print_log("[St_Port] $ Soft ap is off\n");

exit:
  st_thread_exit(NULL);
  return NULL;
}