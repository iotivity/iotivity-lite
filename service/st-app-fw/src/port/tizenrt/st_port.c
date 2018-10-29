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
#include "port/oc_connectivity.h"
#include "st_process.h"
#include "util/oc_memb.h"
#include "wifi_soft_ap_util.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <wifi_manager/wifi_manager.h>
/* setting up the stack size for st_thread */
#define STACKSIZE 8192

#define SYSTEM_RET_CHECK(ret)                                                  \
  do {                                                                         \
    if (system_ret_check(ret) != 0) {                                          \
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

static st_wifi_ap_t *g_wifi_scan_info;
static int g_wifi_count = 0;
static void wifi_sta_connected_cb(wifi_manager_result_e res); // in station mode, connected to ap
static void wifi_sta_disconnected_cb(void); // in station mode, disconnected from ap
static void wifi_scan_done(wifi_manager_scan_info_s **scan_result,wifi_manager_scan_result_e res);
static void wifi_softap_sta_join(void);
void wifi_softap_sta_leave(void);

static wifi_manager_cb_s wifi_callbacks = {
  wifi_sta_connected_cb,
  wifi_sta_disconnected_cb,
  wifi_softap_sta_join,
  wifi_softap_sta_leave,
  wifi_scan_done,
};

static st_soft_ap_t g_soft_ap;

OC_MEMB(st_mutex_s, pthread_mutex_t, 10);
OC_MEMB(st_cond_s, pthread_cond_t, 10);
OC_MEMB(st_thread_s, pthread_t, 10);

static void *soft_ap_process_routine(void *data);

static void wifi_sta_connected_cb(wifi_manager_result_e res)
{
  st_print_log("wifi_sta_connected: send signal!!! \n");
}

static void wifi_sta_disconnected_cb(void)
{
  st_print_log("wifi_sta_disconnected: send signal!!! \n");
}

void wifi_softap_sta_join(void){
  st_print_log("%s\n",__FUNCTION__);
}

void wifi_softap_sta_leave(void){
  st_print_log("%s\n",__FUNCTION__);
}

  /*  Initialize Wifi_callbacks  */
int
st_port_specific_init(void)
{
  st_print_log("%s Start\n",__FUNCTION__);
  wifi_manager_result_e ret = WIFI_MANAGER_FAIL;

  ret = wifi_manager_init(&wifi_callbacks);
  if (ret != WIFI_MANAGER_SUCCESS) {
    st_print_log("wifi_manager_init failed\n");
    return -1;
  }
  wm_scan();
  sleep(10);
  st_print_log("%s Finish\n",__FUNCTION__);
  return 0;
}

void
st_port_specific_destroy(void)
{
  int ret = wifi_manager_deinit();
  if (ret != WIFI_MANAGER_SUCCESS) {
    st_print_log("wifi_manager_init failed\n");
  }
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
st_thread_create(st_thread_process_t handler, const char *name, int stack_size,
                 void *user_data)
{
  int status;
  pthread_attr_t attr;

  if (!handler || stack_size < 0)
    return NULL;

  stack_size = (stack_size == 0) ? STACKSIZE : stack_size;

  /* initializing thread attributes */
  status = pthread_attr_init(&attr);

  /* setting the size attribute in thread attributes object */
  status = pthread_attr_setstacksize(&attr, stack_size);

  st_thread_t thread = (st_thread_t)oc_memb_alloc(&st_thread_s);
  if (!thread)
    oc_abort("alloc failed");

  pthread_create((pthread_t *)thread, &attr, handler, user_data);

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
    st_print_log("[ST_PORT] Soft AP is already turned on\n");
    return;
  }

  st_print_log("[ST_PORT] st_turn_on_soft_AP\n");

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
    st_thread_create(soft_ap_process_routine, "SOFT_AP", 0, &g_soft_ap);

  st_mutex_lock(g_soft_ap.mutex);
  st_cond_wait(g_soft_ap.cv, g_soft_ap.mutex);
  st_mutex_unlock(g_soft_ap.mutex);

  st_print_log("[ST_PORT] st_turn_on_soft_AP success\n");
}

static int
system_ret_check(int ret)
{
  if (ret == -1 || ret == 127) {
    st_print_log("[ST_PORT] system() invoke error(%d).\n", ret);
    return -1;
  }
  return 0;
}

void
st_turn_off_soft_AP(void)
{
  if (!g_soft_ap.is_soft_ap_on) {
    st_print_log("[ST_PORT] soft AP is already turned off\n");
  }

  st_print_log("[ST_PORT] st_turn_off_soft_AP\n");
  st_mutex_lock(g_soft_ap.mutex);
  if (g_soft_ap.is_soft_ap_on) {
    // Platform specific funtion for stopping Soft AP
   if (es_stop_softap() == -1)
      st_print_log("[ST_PORT] Failed to stop soft ap\n");
    st_thread_cancel(g_soft_ap.thread);
    g_soft_ap.is_soft_ap_on = 0;
  }
  st_print_log("[ST_PORT] st_turn_off_soft_AP success.\n");

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

int
st_connect_wifi(const char *ssid, const char *pwd)
{
  st_print_log("[ST_PORT] st_connect_wifi in\n");

  st_sleep(5);

  // TODO: auth and enc type should be passed from Wi-Fi Prob Cb
  char auth_type[20] = "wpa2_psk";
  char enc_type[20] = "aes";

  int retry;
  for (retry = 0; retry < 5; ++retry) {
    if (0 == wifi_join(ssid, auth_type, enc_type, pwd)) {
      st_print_log("[ST_PORT] wifi_join success\n");
      break;
    } else {
      st_print_log("[ST_PORT] wifi_join failed\n");
    }
  }

  st_print_log("[ST_PORT] AP join done\n");

  st_print_log("[ST_PORT] st_connect_wifi out\n");
  return 0;
}

void
st_wifi_free_scan_list(st_wifi_ap_t *ap_list)
{
  while (ap_list) {
    st_wifi_ap_t *del = ap_list;
    ap_list = ap_list->next;

    free(del->ssid);
    free(del->mac_addr);
    free(del->channel);
    free(del->max_bitrate);
    free(del->rssi);
    free(del->enc_type);
    free(del->sec_type);
    free(del);
  }
}

void
st_wifi_scan(st_wifi_ap_t **ap_list)
{
//  oc_abort(__func__);
}

#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
static st_wifi_ap_t *g_ap_scan_list = NULL;

void
st_wifi_set_cache(st_wifi_ap_t *scanlist)
{
//  oc_abort(__func__);
}

st_wifi_ap_t*
st_wifi_get_cache(void)
{
  oc_abort(__func__);
}

void
st_wifi_clear_cache(void)
{
  st_wifi_free_scan_list(g_ap_scan_list);
  g_ap_scan_list = NULL;
}
#endif

static void *
soft_ap_process_routine(void *data)
{
  st_soft_ap_t *soft_ap = (st_soft_ap_t *)data;

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  st_print_log("[ST_PORT] soft_ap_handler in\n");

  if (es_create_softap(oc_string(soft_ap->ssid),oc_string(soft_ap->pwd)) == -1) {
    st_print_log("[ST_PORT] Soft AP mode failed!!\n");
    st_mutex_lock(soft_ap->mutex);
    soft_ap->is_soft_ap_on = 0;
    st_mutex_unlock(soft_ap->mutex);
    return NULL;
  }

  st_mutex_lock(soft_ap->mutex);
  st_cond_signal(soft_ap->cv);
  st_mutex_unlock(soft_ap->mutex);

  st_print_log("[ST_PORT] soft_ap_handler out\n");
  st_thread_exit(NULL);
  return NULL;
}

void
wm_scan (void)
{
  st_print_log("%s Start\n",__FUNCTION__);
  wifi_manager_result_e res = WIFI_MANAGER_SUCCESS;
  res = wifi_manager_scan_ap();
  if (res != WIFI_MANAGER_SUCCESS) {
    st_print_log("[ST_PORT] scan failed & val of res %d \n",res);
    return;
  }
  st_print_log("%s Finish\n",__FUNCTION__);
}

void
wifi_scan_done(wifi_manager_scan_info_s **scan_result,wifi_manager_scan_result_e res)
{
  st_print_log("%s Start\n",__FUNCTION__);
  if (!scan_result) {
    st_print_log("ap_list is NULL\n");
    return;
  }
  st_mutex_lock(g_soft_ap.mutex);
  wifi_manager_scan_info_s *wifi_scan_iter = *scan_result;
  st_wifi_ap_t *pinfo = NULL;
  st_wifi_ap_t *p_last_info = NULL;
  while (wifi_scan_iter != NULL) {
    if ( strlen(wifi_scan_iter->ssid) != 0) {
      pinfo = (st_wifi_ap_t*)calloc(1,sizeof(st_wifi_ap_t));
      pinfo->next = NULL;
      //ssid
      int len = strlen(wifi_scan_iter->ssid);
      pinfo->ssid = (char*) calloc(len+1,sizeof(char));
      strncpy(pinfo->ssid,wifi_scan_iter->ssid,len);
      //mac address
      len = strlen(wifi_scan_iter->bssid);
      pinfo->mac_addr = (char*)calloc(len+1,sizeof(char));
      strncpy(pinfo->mac_addr,wifi_scan_iter->bssid,len);
      //channel
      pinfo->channel = (char*) calloc(4,sizeof(char));
      snprintf(pinfo->channel,4,"%d",wifi_scan_iter->channel);
      //rssi
      pinfo->rssi = (char*) calloc(4,sizeof(char));
      snprintf(pinfo->rssi,4,"%d",wifi_scan_iter->rssi);
      //sec type
      const char *sec_type = "WPA2";
      pinfo->sec_type = (char*) calloc(strlen(sec_type)+1,sizeof(char));
      strncpy(pinfo->sec_type,sec_type,strlen(sec_type));
      //enc type
      const char * enc_type = "AES";
      pinfo->enc_type = (char*) calloc(strlen(enc_type)+1,sizeof(char));
      strncpy(pinfo->enc_type,enc_type,strlen(enc_type));

      if (g_wifi_scan_info == NULL) {
        g_wifi_scan_info = pinfo;
      } else {
          p_last_info->next = pinfo;
        }

      p_last_info = pinfo;
      g_wifi_count++;
    }
    wifi_scan_iter = wifi_scan_iter->next;
  }
  pinfo = g_wifi_scan_info;
  while (pinfo != NULL) {
    st_print_log("[St Port] WiFi AP - SSID: %20s, WiFi AP BSSID: %-20s\n", pinfo->ssid, pinfo->mac_addr);
    pinfo = pinfo->next;
  }
  st_print_log("[St Port] Found %d neighbouring access points\n", g_wifi_count);
  st_print_log("%s Finish\n",__FUNCTION__);
  st_mutex_unlock(g_soft_ap.mutex);
}

int
st_get_ap_list(st_wifi_ap_t** p_info, int* p_count)
{
  if (p_info == NULL || p_count == NULL) {
    st_print_log("[St Port] cant be NULL");
    return 0;
  }
  st_mutex_lock(g_soft_ap.mutex);
  *p_count = g_wifi_count;
  st_wifi_ap_t *wifi_scan_iter = g_wifi_scan_info;
  st_wifi_ap_t *pinfo = NULL;
  st_wifi_ap_t *p_last_info = NULL;
  while (wifi_scan_iter != NULL ) {
    pinfo = (st_wifi_ap_t*)calloc(1,sizeof(st_wifi_ap_t));
    pinfo->next = NULL;
    //ssid
    int len = strlen(wifi_scan_iter->ssid);
    pinfo->ssid = (char*) calloc(len+1,sizeof(char));
    strncpy(pinfo->ssid,wifi_scan_iter->ssid,len);
    //mac address
    len = strlen(wifi_scan_iter->mac_addr);
    pinfo->mac_addr = (char*)calloc(len+1,sizeof(char));
    strncpy(pinfo->mac_addr,wifi_scan_iter->mac_addr,len);
    //channel
    pinfo->channel = (char*) calloc(4,sizeof(char));
    snprintf(pinfo->channel,4,"%d",wifi_scan_iter->channel);
    //rssi
    pinfo->rssi = (char*) calloc(4,sizeof(char));
    snprintf(pinfo->rssi,4,"%d",wifi_scan_iter->rssi);
    // sec type
    len = strlen(wifi_scan_iter->sec_type);
    pinfo->sec_type = (char*) calloc(len+1,sizeof(char));
    strncpy(pinfo->sec_type,wifi_scan_iter->sec_type,len);
    // enc type
    len = strlen(wifi_scan_iter->enc_type);
    pinfo->enc_type = (char*) calloc(len+1,sizeof(char));
    strncpy(pinfo->enc_type,wifi_scan_iter->enc_type,len);
    if (*p_info == NULL) {
      *p_info = pinfo;
    } else {
        p_last_info->next = pinfo;
      }
      p_last_info = pinfo;
      wifi_scan_iter = wifi_scan_iter->next;
  }
  st_mutex_unlock(g_soft_ap.mutex);
  return 1;
}
