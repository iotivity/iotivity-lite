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

/* setting up the stack size for st_thread */
#define STACKSIZE 4096

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

static st_soft_ap_t g_soft_ap;

OC_MEMB(st_mutex_s, pthread_mutex_t, 10);
OC_MEMB(st_cond_s, pthread_cond_t, 10);
OC_MEMB(st_thread_s, pthread_t, 10);

static void *soft_ap_process_routine(void *data);

int
st_port_specific_init(void)
{
  /* set port specific logics. in here */
  return 0;
}

void
st_port_specific_destroy(void)
{
  /* set initialized port specific logics destroyer. in here */
  return;
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
    st_thread_create(soft_ap_process_routine, "SOFT_AP", 0, &g_soft_ap);

  st_mutex_lock(g_soft_ap.mutex);
  st_cond_wait(g_soft_ap.cv, g_soft_ap.mutex);
  st_mutex_unlock(g_soft_ap.mutex);

  st_print_log("[St_Port] st_turn_on_soft_AP success\n");
}

static int
system_ret_check(int ret)
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
    // Platform specific funtion for stopping Soft AP
    es_stop_softap();
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

int
st_connect_wifi(const char *ssid, const char *pwd)
{
  st_print_log("[St_Port] st_connect_wifi in\n");

  st_sleep(5);

  // TODO: auth and enc type should be passed from Wi-Fi Prob Cb
  char auth_type[20] = "wpa2_psk";
  // char enc_type[20] = "aes";

  if (wifi_start_station() < 0) {
    st_print_log("start station error! \n");
    return -1;
  }

  int retry;
  for (retry = 0; retry < 5; ++retry) {
    if (0 == wifi_join(ssid, auth_type, pwd)) {
      st_print_log("wifi_join success\n");
      break;
    } else {
      st_print_log("wifi_join failed\n");
    }
  }

  st_print_log("AP join done\n");

  for (retry = 0; retry < 5; ++retry) {
    if (0 == dhcpc_start()) {
      st_print_log("dhcpc_start success\n");
      break;
    } else {
      st_print_log("Get IP address failed\n");
    }
  }

  st_print_log("[St_Port] st_connect_wifi out\n");
  return 0;
}

static void wm_start();
static void wm_scan();
static void wm_stop();
//callbacks
static void wm_scan_done(wifi_manager_scan_info_s **scan_result,wifi_manager_scan_result_e res);
static void wm_sta_connected(wifi_manager_result_e);
static void wm_sta_disconnected(void);
static void wm_softap_sta_join(void);
static void wm_softap_sta_leave(void);

static wifi_manager_cb_s wifi_callbacks = {
    wm_sta_connected,
    wm_sta_disconnected,
    wm_softap_sta_join,
    wm_softap_sta_leave,
    wm_scan_done,
};

static wifi_manager_cb_s wifi_null_callbacks = {
    NULL,NULL,NULL,NULL,NULL,
};

static pthread_mutex_t g_wm_mutex = PTHREAD_MUTEX_INITIALIZER;;
static pthread_cond_t g_wm_cond;
static pthread_mutex_t g_wm_func_mutex = PTHREAD_MUTEX_INITIALIZER;;
static pthread_cond_t g_wm_func_cond;
static int g_mode = 0;

#define WM_TEST_FUNC_WAIT                                                           \
    do{                                                                             \
        pthread_mutex_lock(&g_wm_func_mutex);                                       \
        st_print_log( "wait func signal\n" );                                       \
        pthread_cond_wait(&g_wm_func_cond,&g_wm_func_mutex);                        \
        pthread_mutex_unlock(&g_wm_func_mutex);                                     \
    }while(0)

#define WM_TEST_WAIT                                                                \
    do{                                                                             \
        pthread_mutex_lock(&g_wm_mutex);                                            \
        st_print_log("wait signal\n");                                              \
        pthread_cond_wait(&g_wm_cond,&g_wm_mutex);                                  \
        pthread_mutex_unlock(&g_wm_mutex);                                          \
    }while(0)

#define WM_TEST_LOG_START                                                           \
    do{                                                                             \
        st_print_log("%s\n",__FUNCTION__);                                          \
    }while(0)

#define WM_TEST_LOG_END                                                             \
    do{                                                                             \
        st_print_log("%s\n",__FUNCTION__);                                          \
    }while(0)

#define WM_TEST_SIGNAL                                                              \
    do{                                                                             \
        pthread_mutex_lock(&g_wm_mutex);                                            \
        printf("%d send signal\n",getpid());                                        \
        pthread_cond_signal(&g_wm_cond);                                            \
        pthread_mutex_unlock(&g_wm_mutex);                                          \
    }while(0)

//global variable
wifi_manager_scan_info_s *g_store_result = NULL;

//callback
void wm_sta_connected(wifi_manager_result_e res){
    printf("res (%d)\n",res);
    WM_TEST_SIGNAL;
}
void wm_sta_disconnected(void){
    sleep(2);
    printf("%s\n",__FUNCTION__);
    WM_TEST_SIGNAL;
}
void wm_softap_sta_join(void){
    printf("%s\n",__FUNCTION__);
    WM_TEST_SIGNAL;
}
void wm_softap_sta_leave(void){
    printf("%s\n",__FUNCTION__);
    WM_TEST_SIGNAL;
}

int ws_signal_init(void){
    if(g_mode != 0){
        printf("Program is already running\n");
        return -1;
    }
    g_mode = 1;
    int res = pthread_mutex_init(&g_wm_func_mutex,NULL);
    if(res != 0){
        printf("Pthread mutex func init fail(%d)\n",res);
        return -1;
    }
    res = pthread_cond_init(&g_wm_func_cond,NULL);
    if(res != 0){
        printf("Conditional mutex func init fail\n");
        return -1;
    }
    res = pthread_mutex_init(&g_wm_mutex,NULL);
    if(res != 0){
        printf("Pthread mutex init failed\n");
        return -1;
    }
    res = pthread_cond_init(&g_wm_cond,NULL);
    if(res != 0){
        printf("Conditional mutex init failed\n");
        return -1;
    }
    return 0;
}

void ws_signal_deinit(){
    pthread_mutex_destroy(&g_wm_func_mutex);
    pthread_cond_destroy(&g_wm_func_cond);
    pthread_mutex_destroy(&g_wm_mutex);
    pthread_cond_destroy(&g_wm_cond);
    g_mode = 0;
}
void wm_start(){
    wifi_manager_result_e res = WIFI_MANAGER_SUCCESS;
    res = wifi_manager_init(&wifi_callbacks);
    if(res != WIFI_MANAGER_SUCCESS){
        printf("wifi manager init failed\n");
    }
}
void wm_scan_done(wifi_manager_scan_info_s **scan_result,wifi_manager_scan_result_e res){
    printf("%d->%d\n",getpid(),__FUNCTION__);
    if(scan_result == NULL){
        WM_TEST_SIGNAL;
        return;
    }
    wifi_manager_scan_info_s *cur = NULL, *prev = NULL;
    wifi_manager_scan_info_s *scan_iter = *scan_result;
    while(scan_iter != NULL){
        wifi_manager_scan_info_s *temp = (wifi_manager_scan_info_s *)calloc(1,sizeof(wifi_manager_scan_info_s));
        temp->next = NULL;

        temp->rssi = scan_iter->rssi;
        temp->channel = scan_iter->channel;
        temp->phy_mode = scan_iter->phy_mode;
        strncpy(temp->ssid,(char *)scan_iter->ssid,32);
        strncpy(temp->bssid,(char *)scan_iter->bssid,17);
        if(cur == NULL){
            cur = temp;
            prev = temp;
        }
        else{
            prev->next = temp;
            prev = temp;
        }
        scan_iter = scan_iter->next;
    }
    g_store_result = cur;
    WM_TEST_SIGNAL;
}
void wm_scan(){
    WM_TEST_LOG_START;
    wifi_manager_result_e res = WIFI_MANAGER_SUCCESS;

    res = wifi_manager_scan_ap();
    if(res != WIFI_MANAGER_SUCCESS){
        printf("scan failed\n");
        return;
    }
    WM_TEST_WAIT;
    WM_TEST_LOG_END;
}
void wm_stop(){
    WM_TEST_LOG_START;
    wifi_manager_result_e res = wifi_manager_deinit();
    if(res != WIFI_MANAGER_SUCCESS){
        printf("Wifi manager failed to stop\n");
    }
    WM_TEST_LOG_END;
}
void st_scan_wifi(){
    int res = ws_signal_init();
    if(res < 0){
        return;
    }
    wm_start();
    wm_scan();
    wm_stop();

    wifi_manager_scan_info_s *iter = g_store_result;
    while(iter != NULL){
        printf("BSSID = %-20s, SSID = %-20s,Rssi : %d\n",iter->bssid,iter->ssid,iter->rssi);
        iter = iter->next;
    }
    ws_signal_deinit();
    return;
}

void
st_wifi_scan(st_wifi_ap_t **ap_list)
{
    if(!ap_list){
        return;
    }
    st_scan_wifi();
    wifi_manager_scan_info_s *res = g_store_result;
    st_wifi_ap_t *tail = NULL;
    *ap_list = NULL;
    int cnt = 0;
    while(res && cnt < 10){
        st_wifi_ap_t *ap = (st_wifi_ap_t*)calloc(1,sizeof(st_wifi_ap_t));

        //ssid
        int len = strlen(res->ssid);
        ap->ssid = (char*) calloc(len+1,sizeof(char));
        strncpy(ap->ssid,res->ssid,len);

        //mac address
        len = strlen(res->bssid);
        ap->mac_addr = (char*)calloc(len+1,sizeof(char));
        strncpy(ap->mac_addr,res->bssid,len);

        //channel
        ap->channel = (char*) calloc(4,sizeof(char));
        snprintf(ap->channel,4,"%d",res->channel);

        //rssi
        ap->rssi = (char*) calloc(4,sizeof(char));
        snprintf(ap->rssi,4,"%d",res->rssi);

        //enc type
        const char *sec_type = "WPA2";
        ap->sec_type = (char*) calloc(strlen(sec_type)+1,sizeof(char));
        strncpy(ap->sec_type,sec_type,strlen(sec_type));


        //sec type
        const char * enc_type = "AES";
        ap->enc_type = (char*) calloc(strlen(enc_type)+1,sizeof(char));
        strncpy(ap->enc_type,enc_type,strlen(enc_type));

        if(!*ap_list){
            *ap_list = ap;
        }else{
            tail->next = ap;
        }
        tail = ap;
        res = res->next;
        cnt++;
    }
    printf("[St Port] Found %d neighbouring access points\n",cnt);
}

void
st_wifi_free_scan_list(st_wifi_ap_t *ap_list){
    while(ap_list){
        st_wifi_ap_t *del = ap_list;
        ap_list = ap_list->next;

        free(del->ssid);
        free(del->mac_addr);
        free(del->channel);
        free(del->rssi);
        free(del->max_bitrate);
        free(del->enc_type);
        free(del->sec_type);
        free(del);
    }
}

static st_wifi_ap_t *g_ap_scan_list = NULL;

void
st_wifi_set_cache(st_wifi_ap_t *scanlist)
{
    st_wifi_clear_cache();
    g_ap_scan_list = scanlist;
}

st_wifi_ap_t*
st_wifi_get_cache(void)
{
  return g_ap_scan_list;
}

void
st_wifi_clear_cache(void){
    st_wifi_free_scan_list(g_ap_scan_list);
    g_ap_scan_list = NULL;
}

static void *
soft_ap_process_routine(void *data)
{
  st_soft_ap_t *soft_ap = (st_soft_ap_t *)data;

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  st_print_log("[St_Port] soft_ap_handler in\n");

  if (es_create_softap() == -1) {
    st_print_log("Soft AP mode failed!!\n");
    st_mutex_lock(soft_ap->mutex);
    soft_ap->is_soft_ap_on = 0;
    st_mutex_unlock(soft_ap->mutex);
    return NULL;
  }

  dhcpserver_start();

  st_mutex_lock(soft_ap->mutex);
  st_cond_signal(soft_ap->cv);
  st_mutex_unlock(soft_ap->mutex);

  st_print_log("[St_Port] soft_ap_handler out\n");
  st_thread_exit(NULL);
  return NULL;
}
