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
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "st_manager.h"
#include "st_process.h"
#include "st_resource_manager.h"
#include "util/oc_memb.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>

#ifndef MOCK_WIFI_SCAN
#include <iwlib.h>
#endif

#define ST_DEFAULT_STACK_SIZE 8192

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
#ifdef STATE
  st_mutex_t mutex = (st_mutex_t)malloc(sizeof(pthread_mutex_t));
#else
  st_mutex_t mutex = (st_mutex_t)oc_memb_alloc(&st_mutex_s);
#endif
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
#ifdef STATE
  free(mutex);
#else
  oc_memb_free(&st_mutex_s, mutex);
#endif

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
#ifdef STATE
  st_cond_t cv = (st_cond_t)malloc(sizeof(pthread_cond_t));
#else
  st_cond_t cv = (st_cond_t)oc_memb_alloc(&st_cond_s);
#endif
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
#ifdef STATE
  free(cv);
#else
  oc_memb_free(&st_cond_s, cv);
#endif

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
  if (!handler || stack_size < 0)
    return NULL;

  stack_size = stack_size == 0 ? ST_DEFAULT_STACK_SIZE : stack_size;
#ifdef STATE
  st_thread_t thread = (st_thread_t)malloc(sizeof(pthread_t));
#else
  st_thread_t thread = (st_thread_t)oc_memb_alloc(&st_thread_s);
#endif
  if (!thread)
    oc_abort("alloc failed");

  // TODO : stack size set api call.
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
#ifdef STATE
  free(thread);
#else
  oc_memb_free(&st_thread_s, thread);
#endif

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
    SYSTEM_RET_CHECK(system("sudo pkill hostapd"));
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
  if (!ssid) {
    st_print_log("[ST_PORT] st_connect_wifi failed\n");
    return -1;
  }
  st_print_log("[ST_PORT] st_connect_wifi in\n");

  /** sleep to allow response sending from post_callback thread before turning
   * Off Soft AP. */
  st_sleep(1);

  st_print_log("[ST_PORT] target ap ssid: %s\n", ssid);
  st_print_log("[ST_PORT] password: %s\n", pwd);

  /** Stop Soft AP */
  st_print_log("[ST_PORT] Stopping Soft AP\n");
  SYSTEM_RET_CHECK(system("sudo service hostapd stop"));

  /** Turn On Wi-Fi */
  st_print_log("[ST_PORT] Turn on the AP\n");
  SYSTEM_RET_CHECK(system("sudo nmcli radio wifi on"));

  /** On some systems it may take time for Wi-Fi to turn ON. */
  st_sleep(1);

  /** Connect to Target Wi-Fi AP */
  st_print_log("[ST_PORT] connect to %s AP.\n", ssid);
  int len = 32 + strlen(ssid) + strlen(pwd);
  char nmcli_command[200];
  snprintf(nmcli_command, len, "nmcli d wifi connect %s password %s", ssid,
           pwd);
  st_print_log("[ST_PORT] $ %s\n", nmcli_command);
  SYSTEM_RET_CHECK(system(nmcli_command));

  st_print_log("[ST_PORT] st_connect_wifi out\n");
  return 0;

exit:
  st_print_log("[ST_PORT] st_connect_wifi error occur\n");
  return -1;
}

/* TODO: libiw-dev is required to be installed to scan wifi access
 * points. Jenkins build system lacks this package and to avoid build
 * failure in Jenkins we are mocking wifi scan.
 * Disable MOCK_WIFI_SCAN when libiw-dev is intalled in Jenkins build
 * system.
 */
#ifdef MOCK_WIFI_SCAN
void
st_wifi_scan(st_wifi_ap_t **ap_list)
{
  st_print_log("[ST_PORT] Mock wifi scan...\n");

  st_wifi_ap_t *list_tail = NULL;
  *ap_list = NULL;
  int cnt=3;
  while (cnt--) {
    st_wifi_ap_t *ap = (st_wifi_ap_t*) calloc(1, sizeof(st_wifi_ap_t));

    // ssid
    char name[15];
    sprintf(name, "iot_home_%d", cnt);
    int len = strlen(name);
    ap->ssid = (char*) calloc(len+1, sizeof(char));
    strncpy(ap->ssid, name, len);

    // Mac
    ap->mac_addr = (char*) calloc(18, sizeof(char));
    strncpy(ap->mac_addr, "00:11:22:33:44:55", strlen("00:11:22:33:44:55"));

    // Channel
    ap->channel = (char*)calloc(4, sizeof(char));
    strncpy(ap->channel, "15", strlen("15"));

    // Max-bitrate
    ap->max_bitrate = (char*)calloc(5, sizeof(char));
    strncpy(ap->max_bitrate, "38", strlen("38"));

    // rssi
    ap->rssi = (char*)calloc(5, sizeof(char));
    strncpy(ap->rssi, "-10", strlen("-10"));

    // security type
    const char *sec_type = "WPA2";
    ap->sec_type = (char*) calloc(strlen(sec_type)+1, sizeof(char));
    strncpy(ap->sec_type, sec_type, strlen(sec_type));

    // encryption type
    const char *enc_type = "AES";
    ap->enc_type = (char*) calloc(strlen(enc_type)+1, sizeof(char));
    strncpy(ap->enc_type, enc_type, strlen(enc_type));

    if (!*ap_list) {
      *ap_list = ap;
    } else {
      list_tail->next = ap;
    }
    list_tail = ap;
  }
}
#else
void
st_wifi_scan(st_wifi_ap_t **ap_list)
{
  if (!ap_list) {
    return;
  }

  wireless_scan_head head;
  iwrange range;
  int sock;
  char *wiface = "wlp2s0";  // NOTE: Replace wlp2s0 with proper interface name.

  st_print_log("[ST_PORT] Scanning for neighbour wifi accesspoints\n");

  /* Open socket to kernel */
  sock = iw_sockets_open();

  /* Get some metadata to use for scanning */
  if (iw_get_range_info(sock, wiface, &range) < 0) {
    st_print_log("[ST_PORT] failed to get range info\n");
    return;
  }

  /* Perform the scan */
  if (iw_scan(sock, wiface, range.we_version_compiled, &head) < 0) {
    st_print_log("[ST_PORT] scan failed!\n");
    return;
  }

  wireless_scan *result = head.result;
  st_wifi_ap_t *tail = NULL;
  *ap_list = NULL;
  int cnt = 0;
  // TODO: Restricting to 10 as failed to send response with more wifi aps.
  // Is there a priority to select wifi aps to include in response ?
  while (result && cnt < 10) {
    st_wifi_ap_t *ap = (st_wifi_ap_t*) calloc(1, sizeof(st_wifi_ap_t));

    // ssid
    int len = strlen(result->b.essid);
    ap->ssid = (char*) calloc(len+1, sizeof(char));
    strncpy(ap->ssid, result->b.essid, len);

    // mac address
    ap->mac_addr = (char*) calloc(18, sizeof(char));
    iw_sawap_ntop(&result->ap_addr, ap->mac_addr);

    // channel
    ap->channel = (char*)calloc(4, sizeof(char));
    snprintf(ap->channel, 4, "%d", iw_freq_to_channel(result->b.freq, &range));

    // max bitrate
    ap->max_bitrate = (char*)calloc(5, sizeof(char));
    snprintf(ap->max_bitrate, 5, "%d", result->maxbitrate.value/(int)1e6);

    // rssi
    if (result->has_stats) {
      char quality[40]={0};
      iw_print_stats(quality, sizeof(quality), &result->stats.qual, &range, 1);
      char *sig_start = strstr(quality, "Signal level=");
      if (sig_start) {
        sig_start += strlen("Signal level=");
        char *sig_end = strstr(sig_start, " ");
        ap->rssi = (char*) calloc((sig_end - sig_start)+1, sizeof(char));
        strncpy(ap->rssi, sig_start, sig_end-sig_start);
      }
    }

    // encryption type and security type
    if (result->b.has_key) {
      // TODO: Getting security type is tough, thus using hardcode value
      // as of now
      const char *sec_type = "WPA2";
      ap->sec_type = (char*) calloc(strlen(sec_type)+1, sizeof(char));
      strncpy(ap->sec_type, sec_type, strlen(sec_type));

      const char *enc_type = "AES";
      ap->enc_type = (char*) calloc(strlen(enc_type)+1, sizeof(char));
      strncpy(ap->enc_type, enc_type, strlen(enc_type));
    }

    if (!*ap_list) {
      *ap_list = ap;
    } else {
      tail->next = ap;
    }
    tail = ap;
    result = result->next;
    cnt++;
  }

  st_print_log("[ST_PORT] Found %d neighbor wifi access points\n", cnt);
}
#endif

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

#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
static st_wifi_ap_t *g_ap_scan_list = NULL;

void
st_wifi_set_cache(st_wifi_ap_t *ap_list)
{
  st_wifi_clear_cache();
  g_ap_scan_list = ap_list;
}

st_wifi_ap_t*
st_wifi_get_cache(void)
{
  return g_ap_scan_list;
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

  /** Stop AP */
  st_print_log("[ST_PORT] Stopping AP\n");
  SYSTEM_RET_CHECK(system("sudo nmcli radio wifi off"));
  SYSTEM_RET_CHECK(system("sudo rfkill unblock wlan"));

  /** Turn On Wi-Fi interface */
  st_print_log("[ST_PORT] Turn on the wifi interface\n");

  char interface[100];
  FILE *p = popen("iw dev | awk '$1==\"Interface\"{printf $2}'", "r");
  if (!p) {
    st_print_log("[ST_PORT] popen failed.\n");
    goto exit;
  }
  while (fgets(interface, sizeof(interface), p) != NULL)
    ;
  int interface_len = strlen(interface);
  if (interface_len <= 0) {
    st_print_log("[ST_PORT] Can't find wifi interface.\n");
    goto exit;
  }

  int len = 30 + interface_len;
  char nmcli_command[200];
  snprintf(nmcli_command, len, "sudo ifconfig %s 10.0.0.2/24 up", interface);
  st_print_log("[ST_PORT] $ %s\n", nmcli_command);
  SYSTEM_RET_CHECK(system(nmcli_command));

  /** On some systems it may take time for Wi-Fi to turn ON. */
  st_print_log("[ST_PORT] $ sudo service dnsmasq restart\n");
  SYSTEM_RET_CHECK(system("sudo service dnsmasq restart"));

  st_print_log("[ST_PORT] $ sudo service radvd restart\n");
  SYSTEM_RET_CHECK(system("sudo service radvd restart"));

  st_print_log("[ST_PORT] $ sudo service hostapd start\n");
  SYSTEM_RET_CHECK(system("sudo service hostapd start"));

  st_mutex_lock(soft_ap->mutex);
  st_cond_signal(soft_ap->cv);
  st_mutex_unlock(soft_ap->mutex);

  st_print_log("[ST_PORT] $ sudo hostapd /etc/hostapd/hostapd.conf\n");
  SYSTEM_RET_CHECK(system("sudo hostapd /etc/hostapd/hostapd.conf"));

  st_print_log("[ST_PORT] $ Soft ap is off\n");
  goto exit_normal;

exit:
  st_mutex_lock(soft_ap->mutex);
  st_cond_signal(soft_ap->cv);
  st_mutex_unlock(soft_ap->mutex);
exit_normal:
  st_thread_exit(NULL);
  return NULL;
}
