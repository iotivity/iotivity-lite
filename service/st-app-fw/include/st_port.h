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
#include "oc_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *st_mutex_t;
typedef void *st_cond_t;
typedef void *st_thread_t;
typedef void *(*st_thread_process_t)(void *);
typedef void (*st_sig_handler_t)(int);

typedef enum { ST_LOOP_QUIT, ST_LOOP_RESET } st_loop_status_t;

typedef struct st_wifi_ap_s
{
  char *ssid;
  char *mac_addr;
  char *channel;
  char *max_bitrate;
  char *rssi;
  char *enc_type;
  char *sec_type;
  struct st_wifi_ap_s *next;
} st_wifi_ap_t;

int st_port_specific_init(void);
void st_port_specific_destroy(void);

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

st_thread_t st_thread_create(st_thread_process_t handler, const char *name,
                             int stack_size, void *user_data);
int st_thread_destroy(st_thread_t thread);
int st_thread_join(st_thread_t thread);
int st_thread_cancel(st_thread_t thread);
void st_thread_exit(void *retval);

void st_sleep(int seconds);
void st_turn_on_soft_AP(const char *ssid, const char *pwd, int channel);
void st_turn_off_soft_AP(void);
int st_connect_wifi(const char *ssid, const char *pwd);

void st_wifi_scan(st_wifi_ap_t **ap_list);
void st_wifi_free_scan_list(st_wifi_ap_t *ap_list);
#ifndef WIFI_SCAN_IN_SOFT_AP_SUPPORTED
void st_wifi_set_cache(st_wifi_ap_t *ap_list);
st_wifi_ap_t* st_wifi_get_cache(void);
void st_wifi_clear_cache(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ST_PORT_H */
