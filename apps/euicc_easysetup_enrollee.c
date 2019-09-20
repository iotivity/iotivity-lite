/****************************************************************************
 *
 * Copyright (c) 2019 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include "oc_api.h"
#include "port/oc_clock.h"
#include "oc_easysetup_enrollee.h"

#define MAX_APP_DATA_SIZE 8192
#define MAX_MTU_SIZE 2048

#define	DEVICE_INDEX	1

static pthread_mutex_t mutex;
static pthread_cond_t cond;
static struct timespec ts;
static bool g_exit = 0;

void ees_prov_cb(oc_ees_data *ees_prov_data)
{
  (void)ees_prov_data;
  PRINT("ees_prov_cb triggered\n");
}

void rsp_prov_cb(oc_ees_rsp_data *rsp_prov_data)
{
  (void)rsp_prov_data;
  // TODO : Wite Access code to LPA
  PRINT("rsp_prov_cb triggered\n");
}

void rspcap_prov_cb(oc_ees_rspcap_data *rspcap_prov_data)
{
  (void)rspcap_prov_data;
  PRINT("rspcap_prov_cb triggered\n");
}

static void free_userdata_cb(void* userdata, char* resource_type)
{
    (void)resource_type;
    (void)userdata;

    printf("free_userdata_cb");
}

static void read_userdata_cb(oc_rep_t* payload, char* resource_type,
	void** userdata)
{
    (void)resource_type;
    (void)payload;
    (void)userdata;

    printf("read_userdata_cb");
}

static void write_userdata_cb(oc_rep_t* payload, char* resource_type)
{
    (void)resource_type;
    (void)payload;

    printf("write_userdata_cb");
}

static int
app_init(void)
{
  int err = oc_init_platform("Samsung", NULL, NULL);

  // oc_create_esim_easysetup_resource will be called by IoT Core
  err |= oc_add_device("/oic/d", "oic.d.electricmeter", "eSIM Easysetup Test", "ocf.2.0.2",
                       "ocf.res.2.0.2", NULL, NULL);

  // Start Sof AP
  
  // Start DHCP Server
  
  return err;
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cond);
  pthread_mutex_unlock(&mutex);
}

static void
register_resources(void)
{
  char euicc_info[256];
  char device_info[256];
  oc_ees_device_info ees_device_info;

  // TODO : Register oic.r.energy.consumption resource here

  // Set callbacks for Resource operations
  oc_ees_set_resource_callbacks(DEVICE_INDEX, &ees_prov_cb, &rsp_prov_cb, &rspcap_prov_cb);
  // Set callbacks for Vendor Specific Properties
  oc_ees_set_userdata_callbacks(DEVICE_INDEX, &read_userdata_cb, &write_userdata_cb, &free_userdata_cb);
  
  // Read euicc_info, device_info from LPA

  
  // Set Device Info
  oc_new_string(&ees_device_info.LPA.euicc_info, euicc_info, strlen(euicc_info));
  oc_new_string(&ees_device_info.LPA.device_info, device_info, strlen(device_info));
  
   if (oc_ees_set_device_info(DEVICE_INDEX, &ees_device_info) == OC_ES_ERROR)
       printf("oc_es_set_device_info error!\n");

}

static void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  g_exit = true;
}

void main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  // Init LPA Here

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cond, NULL);
  
  // Create OCF handler
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =  register_resources };
  

  oc_set_mtu_size(MAX_MTU_SIZE);
  oc_set_max_app_data_size(MAX_APP_DATA_SIZE);

#ifdef OC_SECURITY
  oc_storage_config("/mnt/smart_meter_creds");
#endif

  if (oc_main_init(&handler) < 0) {
    PRINT("oc_main_init failed");
    return;
  }
  
  oc_clock_time_t next_event;

  while (!g_exit) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cond, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cond, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_delete_esim_easysetup_resource(DEVICE_INDEX);
  oc_main_shutdown();
  return;
}
