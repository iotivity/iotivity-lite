/****************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics
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
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include "oc_easysetup_enrollee.h"
#include "wifi.h"

#define SOFT_AP_SSID "TestEnrollee"
#define SOFT_AP_PSK "111222333"

// There are indicative values and might vary with application requirement
#define MAX_APP_DATA_SIZE 8192
#define MAX_MTU_SIZE 2048

static int g_device_count = 0;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
static struct timespec ts;
static bool g_exit = 0;

// Device 1 Callbaks
static void
wes_prov_cb1(oc_wes_data_t *wes_prov_data)
{
  PRINT("wes_prov_cb1\n");
  if (wes_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
}

static void
device_prov_cb1(oc_wes_device_data_t *device_prov_data)
{
  PRINT("device_prov_cb1\n");
  if (device_prov_data == NULL) {
      PRINT("device_prov_data is NULL\n");
      return;
  }
  PRINT("Device Name: %s\n", oc_string(device_prov_data->device_name));
}

static void
wifi_prov_cb1(oc_wes_wifi_data_t *wifi_prov_data)
{
  PRINT("wifi_prov_cb1 triggered\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->pwd));
  PRINT("AuthType : %d\n", wifi_prov_data->authtype);
  PRINT("EncType : %d\n", wifi_prov_data->enctype);

  //1  Stop DHCP Server
  wifi_stop_dhcp_server();
  //1 Start WiFi Station
  wifi_start_station();
  //1 Join WiFi AP with ssid, authtype and pwd
  wifi_join(NULL, NULL);
  //1 Start DHCP client
  wifi_start_dhcp_client();
}

static void
free_userdata_cb1(void* userdata, char* resource_type)
{
    (void)resource_type;
    (void)userdata;
    PRINT("free_userdata_cb1");
}

static void
read_userdata_cb1(oc_rep_t* payload, char* resource_type,
	void** userdata)
{
    (void)resource_type;
    (void)payload;
    (void)userdata;
    PRINT("read_userdata_cb1");
}

static void
write_userdata_cb1(oc_rep_t* payload, char* resource_type)
{
    (void)resource_type;
    (void)payload;
    PRINT("write_userdata_cb1");
}

// Device 2 Callbaks
static void
wes_prov_cb2(oc_wes_data_t *wes_prov_data)
{
  PRINT("wes_prov_cb2\n");
  if (wes_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
}

static void
device_prov_cb2(oc_wes_device_data_t *device_prov_data)
{
  PRINT("device_prov_cb2\n");
  if (device_prov_data == NULL) {
      PRINT("device_prov_data is NULL\n");
      return;
  }
  PRINT("Device Name: %s\n", oc_string(device_prov_data->device_name));
}

static void
wifi_prov_cb2(oc_wes_wifi_data_t *wifi_prov_data)
{
  PRINT("wifi_prov_cb2\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->pwd));
  PRINT("AuthType : %d\n", wifi_prov_data->authtype);
  PRINT("EncType : %d\n", wifi_prov_data->enctype);
  //1  Stop DHCP Server
  wifi_stop_dhcp_server();
  //1 Start WiFi Station
  wifi_start_station();
  //1 Join WiFi AP with ssid, authtype and pwd
  wifi_join(NULL, NULL);
  //1 Start DHCP client
  wifi_start_dhcp_client();
}

static void
free_userdata_cb2(void* userdata, char* resource_type)
{
    (void)resource_type;
    (void)userdata;
    PRINT("free_userdata_cb2");
}

static void
read_userdata_cb2(oc_rep_t* payload, char* resource_type,
	void** userdata)
{
    (void)resource_type;
    (void)payload;
    (void)userdata;
    PRINT("read_userdata_cb2");
}

static void
write_userdata_cb2(oc_rep_t* payload, char* resource_type)
{
    (void)resource_type;
    (void)payload;
    PRINT("write_userdata_cb2");
}

// resource proisining callbacks for 2 devices
wes_device_callbacks_s g_rsc_cbks[] = {
  {
    .oc_wes_prov_cb_t = &wes_prov_cb1,
    .oc_wes_wifi_prov_cb_t = &wifi_prov_cb1,
    .oc_wes_dev_prov_cb_t = &device_prov_cb1,
  },
  {
    .oc_wes_prov_cb_t = &wes_prov_cb2,
    .oc_wes_wifi_prov_cb_t = &wifi_prov_cb2,
    .oc_wes_dev_prov_cb_t = &device_prov_cb2,
  }
};

// vendor specific callbacks for 2 devices
es_userdata_callbacks_s g_ud_cbks[] = {
  {
    .oc_es_write_userdata_cb_t = &write_userdata_cb1,
    .oc_es_read_userdata_cb_t = &read_userdata_cb1,
    .oc_es_free_userdata_cb_t = &free_userdata_cb1
  },
  {
    .oc_es_write_userdata_cb_t = &write_userdata_cb2,
    .oc_es_read_userdata_cb_t = &read_userdata_cb2,
    .oc_es_free_userdata_cb_t = &free_userdata_cb2
  }
};
static int
app_init(void)
{
  int err = oc_init_platform("Samsung", NULL, NULL);
  if(err) {
    PRINT("oc_init_platform error %d\n", err);
    return err;
  }

  // oc_create_wifi_easysetup_resource will be called by IoT Core
  err = oc_add_device("/oic/d", "oic.d.test1", "WiFi Easysetup Test", "ocf.2.0",
                       "ocf.res.2.0", NULL, NULL);
  if(err) {
    PRINT("Add oic.d.test1 device error %d\n", err);
    return err;
  }
  err = oc_add_device("/oic/d", "oic.d.test2", "WiFi Easysetup Test", "ocf.2.0",
                       "ocf.res.2.0", NULL, NULL);
  if(err) {
    PRINT("Add oic.d.test2 device error %d\n", err);
    return err;
  }

  g_device_count = oc_core_get_num_devices();
  PRINT("Numer of registered  Devices %d\n", g_device_count);
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
  char *device_name = "TestDevice";
  oc_wes_device_info_t wes_device_info ={{{WIFI_11G, WIFI_11N, WIFI_11AC, WIFI_EOF },WIFI_5G},{{0}}};

  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {

    // Set callbacks for Resource operations
    oc_wes_set_resource_callbacks(dev_index, g_rsc_cbks[dev_index].oc_wes_prov_cb_t,
    		g_rsc_cbks[dev_index].oc_wes_wifi_prov_cb_t, g_rsc_cbks[dev_index].oc_wes_dev_prov_cb_t);

    // Set callbacks for Vendor Specific Properties
    oc_ees_set_userdata_callbacks(dev_index, g_ud_cbks[dev_index].oc_es_read_userdata_cb_t,
    		g_ud_cbks[dev_index].oc_es_write_userdata_cb_t, g_ud_cbks[dev_index].oc_es_free_userdata_cb_t);

    // Set Device Info
    oc_new_string(&wes_device_info.Device.device_name, device_name, strlen(device_name));
     if (oc_wes_set_device_info(dev_index, &wes_device_info) == OC_ES_ERROR)
         PRINT("oc_wes_set_device_info error!\n");
  }
}

static void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  g_exit = true;
}

void
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  PRINT("wifi_easysetup_enrollee : Start\n");

  //1 TODO : Platform Interface
  wifi_start_softap(SOFT_AP_SSID, SOFT_AP_PSK);
  wifi_start_dhcp_server();

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

  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    oc_delete_wifi_easysetup_resource(dev_index);
  }
  oc_main_shutdown();

  PRINT("wifi_easysetup_enrollee : Exit\n");

  return;
}
