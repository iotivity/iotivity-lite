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
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_config.h"
#include "port/oc_clock.h"
#include "oc_easysetup_enrollee.h"
#include "lpa.h"
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

int delete_directory(const char *path)
{
   int r = -1;
   size_t path_len = strlen(path);
   DIR *dir = opendir(path);
   if (dir) {
      struct dirent *p;
      r = 0;
      while (!r && (p=readdir(dir))) {
          int r2 = -1; char *buf; size_t len;
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))  continue;
          len = path_len + strlen(p->d_name) + 2;
          buf = malloc(len);
          if (buf) {
             struct stat statbuf;
             snprintf(buf, len, "%s/%s", path, p->d_name);
             if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode)) r2 = delete_directory(buf);
                else r2 = unlink(buf);
             }
             free(buf);
          }
          r = r2;
      }
      closedir(dir);
   }
   if (!r) r = rmdir(path);
   return r;
}

// Device 1 Callbaks
static void
ees_profile_install_cb1(int status)
{
  if(status == 0) {
    PRINT("oc_ees_set_state ==> EES_PS_INSTALLED\n");
    oc_ees_set_state(0, EES_PS_INSTALLED);
  } else {
    PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
    oc_ees_set_state(0, EES_PS_ERROR);
  }
}

static void
ees_profile_download_cb1(int status)
{
  if(status == 0) {
    PRINT("oc_ees_set_state ==> EES_PS_DOWNLOADED\n");
    oc_ees_set_state(0, EES_PS_DOWNLOADED);
  } else {
    PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
    oc_ees_set_state(0, EES_PS_ERROR);
  }
}

oc_event_callback_retval_t reset_callback1(void *data)
{
  (void)data;
  oc_ees_reset_resources(0);
  return OC_EVENT_DONE;
}

static void
ees_prov_cb1(oc_ees_data_t *ees_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("ees_prov_cb1\n");
  if (ees_prov_data == NULL) {
      PRINT("ees_prov_data is NULL\n");
      return;
  }

  if(!strncmp(oc_ees_get_state(0), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING)))  {
    if(!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_OK, strlen(EES_EUC_DOWNLOAD_OK))) {
        PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_RECEIVED\n");
        oc_ees_set_state(0, EES_PS_USER_CONF_RECEIVED);
        lpa_download_profile(&ees_profile_download_cb1);
        lpa_install_profile(&ees_profile_install_cb1);
    } else if (!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_ENABLE_OK, strlen(EES_EUC_DOWNLOAD_ENABLE_OK))) {
        PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_RECEIVED\n");
        oc_ees_set_state(0, EES_PS_USER_CONF_RECEIVED);
        lpa_download_profile(&ees_profile_download_cb1);
        lpa_install_profile(&ees_profile_install_cb1);
		oc_set_delayed_callback(NULL, reset_callback1, 1);
    } else {
        PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
        oc_ees_set_state(0, EES_PS_ERROR);
		oc_set_delayed_callback(NULL, reset_callback1, 1);
    }
  }
}

static void
rsp_prov_cb1(oc_ees_rsp_data_t *rsp_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("rsp_prov_cb1\n");
  if (rsp_prov_data == NULL) {
    PRINT("rsp_prov_data is NULL\n");
    return;
  }
  if(!strncmp(oc_ees_get_state(0), EES_PS_UNDEFINED, strlen(EES_PS_UNDEFINED)))  {
    if(oc_string(rsp_prov_data->activation_code)) {
      PRINT("Actiation Code : %s\n", oc_string(rsp_prov_data->activation_code));
      PRINT("oc_ees_set_state ==> EES_PS_INITIATED\n");
      oc_ees_set_state(0, EES_PS_INITIATED);
      //Write Access code to LPA
      lpa_write_activation_code(oc_string(rsp_prov_data->activation_code));
      PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_PENDING\n");
      oc_ees_set_state(0, EES_PS_USER_CONF_PENDING);
    }
  }
  if(!strncmp(oc_ees_get_state(0), EES_PS_USER_CONF_RECEIVED, strlen(EES_PS_USER_CONF_RECEIVED)))  {
    if(oc_string(rsp_prov_data->confirm_code)) {
      PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));
    }
  }
}

static void
rspcap_prov_cb1(oc_ees_rspcap_data_t *rspcap_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("rspcap_prov_cb1\n");
  if (rspcap_prov_data == NULL) {
      PRINT("rspcap_prov_data is NULL\n");
      return;
  }
  //1 Check the Integrity of data set by application
  PRINT("Euicc Info : %s\n", oc_string(rspcap_prov_data->euicc_info));
  PRINT("Device Info : %s\n", oc_string(rspcap_prov_data->device_info));
}

// Device 1 Callbaks
static void
ees_wes_prov_cb1(oc_wes_data_t *wes_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("wes_prov_cb1\n");
  if (wes_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
}

static void
ees_device_prov_cb1(oc_wes_device_data_t *device_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("device_prov_cb1\n");
  if (device_prov_data == NULL) {
      PRINT("device_prov_data is NULL\n");
      return;
  }
  PRINT("Device Name: %s\n", oc_string(device_prov_data->dev_name));
}

static void
ees_wifi_prov_cb1(oc_wes_wifi_data_t *wifi_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("wifi_prov_cb1 triggered\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->cred));
  PRINT("AuthType : %d\n", wifi_prov_data->auth_type);
  PRINT("EncType : %d\n", wifi_prov_data->enc_type);
}

// Device 2 Callbacks
static void
ees_profile_install_cb2(int status)
{
  if(status == 0) {
    PRINT("oc_ees_set_state ==> EES_PS_INSTALLED\n");
    oc_ees_set_state(1, EES_PS_INSTALLED);
  } else {
    PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
    oc_ees_set_state(1, EES_PS_ERROR);
  }
}

static void
ees_profile_download_cb2(int status)
{
  if(status == 0) {
    PRINT("oc_ees_set_state ==> EES_PS_DOWNLOADED\n");
    oc_ees_set_state(1, EES_PS_DOWNLOADED);
  } else {
    PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
    oc_ees_set_state(1, EES_PS_ERROR);
  }
}

oc_event_callback_retval_t reset_callback2(void *data)
{
  (void)data;
  oc_ees_reset_resources(1);
  return OC_EVENT_DONE;
}

static void
ees_prov_cb2(oc_ees_data_t *ees_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("ees_prov_cb2\n");
  if (ees_prov_data == NULL) {
      PRINT("ees_prov_data is NULL\n");
      return;
  }

  if(!strncmp(oc_ees_get_state(1), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING)))  {
    if(!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_OK, strlen(EES_EUC_DOWNLOAD_OK))) {
        PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_RECEIVED\n");
        oc_ees_set_state(1, EES_PS_USER_CONF_RECEIVED);
        lpa_download_profile(&ees_profile_download_cb2);
        lpa_install_profile(&ees_profile_install_cb2);
    } else if (!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_ENABLE_OK, strlen(EES_EUC_DOWNLOAD_ENABLE_OK))) {
        PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_RECEIVED\n");
        oc_ees_set_state(1, EES_PS_USER_CONF_RECEIVED);
        lpa_download_profile(&ees_profile_download_cb2);
        lpa_install_profile(&ees_profile_install_cb2);
		oc_set_delayed_callback(NULL, reset_callback2, 1);
    } else {
        PRINT("oc_ees_set_state ==> EES_PS_ERROR\n");
        oc_ees_set_state(0, EES_PS_ERROR);
		oc_set_delayed_callback(NULL, reset_callback2, 1);
    }
  }
}

static void
rsp_prov_cb2(oc_ees_rsp_data_t *rsp_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("rsp_prov_cb2\n");
  if (rsp_prov_data == NULL) {
    PRINT("rsp_prov_data is NULL\n");
    return;
  }
  if(!strncmp(oc_ees_get_state(1), EES_PS_UNDEFINED, strlen(EES_PS_UNDEFINED)))  {
    if(oc_string(rsp_prov_data->activation_code)) {
      PRINT("Actiation Code : %s\n", oc_string(rsp_prov_data->activation_code));
      PRINT("oc_ees_set_state ==> EES_PS_INITIATED\n");
      oc_ees_set_state(1, EES_PS_INITIATED);
      //Write Access code to LPA
      lpa_write_activation_code(oc_string(rsp_prov_data->activation_code));
      PRINT("oc_ees_set_state ==> EES_PS_USER_CONF_PENDING\n");
      oc_ees_set_state(1, EES_PS_USER_CONF_PENDING);
    }
  }
  if(!strncmp(oc_ees_get_state(1), EES_PS_USER_CONF_RECEIVED, strlen(EES_PS_USER_CONF_RECEIVED)))  {
    if(oc_string(rsp_prov_data->confirm_code)) {
      PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));
    }
  }
}

static void
rspcap_prov_cb2(oc_ees_rspcap_data_t *rspcap_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("rspcap_prov_cb2\n");
  if (rspcap_prov_data == NULL) {
      PRINT("rspcap_prov_data is NULL\n");
      return;
  }
  //1 Check the Integrity of data set by application
  PRINT("Euicc Info : %s\n", oc_string(rspcap_prov_data->euicc_info));
  PRINT("Device Info : %s\n", oc_string(rspcap_prov_data->device_info));
}


// Device 2 Callbaks
static void
ees_wes_prov_cb2(oc_wes_data_t *wes_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("wes_prov_cb2\n");
  if (wes_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
}

static void
ees_device_prov_cb2(oc_wes_device_data_t *device_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("device_prov_cb2\n");
  if (device_prov_data == NULL) {
      PRINT("device_prov_data is NULL\n");
      return;
  }
  PRINT("Device Name: %s\n", oc_string(device_prov_data->dev_name));
}

static void
ees_wifi_prov_cb2(oc_wes_wifi_data_t *wifi_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("wifi_prov_cb2\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->cred));
  PRINT("AuthType : %d\n", wifi_prov_data->auth_type);
  PRINT("EncType : %d\n", wifi_prov_data->enc_type);
}

// resource provisioning callbacks for 2 devices
ees_device_callbacks_s g_ees_cbks[] = {
  {
    .oc_ees_prov_cb_t = &ees_prov_cb1,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb1,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb1,
  }
,
  {
    .oc_ees_prov_cb_t = &ees_prov_cb2,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb2,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb2,
  }
};

// resource proisining callbacks for 2 devices
wes_device_callbacks_s g_wes_cbks[] = {
  {
    .oc_wes_prov_cb_t = &ees_wes_prov_cb1,
    .oc_wes_wifi_prov_cb_t = &ees_wifi_prov_cb1,
    .oc_wes_dev_prov_cb_t = &ees_device_prov_cb1,
  },
  {
    .oc_wes_prov_cb_t = &ees_wes_prov_cb2,
    .oc_wes_wifi_prov_cb_t = &ees_wifi_prov_cb2,
    .oc_wes_dev_prov_cb_t = &ees_device_prov_cb2,
  }
};


static int
app_init(void)
{
  void *user_data = NULL;

  int err = oc_init_platform("Samsung", NULL, NULL);
  if(err) {
    PRINT("oc_init_platform error %d\n", err);
    return err;
  }

  // user_data passed here will be retunred in resource callbacks,
  // application shall allocate and free the memory for user_data
  err = oc_add_device("/oic/d", "oic.d.binaryswitch", "Binary Switch", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, user_data);
  if(err) {
    PRINT("Add oic.d.binaryswitch device error %d\n", err);
    return err;
  }
/*
  err = oc_add_device("/oic/d", "oic.d.voiceassistant", "Voice Assistant", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, user_data);
  if(err) {
    PRINT("Add oic.d.voiceassistant device error %d\n", err);
    return err;
  }
*/
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
  //Read these values from LPA
  char euicc_info[EUICC_INFO_LEN];
  char device_info[DEVICE_INFO_LEN];
  char profile_metadata[PROFILE_METADATA_LEN];

  wifi_mode supported_mode[NUM_WIFIMODE] = {WIFI_11A, WIFI_11B,WIFI_11G, WIFI_11N, WIFI_11AC, WIFI_MODE_MAX};
  wifi_freq supported_freq[NUM_WIFIFREQ] = {WIFI_24G, WIFI_5G, WIFI_FREQ_MAX};
  char *device_name = "WiFiTestDevice";


  PRINT("register_resources\n");

  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    // Set callbacks for Resource operations
    oc_ees_set_resource_callbacks(dev_index, g_ees_cbks[dev_index].oc_ees_prov_cb_t,
          g_ees_cbks[dev_index].oc_ees_rsp_prov_cb_t, g_ees_cbks[dev_index].oc_ees_rspcap_prov_cb_t);

	// Set callbacks for Resource operations
	oc_wes_set_resource_callbacks(dev_index, g_wes_cbks[dev_index].oc_wes_prov_cb_t,
		  g_wes_cbks[dev_index].oc_wes_wifi_prov_cb_t, g_wes_cbks[dev_index].oc_wes_dev_prov_cb_t);

    // Read Device Info and eUICC Info from LPA
    lpa_read_euicc_info(euicc_info);
    lpa_read_device_info(device_info);
    lpa_read_profile_metadata(profile_metadata);

    if (oc_ees_set_confirmation_code_required(dev_index, lpa_is_user_confirmation_required()) == OC_ES_ERROR)
        PRINT("oc_ees_set_confirmation_code_required error!\n");

    if (oc_ees_set_device_info(dev_index, euicc_info, device_info, profile_metadata) == OC_ES_ERROR)
        PRINT("oc_es_set_device_info error!\n");

    if (oc_wes_set_device_info(dev_index, supported_mode, supported_freq, device_name) == OC_ES_ERROR)
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

  PRINT("euicc_easysetup_enrollee : Start\n");

  // Start WiFi Soft AP and DHCP server for IP assignment
  wifi_start_softap(SOFT_AP_SSID, SOFT_AP_PSK);
  wifi_start_dhcp_server();

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cond, NULL);

  //Create OCF handler
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =  register_resources };

  oc_set_mtu_size(MAX_MTU_SIZE);
  oc_set_max_app_data_size(MAX_APP_DATA_SIZE);

#ifdef OC_SECURITY
  delete_directory("euicc_easysetup_enrollee_creds");
  oc_storage_config("./euicc_easysetup_enrollee_creds");
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

  oc_main_shutdown();
  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    oc_delete_esim_easysetup_resource(dev_index);
  }
  wifi_stop_dhcp_server();
  PRINT("euicc_easysetup_enrollee : Exit\n");
  return;
}
