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

// Device 1 Callbaks
static void
ees_profile_install_cb1(int status)
{
  if(status == 0) {
    oc_ees_set_state(0, EES_PS_INSTALLED);
  } else {
    oc_ees_set_state(0, EES_PS_ERROR);
  }
}

static void
ees_profile_download_cb1(int status)
{
  if(status == 0) {
    oc_ees_set_state(0, EES_PS_DOWNLOADED);
  } else {
    oc_ees_set_state(0, EES_PS_ERROR);
  }
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
  if(oc_string(ees_prov_data->last_err_reason))
    PRINT("Last Error Reason : %s\n", oc_string(ees_prov_data->last_err_reason));
  if(oc_string(ees_prov_data->last_err_code))
    PRINT("Last Error Code : %s\n", oc_string(ees_prov_data->last_err_code));
  if(oc_string(ees_prov_data->last_err_desc))
    PRINT("Last Error Description : %s\n", oc_string(ees_prov_data->last_err_desc));
  if(oc_string(ees_prov_data->end_user_consent)) {
    PRINT("End User Confirmation\n : %s\n", oc_string(ees_prov_data->end_user_consent));
  }
  if(!strncmp(oc_ees_get_state(0), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING)))  {
    if((!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_OK, strlen(EES_EUC_DOWNLOAD_OK))) ||
        (!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_ENABLE_OK, strlen(EES_EUC_DOWNLOAD_ENABLE_OK)))) {
        lpa_download_profile(&ees_profile_download_cb1);
        lpa_install_profile(&ees_profile_install_cb1);
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
  if(!strncmp(oc_ees_get_state(0), EES_PS_INITIATED, strlen(EES_PS_INITIATED)))  {
    if(oc_string(rsp_prov_data->activation_code)) {
      PRINT("Actiation Code : %s\n", rsp_prov_data->activation_code);
    }
    if(oc_string(rsp_prov_data->profile_metadata)) {
      PRINT("Profile Metadata Code : %s\n", rsp_prov_data->profile_metadata);
    }
    if(oc_string(rsp_prov_data->profile_metadata)) {
      PRINT("Confirmation Code Required : %d\n", rsp_prov_data->confirm_code_required);
    }

    //Write Access code to LPA
    lpa_write_activation_code(oc_string(rsp_prov_data->activation_code));
    oc_ees_set_state(0, EES_PS_USER_CONF_PENDING);
  } else if(!strncmp(oc_ees_get_state(0), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING))) {
    if(oc_string(rsp_prov_data->confirm_code))
      PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));
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

static void
ees_wifi_prov_cb1(oc_wes_wifi_data_t *wifi_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("ees_wifi_prov_cb1 triggered\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->cred));
  PRINT("AuthType : %d\n", wifi_prov_data->auth_type);
  PRINT("EncType : %d\n", wifi_prov_data->enc_type);

  //1  Stop DHCP Server
  wifi_stop_dhcp_server();
  //1 Start WiFi Station
  wifi_start_station();
  //1 Join WiFi AP with ssid, authtype and pwd
  wifi_join(oc_string(wifi_prov_data->ssid), oc_string(wifi_prov_data->cred));
  //1 Start DHCP client
  wifi_start_dhcp_client();
}

// Device 2 Callbacks
static void
ees_profile_install_cb2(int status)
{
  if(status == 0) {
    oc_ees_set_state(1, EES_PS_INSTALLED);
  } else {
    oc_ees_set_state(1, EES_PS_ERROR);
  }
}

static void
ees_profile_download_cb2(int status)
{
  if(status == 0) {
    oc_ees_set_state(1, EES_PS_DOWNLOADED);
  } else {
    oc_ees_set_state(1, EES_PS_ERROR);
  }
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
  if(oc_string(ees_prov_data->last_err_reason))
    PRINT("Last Error Reason : %s\n", oc_string(ees_prov_data->last_err_reason));
  if(oc_string(ees_prov_data->last_err_code))
    PRINT("Last Error Code : %s\n", oc_string(ees_prov_data->last_err_code));
  if(oc_string(ees_prov_data->last_err_desc))
    PRINT("Last Error Description : %s\n", oc_string(ees_prov_data->last_err_desc));
  if(oc_string(ees_prov_data->end_user_consent)) {
    PRINT("End User Confirmation\n : %s\n", oc_string(ees_prov_data->end_user_consent));
  }
  if(!strncmp(oc_ees_get_state(1), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING)))  {
    if((!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_OK, strlen(EES_EUC_DOWNLOAD_OK))) ||
        (!strncmp(oc_string(ees_prov_data->end_user_consent), EES_EUC_DOWNLOAD_ENABLE_OK, strlen(EES_EUC_DOWNLOAD_ENABLE_OK)))) {
        lpa_download_profile(&ees_profile_download_cb2);
        lpa_install_profile(&ees_profile_install_cb2);
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
  if(!strncmp(oc_ees_get_state(1), EES_PS_INITIATED, strlen(EES_PS_INITIATED)))  {
    if(oc_string(rsp_prov_data->activation_code)) {
      PRINT("Actiation Code : %s\n", rsp_prov_data->activation_code);
    }
    if(oc_string(rsp_prov_data->profile_metadata)) {
      PRINT("Profile Metadata Code : %s\n", rsp_prov_data->profile_metadata);
    }
    PRINT("Confirmation Code Required : %d\n", rsp_prov_data->confirm_code_required);

    //Write Access code to LPA
    lpa_write_activation_code(oc_string(rsp_prov_data->activation_code));
    oc_ees_set_state(1, EES_PS_USER_CONF_PENDING);
  } else if(!strncmp(oc_ees_get_state(1), EES_PS_USER_CONF_PENDING, strlen(EES_PS_USER_CONF_PENDING))) {
    if(oc_string(rsp_prov_data->confirm_code))
      PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));
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

static void
ees_wifi_prov_cb2(oc_wes_wifi_data_t *wifi_prov_data, void *user_data)
{
  (void)user_data;
  PRINT("ees_wifi_prov_cb2 triggered\n");
  if (wifi_prov_data == NULL) {
      PRINT("wes_prov_data is NULL\n");
      return;
  }
  PRINT("SSID : %s\n", oc_string(wifi_prov_data->ssid));
  PRINT("Password : %s\n", oc_string(wifi_prov_data->cred));
  PRINT("AuthType : %d\n", wifi_prov_data->auth_type);
  PRINT("EncType : %d\n", wifi_prov_data->enc_type);

  //1  Stop DHCP Server
  wifi_stop_dhcp_server();
  //1 Start WiFi Station
  wifi_start_station();
  //1 Join WiFi AP with ssid, authtype and pwd
  wifi_join(oc_string(wifi_prov_data->ssid), oc_string(wifi_prov_data->cred));
  //1 Start DHCP client
  wifi_start_dhcp_client();
}
// resource provisioning callbacks for 2 devices
ees_device_callbacks_s g_rsc_cbks[] = {
  {
    .oc_ees_prov_cb_t = &ees_prov_cb1,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb1,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb1,
    .oc_wes_wifi_prov_cb_t = &ees_wifi_prov_cb1,
  }
,
  {
    .oc_ees_prov_cb_t = &ees_prov_cb2,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb2,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb2,
    .oc_wes_wifi_prov_cb_t = &ees_wifi_prov_cb2,
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

  PRINT("register_resources\n");

  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    // Set callbacks for Resource operations
    oc_ees_set_resource_callbacks(dev_index, g_rsc_cbks[dev_index].oc_ees_prov_cb_t,
          g_rsc_cbks[dev_index].oc_ees_rsp_prov_cb_t, g_rsc_cbks[dev_index].oc_ees_rspcap_prov_cb_t);

    // Read Device Info and eUICC Info from LPA
    lpa_read_euicc_info(euicc_info);
    lpa_read_device_info(device_info);

     if (oc_ees_set_confirmation_code_required(dev_index, lpa_is_user_confirmation_required()) == OC_ES_ERROR)
         PRINT("oc_ees_set_confirmation_code_required error!\n");

     if (oc_ees_set_device_info(dev_index, euicc_info, device_info) == OC_ES_ERROR)
         PRINT("oc_es_set_device_info error!\n");
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

  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    oc_delete_esim_easysetup_resource(dev_index);
  }
  wifi_stop_dhcp_server();
  oc_main_shutdown();

  PRINT("euicc_easysetup_enrollee : Exit\n");

  return;
}
