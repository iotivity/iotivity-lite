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
//#include "lpa.h"

// There are indicative values and might vary with application requirement
#define MAX_APP_DATA_SIZE 8192
#define MAX_MTU_SIZE 2048

static int g_device_count = 0;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
static struct timespec ts;
static bool g_exit = 0;

// Information read from eUICC
oc_ees_device_info_t info;

// Device 1 Callbaks
static void 
ees_prov_cb1(oc_ees_data_t *ees_prov_data)
{
  PRINT("ees_prov_cb1\n");
  if (ees_prov_data == NULL) {
      PRINT("ees_prov_data is NULL\n");
      return;
  }
  PRINT("RSP Status : %s\n", oc_string(ees_prov_data->rsp_status));
  PRINT("Last Error Rason : %s\n", oc_string(ees_prov_data->last_err_reason));
  PRINT("Last Error Code : %s\n", oc_string(ees_prov_data->last_err_code));
  PRINT("Last Error Description : %s\n", oc_string(ees_prov_data->last_err_desc));
  PRINT("End User Conformation\n : %s\n", oc_string(ees_prov_data->end_user_conf));
}

static void 
rsp_prov_cb1(oc_ees_rsp_data_t *rsp_prov_data)
{
  PRINT("rsp_prov_cb1\n");
  if (rsp_prov_data == NULL) {
      PRINT("rsp_prov_data is NULL\n");
      return;
  }
  PRINT("Activation Code : %s\n", oc_string(rsp_prov_data->activation_code));
  //1 Wite Access code to LPA here
  PRINT("Profile Meta Data : %s\n", oc_string(rsp_prov_data->profile_metadata));
  PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));  
  PRINT("Confirmation Code Required : %d\n", rsp_prov_data->confirm_code_required);  
}

static void 
rspcap_prov_cb1(oc_ees_rspcap_data_t *rspcap_prov_data)
{
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

// Device 2 Callbacks
static void 
ees_prov_cb2(oc_ees_data_t *ees_prov_data)
{
  PRINT("ees_prov_cb2 triggered\n");
  if (ees_prov_data == NULL) {
      PRINT("ees_prov_data is NULL\n");
      return;
  }
  PRINT("RSP Status : %s\n", oc_string(ees_prov_data->rsp_status));
  PRINT("Last Error Rason : %s\n", oc_string(ees_prov_data->last_err_reason));
  PRINT("Last Error Code : %s\n", oc_string(ees_prov_data->last_err_code));
  PRINT("Last Error Description : %s\n", oc_string(ees_prov_data->last_err_desc));
  PRINT("End User Conformation\n : %s\n", oc_string(ees_prov_data->end_user_conf));
}

static void 
rsp_prov_cb2(oc_ees_rsp_data_t *rsp_prov_data)
{
  PRINT("rsp_prov_cb2 triggered\n");
  if (rsp_prov_data == NULL) {
      PRINT("rsp_prov_data is NULL\n");
      return;
  }
  PRINT("Activation Code : %s\n", oc_string(rsp_prov_data->activation_code));
  //1 Wite Access code to LPA here
  PRINT("Profile Meta Data : %s\n", oc_string(rsp_prov_data->profile_metadata));
  PRINT("Confirmation Code : %s\n", oc_string(rsp_prov_data->confirm_code));  
  PRINT("Confirmation Code Required : %d\n", rsp_prov_data->confirm_code_required);  
}

static void 
rspcap_prov_cb2(oc_ees_rspcap_data_t *rspcap_prov_data)
{
  PRINT("rspcap_prov_cb2 triggered\n");
  if (rspcap_prov_data == NULL) {
      PRINT("rspcap_prov_data is NULL\n");
      return;
  }
  //1 Check the Integrity of data set by application
  PRINT("Euicc Info : %s\n", oc_string(rspcap_prov_data->euicc_info));
  PRINT("Device Info : %s\n", oc_string(rspcap_prov_data->device_info));
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

// resource provisioning callbacks for 2 devices
ees_device_callbacks_s g_rsc_cbks[] = {
  {
    .oc_ees_prov_cb_t = &ees_prov_cb1,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb1,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb1,
  },
  {
    .oc_ees_prov_cb_t = &ees_prov_cb2,
    .oc_ees_rsp_prov_cb_t = &rsp_prov_cb2,
    .oc_ees_rspcap_prov_cb_t = &rspcap_prov_cb2,
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

  err = oc_add_device("/oic/d", "oic.d.test1", "eSIM Easysetup Test", "ocf.2.0",
                       "ocf.res.2.0", NULL, NULL);
  if(err) {
    PRINT("Add oic.d.test1 device error %d\n", err);
    return err;
  }
  
  err = oc_add_device("/oic/d", "oic.d.test2", "eSIM Easysetup Test", "ocf.2.0",
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
  char euicc_info[128] = "TestESIMInfo";
  char device_info[128] =  "TestDevicInfo";
  oc_ees_device_info_t ees_device_info; 
  
  for(int dev_index = 0; dev_index < g_device_count; ++dev_index) {
    // Set callbacks for Resource operations
    oc_ees_set_resource_callbacks(dev_index, g_rsc_cbks[dev_index].oc_ees_prov_cb_t, 
    		g_rsc_cbks[dev_index].oc_ees_rsp_prov_cb_t, g_rsc_cbks[dev_index].oc_ees_rspcap_prov_cb_t);

    // Set callbacks for Vendor Specific Properties
    oc_ees_set_userdata_callbacks(dev_index, g_ud_cbks[dev_index].oc_es_read_userdata_cb_t, 
    		g_ud_cbks[dev_index].oc_es_write_userdata_cb_t, g_ud_cbks[dev_index].oc_es_free_userdata_cb_t);
     
    //1 Read euicc_info, device_info from LPA module here for each device
    //lpa_get_euicc_info(euicc_info);
    //lpa_get_device_info
    
    //1 Set euicc info , device Info to OCF resources for each device
    oc_new_string(&ees_device_info.LPA.euicc_info, euicc_info, strlen(euicc_info));
    oc_new_string(&ees_device_info.LPA.device_info, device_info, strlen(device_info));
    
     if (oc_ees_set_device_info(dev_index, &ees_device_info) == OC_ES_ERROR)
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

  // Init LPA Here
  PRINT("euicc_easysetup_enrollee : Start\n");

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cond, NULL);
  //Create OCF handler
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
    oc_delete_esim_easysetup_resource(dev_index);
  }
  oc_main_shutdown();

  PRINT("euicc_easysetup_enrollee : Exit\n");

  return;
}
