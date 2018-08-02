/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_api.h"
#include "port/oc_clock.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "easysetup.h"

/** Note: Comment below line to test without Soft AP and automatic Wi-Fi
 * Connection. */
#define WITH_SOFTAP

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

static double temp_C = 5.0, min_C = 0.0, max_C = 100.0, min_K = 273.15,
              max_K = 373.15, min_F = 32, max_F = 212;
typedef enum { C = 100, F, K } units_t;

/**
 * @var g_is_secured
 * @brief Variable to check if secure mode is enabled or not.
 */
static bool g_is_secured = true;

#define STR_USERPROPERTY_KEY_INT "x.user.property.int"

#define USERPROPERTY_KEY_INT x.user.property.int
#define USERPROPERTY_KEY_STR x.user.property.str

#define set_custom_property_str(object, key, value)                            \
  oc_rep_set_text_string(object, key, value)
#define set_custom_property_int(object, key, value)                            \
  oc_rep_set_int(object, key, value)

#define MAXLEN_STRING 100

typedef struct {
  int user_value_int; /**< User-specific property in WiFi Resource **/
  char user_value_str[MAXLEN_STRING]; /**< User-specific property in DevConf
                                         Resource **/
} user_properties_t;

user_properties_t g_user_properties;

#ifdef WITH_SOFTAP

#define ES_WIFI_SSID_MAX_LEN 128
#define ES_WIFI_PASSWD_MAX_LEN 128
#define COMMAND_BUFFER_MAX_LEN 128
#define COMMAND_RESULT_MAX_LEN 256

typedef struct {
  char ssid[ES_WIFI_SSID_MAX_LEN];
  char password[ES_WIFI_SSID_MAX_LEN];
} soft_ap_data_t;

bool execute_command(const char *cmd, char *result, size_t result_len) {
  char buffer[COMMAND_BUFFER_MAX_LEN];
  FILE *fp = popen(cmd, "r");

  if (!fp) {
    return false;
  }

  size_t add_len = 0;
  while (!feof(fp)) {
    if (fgets(buffer, COMMAND_BUFFER_MAX_LEN, fp) != NULL) {
      add_len += strlen(buffer);

      if (add_len < result_len) {
        strncat(result, buffer, strlen(buffer));
      }
    }
  }

  fclose(fp);
  return true;
}

void *es_worker_thread_routine(void *thread_data) {
  printf("es_worker_thread_routine in\n");

  soft_ap_data_t *wifi_data = (soft_ap_data_t *)thread_data;
  char *ssid = wifi_data->ssid;
  char *pwd = wifi_data->password;

  /** Sleep to allow response sending from post_callback thread before turning
   * Off Soft AP. */
  sleep(1);
  printf("\nes_worker_thread_routine Woke up from sleep\n");

  printf("target ap ssid: %s\n", ssid);
  printf("password: %s\n", pwd);

  printf("Stopping Soft AP\n");

  char result[COMMAND_RESULT_MAX_LEN];

  /** Stop Soft AP */
  execute_command("sudo service hostapd stop", result, COMMAND_RESULT_MAX_LEN);
  printf("outputString 1: %s\n", result);

  /** Turn On Wi-Fi */
  execute_command("sudo nmcli nm wifi on", result, COMMAND_RESULT_MAX_LEN);

  /**
   * Note: On some linux distributions, nmcli nm may not work. In that case
   * need to enable below command:
   */
  // execute_command("sudo nmcli n wifi on", result, COMMAND_RESULT_MAX_LEN);

  printf("outputString 2: %s\n", result);

  /** On some systems it may take time for Wi-Fi to turn ON. */
  sleep(1);

  /** Connect to Target Wi-Fi AP */
  char nmcli_command[64 + strlen(ssid) + strlen(pwd)];
  snprintf(nmcli_command, sizeof(nmcli_command),
           "nmcli d wifi connect %s password %s", ssid, pwd);

  printf("executing commnad: %s\n", nmcli_command);

  execute_command(nmcli_command, result, 256);
  printf("outputString 3: %s\n", result);
  if (strlen(result) == 0) {
    es_set_error_code(ES_ERRCODE_NO_ERROR);
  }

  free(wifi_data);
  wifi_data = NULL;

  printf("es_worker_thread_routine out\n");
  return NULL;
}

#endif // WITH_SOFTAP

void set_user_properties() {
  g_user_properties.user_value_int = 0;
  strncpy(g_user_properties.user_value_str, "User String", MAXLEN_STRING);
  printf("[ES App] set_user_properties done\n");
}

void read_user_data_cb(oc_rep_t *payload, char *resourceType, void **userdata) {
  (void)resourceType;

  printf("[ES App] read_user_data_cb in\n");

  int user_prop_value = 0;

  oc_rep_t *rep = payload;
  while (rep != NULL) {
    OC_DBG("key %s", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_INT: {
      if (strcmp(oc_string(rep->name), STR_USERPROPERTY_KEY_INT) == 0) {
        user_prop_value = rep->value.integer;
        OC_DBG("user_prop_value %u", user_prop_value);

        if (userdata != NULL) {
          *userdata = (void *)malloc(sizeof(user_properties_t));

          if (*userdata) {
          ((user_properties_t *)(*userdata))->user_value_int = user_prop_value;
          }
        }

        g_user_properties.user_value_int = user_prop_value;
      }
    }

    default:
      break;
    }
    rep = rep->next;
  }
  printf("[ES App] read_user_data_cb out\n");
}

void write_user_data_cb(oc_rep_t *payload, char *resourceType) {
  (void)resourceType;
  (void)payload;

  printf("[ES App] write_user_data_cb in\n");

  set_custom_property_int(root, USERPROPERTY_KEY_INT,
                          g_user_properties.user_value_int);
  set_custom_property_str(root, USERPROPERTY_KEY_STR,
                          g_user_properties.user_value_str);

  printf("[ES App] write_user_data_cb out\n");
}

static int app_init(void) {
  int err = oc_init_platform("Samsung", NULL, NULL);

  err |= oc_add_device("/oic/d", "oic.d.airconditioner", "[Floor A/C] Samsung",
                       "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
  return err;
}

static void get_temp(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data) {
  (void)user_data;
  PRINT("[ES App] GET_temp:\n");
  bool invalid_query = false;
  double temp = temp_C;
  units_t temp_units = C;
  char *units;
  int units_len = oc_get_query_value(request, "units", &units);
  if (units_len != -1) {
    if (units[0] == 'K') {
      temp = temp_C + 273.15;
      temp_units = K;
    } else if (units[0] == 'F') {
      temp = (temp_C / 100) * 180 + 32;
      temp_units = F;
    } else if (units[0] != 'C')
      invalid_query = true;
  }

  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    oc_rep_set_text_string(root, id, "home_thermostat");
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    oc_rep_set_double(root, temperature, temp);
    switch (temp_units) {
    case C:
      oc_rep_set_text_string(root, units, "C");
      break;
    case F:
      oc_rep_set_text_string(root, units, "F");
      break;
    case K:
      oc_rep_set_text_string(root, units, "K");
      break;
    }
    break;
  default:
    break;
  }

  if (!invalid_query) {
    oc_rep_set_array(root, range);
    switch (temp_units) {
    case C:
      oc_rep_add_double(range, min_C);
      oc_rep_add_double(range, max_C);
      break;
    case K:
      oc_rep_add_double(range, min_K);
      oc_rep_add_double(range, max_K);
      break;
    case F:
      oc_rep_add_double(range, min_F);
      oc_rep_add_double(range, max_F);
      break;
    }
    oc_rep_close_array(root, range);
  }

  oc_rep_end_root_object();

  if (invalid_query)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_OK);
}

static void post_temp(oc_request_t *request, oc_interface_mask_t interface,
                      void *user_data) {
  (void)interface;
  (void)user_data;
  PRINT("[ES App] POST_temp:\n");
  bool out_of_range = false;
  double temp = -1;

  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      temp = rep->value.double_p;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (temp < min_C || temp > max_C)
    out_of_range = true;

  temp_C = temp;

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, id, "home_thermostat");
  oc_rep_set_double(root, temperature, temp_C);
  oc_rep_set_text_string(root, units, "C");
  oc_rep_set_array(root, range);
  oc_rep_add_double(range, min_C);
  oc_rep_add_double(range, max_C);
  oc_rep_close_array(root, range);
  oc_rep_end_root_object();

  if (out_of_range)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_CHANGED);
}

void wifi_prov_cb_in_app(es_wifi_conf_data *event_data) {
  printf("[ES App] wifi_prov_cb_in_app in\n");

  if (event_data == NULL) {
    printf("[ES App] es_wifi_conf_data is NULL\n");
    return;
  }

  printf("SSID : %s\n", event_data->ssid);
  printf("Password : %s\n", event_data->pwd);
  printf("AuthType : %d\n", event_data->authtype);
  printf("EncType : %d\n", event_data->enctype);

#ifdef WITH_SOFTAP
  /** Create a Thread for Target Wi-Fi AP Connection. */
  pthread_t wifi_cn_thread;

  soft_ap_data_t *soft_ap_data =
      (soft_ap_data_t *)malloc(sizeof(soft_ap_data_t));
  memset(soft_ap_data, 0, sizeof(soft_ap_data_t));
  strncpy(soft_ap_data->ssid, oc_string(event_data->ssid), ES_WIFI_SSID_MAX_LEN-1);
  strncpy(soft_ap_data->password, oc_string(event_data->pwd), ES_WIFI_PASSWD_MAX_LEN-1);
  pthread_create(&wifi_cn_thread, NULL, es_worker_thread_routine,
                 (void *)soft_ap_data);
#endif // WITH_SOFTAP

  printf("[ES App] wifi_prov_cb_in_app out\n");
}

void dev_conf_prov_cb_in_app(es_dev_conf_data *event_data) {
  printf("[ES App] dev_conf_prov_cb_in_app in\n");

  if (event_data == NULL) {
    printf("[ES App] es_dev_conf_data is NULL\n");
    return;
  }

  printf("[ES App] dev_conf_prov_cb_in_app out\n");
}

void cloud_conf_prov_cb_in_app(es_coap_cloud_conf_data *event_data) {
  printf("[ES App] cloud_conf_prov_cb_in_app in\n");

  if (event_data == NULL) {
    printf("es_coap_cloud_conf_data is NULL\n");
    return;
  }

  if (oc_string(event_data->auth_code)) {
    printf("AuthCode : %s\n", event_data->auth_code);
  }

  if (oc_string(event_data->access_token)) {
    printf("Access Token : %s\n", event_data->access_token);
  }

  if (oc_string(event_data->auth_provider)) {
    printf("AuthProvider : %s\n", event_data->auth_provider);
  }

  if (oc_string(event_data->ci_server)) {
    printf("CI Server : %s\n", event_data->ci_server);
  }

  printf("[ES App] cloud_conf_prov_cb_in_app out\n");
}

es_provisioning_callbacks_s g_callbacks = {
    .wifi_prov_cb = &wifi_prov_cb_in_app,
    .dev_conf_prov_cb = &dev_conf_prov_cb_in_app,
    .cloud_data_prov_cb = &cloud_conf_prov_cb_in_app};

void start_easy_setup() {
  printf("[ES App] start_easy_setup in\n");

  es_connect_type resourcemMask =
      ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE | ES_DEVCONF_RESOURCE;
  if (es_init_enrollee(g_is_secured, resourcemMask, g_callbacks) != ES_OK) {
    printf("[ES App] es_init_enrollee error!\n");
    return;
  }

  printf("[ES App] es_init_enrollee Success\n");

  // Set callbacks for Vendor Specific Properties
  es_set_callback_for_userdata(&read_user_data_cb, &write_user_data_cb, NULL);
  printf("[ES App] start_easy_setup out\n");
}

void set_device_info() {
  printf("[ES App] set_device_info in\n");
  char *device_name = "TEST_DEVICE";

  es_device_property device_property = {
      {{WIFI_11G, WIFI_11N, WIFI_11AC, WiFi_EOF}, WIFI_5G}, {{0}}};

  oc_new_string(&device_property.DevConf.device_name, device_name,
                strlen(device_name));

  if (es_set_device_property(&device_property) == ES_ERROR)
    printf("[ES App] es_set_device_property error!\n");

  printf("[ES App] set_device_info out\n");
}

void stop_easy_setup() {
  printf("[ES App] stop_easy_setup in\n");

  if (es_terminate_enrollee() == ES_ERROR) {
    printf("es_terminate_enrollee failed!\n");
    return;
  }

  printf("[ES App] stop_easy_setup out\n");
}

static void register_resources(void) {
  printf("[ES App] register_resources in\n");

  oc_resource_t *temp = oc_new_resource("tempsensor", "/temp", 1, 0);
  oc_resource_bind_resource_type(temp, "oic.r.temperature");
  oc_resource_bind_resource_interface(temp, OC_IF_A);
  oc_resource_bind_resource_interface(temp, OC_IF_S);
  oc_resource_set_default_interface(temp, OC_IF_A);
  oc_resource_set_discoverable(temp, true);
  oc_resource_set_periodic_observable(temp, 1);
  oc_resource_set_request_handler(temp, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(temp, OC_POST, post_temp, NULL);
  oc_add_resource(temp);

#ifdef OC_SECURITY
  g_is_secured = true;
#else
  g_is_secured = false;
#endif

  start_easy_setup();
  set_device_info();
  set_user_properties();

  printf("[ES App] register_resources out\n");
}

static void signal_event_loop(void) {
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void handle_signal(int signal) {
  (void)signal;
  signal_event_loop();
  quit = 1;
}

int main(void) {
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cv, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                           register_resources};

  oc_clock_time_t next_event;

  oc_set_mtu_size(2048);
  oc_set_max_app_data_size(OC_MAX_APP_DATA_SIZE);

#ifdef OC_SECURITY
  oc_storage_config("./easy_setup_linux_creds");
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  printf("[ES App] stop_easy_setup..\n");
  stop_easy_setup();
  printf("[ES App] stop_easy_setup done\n");

  oc_main_shutdown();

  printf("[ES App] Exit..\n");
  return 0;
}
