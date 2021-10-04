/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_swupdate.h"
#include "port/oc_clock.h"
#include "rd_client.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#ifdef OC_CLOUD
#include "oc_cloud.h"
#endif

#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

static const size_t DEVICE = 0;

// define application specific values.
static const char *spec_version = "ocf.2.2.4";
static const char *data_model_version = "ocf.res.1.3.0,ocf.sh.1.3.0";

static const char *deivce_uri = "/oic/d";
static const char *device_rt = "oic.d.switch";
static const char *device_name = "OCFTestServer";

static const char *manufacturer = "OCF";

#define btoa(x) ((x) ? "true" : "false")
#define MAX_ARRAY 10 /* max size of the array */

/* global property variables for path: "/dali" */
static char *g_dali_RESOURCE_PROPERTY_NAME_pld =
  "pld"; /* the name for the attribute */
/* array pld  Each DALI byte is conveyed as an byte */
uint8_t g_dali_pld[MAX_ARRAY];
size_t g_dali_pld_array_size;
static char *g_dali_RESOURCE_PROPERTY_NAME_pld_s =
  "pld_s";            /* the name for the attribute */
int g_dali_pld_s = 0; /* current value of property "pld_s" The amount of
                         integers in the Dali payload. */
static char *g_dali_RESOURCE_PROPERTY_NAME_prio =
  "prio"; /* the name for the attribute */
int g_dali_prio =
  0; /* current value of property "prio" The priority of the command. */
static char *g_dali_RESOURCE_PROPERTY_NAME_src =
  "src"; /* the name for the attribute */
int g_dali_src =
  0; /* current value of property "src" assigned source address. -1 means not
        yet assigned by the Application controller. */
static char *g_dali_RESOURCE_PROPERTY_NAME_st =
  "st"; /* the name for the attribute */
bool g_dali_st =
  false; /* current value of property "st" The command has to be send twice. */
static char *g_dali_RESOURCE_PROPERTY_NAME_tbus =
  "tbus"; /* the name for the attribute */
/* array tbus  The set of  bus identifiers to which the command should be
 * applied. */
int g_dali_tbus[MAX_ARRAY];
size_t g_dali_tbus_array_size;

/* global property variables for path: "/dali_conf" */
static char *g_config_RESOURCE_PROPERTY_NAME_bus =
  "bus"; /* the name for the attribute */
int g_config_bus =
  2; /* current value of property "bus" assign the bus identifier. */
static char *g_config_RESOURCE_PROPERTY_NAME_src =
  "src"; /* the name for the attribute */
int g_config_src =
  5; /* current value of property "src" assigned source address. -1 means not
        yet assigned by the Application controller. */
static char *g_config_RESOURCE_PROPERTY_NAME_ver =
  "ver"; /* the name for the attribute */
int g_config_ver =
  2; /* current value of property "ver" version of dali on the device. */

static pthread_t event_thread;
static pthread_mutex_t cloud_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

static double temp = 5.0, temp_K = (5.0 + 273.15), temp_F = (5.0 * 9 / 5 + 32),
              min_C = 0.0, max_C = 100.0, min_K = 273.15, max_K = 373.15,
              min_F = 32, max_F = 212;
typedef enum { C = 100, F, K } units_t;
units_t temp_units = C;

int g_switch_storage_status = 0; /* 0=no storage, 1=startup, 2=startup.revert */
bool g_switch_value = false; /* current value of property "value" The status of the switch. */

const char *mfg_persistent_uuid = "f6e10d9c-a1c9-43ba-a800-f1b0aad2a889";

const char *ee_certificate = "pki_certs/certification_tests_ee.pem";
const char *key_certificate = "pki_certs/certification_tests_key.pem";
const char *subca_certificate = "pki_certs/certification_tests_subca1.pem";
const char *rootca_certificate = "pki_certs/certification_tests_rootca1.pem";

oc_string_array_t my_supportedactions;

oc_resource_t *temp_resource = NULL, *bswitch = NULL, *col = NULL;

#define SCANF(...)                                                             \
  {                                                                            \
    char line[256];                                                            \
    while (fgets(line, sizeof(line), stdin) == 0 || line[0] == '\n') {         \
    }                                                                          \
    do {                                                                       \
      if (sscanf(line, __VA_ARGS__) != 1) {                                    \
        PRINT("ERROR Invalid input\n");                                        \
      }                                                                        \
    } while (0);                                                               \
  }

static void
display_menu(void)
{
  PRINT("\n\n################################################\nOCF "
        "Server Certification Test "
        "Tool\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("Server\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Toggle switch resource\n");
  PRINT("-----------------------------------------------\n");
#ifdef OC_CLOUD
  PRINT("Cloud\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[10] Cloud Register\n");
  PRINT("[11] Cloud Login\n");
  PRINT("[12] Cloud Logout\n");
  PRINT("[13] Cloud DeRegister\n");
  PRINT("[14] Cloud Refresh Token\n");
  PRINT("[15] Publish Resources\n");
  PRINT("[16] Send Ping\n");
  PRINT("-----------------------------------------------\n");
#endif /* OC_CLOUD */
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

#ifdef OC_SOFTWARE_UPDATE
int
validate_purl(const char *purl)
{
  (void)purl;
  return 0;
}

int
check_new_version(size_t device, const char *url, const char *version)
{
  if (!url) {
    oc_swupdate_notify_done(device, OC_SWUPDATE_RESULT_INVALID_URL);
    return -1;
  }
  PRINT("Package url %s\n", url);
  if (version) {
    PRINT("Package version: %s\n", version);
  }
  oc_swupdate_notify_new_version_available(device, "2.0",
                                           OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

int
download_update(size_t device, const char *url)
{
  (void)url;
  oc_swupdate_notify_downloaded(device, "2.0", OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

int
perform_upgrade(size_t device, const char *url)
{
  (void)url;
  oc_swupdate_notify_upgrading(device, "2.0", oc_clock_time(),
                               OC_SWUPDATE_RESULT_SUCCESS);

  oc_swupdate_notify_done(device, OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_CLOUD
static void
cloud_refresh_token_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                       void *data)
{
  (void)data;
  PRINT("\nCloud Refresh Token status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    PRINT("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    PRINT("\t\t-Refreshed Token\n");
  }
}

static void
cloud_refresh_token(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&cloud_sync_lock);
  int ret = oc_cloud_refresh_token(ctx, cloud_refresh_token_cb, NULL);
  pthread_mutex_unlock(&cloud_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Refresh Token request\n");
  } else {
    PRINT("\nIssued Refresh Token request\n");
  }
}

static void
cloud_deregister_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                    void *data)
{
  (void)data;
  PRINT("\nCloud DeRegister status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    PRINT("\t\t-DeRegistered\n");
  }
}

static void
cloud_deregister(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&cloud_sync_lock);
  int ret = oc_cloud_deregister(ctx, cloud_deregister_cb, NULL);
  pthread_mutex_unlock(&cloud_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud DeRegister request\n");
  } else {
    PRINT("\nIssued Cloud DeRegister request\n");
  }
}

static void
cloud_logout_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Logout status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
}

static void
cloud_logout(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&cloud_sync_lock);
  int ret = oc_cloud_logout(ctx, cloud_logout_cb, NULL);
  pthread_mutex_unlock(&cloud_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Logout request\n");
  } else {
    PRINT("\nIssued Cloud Logout request\n");
  }
}

static void
cloud_login_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Login status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
  }
}

static void
cloud_login(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&cloud_sync_lock);
  int ret = oc_cloud_login(ctx, cloud_login_cb, NULL);
  pthread_mutex_unlock(&cloud_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Login request\n");
  } else {
    PRINT("\nIssued Cloud Login request\n");
  }
}

static void
cloud_register_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Register status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
}

static void
cloud_register(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&cloud_sync_lock);
  int ret = oc_cloud_register(ctx, cloud_register_cb, NULL);
  pthread_mutex_unlock(&cloud_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Register request\n");
  } else {
    PRINT("\nIssued Cloud Register request\n");
  }
}

static void
ping_handler(oc_client_response_t *data)
{
  (void)data;
  PRINT("\nReceived Pong\n");
}

static void
cloud_send_ping(void)
{
  PRINT("\nEnter receiving endpoint: ");
  char addr[256];
  SCANF("%255s", addr);
  char endpoint_string[267];
  sprintf(endpoint_string, "coap+tcp://%s", addr);
  oc_string_t ep_string;
  oc_new_string(&ep_string, endpoint_string, strlen(endpoint_string));
  oc_endpoint_t endpoint;
  int ret = oc_string_to_endpoint(&ep_string, &endpoint, NULL);
  oc_free_string(&ep_string);
  if (ret < 0) {
    PRINT("\nERROR parsing endpoint string\n");
    return;
  }

  if (oc_send_ping(false, &endpoint, 10, ping_handler, NULL)) {
    PRINT("\nSuccessfully issued Ping request\n");
    return;
  }

  PRINT("\nERROR issuing Ping request\n");
}
#endif /* OC_CLOUD */

/**
 * helper function to check if the POST input document contains
 * the common readOnly properties or the resouce readOnly properties
 * @param name the name of the property
 * @return the error_status, e.g. if error_status is true, then the input
 * document contains something illegal
 */
static bool
check_on_readonly_common_resource_properties(oc_string_t name, bool error_state)
{
  if (strcmp(oc_string(name), "n") == 0) {
    error_state = true;
    PRINT("   property \"n\" is ReadOnly \n");
  } else if (strcmp(oc_string(name), "if") == 0) {
    error_state = true;
    PRINT("   property \"if\" is ReadOnly \n");
  } else if (strcmp(oc_string(name), "rt") == 0) {
    error_state = true;
    PRINT("   property \"rt\" is ReadOnly \n");
  } else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    PRINT("   property \"id\" is ReadOnly \n");
  }
  return error_state;
}

oc_define_interrupt_handler(toggle_switch)
{
  if (bswitch) {
    oc_notify_observers(bswitch);
  }
}

static void
toggle_switch_resource()
{
  PRINT("\nSwitch toggled\n");
  g_switch_value = !g_switch_value;
  oc_signal_interrupt_handler(toggle_switch);
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(toggle_switch);
  int err = oc_init_platform(manufacturer, NULL, NULL);

  err |= oc_add_device(deivce_uri, device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  PRINT("\tSwitch device added.\n");

  oc_new_string_array(&my_supportedactions, (size_t)19);
  oc_string_array_add_item(my_supportedactions, "arrowup");
  oc_string_array_add_item(my_supportedactions, "arrowdown");
  oc_string_array_add_item(my_supportedactions, "arrowleft");
  oc_string_array_add_item(my_supportedactions, "arrowright");
  oc_string_array_add_item(my_supportedactions, "enter");
  oc_string_array_add_item(my_supportedactions, "return");
  oc_string_array_add_item(my_supportedactions, "exit");
  oc_string_array_add_item(my_supportedactions, "home");
  oc_string_array_add_item(my_supportedactions, "1");
  oc_string_array_add_item(my_supportedactions, "2");
  oc_string_array_add_item(my_supportedactions, "3");
  oc_string_array_add_item(my_supportedactions, "4");
  oc_string_array_add_item(my_supportedactions, "5");
  oc_string_array_add_item(my_supportedactions, "6");
  oc_string_array_add_item(my_supportedactions, "7");
  oc_string_array_add_item(my_supportedactions, "8");
  oc_string_array_add_item(my_supportedactions, "9");
  oc_string_array_add_item(my_supportedactions, "0");
  oc_string_array_add_item(my_supportedactions, "-");
#if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read server_certification_tests_IDD.cbor\n"
    "\tIntrospection data not set for device.\n";
  fp = fopen("./server_certification_tests_IDD.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      PRINT("\tIntrospection data set for device.\n");
    } else {
      PRINT("%s", introspection_error);
    }
    free(buffer);
  } else {
    PRINT("%s", introspection_error);
  }
#endif

  if (err >= 0) {
    oc_uuid_t my_uuid;
    oc_str_to_uuid(mfg_persistent_uuid, &my_uuid);
    oc_set_immutable_device_identifier(0, &my_uuid);
  }
  return err;
}

static void
get_temp(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  PRINT("GET_temp:\n");
  bool invalid_query = false;
  char *units;
  units_t u = temp_units;
  int units_len = oc_get_query_value(request, "units", &units);
  if (units_len != -1) {
    if (units[0] == 'K') {
      u = K;
    } else if (units[0] == 'F') {
      u = F;
    } else if (units[0] == 'C') {
      u = C;
    } else {
      invalid_query = true;
    }
  }

  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    switch (u) {
    case C:
      oc_rep_set_text_string(root, units, "C");
      oc_rep_set_double(root, temperature, temp);
      break;
    case F:
      oc_rep_set_text_string(root, units, "F");
      oc_rep_set_double(root, temperature, temp_F);
      break;
    case K:
      oc_rep_set_text_string(root, units, "K");
      oc_rep_set_double(root, temperature, temp_K);
      break;
    }
    break;
  default:
    break;
  }

  oc_rep_set_array(root, range);
  switch (u) {
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

  oc_rep_end_root_object();

  if (invalid_query)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_OK);
}

static void
post_temp(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_temp:\n");
  bool out_of_range = false;
  double t = -1;
  units_t units = C;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      t = rep->value.double_p;
      break;
    case OC_REP_STRING:
      if (oc_string(rep->value.string)[0] == 'C') {
        units = C;
      } else if (oc_string(rep->value.string)[0] == 'F') {
        units = F;
      } else if (oc_string(rep->value.string)[0] == 'K') {
        units = K;
      } else {
        out_of_range = true;
      }
      break;
    default:
      out_of_range = true;
      break;
    }
    rep = rep->next;
  }

  if (t == -1) {
    out_of_range = true;
  }

  if (!out_of_range && t != -1 &&
      ((units == C && t < min_C && t > max_C) ||
       (units == F && t < min_F && t > max_F) ||
       (units == K && t < min_K && t > max_K))) {
    out_of_range = true;
  }

  if (!out_of_range) {
    if (units == C) {
      temp = t;
      temp_F = (temp * 9 / 5) + 32;
      temp_K = (temp + 273.15);
    } else if (units == F) {
      temp_F = t;
      temp = (temp_F - 32) * 5 / 9;
      temp_K = (temp + 273.15);
    } else if (units == K) {
      temp_K = t;
      temp = (temp_K - 273.15);
      temp_F = (temp * 9 / 5) + 32;
    }
    temp_units = units;
  }

  oc_rep_start_root_object();
  switch (temp_units) {
  case C:
    oc_rep_set_double(root, temperature, temp);
    oc_rep_set_text_string(root, units, "C");
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_C);
    oc_rep_add_double(range, max_C);
    oc_rep_close_array(root, range);
    break;
  case F:
    oc_rep_set_double(root, temperature, temp_F);
    oc_rep_set_text_string(root, units, "F");
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_F);
    oc_rep_add_double(range, max_F);
    oc_rep_close_array(root, range);
    break;
  case K:
    oc_rep_set_double(root, temperature, temp_K);
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_K);
    oc_rep_add_double(range, max_K);
    oc_rep_close_array(root, range);
    oc_rep_set_text_string(root, units, "K");
    break;
  }
  oc_rep_end_root_object();

  if (out_of_range)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)user_data;
  PRINT("GET_switch:\n");
  bool error_state = false;
  int oc_status_code = OC_STATUS_OK;

  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, g_switch_value);
    break;
  case OC_IF_STARTUP:
    if (g_switch_storage_status != 1) {
      error_state = true;
      break;
    }

    /* property (boolean) 'value' */
    {
      bool temp_value;
      oc_storage_read("g_switch_value", (uint8_t *)&temp_value, sizeof(temp_value));
      oc_rep_set_boolean(root, value, temp_value);
    }
    break;
  case OC_IF_STARTUP_REVERT:
    if (g_switch_storage_status != 2) {
      error_state = true;
      break;
    }

    oc_status_code = OC_STATUS_NOT_MODIFIED;
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  if (error_state == false) {
    oc_send_response(request, oc_status_code);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  
  bool error_state = false;
  int oc_status_code = OC_STATUS_CHANGED;
  
  PRINT("POST_switch:\n");
  bool state = false, bad_request = false, var_in_request = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
        if (strcmp(oc_string(rep->name), "value") == 0) {
            var_in_request = true;
            state = rep->value.boolean;
        }
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }
  if(!var_in_request){
      bad_request = true;
  }
  if (bad_request) {
    error_state = true;
  }

  if (error_state == false) {
      switch (iface_mask) {
          case OC_IF_STARTUP: {
            g_switch_storage_status = 1;
            oc_storage_write("g_switch_storage_status",
                       (uint8_t *)&g_switch_storage_status,
                       sizeof(g_switch_storage_status));
            oc_storage_write("g_switch_value",
                             (uint8_t *)&state,
                             sizeof(g_switch_value));
            oc_rep_start_root_object();
            oc_rep_set_boolean(root, value, g_switch_value);
            oc_rep_end_root_object();
            break;
          }
          case OC_IF_STARTUP_REVERT: {
            g_switch_storage_status = 2;
            oc_storage_write("g_switch_storage_status",
                       (uint8_t *)&g_switch_storage_status,
                       sizeof(g_switch_storage_status));
            oc_storage_write("g_switch_value",
                             (uint8_t *)&state,
                             sizeof(g_switch_value));
            oc_rep_start_root_object();
            oc_rep_set_boolean(root, value, g_switch_value);
            oc_rep_end_root_object();
            break;
          }
          default: {
            if (g_switch_storage_status == 2) {
                oc_storage_write("g_switch_value",
                                 (uint8_t *)&state,
                                 sizeof(g_switch_value));
            }
            oc_rep_start_root_object();
            oc_rep_set_boolean(root, value, g_switch_value);
            oc_rep_end_root_object();
            break;
          }
              
      }
  }

  if (!bad_request) {
    oc_send_response(request, oc_status_code);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

/**
 * get method for "/dali" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: This Resource describes the DALI write
 * resource, able to convey FF and BF according  IEC 62386-104, Digital
 * addressable lighting interface - Part 104: General requirements - Wireless
 * and alternative wired system. Retrieve on this Resource only returns common
 * Properties.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_dali(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data; /* variable not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a
     sensor. the call to the HW needs to fill in the global variable before it
     returns to this function here. alternative is to have a callback from the
     hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will
     pass CTT1.2.2 */
  bool error_state = false;

  PRINT("-- Begin get_dali: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    break;
  case OC_IF_W:
    error_state = true;
    break;

  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End get_dali %s\n", btoa(error_state));
}

/**
 * post method for "/dali" resource.
 * The function has as input the request body, which are the input values of the
 * POST method. The input values (as a set) are checked if all supplied values
 * are correct. If the input values are correct, they will be assigned to the
 * global  property values. Resource Description: The POST can be used to issue
 * an DALI FF frame. The command can be issued as Multicast (SSM) or as unicast.
 * The Multicast command will have no response. The unicast command can have a
 * BF response.
 *
 * @param request the request representation.
 * @param interfaces the used interfaces during the request.
 * @param user_data the supplied user data.
 */
static void
post_dali(oc_request_t *request, oc_interface_mask_t interfaces,
          void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("-- Begin post_dali:\n");
  oc_rep_t *rep = request->request_payload;

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  bool var_in_request = false;
  rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    PRINT(" required property: 'pld' not in request\n");
  }
  var_in_request = false;
  rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld_s) ==
        0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    PRINT(" required property: 'pld_s' not in request\n");
  }
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld) == 0) {
      /* property "pld" of type array exist in payload */

      size_t array_size = 0;

      if (rep->type == OC_REP_BYTE_STRING) {
        char *temp_byte_array = 0;
        oc_rep_get_byte_string(rep, "pld", &temp_byte_array, &array_size);
      } else {
        int64_t *temp_array = 0;
        oc_rep_get_int_array(rep, "pld", &temp_array, &array_size);
      }
      if (array_size > MAX_ARRAY) {
        error_state = true;
        PRINT("   property array 'pld' is too long: %d expected: MAX_ARRAY \n",
              (int)array_size);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld_s) ==
        0) {
      /* property "pld_s" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        PRINT("   property 'pld_s' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_prio) == 0) {
      /* property "prio" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        PRINT("   property 'prio' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_src) == 0) {
      /* property "src" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        PRINT("   property 'src' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_st) == 0) {
      /* property "st" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        PRINT("   property 'st' is not of type bool %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_tbus) == 0) {
      /* property "tbus" of type array exist in payload */

      size_t array_size = 0;

      if (rep->type == OC_REP_BYTE_STRING) {
        char *temp_byte_array = 0;
        oc_rep_get_byte_string(rep, "tbus", &temp_byte_array, &array_size);
      } else {
        int64_t *temp_array = 0;
        oc_rep_get_int_array(rep, "tbus", &temp_array, &array_size);
      }
      if (array_size > MAX_ARRAY) {
        error_state = true;
        PRINT("   property array 'tbus' is too long: %d expected: MAX_ARRAY \n",
              (int)array_size);
      }
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    default: {
      /* loop over all the properties in the input document */
      oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        PRINT("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld) ==
            0) {
          /* retrieve the array pointer to the int array of of property "pld"
             note that the variable g_dali_pld_array_size will contain the array
             size in the payload. */
          if (rep->type == OC_REP_BYTE_STRING) {
            char *temp_array = 0;
            oc_rep_get_byte_string(rep, "pld", &temp_array,
                                   &g_dali_pld_array_size);
            /* copy over the data of the retrieved (byte) array to the global
             * variable */
            for (int j = 0; j < (int)g_dali_pld_array_size; j++) {
              PRINT(" byte %d ", temp_array[j]);
              g_dali_pld[j] = temp_array[j];
            }
          } else {
            int64_t *temp_integer = 0;
            oc_rep_get_int_array(rep, "pld", &temp_integer,
                                 &g_dali_pld_array_size);
            /* copy over the data of the retrieved (integer) array to the global
             * variable */
            for (int j = 0; j < (int)g_dali_pld_array_size; j++) {
              PRINT(" integer %lld ", temp_integer[j]);
              g_dali_pld[j] = (uint8_t)temp_integer[j];
            }
          }
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld_s) ==
            0) {
          /* assign "pld_s" */
          PRINT("  property 'pld_s' : %d\n", (int)rep->value.integer);
          g_dali_pld_s = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_prio) ==
            0) {
          /* assign "prio" */
          PRINT("  property 'prio' : %d\n", (int)rep->value.integer);
          g_dali_prio = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_src) ==
            0) {
          /* assign "src" */
          PRINT("  property 'src' : %d\n", (int)rep->value.integer);
          g_dali_src = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_st) ==
            0) {
          /* assign "st" */
          PRINT("  property 'st' : %s\n", (char *)btoa(rep->value.boolean));
          g_dali_st = rep->value.boolean;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_tbus) ==
            0) {
          /* retrieve the array pointer to the int array of of property "tbus"
             note that the variable g_dali_tbus_array_size will contain the
             array size in the payload. */
          if (rep->type == OC_REP_BYTE_STRING) {
            char *temp_array = 0;
            oc_rep_get_byte_string(rep, "tbus", &temp_array,
                                   &g_dali_tbus_array_size);
            /* copy over the data of the retrieved (byte) array to the global
             * variable */
            for (int j = 0; j < (int)g_dali_tbus_array_size; j++) {
              PRINT(" byte %d ", temp_array[j]);
              g_dali_tbus[j] = temp_array[j];
            }
          } else {
            int64_t *temp_integer = 0;
            oc_rep_get_int_array(rep, "tbus", &temp_integer,
                                 &g_dali_tbus_array_size);
            /* copy over the data of the retrieved (integer) array to the global
             * variable */
            for (int j = 0; j < (int)g_dali_tbus_array_size; j++) {
              PRINT(" integer %lld ", temp_integer[j]);
              g_dali_tbus[j] = temp_integer[j];
            }
          }
        }
        rep = rep->next;
      }
      /* set the response */
      PRINT("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */

      oc_rep_set_array(root, pld);
      for (int i = 0; i < (int)g_dali_pld_array_size; i++) {
        oc_rep_add_int(pld, g_dali_pld[i]);
      }
      oc_rep_close_array(root, pld);

      PRINT("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_pld_s, g_dali_pld_s);
      oc_rep_set_int(root, pld_s, g_dali_pld_s);
      PRINT("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_prio, g_dali_prio);
      oc_rep_set_int(root, prio, g_dali_prio);
      PRINT("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_src, g_dali_src);
      oc_rep_set_int(root, src, g_dali_src);
      PRINT("   %s : %s", g_dali_RESOURCE_PROPERTY_NAME_st,
            (char *)btoa(g_dali_st));
      oc_rep_set_boolean(root, st, g_dali_st);

      oc_rep_set_array(root, tbus);
      for (int i = 0; i < (int)g_dali_tbus_array_size; i++) {
        oc_rep_add_int(tbus, g_dali_tbus[i]);
      }
      oc_rep_close_array(root, tbus);

      oc_rep_end_root_object();
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
       actuator. one can use the global variables as input to those calls the
       global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    PRINT("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  PRINT("-- End post_dali\n");
}

/**
 * get method for "/dali_conf" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: This Resource describes a DALI (addressing)
 * configuration,  IEC 62386-104, Digital  addressable lighting interface - Part
 * 104: General requirements - Wireless and alternative wired system.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_dali_config(oc_request_t *request, oc_interface_mask_t interfaces,
                void *user_data)
{
  (void)user_data; /* variable not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a
     sensor. the call to the HW needs to fill in the global variable before it
     returns to this function here. alternative is to have a callback from the
     hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will
     pass CTT1.2.2 */
  bool error_state = false;

  PRINT("-- Begin get_config: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (integer) 'bus' */
    oc_rep_set_int(root, bus, g_config_bus);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus, g_config_bus);
    /* property (integer) 'src' */
    oc_rep_set_int(root, src, g_config_src);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src, g_config_src);
    /* property (integer) 'ver' */
    oc_rep_set_int(root, ver, g_config_ver);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver, g_config_ver);
    break;
  case OC_IF_RW:

    /* property (integer) 'bus' */
    oc_rep_set_int(root, bus, g_config_bus);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus, g_config_bus);
    /* property (integer) 'src' */
    oc_rep_set_int(root, src, g_config_src);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src, g_config_src);
    /* property (integer) 'ver' */
    oc_rep_set_int(root, ver, g_config_ver);
    PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver, g_config_ver);
    break;

  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End get_config\n");
}

/**
 * post method for "/dali_conf" resource.
 * The function has as input the request body, which are the input values of the
 * POST method. The input values (as a set) are checked if all supplied values
 * are correct. If the input values are correct, they will be assigned to the
 * global  property values. Resource Description: The POST can be used to set
 * the bus identification or to issue an DALI FF frame. The command can be
 * issued as Multicast (SSM) or as unicast. The Multicast command will have no
 * response, the unicast command can have a BF response
 *
 * @param request the request representation.
 * @param interfaces the used interfaces during the request.
 * @param user_data the supplied user data.
 */
static void
post_dali_config(oc_request_t *request, oc_interface_mask_t interfaces,
                 void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("-- Begin post_config:\n");
  oc_rep_t *rep = request->request_payload;

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_bus) ==
        0) {
      /* property "bus" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        PRINT("   property 'bus' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_src) ==
        0) {
      /* property "src" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        PRINT("   property 'src' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), "ver") == 0) {
      error_state = true;
      PRINT("   property 'ver' is not allowed \n");
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    default: {
      /* loop over all the properties in the input document */
      oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        PRINT("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_bus) ==
            0) {
          /* assign "bus" */
          PRINT("  property 'bus' : %d\n", (int)rep->value.integer);
          g_config_bus = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_src) ==
            0) {
          /* assign "src" */
          PRINT("  property 'src' : %d\n", (int)rep->value.integer);
          g_config_src = (int)rep->value.integer;
        }
        rep = rep->next;
      }
      /* set the response */
      PRINT("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */
      PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus, g_config_bus);
      oc_rep_set_int(root, bus, g_config_bus);
      PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src, g_config_src);
      oc_rep_set_int(root, src, g_config_src);
      PRINT("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver, g_config_ver);
      oc_rep_set_int(root, ver, g_config_ver);

      oc_rep_end_root_object();
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
       actuator. one can use the global variables as input to those calls the
       global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    PRINT("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  PRINT("-- End post_config\n");
}

#ifdef OC_COLLECTIONS_IF_CREATE
/* Resource creation and request handlers for oic.r.switch.binary instances */
typedef struct oc_switch_t
{
  struct oc_switch_t *next;
  oc_resource_t *resource;
  bool state;
} oc_switch_t;
OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches);

bool
set_switch_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)resource;
  oc_switch_t *cswitch = (oc_switch_t *)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      cswitch->state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
get_switch_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                      void *data)
{
  oc_switch_t *cswitch = (oc_switch_t *)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, cswitch->state);
    break;
  default:
    break;
  }
}

void
post_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;
  oc_rep_t *rep = request->request_payload;
  bool bad_request = false;
  while (rep) {
    switch (rep->type) {
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) != 5 ||
          memcmp(oc_string(rep->name), "value", 5) != 0) {
        bad_request = true;
      }
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }

  if (!bad_request) {
    set_switch_properties(request->resource, request->request_payload, cswitch);
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, cswitch->state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

void
get_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  oc_rep_start_root_object();
  get_switch_properties(request->resource, iface_mask, user_data);
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

oc_resource_t *
get_switch_instance(const char *href, oc_string_array_t *types,
                    oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                    size_t device)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_memb_alloc(&switch_s);
  if (cswitch) {
    cswitch->resource = oc_new_resource(
      NULL, href, oc_string_array_get_allocated_size(*types), device);
    if (cswitch->resource) {
      size_t i;
      for (i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
        const char *rt = oc_string_array_get_item(*types, i);
        oc_resource_bind_resource_type(cswitch->resource, rt);
      }
      oc_resource_bind_resource_interface(cswitch->resource, iface_mask);
      cswitch->resource->properties = bm;
      oc_resource_set_default_interface(cswitch->resource, OC_IF_A);
      oc_resource_set_request_handler(cswitch->resource, OC_GET, get_cswitch,
                                      cswitch);
      oc_resource_set_request_handler(cswitch->resource, OC_POST, post_cswitch,
                                      cswitch);
      oc_resource_set_properties_cbs(cswitch->resource, get_switch_properties,
                                     cswitch, set_switch_properties, cswitch);
      oc_add_resource(cswitch->resource);

      oc_list_add(switches, cswitch);
      return cswitch->resource;
    } else {
      oc_memb_free(&switch_s, cswitch);
    }
  }
  return NULL;
}

void
free_switch_instance(oc_resource_t *resource)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_list_head(switches);
  while (cswitch) {
    if (cswitch->resource == resource) {
      oc_delete_resource(resource);
      oc_list_remove(switches, cswitch);
      oc_memb_free(&switch_s, cswitch);
      return;
    }
    cswitch = cswitch->next;
  }
}

#endif /* OC_COLLECTIONS_IF_CREATE */

/* Setting custom Collection-level properties */
int64_t battery_level = 94;
bool
set_platform_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)resource;
  (void)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 2 &&
          memcmp(oc_string(rep->name), "bl", 2) == 0) {
        battery_level = rep->value.integer;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
get_platform_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)resource;
  (void)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_rep_set_int(root, x.org.openconnectivity.bl, battery_level);
    break;
  default:
    break;
  }
}

bool
verify_action_in_supported_set(char *action, unsigned int action_len)
{
  bool rc = false;
  size_t i;

  for (i = 0; i < oc_string_array_get_allocated_size(my_supportedactions);
       i++) {
    const char *sv = oc_string_array_get_item(my_supportedactions, i);
    PRINT("Action compare. Supported action %s against received action %s \n",
          sv, action);
    if (strlen(sv) == action_len && memcmp(sv, action, action_len) == 0) {
      rc = true;
      break;
    }
  }

  return rc;
}

static void
get_remotecontrol(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  (void)user_data;

  /* Check if query string includes action selectio, it is does, reject the
   * request. */
  char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values(request, "action", &action, &action_len);

  if (action_len > 0) {
    // An action parm was received
    //
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  PRINT("GET_remotecontrol:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_key(oc_rep_object(root), "supportedactions");
    oc_rep_begin_array(oc_rep_object(root), supportedactions);
    for (size_t i = 0;
         i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
      oc_rep_add_text_string(supportedactions,
                             oc_string_array_get_item(my_supportedactions, i));
    }
    oc_rep_end_array(oc_rep_object(root), supportedactions);
    oc_rep_end_root_object();
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_remotecontrol(oc_request_t *request, oc_interface_mask_t iface_mask,
                   void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_remotecontrol:\n");

  /* Check if query string includes action selection. */
  char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values(request, "action", &action, &action_len);

  if (action_len > 0) {
    PRINT("POST action length = %d \n", action_len);
    PRINT("POST action string actual size %d \n", strlen(action));
    PRINT("POST action received raw = %s \n", action);

    // Validate that the action requests is in the set
    //
    action[action_len] = '\0';
    bool valid_action = verify_action_in_supported_set(action, action_len);

    // Build response with selected action
    //
    if (valid_action) {
      oc_rep_start_root_object();
      oc_rep_set_key(oc_rep_object(root), "selectedactions");
      oc_rep_begin_array(oc_rep_object(root), selectedactions);
      oc_rep_add_text_string(selectedactions, action);
      oc_rep_end_array(oc_rep_object(root), selectedactions);
      oc_rep_end_root_object();
      oc_send_response(request, OC_STATUS_CHANGED);
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
  } else {
    PRINT("POST no action received \n");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
register_resources(void)
{
  temp_resource = oc_new_resource(NULL, "/temp", 1, 0);
  oc_resource_bind_resource_type(temp_resource, "oic.r.temperature");
  oc_resource_bind_resource_interface(temp_resource, OC_IF_A);
  oc_resource_bind_resource_interface(temp_resource, OC_IF_S);
  oc_resource_set_default_interface(temp_resource, OC_IF_A);
  oc_resource_set_discoverable(temp_resource, true);
  oc_resource_set_periodic_observable(temp_resource, 1);
  oc_resource_set_request_handler(temp_resource, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(temp_resource, OC_POST, post_temp, NULL);
  oc_resource_tag_func_desc(temp_resource, OC_ENUM_HEATING);
  oc_resource_tag_pos_desc(temp_resource, OC_POS_CENTRE);
#ifdef OC_OSCORE
  oc_resource_set_secure_mcast(temp_resource, true);
#endif /* OC_OSCORE */
  oc_add_resource(temp_resource);
  PRINT("\tTemperature resource added.\n");
  bswitch = oc_new_resource(NULL, "/switch", 1, 0);
  oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(bswitch, OC_IF_A);
  oc_resource_bind_resource_interface(bswitch, OC_IF_STARTUP);
  oc_resource_bind_resource_interface(bswitch, OC_IF_STARTUP_REVERT); /* oic.if.startup.revert */
  oc_resource_set_default_interface(bswitch, OC_IF_A);
  oc_resource_set_observable(bswitch, true);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
  oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
  oc_resource_tag_func_desc(bswitch, OC_ENUM_SMART);
  oc_resource_tag_pos_rel(bswitch, 0.34, 0.5, 0.8);
  oc_resource_tag_pos_desc(bswitch, OC_POS_TOP);
  oc_add_resource(bswitch);
  PRINT("\tSwitch resource added.\n");

  oc_resource_t *remotecontrol =
    oc_new_resource("Remote Control", "/remotecontrol", 1, 0);
  oc_resource_bind_resource_type(remotecontrol, "oic.r.remotecontrol");
  oc_resource_bind_resource_interface(remotecontrol, OC_IF_A);
  oc_resource_set_default_interface(remotecontrol, OC_IF_A);
  oc_resource_set_discoverable(remotecontrol, true);
  oc_resource_set_request_handler(remotecontrol, OC_GET, get_remotecontrol,
                                  NULL);
  oc_resource_set_request_handler(remotecontrol, OC_POST, post_remotecontrol,
                                  NULL);
  oc_add_resource(remotecontrol);
  PRINT("\t Remotecontrol resource added\n");

  oc_resource_t *res_dali = oc_new_resource(NULL, "/dali", 1, 0);
  oc_resource_bind_resource_type(res_dali, "oic.r.dali");
  oc_resource_bind_resource_interface(res_dali,
                                      OC_IF_BASELINE);    /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_dali, OC_IF_W); /* oic.if.w */
  oc_resource_set_default_interface(res_dali, OC_IF_BASELINE);
  oc_resource_set_discoverable(res_dali, true);
  oc_resource_set_secure_mcast(res_dali, true);
  oc_resource_set_periodic_observable(res_dali, 1);
  oc_resource_set_request_handler(res_dali, OC_GET, get_dali, NULL);
  oc_resource_set_request_handler(res_dali, OC_POST, post_dali, NULL);
#ifdef OC_CLOUD
  oc_cloud_add_resource(res_dali);
#endif
  oc_add_resource(res_dali);
  PRINT("\tDali resource added.\n");

  oc_resource_t *dali_config = oc_new_resource(NULL, "/dali_conf", 1, 0);
  oc_resource_bind_resource_type(dali_config, "oic.r.dali.conf");

  oc_resource_bind_resource_interface(dali_config, OC_IF_RW); /* oic.if.rw */
  oc_resource_bind_resource_interface(dali_config,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_set_default_interface(dali_config, OC_IF_RW);
  oc_resource_set_discoverable(dali_config, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second */
  oc_resource_set_periodic_observable(dali_config, 1);
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is
    called. this function must be called when the value changes, preferable on
    an interrupt when something is read from the hardware. */
  /*oc_resource_set_observable(dali_config, true); */

  oc_resource_set_request_handler(dali_config, OC_GET, get_dali_config, NULL);
  oc_resource_set_request_handler(dali_config, OC_POST, post_dali_config, NULL);

#ifdef OC_CLOUD
  oc_cloud_add_resource(dali_config);
#endif
  oc_add_resource(dali_config);

#ifdef OC_COLLECTIONS
  col = oc_new_collection(NULL, "/platform", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);

  oc_collection_add_supported_rt(col, "oic.r.switch.binary");
  oc_collection_add_mandatory_rt(col, "oic.r.switch.binary");

#ifdef OC_COLLECTIONS_IF_CREATE
  oc_resource_bind_resource_interface(col, OC_IF_CREATE);
  oc_collections_add_rt_factory("oic.r.switch.binary", get_switch_instance,
                                free_switch_instance);
#endif /* OC_COLLECTIONS_IF_CREATE */
  oc_link_t *l1 = oc_new_link(bswitch);
  oc_collection_add_link(col, l1);
  /* Add a defined or custom link parameter to this link */
  oc_link_add_link_param(l1, "x.org.openconnectivity.name", "platform_switch");

  /* The following enables baseline RETRIEVEs/UPDATEs to Collection properties
   */
  oc_resource_set_properties_cbs(col, get_platform_properties, NULL,
                                 set_platform_properties, NULL);
  oc_add_collection(col);
  PRINT("\tResources added to collection.\n");
#endif /* OC_COLLECTIONS */

  oc_resource_t *device_resource = oc_core_get_resource_by_index(OCF_D, DEVICE);
  oc_resource_set_observable(device_resource, false);

  oc_resource_t *platform_resource =
    oc_core_get_resource_by_index(OCF_P, DEVICE);
  oc_resource_set_observable(platform_resource, false);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

#ifdef OC_SECURITY
void
random_pin_cb(const unsigned char *pin, size_t pin_len, void *data)
{
  (void)data;
  PRINT("\n\nRandom PIN: %.*s\n\n", (int)pin_len, pin);
}
#endif /* OC_SECURITY */

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    PRINT("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    PRINT("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    PRINT("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  if (fread(buffer, 1, pem_len, fp) < (size_t)pem_len) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  char cert[8192];
  size_t cert_len = 8192;
  if (read_pem(ee_certificate, cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  char key[4096];
  size_t key_len = 4096;
  if (read_pem(key_certificate, key, &key_len) < 0) {
    PRINT("ERROR: unable to read private key");
    return;
  }

  int ee_credid = oc_pki_add_mfg_cert(0, (const unsigned char *)cert, cert_len,
                                      (const unsigned char *)key, key_len);

  if (ee_credid < 0) {
    PRINT("ERROR installing manufacturer EE cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem(subca_certificate, cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int subca_credid = oc_pki_add_mfg_intermediate_cert(
    0, ee_credid, (const unsigned char *)cert, cert_len);

  if (subca_credid < 0) {
    PRINT("ERROR installing intermediate CA cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem(rootca_certificate, cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }

  oc_pki_set_security_profile(
    0, OC_SP_BASELINE | OC_SP_BLACK | OC_SP_BLUE | OC_SP_PURPLE, OC_SP_BASELINE,
    ee_credid);
#endif /* OC_SECURITY && OC_PKI */
}

static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&cloud_sync_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&cloud_sync_lock);

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
  oc_main_shutdown();
  return NULL;
}

void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  PRINT("Started device with ID: %s\n", buffer);
}
void
initialize_variables(void)
{
  int ret_size = 0;
  /* initialize global variables for resource "/switch" */
  oc_storage_read("g_switch_storage_status",
                  (uint8_t *)&g_switch_storage_status,
                  sizeof(g_switch_storage_status));
  g_switch_value =
    false; /* current value of property "value" The status of the switch. */
  ret_size = oc_storage_read("g_switch_value",
                             (uint8_t *)&g_switch_value,
                             sizeof(g_switch_value));
  if (ret_size != sizeof(g_switch_value))
    PRINT(" could not read store g_switch_value : %d\n", ret_size);
}
int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  initialize_variables();

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  oc_set_con_res_announced(true);
  // max app data size set to 16k large enough to hold full IDD
  oc_set_max_app_data_size(16384);

#ifdef OC_STORAGE
  oc_storage_config("./server_certification_tests_creds");
#endif /* OC_STORAGE */

  oc_set_factory_presets_cb(factory_presets_cb, NULL);
#ifdef OC_SECURITY
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY */

#ifdef OC_SOFTWARE_UPDATE
  static oc_swupdate_cb_t swupdate_impl;
  swupdate_impl.validate_purl = validate_purl;
  swupdate_impl.check_new_version = check_new_version;
  swupdate_impl.download_update = download_update;
  swupdate_impl.perform_upgrade = perform_upgrade;
  oc_swupdate_set_impl(&swupdate_impl);
#endif /* OC_SOFTWARE_UPDATE */

  PRINT("Initializing Server.\n");
  int init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

  oc_resource_t *con_resource = oc_core_get_resource_by_index(OCF_CON, DEVICE);
  oc_resource_set_observable(con_resource, false);

  display_device_uuid();

  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
    case 0:
      continue;
    case 1:
      toggle_switch_resource();
      break;
#ifdef OC_CLOUD
    case 10:
      cloud_register();
      break;
    case 11:
      cloud_login();
      break;
    case 12:
      cloud_logout();
      break;
    case 13:
      cloud_deregister();
      break;
    case 14:
      cloud_refresh_token();
      break;
    case 15:
      oc_cloud_publish_resources(0);
      break;
    case 16:
      cloud_send_ping();
      break;
#endif /* OC_CLOUD */
    case 99:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);

  return 0;
}
