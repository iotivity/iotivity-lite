/****************************************************************************
 *
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
#include "oc_core_res.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "oc_swupdate.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef OC_CLOUD
#include "oc_cloud.h"
#endif /* OC_CLOUD */

#ifdef OC_SOFTWARE_UPDATE
#include "oc_swupdate.h"
#endif /* OC_SOFTWARE_UPDATE */

#if defined(OC_INTROSPECTION) && defined(OC_IDD_API)
#include "oc_introspection.h"
#endif /* OC_INTROSPECTION && OC_IDD_API */

static const size_t DEVICE = 0;

// define application specific values.
static const char *spec_version = "ocf.2.2.5";
static const char *data_model_version = "ocf.res.1.3.0,ocf.sh.1.3.0";

static const char *deivce_uri = "/oic/d";
static const char *device_rt = "oic.d.switch";
static const char *device_name = "OCFTestServer";

static const char *manufacturer = "OCF";

#define btoa(x) ((x) ? "true" : "false")
#define MAX_ARRAY 10 /* max size of the array */

#define CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

/* global property variables for path: "/dali" */
static const char *g_dali_RESOURCE_PROPERTY_NAME_pld =
  "pld"; /* the name for the attribute */
/* array pld  Each DALI byte is conveyed as an byte */
uint8_t g_dali_pld[MAX_ARRAY];
size_t g_dali_pld_array_size;
static const char *g_dali_RESOURCE_PROPERTY_NAME_pld_s =
  "pld_s";            /* the name for the attribute */
int g_dali_pld_s = 0; /* current value of property "pld_s" The amount of
                         integers in the Dali payload. */
static const char *g_dali_RESOURCE_PROPERTY_NAME_prio =
  "prio"; /* the name for the attribute */
int g_dali_prio =
  0; /* current value of property "prio" The priority of the command. */
static const char *g_dali_RESOURCE_PROPERTY_NAME_src =
  "src"; /* the name for the attribute */
int g_dali_src =
  0; /* current value of property "src" assigned source address. -1 means not
        yet assigned by the Application controller. */
static const char *g_dali_RESOURCE_PROPERTY_NAME_st =
  "st"; /* the name for the attribute */
bool g_dali_st =
  false; /* current value of property "st" The command has to be send twice. */
static const char *g_dali_RESOURCE_PROPERTY_NAME_tbus =
  "tbus"; /* the name for the attribute */
/* array tbus  The set of  bus identifiers to which the command should be
 * applied. */
int g_dali_tbus[MAX_ARRAY];
size_t g_dali_tbus_array_size;

/* global property variables for path: "/dali_conf" */
static const char *g_config_RESOURCE_PROPERTY_NAME_bus =
  "bus"; /* the name for the attribute */
int g_config_bus =
  2; /* current value of property "bus" assign the bus identifier. */
static const char *g_config_RESOURCE_PROPERTY_NAME_src =
  "src"; /* the name for the attribute */
int g_config_src =
  5; /* current value of property "src" assigned source address. -1 means not
        yet assigned by the Application controller. */
static const char *g_config_RESOURCE_PROPERTY_NAME_ver =
  "ver"; /* the name for the attribute */
int g_config_ver =
  2; /* current value of property "ver" version of dali on the device. */

static pthread_t event_thread;
static pthread_mutex_t cloud_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

static OC_ATOMIC_INT8_T quit = 0;

static double temp = 5.0;
static double temp_K = (5.0 + 273.15);
static double temp_F = (5.0 * 9 / 5 + 32);
static double min_C = 0.0;
static double max_C = 100.0;
static double min_K = 273.15;
static double max_K = 373.15;
static double min_F = 32;
static double max_F = 212;
typedef enum {
  C = 100,
  F,
  K,
} units_t;
units_t temp_units = C;

#ifdef OC_STORAGE
static int g_switch_storage_status =
  0;   // 0=no storage, 1=startup, 2=startup.revert
#endif /* OC_STORAGE */
static bool g_switch_value =
  false; /* current value of property "value" The status of the switch. */

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
        OC_PRINTF("ERROR Invalid input\n");                                    \
      }                                                                        \
    } while (0);                                                               \
  }

static void
display_menu(void)
{
  OC_PRINTF("\n\n################################################\nOCF "
            "Server Certification Test "
            "Tool\n################################################\n");
  OC_PRINTF("[0] Display this menu\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("Server\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[1] Toggle switch resource\n");
  OC_PRINTF("-----------------------------------------------\n");
#ifdef OC_CLOUD
  OC_PRINTF("Cloud\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[10] Cloud Register\n");
  OC_PRINTF("[11] Cloud Login\n");
  OC_PRINTF("[12] Cloud Logout\n");
  OC_PRINTF("[13] Cloud DeRegister\n");
  OC_PRINTF("[14] Cloud Refresh Token\n");
  OC_PRINTF("[15] Publish Resources\n");
  OC_PRINTF("[16] Send Ping\n");
  OC_PRINTF("-----------------------------------------------\n");
#endif /* OC_CLOUD */
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[99] Exit\n");
  OC_PRINTF("################################################\n");
  OC_PRINTF("\nSelect option: \n");
}

#ifdef OC_SOFTWARE_UPDATE
static int
validate_purl(const char *purl)
{
  (void)purl;
  return 0;
}

static int
check_new_version(size_t device, const char *url, const char *version)
{
  if (!url) {
    oc_swupdate_notify_done(device, OC_SWUPDATE_RESULT_INVALID_URL);
    return -1;
  }
  OC_PRINTF("Package url %s\n", url);
  if (version) {
    OC_PRINTF("Package version: %s\n", version);
  }
  oc_swupdate_notify_new_version_available(device, "2.0",
                                           OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

static int
download_update(size_t device, const char *url)
{
  (void)url;
  oc_swupdate_notify_downloaded(device, "2.0", OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

static int
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
  OC_PRINTF("\nCloud Refresh Token status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    OC_PRINTF("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    OC_PRINTF("\t\t-Refreshed Token\n");
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
    OC_PRINTF("\nCould not issue Refresh Token request\n");
  } else {
    OC_PRINTF("\nIssued Refresh Token request\n");
  }
}

static void
cloud_deregister_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                    void *data)
{
  (void)data;
  OC_PRINTF("\nCloud DeRegister status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    OC_PRINTF("\t\t-DeRegistered\n");
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
    OC_PRINTF("\nCould not issue Cloud DeRegister request\n");
  } else {
    OC_PRINTF("\nIssued Cloud DeRegister request\n");
  }
}

static void
cloud_logout_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Logout status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
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
    OC_PRINTF("\nCould not issue Cloud Logout request\n");
  } else {
    OC_PRINTF("\nIssued Cloud Logout request\n");
  }
}

static void
cloud_login_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Login status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
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
    OC_PRINTF("\nCould not issue Cloud Login request\n");
  } else {
    OC_PRINTF("\nIssued Cloud Login request\n");
  }
}

static void
cloud_register_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Register status flags:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
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
    OC_PRINTF("\nCould not issue Cloud Register request\n");
  } else {
    OC_PRINTF("\nIssued Cloud Register request\n");
  }
}

static void
ping_handler(oc_client_response_t *data)
{
  (void)data;
  OC_PRINTF("\nReceived Pong\n");
}

static void
cloud_send_ping(void)
{
  OC_PRINTF("\nEnter receiving endpoint: ");
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
    OC_PRINTF("\nERROR parsing endpoint string\n");
    return;
  }

  if (oc_send_ping(false, &endpoint, 10, ping_handler, NULL)) {
    OC_PRINTF("\nSuccessfully issued Ping request\n");
    return;
  }

  OC_PRINTF("\nERROR issuing Ping request\n");
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
    OC_PRINTF("   property \"n\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "if") == 0) {
    OC_PRINTF("   property \"if\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "rt") == 0) {
    OC_PRINTF("   property \"rt\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "id") == 0) {
    OC_PRINTF("   property \"id\" is ReadOnly \n");
    return true;
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
toggle_switch_resource(void)
{
  OC_PRINTF("\nSwitch toggled\n");
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
  OC_PRINTF("\tSwitch device added.\n");

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
      OC_PRINTF("\tIntrospection data set for device.\n");
    } else {
      OC_PRINTF("%s", introspection_error);
    }
    free(buffer);
  } else {
    OC_PRINTF("%s", introspection_error);
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
  OC_PRINTF("GET_temp:\n");
  bool invalid_query = false;
  const char *units;
  units_t u = temp_units;
  int units_len =
    oc_get_query_value_v1(request, "units", CHAR_ARRAY_LEN("units"), &units);
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
  OC_PRINTF("POST_temp:\n");
  bool out_of_range = false;
  double t = -1;
  units_t units = C;
  const oc_rep_t *rep = request->request_payload;
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
  OC_PRINTF("GET_switch:\n");
  int oc_status_code = OC_STATUS_OK;

  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, g_switch_value);
    break;
#ifdef OC_STORAGE
  case OC_IF_STARTUP:
    if (g_switch_storage_status != 1) {
      oc_status_code = OC_STATUS_BAD_OPTION;
      break;
    }

    /* property (boolean) 'value' */
    {
      bool temp_value;
      oc_storage_read("g_switch_value", (uint8_t *)&temp_value,
                      sizeof(temp_value));
      oc_rep_set_boolean(root, value, temp_value);
    }
    break;
  case OC_IF_STARTUP_REVERT:
    if (g_switch_storage_status != 2) {
      oc_status_code = OC_STATUS_BAD_OPTION;
      break;
    }

    oc_status_code = OC_STATUS_NOT_MODIFIED;
    break;
#endif /* OC_STORAGE */

  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, oc_status_code);
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  int oc_status_code = OC_STATUS_CHANGED;

  OC_PRINTF("POST_switch:\n");
  bool state = false;
  bool bad_request = false;
  bool var_in_request = false;
  const oc_rep_t *rep = request->request_payload;
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
  if (!var_in_request) {
    bad_request = true;
  }
  if (!bad_request) {
#ifdef OC_STORAGE
    switch (iface_mask) {
    case OC_IF_STARTUP: {
      g_switch_storage_status = 1;
      oc_storage_write("g_switch_storage_status",
                       (uint8_t *)&g_switch_storage_status,
                       sizeof(g_switch_storage_status));
      long tmp_size =
        oc_storage_write("g_switch_value", (uint8_t *)&state, sizeof(state));
      OC_PRINTF("storage (startup)  property 'value' : %s (%ld)\n", btoa(state),
                tmp_size);
      oc_rep_start_root_object();
      oc_rep_set_boolean(root, value, state);
      oc_rep_end_root_object();
      break;
    }
    case OC_IF_STARTUP_REVERT: {
      g_switch_storage_status = 2;
      oc_storage_write("g_switch_storage_status",
                       (uint8_t *)&g_switch_storage_status,
                       sizeof(g_switch_storage_status));
      long tmp_size =
        oc_storage_write("g_switch_value", (uint8_t *)&state, sizeof(state));
      OC_PRINTF("storage (startup.revert)  property 'value' : %s (%ld)\n",
                btoa(state), tmp_size);
      g_switch_value = state;
      oc_rep_start_root_object();
      oc_rep_set_boolean(root, value, g_switch_value);
      oc_rep_end_root_object();
      break;
    }
    default: {
      if (g_switch_storage_status == 2) {
        long tmp_size =
          oc_storage_write("g_switch_value", (uint8_t *)&state, sizeof(state));
        OC_PRINTF("storage (startup.revert)  property 'value' : %s (%ld)\n",
                  btoa(state), tmp_size);
      }
      g_switch_value = state;
      oc_rep_start_root_object();
      oc_rep_set_boolean(root, value, g_switch_value);
      oc_rep_end_root_object();
      break;
    }
    }
#else  /* !OC_STORAGE */
    g_switch_value = state;
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, value, g_switch_value);
    oc_rep_end_root_object();
#endif /* OC_STORAGE */
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

  OC_PRINTF("-- Begin get_dali: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    OC_PRINTF("   Adding Baseline info\n");
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
  OC_PRINTF("-- End get_dali %s\n", btoa(error_state));
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
  OC_PRINTF("-- Begin post_dali:\n");

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  bool var_in_request = false;
  const oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    OC_PRINTF(" required property: 'pld' not in request\n");
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
    OC_PRINTF(" required property: 'pld_s' not in request\n");
  }
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: (check) %s \n", oc_string(rep->name));

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
        OC_PRINTF(
          "   property array 'pld' is too long: %d expected: MAX_ARRAY \n",
          (int)array_size);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld_s) ==
        0) {
      /* property "pld_s" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        OC_PRINTF("   property 'pld_s' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_prio) == 0) {
      /* property "prio" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        OC_PRINTF("   property 'prio' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_src) == 0) {
      /* property "src" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        OC_PRINTF("   property 'src' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_st) == 0) {
      /* property "st" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        OC_PRINTF("   property 'st' is not of type bool %d \n", rep->type);
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
        OC_PRINTF(
          "   property array 'tbus' is too long: %d expected: MAX_ARRAY \n",
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
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        OC_PRINTF("key: (assign) %s \n", oc_string(rep->name));
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
              OC_PRINTF(" byte %d ", temp_array[j]);
              g_dali_pld[j] = temp_array[j];
            }
          } else {
            int64_t *temp_integer = 0;
            oc_rep_get_int_array(rep, "pld", &temp_integer,
                                 &g_dali_pld_array_size);
            /* copy over the data of the retrieved (integer) array to the global
             * variable */
            for (int j = 0; j < (int)g_dali_pld_array_size; j++) {
              OC_PRINTF(" integer %" PRId64 " ", temp_integer[j]);
              g_dali_pld[j] = (uint8_t)temp_integer[j];
            }
          }
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_pld_s) ==
            0) {
          /* assign "pld_s" */
          OC_PRINTF("  property 'pld_s' : %d\n", (int)rep->value.integer);
          g_dali_pld_s = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_prio) ==
            0) {
          /* assign "prio" */
          OC_PRINTF("  property 'prio' : %d\n", (int)rep->value.integer);
          g_dali_prio = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_src) ==
            0) {
          /* assign "src" */
          OC_PRINTF("  property 'src' : %d\n", (int)rep->value.integer);
          g_dali_src = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_dali_RESOURCE_PROPERTY_NAME_st) ==
            0) {
          /* assign "st" */
          OC_PRINTF("  property 'st' : %s\n", (char *)btoa(rep->value.boolean));
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
            for (size_t j = 0; j < g_dali_tbus_array_size; j++) {
              OC_PRINTF(" byte %d ", temp_array[j]);
              g_dali_tbus[j] = (int)temp_array[j];
            }
          } else {
            int64_t *temp_integer = 0;
            oc_rep_get_int_array(rep, "tbus", &temp_integer,
                                 &g_dali_tbus_array_size);
            /* copy over the data of the retrieved (integer) array to the global
             * variable */
            for (size_t j = 0; j < g_dali_tbus_array_size; j++) {
              OC_PRINTF(" integer %" PRId64 " ", temp_integer[j]);
              g_dali_tbus[j] = (int)temp_integer[j];
            }
          }
        }
        rep = rep->next;
      }
      /* set the response */
      OC_PRINTF("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */

      oc_rep_set_array(root, pld);
      for (int i = 0; i < (int)g_dali_pld_array_size; i++) {
        oc_rep_add_int(pld, g_dali_pld[i]);
      }
      oc_rep_close_array(root, pld);

      OC_PRINTF("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_pld_s,
                g_dali_pld_s);
      oc_rep_set_int(root, pld_s, g_dali_pld_s);
      OC_PRINTF("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_prio,
                g_dali_prio);
      oc_rep_set_int(root, prio, g_dali_prio);
      OC_PRINTF("   %s : %d\n", g_dali_RESOURCE_PROPERTY_NAME_src, g_dali_src);
      oc_rep_set_int(root, src, g_dali_src);
      OC_PRINTF("   %s : %s", g_dali_RESOURCE_PROPERTY_NAME_st,
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
    OC_PRINTF("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_PRINTF("-- End post_dali\n");
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

  OC_PRINTF("-- Begin get_config: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    OC_PRINTF("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (integer) 'bus' */
    oc_rep_set_int(root, bus, g_config_bus);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus,
              g_config_bus);
    /* property (integer) 'src' */
    oc_rep_set_int(root, src, g_config_src);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src,
              g_config_src);
    /* property (integer) 'ver' */
    oc_rep_set_int(root, ver, g_config_ver);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver,
              g_config_ver);
    break;
  case OC_IF_RW:

    /* property (integer) 'bus' */
    oc_rep_set_int(root, bus, g_config_bus);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus,
              g_config_bus);
    /* property (integer) 'src' */
    oc_rep_set_int(root, src, g_config_src);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src,
              g_config_src);
    /* property (integer) 'ver' */
    oc_rep_set_int(root, ver, g_config_ver);
    OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver,
              g_config_ver);
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
  OC_PRINTF("-- End get_config\n");
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
  OC_PRINTF("-- Begin post_config:\n");

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  /* loop over the request document to check if all inputs are ok */
  const oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_bus) ==
        0) {
      /* property "bus" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        OC_PRINTF("   property 'bus' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_src) ==
        0) {
      /* property "src" of type integer exist in payload */
      if (rep->type != OC_REP_INT) {
        error_state = true;
        OC_PRINTF("   property 'src' is not of type int %d \n", rep->type);
      }
    }
    if (strcmp(oc_string(rep->name), "ver") == 0) {
      error_state = true;
      OC_PRINTF("   property 'ver' is not allowed \n");
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    default: {
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        OC_PRINTF("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_bus) ==
            0) {
          /* assign "bus" */
          OC_PRINTF("  property 'bus' : %d\n", (int)rep->value.integer);
          g_config_bus = (int)rep->value.integer;
        }
        if (strcmp(oc_string(rep->name), g_config_RESOURCE_PROPERTY_NAME_src) ==
            0) {
          /* assign "src" */
          OC_PRINTF("  property 'src' : %d\n", (int)rep->value.integer);
          g_config_src = (int)rep->value.integer;
        }
        rep = rep->next;
      }
      /* set the response */
      OC_PRINTF("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */
      OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_bus,
                g_config_bus);
      oc_rep_set_int(root, bus, g_config_bus);
      OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_src,
                g_config_src);
      oc_rep_set_int(root, src, g_config_src);
      OC_PRINTF("   %s : %d\n", g_config_RESOURCE_PROPERTY_NAME_ver,
                g_config_ver);
      oc_rep_set_int(root, ver, g_config_ver);

      oc_rep_end_root_object();
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
       actuator. one can use the global variables as input to those calls the
       global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    OC_PRINTF("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_PRINTF("-- End post_config\n");
}

#ifdef OC_COLLECTIONS
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

static bool
set_switch_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                      void *data)
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

static void
get_switch_properties(const oc_resource_t *resource,
                      oc_interface_mask_t iface_mask, void *data)
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

static void
post_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;
  const oc_rep_t *rep = request->request_payload;
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

static void
get_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  oc_rep_start_root_object();
  get_switch_properties(request->resource, iface_mask, user_data);
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static oc_resource_t *
get_switch_instance(const char *href, const oc_string_array_t *types,
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

static void
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
static bool
set_platform_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                        void *data)
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

static void
get_platform_properties(const oc_resource_t *resource,
                        oc_interface_mask_t iface_mask, void *data)
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
#endif /* OC_COLLECTIONS */

static bool
verify_action_in_supported_set(oc_string_t action)
{
  const char *act = oc_string(action);
  size_t act_len = oc_string_len(action);
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
    const char *sv = oc_string_array_get_item(my_supportedactions, i);
    OC_PRINTF(
      "Action compare. Supported action %s against received action %s \n", sv,
      act);
    if (strlen(sv) == act_len && memcmp(sv, act, act_len) == 0) {
      return true;
    }
  }

  return false;
}

static void
get_remotecontrol(oc_request_t *request, oc_interface_mask_t iface_mask,
                  void *user_data)
{
  (void)user_data;

  /* Check if query string includes action selection, it is does, reject the
   * request. */
  const char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values_v1(request, "action", CHAR_ARRAY_LEN("action"),
                                 &action, &action_len);

  if (action_len > 0) {
    // An action parm was received
    //
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  OC_PRINTF("GET_remotecontrol:\n");
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
  OC_PRINTF("POST_remotecontrol:\n");

  /* Check if query string includes action selection. */
  const char *action = NULL;
  int action_len = -1;
  oc_init_query_iterator();
  oc_iterate_query_get_values_v1(request, "action", CHAR_ARRAY_LEN("action"),
                                 &action, &action_len);

  if (action_len > 0) {
    OC_PRINTF("POST action length = %d \n", action_len);
    OC_PRINTF("POST action string actual size %zu \n", strlen(action));
    OC_PRINTF("POST action received raw = %s \n", action);

    // Validate that the action requests is in the set
    //
    oc_string_t act;
    oc_new_string(&act, action, action_len);
    bool valid_action = verify_action_in_supported_set(act);

    // Build response with selected action
    //
    if (valid_action) {
      oc_rep_start_root_object();
      oc_rep_set_key(oc_rep_object(root), "selectedactions");
      oc_rep_begin_array(oc_rep_object(root), selectedactions);
      oc_rep_add_text_string(selectedactions, oc_string(act));
      oc_rep_end_array(oc_rep_object(root), selectedactions);
      oc_rep_end_root_object();
      oc_send_response(request, OC_STATUS_CHANGED);
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
    oc_free_string(&act);
  } else {
    OC_PRINTF("POST no action received \n");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static bool
register_temp(void)
{
  temp_resource = oc_new_resource(NULL, "/temp", 1, 0);
  if (temp_resource == NULL) {
    OC_PRINTF("ERROR: could not create /temp resource");
    return false;
  }
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
  if (!oc_add_resource(temp_resource)) {
    OC_PRINTF("ERROR: could not add /temp resource to device");
    return false;
  }

#ifdef OC_OSCORE
  oc_resource_set_secure_mcast(temp_resource, true);
#endif /* OC_OSCORE */

  OC_PRINTF("\tTemperature resource added.\n");
  return true;
}

static bool
register_switch(void)
{
  bswitch = oc_new_resource(NULL, "/switch", 1, 0);
  if (bswitch == NULL) {
    OC_PRINTF("ERROR: could not create /switch resource");
    return false;
  }
  oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(bswitch, OC_IF_A);
#ifdef OC_STORAGE
  oc_resource_bind_resource_interface(bswitch, OC_IF_STARTUP);
  oc_resource_bind_resource_interface(
    bswitch, OC_IF_STARTUP_REVERT); // oic.if.startup.revert
#endif                              /* OC_STORAGE */
  oc_resource_set_default_interface(bswitch, OC_IF_A);
  oc_resource_set_observable(bswitch, true);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
  oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
  oc_resource_tag_func_desc(bswitch, OC_ENUM_SMART);
  oc_resource_tag_pos_rel(bswitch, 0.34, 0.5, 0.8);
  oc_resource_tag_pos_desc(bswitch, OC_POS_TOP);
  if (!oc_add_resource(bswitch)) {
    OC_PRINTF("ERROR: could not add /switch resource to device");
    return false;
  }
  OC_PRINTF("\tSwitch resource added.\n");
  return true;
}

static bool
register_remotecontrol(void)
{
  oc_resource_t *remotecontrol =
    oc_new_resource("Remote Control", "/remotecontrol", 1, 0);
  if (remotecontrol == NULL) {
    OC_PRINTF("ERROR: could not create /remotecontrol resource");
    return false;
  }
  oc_resource_bind_resource_type(remotecontrol, "oic.r.remotecontrol");
  oc_resource_bind_resource_interface(remotecontrol, OC_IF_A);
  oc_resource_set_default_interface(remotecontrol, OC_IF_A);
  oc_resource_set_discoverable(remotecontrol, true);
  oc_resource_set_request_handler(remotecontrol, OC_GET, get_remotecontrol,
                                  NULL);
  oc_resource_set_request_handler(remotecontrol, OC_POST, post_remotecontrol,
                                  NULL);
  if (!oc_add_resource(remotecontrol)) {
    OC_PRINTF("ERROR: could not add /remotecontrol resource to device");
    return false;
  }
  OC_PRINTF("\t Remotecontrol resource added\n");
  return true;
}

static bool
register_dali(void)
{
  oc_resource_t *res_dali = oc_new_resource(NULL, "/dali", 1, 0);
  if (res_dali == NULL) {
    OC_PRINTF("ERROR: could not create /dali resource\n");
    return false;
  }

  oc_resource_bind_resource_type(res_dali, "oic.r.dali");
  oc_resource_bind_resource_interface(res_dali,
                                      OC_IF_BASELINE);    /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_dali, OC_IF_W); /* oic.if.w */
  oc_resource_set_default_interface(res_dali, OC_IF_BASELINE);
  oc_resource_set_discoverable(res_dali, true);
#ifdef OC_OSCORE
  oc_resource_set_secure_mcast(res_dali, true);
#endif /* OC_OSCORE */
  oc_resource_set_periodic_observable(res_dali, 1);
  oc_resource_set_request_handler(res_dali, OC_GET, get_dali, NULL);
  oc_resource_set_request_handler(res_dali, OC_POST, post_dali, NULL);
  if (!oc_add_resource(res_dali)) {
    OC_PRINTF("ERROR: could not add /dali resource to device\n");
    return false;
  }

#ifdef OC_CLOUD
  if (oc_cloud_add_resource(res_dali) < 0) {
    OC_PRINTF("ERROR: could not add /dali resource to cloud\n");
    return false;
  }
#endif
  OC_PRINTF("\tDali resource added.\n");
  return true;
}

static bool
register_dali_conf(void)
{
  oc_resource_t *dali_config = oc_new_resource(NULL, "/dali_conf", 1, 0);
  if (dali_config == NULL) {
    OC_PRINTF("ERROR: could not create /dali_conf resource\n");
    return false;
  }
  oc_resource_bind_resource_type(dali_config, "oic.r.dali.conf");

  oc_resource_bind_resource_interface(dali_config, OC_IF_RW); /* oic.if.rw */
  oc_resource_bind_resource_interface(dali_config,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_set_default_interface(dali_config, OC_IF_BASELINE);
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

  if (!oc_add_resource(dali_config)) {
    OC_PRINTF("ERROR: could not add /dali_conf resource to device\n");
    return false;
  }
#ifdef OC_CLOUD
  if (oc_cloud_add_resource(dali_config) < 0) {
    OC_PRINTF("ERROR: could not add /dali_conf resource to cloud\n");
    return false;
  }
#endif /* OC_CLOUD */
  OC_PRINTF("\tDali config resource added.\n");
  return true;
}

#ifdef OC_COLLECTIONS
static bool
register_platform_collection(void)
{
  col = oc_new_collection(NULL, "/platform", 1, 0);
  if (col == NULL) {
    OC_PRINTF("ERROR: could not create /platform collection\n");
    return false;
  }

  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);

  if (!oc_collection_add_supported_rt(col, "oic.r.switch.binary")) {
    OC_PRINTF("ERROR: could not add supported resource type to collection\n");
    return false;
  }
  if (!oc_collection_add_mandatory_rt(col, "oic.r.switch.binary")) {
    OC_PRINTF("ERROR: could not add mandatory resource type to collection\n");
    return false;
  }

#ifdef OC_COLLECTIONS_IF_CREATE
  oc_resource_bind_resource_interface(col, OC_IF_CREATE);
  if (!oc_collections_add_rt_factory("oic.r.switch.binary", get_switch_instance,
                                     free_switch_instance)) {
    OC_PRINTF("ERROR: could not add factory for oic.r.switch.binary\n");
    return false;
  }
#endif /* OC_COLLECTIONS_IF_CREATE */
  oc_link_t *l1 = oc_new_link(bswitch);
  if (l1 == NULL) {
    OC_PRINTF("ERROR: could not create link\n");
    return false;
  }

  oc_collection_add_link(col, l1);
  /* Add a defined or custom link parameter to this link */
  if (!oc_link_add_link_param(l1, "x.org.openconnectivity.name",
                              "platform_switch")) {
    OC_PRINTF("ERROR: could not add link parameter\n");
    return false;
  }

  /* The following enables baseline RETRIEVEs/UPDATEs to Collection properties
   */
  oc_resource_set_properties_cbs(col, get_platform_properties, NULL,
                                 set_platform_properties, NULL);
  if (!oc_add_collection_v1(col)) {
    OC_PRINTF("ERROR: could not add /platform collection\n");
    return false;
  }
  OC_PRINTF("\tResources added to collection.\n");
  return true;
}
#endif /* OC_COLLECTIONS */

static void
register_resources(void)
{
  if (!register_temp()) {
    oc_abort("Failed to register /temp resource");
  }
  if (!register_switch()) {
    oc_abort("Failed to register /switch resource");
  }
  if (!register_remotecontrol()) {
    oc_abort("Failed to register /remotecontrol resource");
  }
  if (!register_dali()) {
    oc_abort("Failed to register /dali resource");
  }
  if (!register_dali_conf()) {
    oc_abort("Failed to register /dali_conf resource");
  }
#ifdef OC_COLLECTIONS
  if (!register_platform_collection()) {
    oc_abort("Failed to register /platform resource");
  }
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
  pthread_cond_signal(&cv);
}

static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

#ifdef OC_SECURITY
static void
random_pin_cb(const unsigned char *pin, size_t pin_len, void *data)
{
  (void)data;
  OC_PRINTF("\n\nRandom PIN: %.*s\n\n", (int)pin_len, pin);
}
#endif /* OC_SECURITY */

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    OC_PRINTF("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    OC_PRINTF("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

static void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  char cert[8192];
  size_t cert_len = 8192;
  if (read_pem(ee_certificate, cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  char key[4096];
  size_t key_len = 4096;
  if (read_pem(key_certificate, key, &key_len) < 0) {
    OC_PRINTF("ERROR: unable to read private key");
    return;
  }

  int ee_credid = oc_pki_add_mfg_cert(0, (const unsigned char *)cert, cert_len,
                                      (const unsigned char *)key, key_len);

  if (ee_credid < 0) {
    OC_PRINTF("ERROR installing manufacturer EE cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem(subca_certificate, cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int subca_credid = oc_pki_add_mfg_intermediate_cert(
    0, ee_credid, (const unsigned char *)cert, cert_len);

  if (subca_credid < 0) {
    OC_PRINTF("ERROR installing intermediate CA cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem(rootca_certificate, cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
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
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    pthread_mutex_lock(&cloud_sync_lock);
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_unlock(&cloud_sync_lock);

    pthread_mutex_lock(&mutex);
    if (next_event_mt == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&cv, &mutex, &next_event);
    }
    pthread_mutex_unlock(&mutex);
  }
  oc_main_shutdown();
  return NULL;
}

static void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  OC_PRINTF("Started device with ID: %s\n", buffer);
}

static void
initialize_variables(void)
{
  g_switch_value =
    false; /* current value of property "value" The status of the switch. */

#ifdef OC_STORAGE
  /* initialize global variables for resource "/switch" */
  oc_storage_read("g_switch_storage_status",
                  (uint8_t *)&g_switch_storage_status,
                  sizeof(g_switch_storage_status));
  long ret_size = oc_storage_read("g_switch_value", (uint8_t *)&g_switch_value,
                                  sizeof(g_switch_value));
  if (ret_size != sizeof(g_switch_value)) {
    OC_PRINTF(" could not read store g_switch_value : %ld\n", ret_size);
  }
#endif /* OC_STORAGE */
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&cloud_sync_lock, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }

  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&cloud_sync_lock);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&cloud_sync_lock);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&cloud_sync_lock);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&cloud_sync_lock);
    return false;
  }
  pthread_condattr_destroy(&attr);
  return true;
}

static void
deinit(void)
{
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&cloud_sync_lock);
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };

  oc_set_con_res_announced(true);
  // max app data size set to 16k large enough to hold full IDD
  oc_set_max_app_data_size(16384);

#ifdef OC_STORAGE
  oc_storage_config("./server_certification_tests_creds");
#endif /* OC_STORAGE */
  initialize_variables();

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

  OC_PRINTF("Initializing Server.\n");
  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    deinit();
    return -1;
  }

  oc_resource_t *con_resource = oc_core_get_resource_by_index(OCF_CON, DEVICE);
  oc_resource_set_observable(con_resource, false);

  display_device_uuid();

  int c;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
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
  deinit();
  return 0;
}
