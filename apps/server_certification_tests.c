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

#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

static const size_t DEVICE = 0;

// define application specific values.
static const char *spec_version = "ocf.2.2.0";
static const char *data_model_version = "ocf.res.1.3.0,ocf.sh.1.3.0";

static const char *deivce_uri = "/oic/d";
static const char *device_rt = "oic.d.switch";
static const char *device_name = "OCFTestServer";

static const char *manufacturer = "OCF";

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
static bool switch_state;
const char *mfg_persistent_uuid = "f6e10d9c-a1c9-43ba-a800-f1b0aad2a889";

const char *ee_certificate = "pki_certs/certification_tests_ee.pem";
const char *key_certificate = "pki_certs/certification_tests_key.pem";
const char *subca_certificate = "pki_certs/certification_tests_subca1.pem";
const char *rootca_certificate = "pki_certs/certification_tests_rootca1.pem";

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
  switch_state = !switch_state;
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
    } else if (units[0] != 'C') {
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
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, switch_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_switch:\n");
  bool state = false, bad_request = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
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
    switch_state = state;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, switch_state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
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
  oc_add_resource(temp_resource);
  PRINT("\tTemperature resource added.\n");
  bswitch = oc_new_resource(NULL, "/switch", 1, 0);
  oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(bswitch, OC_IF_A);
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

int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  oc_set_con_res_announced(true);
  // max app data size set to 13k large enough to hold full IDD
  oc_set_max_app_data_size(13312);

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
