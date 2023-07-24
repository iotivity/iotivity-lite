/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.2.2.1";
static const char *data_model_version = "ocf.res.1.3.0,ocf.sh.1.3.0";

static const char *device_rt = "oic.d.switch";
static const char *device_name = "Cloud Switch";

static const char *manufacturer = "ocfcloud.com";

static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static pthread_t event_thread;

static oc_resource_t *res1 = NULL;

static OC_ATOMIC_INT8_T quit = 0;

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

static const char *cis;
static const char *auth_code;
static const char *sid;
static const char *apn;
static const char *deviceid;

static void
display_menu(void)
{
  OC_PRINTF("\n\n################################################\nOCF "
            "Cloud-connected Device Certification Test "
            "Tool\n################################################\n");
  OC_PRINTF("[0] Display this menu\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[1] Cloud Register\n");
  OC_PRINTF("[2] Cloud Login\n");
  OC_PRINTF("[3] Cloud Logout\n");
  OC_PRINTF("[4] Cloud DeRegister\n");
  OC_PRINTF("[5] Cloud Refresh Token\n");
  OC_PRINTF("[6] Publish Resources\n");
  OC_PRINTF("[7] Send Ping\n");
  OC_PRINTF("[8] Unpublish switch resource\n");
  OC_PRINTF("[9] Publish switch resource\n");
  OC_PRINTF("[10] Create switch resource\n");
  OC_PRINTF("[11] Delete switch resource\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[12] Exit\n");
  OC_PRINTF("################################################\n");
  OC_PRINTF("\nSelect option: \n");
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) != 1) {                                             \
      OC_PRINTF("ERROR Invalid input\n");                                      \
    }                                                                          \
  } while (0)

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_rep_set_array(root, dmn);

  oc_rep_object_array_begin_item(dmn);
  oc_rep_set_text_string(dmn, language, "en");
  oc_rep_set_text_string(dmn, value, manufacturer);
  oc_rep_object_array_end_item(dmn);

  oc_rep_close_array(root, dmn);
}

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, set_device_custom_property, NULL);
  if (ret || !deviceid) {
    return ret;
  }

  oc_device_info_t *info = oc_core_get_device_info(0);
  oc_str_to_uuid(deviceid, &info->di);
  return ret;
}

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
  pthread_mutex_lock(&app_sync_lock);
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    pthread_mutex_unlock(&app_sync_lock);
    return;
  }
  int ret = oc_cloud_refresh_token(ctx, cloud_refresh_token_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
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
  pthread_mutex_lock(&app_sync_lock);
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    pthread_mutex_unlock(&app_sync_lock);
    return;
  }
  int ret = oc_cloud_deregister(ctx, cloud_deregister_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
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
  pthread_mutex_lock(&app_sync_lock);
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    pthread_mutex_unlock(&app_sync_lock);
    return;
  }
  int ret = oc_cloud_logout(ctx, cloud_logout_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
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
  pthread_mutex_lock(&app_sync_lock);
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    pthread_mutex_unlock(&app_sync_lock);
    return;
  }
  int ret = oc_cloud_login(ctx, cloud_login_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
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
  pthread_mutex_lock(&app_sync_lock);
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    pthread_mutex_unlock(&app_sync_lock);
    return;
  }
  oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
  int ret = oc_cloud_register(ctx, cloud_register_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
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
  memset(addr, 0, sizeof(addr));
  SCANF("%255s", addr);
  char endpoint_string[267];
  memset(endpoint_string, 0, sizeof(addr));
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

struct switch_t
{
  bool state;
};

static struct switch_t bswitch = { false };

static void
get_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  struct switch_t *state = (struct switch_t *)user_data;
  OC_PRINTF("GET_switch:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, state->state);
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
  struct switch_t *s = (struct switch_t *)user_data;
  OC_PRINTF("POST_switch:\n");
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
    s->state = state;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, s->state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
register_resources(void)
{
  res1 = oc_new_resource(NULL, "/switch/1", 1, 0);
  oc_resource_bind_resource_type(res1, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res1, OC_IF_A);
  oc_resource_set_default_interface(res1, OC_IF_A);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_observable(res1, true);
  oc_resource_set_request_handler(res1, OC_GET, get_switch, &bswitch);
  oc_resource_set_request_handler(res1, OC_POST, post_switch, &bswitch);
  oc_cloud_add_resource(res1); /* Publish resource to the Cloud RD */
  oc_add_resource(res1);
}

static oc_resource_t *reg_resource = NULL;
static struct switch_t reg_bswitch = { false };

static void
add_resource(void)
{
  // clang-15 seems to have a bug in the analysis of the following code and
  // thinks that reg_resource can be set to NULL by the oc_resource_* functions
  // NOLINTBEGIN
  if (reg_resource != NULL) {
    return;
  }
  reg_resource = oc_new_resource(NULL, "/addDeleteResource", 1, 0);
  oc_resource_bind_resource_type(reg_resource, "oic.r.switch.binary");
  oc_resource_set_discoverable(reg_resource, true);
  oc_resource_set_observable(reg_resource, true);
  oc_resource_set_request_handler(reg_resource, OC_GET, get_switch,
                                  &reg_bswitch);
  oc_resource_set_request_handler(reg_resource, OC_POST, post_switch,
                                  &reg_bswitch);
  // NOLINTEND
  oc_add_resource(reg_resource);
  oc_cloud_add_resource(reg_resource); /* Publish resource to the Cloud RD */
}

static void
delete_resource(void)
{
  oc_cloud_delete_resource(reg_resource); /* Publish resource to the Cloud RD */
  oc_delete_resource(reg_resource);
  reg_resource = NULL;
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
  if (read_pem("pki_certs/ee.pem", cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  char key[4096];
  size_t key_len = 4096;
  if (read_pem("pki_certs/key.pem", key, &key_len) < 0) {
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
  if (read_pem("pki_certs/subca1.pem", cert, &cert_len) < 0) {
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
  if (read_pem("pki_certs/rootca1.pem", cert, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, ee_credid);
#endif /* OC_SECURITY && OC_PKI */
}

static void *
ocf_event_thread(void *data)
{
  (void)data;
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };

#ifdef OC_STORAGE
  oc_storage_config("./cloud_tests_creds");
#endif /* OC_STORAGE */

  oc_set_con_res_announced(false);
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
#ifdef OC_SECURITY
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY */
  oc_set_max_app_data_size(16384);
  if (oc_main_init(&handler) < 0) {
    return NULL;
  }

  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    pthread_mutex_lock(&app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_unlock(&app_sync_lock);

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
deinit(void)
{
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_sync_lock);
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_sync_lock, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_sync_lock);
    return false;
  }
  pthread_condattr_destroy(&attr);

  err = pthread_create(&event_thread, NULL, &ocf_event_thread, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_create failed (error=%d)!\n", err);
    deinit();
    return false;
  }
  return true;
}

int
main(int argc, char *argv[])
{
  if (argc > 1) {
    device_name = argv[1];
    OC_PRINTF("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    OC_PRINTF("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    OC_PRINTF("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    OC_PRINTF("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    OC_PRINTF("apn: %s\n", argv[5]);
  }
  if (argc > 6) {
    deviceid = argv[6];
    OC_PRINTF("deviceID: %s\n", argv[6]);
  }

  if (!init()) {
    return -1;
  }

  int c;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
    case 0:
      continue;
    case 1:
      cloud_register();
      break;
    case 2:
      cloud_login();
      break;
    case 3:
      cloud_logout();
      break;
    case 4:
      cloud_deregister();
      break;
    case 5:
      cloud_refresh_token();
      break;
    case 6:
      oc_cloud_publish_resources(0);
      break;
    case 7:
      cloud_send_ping();
      break;
    case 8:
      oc_cloud_delete_resource(res1);
      break;
    case 9:
      oc_cloud_add_resource(res1);
      break;
    case 10:
      add_resource();
      break;
    case 11:
      delete_resource();
      break;
    case 12:
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
