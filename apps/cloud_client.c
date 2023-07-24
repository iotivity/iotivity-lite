/****************************************************************************
 *
 * Copyright 2020 Intel Corporation
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
#include "oc_log.h"
#include "oc_pki.h"
#include "util/oc_atomic.h"

#include <inttypes.h>
#include <signal.h>
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <pthread.h>
#endif /* _WIN32 */

static OC_ATOMIC_INT8_T quit = 0;

static void
display_menu(void)
{
  OC_PRINTF("\n\n################################################\nOCF 2.x "
            "Cloud-connected "
            "Client\n################################################\n");
  OC_PRINTF("[0] Display this menu\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[1] Discover resources\n");
  OC_PRINTF("[2] Issue GET request to resource\n");
  OC_PRINTF("-----------------------------------------------\n");
  OC_PRINTF("[99] Exit\n");
  OC_PRINTF("################################################\n");
  OC_PRINTF("\nSelect option: \n");
}

// define application specific values.
static const char *spec_version = "ocf.2.0.5";
static const char *data_model_version = "ocf.res.1.3.0";

static const char *device_rt = "oic.d.cloudDevice";
static const char *device_name = "CloudClient";

static const char *manufacturer = "ocfcloud.com";

#ifdef OC_SECURITY
static const char *cis;
static const char *auth_code;
static const char *sid;
static const char *apn;
#else  /* OC_SECURITY */
static const char *cis = "coap+tcp://127.0.0.1:5683";
static const char *auth_code = "test";
static const char *sid = "00000000-0000-0000-0000-000000000001";
static const char *apn = "test";
#endif /* OC_SECURITY */

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      OC_PRINTF("ERROR Invalid input\n");                                      \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

#if defined(_WIN32)
static HANDLE event_thread;
static CRITICAL_SECTION app_sync_lock;
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

/* OS specific definition for lock/unlock */
#define otb_mutex_lock(m) EnterCriticalSection(&m)
#define otb_mutex_unlock(m) LeaveCriticalSection(&m)

#elif defined(__linux__)
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

/* OS specific definition for lock/unlock */
#define otb_mutex_lock(m) pthread_mutex_lock(&(m))
#define otb_mutex_unlock(m) pthread_mutex_unlock(&(m))

#endif /* _WIN32 */

static void
signal_event_loop(void)
{
#if defined(_WIN32)
  WakeConditionVariable(&cv);
#elif defined(__linux__)
  pthread_cond_signal(&cv);
#endif
}

static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

typedef struct resource_t
{
  struct resource_t *next;
  oc_endpoint_t *endpoint;
  char uri[64];
} resource_t;

OC_LIST(resources);
OC_MEMB(resources_m, resource_t, 100);

static void
free_resource(resource_t *res)
{
  oc_free_server_endpoints(res->endpoint);
  oc_memb_free(&resources_m, res);
}

static void
free_all_resources(void)
{
  resource_t *l = (resource_t *)oc_list_pop(resources);
  while (l != NULL) {
    free_resource(l);
    l = (resource_t *)oc_list_pop(resources);
  }
}

static void
show_discovered_resources(resource_t **res)
{
  OC_PRINTF("\nDiscovered resources:\n");
  resource_t *l = (resource_t *)oc_list_head(resources);
  int i = 0;
  OC_PRINTF("\n\n");
  while (l != NULL) {
    if (res != NULL) {
      res[i] = l;
    }
    OC_PRINTF("[%d]: %s", i, l->uri);
    oc_endpoint_t *ep = l->endpoint;
    while (ep != NULL) {
      OC_PRINTF("\n\t\t");
      OC_PRINTipaddr(*ep);
      ep = ep->next;
    }
    OC_PRINTF("\n\n");
    i++;
    l = l->next;
  }
}

static void
GET_handler(oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return;
  }

  char buf[4096];
  oc_rep_to_json(data->payload, buf, 4096, true);
  oc_client_cb_t *cb = (oc_client_cb_t *)data->client_cb;
  OC_PRINTF("uri: %s\n", oc_string(cb->uri));
  OC_PRINTF("payload: %s\n", buf);
}

static void
get_resource(void)
{
  otb_mutex_lock(app_sync_lock);
  if (oc_list_length(resources) > 0) {
    resource_t *res[100];
    show_discovered_resources(res);
    OC_PRINTF("\n\nSelect resource: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(resources)) {
      OC_PRINTF("\nERROR: Invalid selection.. Try again..\n");
    } else {
      oc_endpoint_t *ep = res[c]->endpoint;
      if (!oc_do_get(res[c]->uri, ep, NULL, GET_handler, HIGH_QOS, NULL)) {
        OC_PRINTF("\nERROR Could not issue GET request\n");
      }
    }
  } else {
    OC_PRINTF("\nERROR: No known resources... Please try discovery...\n");
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Manager Status:\n");
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

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, bool more, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  (void)types;
  (void)endpoint;
  resource_t *l = (resource_t *)oc_memb_alloc(&resources_m);
  if (l) {
    oc_endpoint_list_copy(&l->endpoint, endpoint);
    size_t uri_len = strlen(uri);
    uri_len = uri_len > sizeof(l->uri) - 1 ? sizeof(l->uri) - 1 : uri_len;
    memcpy(l->uri, uri, uri_len);
    l->uri[uri_len] = '\0';
    oc_list_add(resources, l);
  }

  if (!more) {
    OC_PRINTF("\nDiscovered resources on the Cloud.. You may now issue "
              "requests...\n");
    display_menu();
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
discover_resources(void)
{
  otb_mutex_lock(app_sync_lock);
  free_all_resources();
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx || oc_cloud_discover_resources(ctx, discovery, NULL) != 0) {
    OC_PRINTF(
      "\n\nERROR: could not issue discovery request\nDevice not yet logged "
      "into OCF Cloud\n");
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

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
  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

#if defined(_WIN32)
static DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
  (void)lpParam;
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = NULL,
    .requests_entry = NULL,
  };
#ifdef OC_STORAGE
  oc_storage_config("./cloud_client_creds/");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_max_app_data_size(16384);
  int ret = oc_main_init(&handler);
  if (ret < 0)
    return TRUE;

  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx) {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    if (cis) {
      oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
    }
  }
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    otb_mutex_unlock(app_sync_lock);

    if (next_event_mt == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now_mt = oc_clock_time_monotonic();
      if (now_mt < next_event_mt) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }

  oc_main_shutdown();
  return TRUE;
}
#elif defined(__linux__)
static void *
ocf_event_thread(void *data)
{
  (void)data;
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = NULL,
    .requests_entry = NULL,
  };
#ifdef OC_STORAGE
  oc_storage_config("./cloud_client_creds/");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_max_app_data_size(16384);
  int ret = oc_main_init(&handler);
  if (ret < 0) {
    return NULL;
  }
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx) {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    if (cis) {
      oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
    }
  }
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event_mt = oc_main_poll_v1();
    otb_mutex_unlock(app_sync_lock);

    otb_mutex_lock(mutex);
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
    otb_mutex_unlock(mutex);
  }
  oc_main_shutdown();
  return NULL;
}
#endif

static void
deinit(void)
{
#if defined(__linux__)
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_sync_lock);
#endif /* __linux__ */
}

static bool
init(void)
{
#if defined(_WIN32)
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  InitializeCriticalSection(&app_sync_lock);
#elif defined(__linux__)
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
    pthread_mutex_destroy(&mutex);
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
#endif /* _WIN32 */

#if defined(_WIN32)
  event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ocf_event_thread,
                              NULL, 0, NULL);
  if (NULL == event_thread) {
    OC_PRINTF("ERROR: CreateThread failed!\n");
    deinit();
    return false;
  }
#elif defined(__linux__)
  err = pthread_create(&event_thread, NULL, &ocf_event_thread, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_create failed (error=%d)!\n", err);
    deinit();
    return false;
  }
#endif /* _WIN32 */
  return true;
}

int
main(int argc, char *argv[])
{
  if (argc == 1) {
    OC_PRINTF(
      "./cloud_client <device-name-without-spaces> <auth-code> <cis> <sid> "
      "<apn>\n");
#ifndef OC_SECURITY
    OC_PRINTF(
      "Using default parameters: device_name: %s, auth_code: %s, cis: %s, "
      "sid: %s, "
      "apn: %s\n",
      device_name, auth_code, cis, sid, apn);
#endif /* !OC_SECURITY */
  }
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
      break;
    case 1:
      discover_resources();
      break;
    case 2:
      get_resource();
      break;
    case 99:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

#if defined(_WIN32)
  WaitForSingleObject(event_thread, INFINITE);
#elif defined(__linux__)
  pthread_join(event_thread, NULL);
#endif
  free_all_resources();
  deinit();
  return 0;
}
