/****************************************************************************
 *
 * Copyright 2020 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_pki.h"
#include <signal.h>
#include <inttypes.h>
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <pthread.h>
#endif
static int quit;

static void
display_menu(void)
{
  PRINT("\n\n################################################\nOCF 2.x "
        "Cloud-connected "
        "Client\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover resources\n");
  PRINT("[2] Issue GET request to resource\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
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
      PRINT("ERROR Invalid input\n");                                          \
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
#define otb_mutex_lock(m) pthread_mutex_lock(&m)
#define otb_mutex_unlock(m) pthread_mutex_unlock(&m)

static struct timespec ts;
#endif

static void
signal_event_loop(void)
{
#if defined(_WIN32)
  WakeConditionVariable(&cv);
#elif defined(__linux__)
  otb_mutex_lock(mutex);
  pthread_cond_signal(&cv);
  otb_mutex_unlock(mutex);
#endif
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
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
  PRINT("\nDiscovered resources:\n");
  resource_t *l = (resource_t *)oc_list_head(resources);
  int i = 0;
  PRINT("\n\n");
  while (l != NULL) {
    if (res != NULL) {
      res[i] = l;
    }
    PRINT("[%d]: %s", i, l->uri);
    oc_endpoint_t *ep = l->endpoint;
    while (ep != NULL) {
      PRINT("\n\t\t");
      PRINTipaddr(*ep);
      ep = ep->next;
    }
    PRINT("\n\n");
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
  PRINT("uri: %s\n", oc_string(cb->uri));
  PRINT("payload: %s\n", buf);
}

static void
get_resource(void)
{
  otb_mutex_lock(app_sync_lock);
  if (oc_list_length(resources) > 0) {
    resource_t *res[100];
    show_discovered_resources(res);
    PRINT("\n\nSelect resource: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(resources)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      oc_endpoint_t *ep = res[c]->endpoint;
      if (!oc_do_get(res[c]->uri, ep, NULL, GET_handler, HIGH_QOS, NULL)) {
        PRINT("\nERROR Could not issue GET request\n");
      }
    }
  } else {
    PRINT("\nERROR: No known resources... Please try discovery...\n");
  }
  otb_mutex_unlock(app_sync_lock);
  signal_event_loop();
}

static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  PRINT("\nCloud Manager Status:\n");
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
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
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
    int uri_len = (strlen(uri) >= 64) ? 63 : strlen(uri);
    memcpy(l->uri, uri, uri_len);
    l->uri[uri_len] = '\0';
    oc_list_add(resources, l);
  }

  if (!more) {
    PRINT(
      "\nDiscovered resources on the Cloud.. You may now issue requests...\n");
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
    PRINT("\n\nERROR: could not issue discovery request\nDevice not yet logged "
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
  if (pem_len > (long)*buffer_len) {
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
  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

#if defined(_WIN32)
DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = NULL,
                                        .requests_entry = NULL };
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
  oc_clock_time_t next_event;
  while (quit != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    otb_mutex_unlock(app_sync_lock);

    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
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
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = NULL,
                                        .requests_entry = NULL };
#ifdef OC_STORAGE
  oc_storage_config("./cloud_client_creds/");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_max_app_data_size(16384);
  int ret = oc_main_init(&handler);
  if (ret < 0)
    return NULL;
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx) {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    if (cis) {
      oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
    }
  }
  oc_clock_time_t next_event;
  while (quit != 1) {
    otb_mutex_lock(app_sync_lock);
    next_event = oc_main_poll();
    otb_mutex_unlock(app_sync_lock);

    otb_mutex_lock(mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    otb_mutex_unlock(mutex);
  }
  oc_main_shutdown();
  return NULL;
}
#endif

int
main(int argc, char *argv[])
{
  if (argc == 1) {
    PRINT("./cloud_client <device-name-without-spaces> <auth-code> <cis> <sid> "
          "<apn>\n");
#ifndef OC_SECURITY
    PRINT("Using default parameters: device_name: %s, auth_code: %s, cis: %s, "
          "sid: %s, "
          "apn: %s\n",
          device_name, auth_code, cis, sid, apn);
#endif /* !OC_SECURITY */
  }
  if (argc > 1) {
    device_name = argv[1];
    PRINT("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    PRINT("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    PRINT("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    PRINT("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    PRINT("apn: %s\n", argv[5]);
  }

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
#endif

#if defined(_WIN32)
  event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ocf_event_thread,
                              NULL, 0, NULL);
  if (NULL == event_thread) {
    return -1;
  }
#elif defined(__linux__)
  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }
#endif

  int c;
  while (quit != 1) {
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
  return 0;
}
