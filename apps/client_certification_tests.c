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
#include "oc_swupdate.h"
#include "port/oc_clock.h"
#include "oc_pki.h"
#include "oc_introspection.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static const size_t DEVICE = 0;

static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;

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

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.wk.d", "OCFTestClient", "ocf.2.2.0",
                       "ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);

#if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read client_certification_tests_IDD.cbor\n"
    "\tIntrospection data not set for device.\n";
  fp = fopen("./client_certification_tests_IDD.cbor", "rb");
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

  return ret;
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) != 1) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
    }                                                                          \
  } while (0)

static void
display_menu(void)
{
  PRINT("\n\n################################################\nClient "
        "Certification Tests"
        "\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Discover resources\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[2] GET resource UDP\n");
  PRINT("[3] GET resource TCP\n");
  PRINT("[4] POST binary switch UDP\n");
  PRINT("[5] POST binary switch TCP\n");
  PRINT("[6] Start OBSERVE resource UDP\n");
  PRINT("[7] Stop OBSERVE resource UDP\n");
  PRINT("[8] Start OBSERVE resource TCP\n");
  PRINT("[9] Stop OBSERVE resource TCP\n");
  PRINT("-----------------------------------------------\n");
#ifdef OC_TCP
  PRINT("[20] Send ping message\n");
  PRINT("-----------------------------------------------\n");
#endif /* OC_TCP */
  PRINT("[99] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

#ifdef OC_SOFTWARE_UPDATE
int
validate_purl(const char *purl)
{
  (void) purl;
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

static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_sync_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_sync_lock);

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

static void
POST_handler(oc_client_response_t *data)
{
  PRINT("POST_handler:\n");
  if (data->code == OC_STATUS_CHANGED) {
    PRINT("POST response OK\n");
  } else {
    PRINT("POST response code %d\n", data->code);
  }

  char buf[4096];
  oc_rep_to_json(data->payload, buf, 4096, true);
  oc_client_cb_t *cb = (oc_client_cb_t *)data->client_cb;
  PRINT("uri: %s\n", oc_string(cb->uri));
  PRINT("query: %s\n", oc_string(cb->query));
  PRINT("payload: %s\n", buf);
  display_menu();
}

static void
GET_handler(oc_client_response_t *data)
{
  PRINT("GET_handler:\n");
  char buf[4096];
  oc_rep_to_json(data->payload, buf, 4096, true);
  oc_client_cb_t *cb = (oc_client_cb_t *)data->client_cb;
  PRINT("uri: %s\n", oc_string(cb->uri));
  PRINT("query: %s\n", oc_string(cb->query));
  PRINT("payload: %s\n", buf);

  display_menu();
}

#ifdef OC_TCP
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
  pthread_mutex_lock(&app_sync_lock);
  if (oc_send_ping(false, &endpoint, 10, ping_handler, NULL)) {
    PRINT("\nSuccessfully issued Ping request\n");
  } else {
    PRINT("\nERROR issuing Ping request\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}
#endif /* OC_TCP */

static void
get_resource(bool tcp, bool observe)
{
  pthread_mutex_lock(&app_sync_lock);
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
      while (ep && (tcp && !(ep->flags & TCP))) {
        ep = ep->next;
      }
      if (observe) {
        if (!oc_do_observe(res[c]->uri, ep, NULL, GET_handler, HIGH_QOS,
                           NULL)) {
          PRINT("\nERROR: Could not issue Observe request\n");
        }
      } else {
        if (!oc_do_get(res[c]->uri, ep, NULL, GET_handler, HIGH_QOS, NULL)) {
          PRINT("\nERROR Could not issue GET request\n");
        }
      }
    }
  } else {
    PRINT("\nERROR: No known resources... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
stop_observe_resource(bool tcp)
{
  pthread_mutex_lock(&app_sync_lock);
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
      while (ep && (tcp && !(ep->flags & TCP))) {
        ep = ep->next;
      }
      oc_stop_observe(res[c]->uri, ep);
    }
  } else {
    PRINT("\nERROR: No known resources... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static void
post_resource(bool tcp)
{
  pthread_mutex_lock(&app_sync_lock);
  if (oc_list_length(resources) > 0) {
    resource_t *res[100];
    show_discovered_resources(res);
    PRINT("\n\nSelect resource: ");
    int c;
    SCANF("%d", &c);
    if (c < 0 || c > oc_list_length(resources)) {
      PRINT("\nERROR: Invalid selection.. Try again..\n");
    } else {
      int s;
      PRINT("Select siwtch value:\n[0]: true\n[1]: false\n\nSelect: ");
      SCANF("%d", &s);
      if (s < 0 || s > 1) {
        PRINT("\nERROR: Invalid selection.. Try again..\n");
      } else {
        oc_endpoint_t *ep = res[c]->endpoint;
        while (ep && (tcp && !(ep->flags & TCP))) {
          ep = ep->next;
        }
        if (oc_init_post(res[c]->uri, ep, NULL, &POST_handler, HIGH_QOS,
                         NULL)) {
          oc_rep_start_root_object();
          if (s == 0) {
            oc_rep_set_boolean(root, value, true);
          } else {
            oc_rep_set_boolean(root, value, false);
          }
          oc_rep_end_root_object();
          if (!oc_do_post()) {
            PRINT("\nERROR: Could not issue POST request\n");
          }
        } else {
          PRINT("\nERROR: Could not initialize POST request\n");
        }
      }
    }
  } else {
    PRINT("\nERROR: No known locks... Please try discovery...\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
}

static oc_discovery_flags_t
discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, bool more, void *user_data)
{
  (void)di;
  (void)iface_mask;
  (void)user_data;
  (void)uri;
  (void)types;
  (void)bm;

  resource_t *l = (resource_t *)oc_memb_alloc(&resources_m);
  if (l) {
    oc_endpoint_list_copy(&l->endpoint, endpoint);
    int uri_len = (strlen(uri) >= 64) ? 63 : strlen(uri);
    memcpy(l->uri, uri, uri_len);
    l->uri[uri_len] = '\0';
    oc_list_add(resources, l);
  }

  if (!more) {
    PRINT("\nDiscovered new device.. You may now issue requests...\n");
    display_menu();
  }

  return OC_CONTINUE_DISCOVERY;
}

static oc_discovery_flags_t
null_discovery(const char *di, const char *uri, oc_string_array_t types,
               oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
               oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)iface_mask;
  (void)user_data;
  (void)uri;
  (void)types;
  (void)endpoint;
  (void)bm;

  return OC_STOP_DISCOVERY;
}

static void
issue_requests(void)
{
  if (!oc_do_ip_discovery(NULL, &null_discovery, NULL)) {
    PRINT("\nERROR: Could not issue discovery request\n");
  }
}

static void
discover_resources(void)
{
  pthread_mutex_lock(&app_sync_lock);
  free_all_resources();
  if (!oc_do_ip_discovery_all(&discovery, NULL)) {
    PRINT("\nERROR: Could not issue discovery request\n");
  }
  pthread_mutex_unlock(&app_sync_lock);
  signal_event_loop();
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
  if (read_pem("pki_certs/certification_tests_ee.pem", cert, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  char key[4096];
  size_t key_len = 4096;
  if (read_pem("pki_certs/certification_tests_key.pem", key, &key_len) < 0) {
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
  if (read_pem("pki_certs/certification_tests_subca1.pem", cert, &cert_len) <
      0) {
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
  if (read_pem("pki_certs/certification_tests_rootca1.pem", cert, &cert_len) <
      0) {
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

  int init;

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .requests_entry = issue_requests };

  oc_set_con_res_announced(true);
#ifdef OC_STORAGE
  oc_storage_config("./client_certification_tests_creds");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
#ifdef OC_SECURITY
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif
#ifdef OC_SOFTWARE_UPDATE
  static oc_swupdate_cb_t swupdate_impl;
  swupdate_impl.validate_purl = validate_purl;
  swupdate_impl.check_new_version = check_new_version;
  swupdate_impl.download_update = download_update;
  swupdate_impl.perform_upgrade = perform_upgrade;
  oc_swupdate_set_impl(&swupdate_impl);
#endif /* OC_SOFTWARE_UPDATE */

  oc_set_max_app_data_size(32768);
  init = oc_main_init(&handler);
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
      break;
    case 1:
      discover_resources();
      break;
    case 2:
      get_resource(false, false);
      break;
    case 3:
      get_resource(true, false);
      break;
    case 4:
      post_resource(false);
      break;
    case 5:
      post_resource(true);
      break;
    case 6:
      get_resource(false, true);
      break;
    case 7:
      stop_observe_resource(false);
      break;
    case 8:
      get_resource(true, true);
      break;
    case 9:
      stop_observe_resource(true);
      break;
#ifdef OC_TCP
    case 20:
      cloud_send_ping();
      break;
#endif /* OC_TCP */
    case 99:
      handle_signal(0);
      break;
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);
  free_all_resources();
  return 0;
}
