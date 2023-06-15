/****************************************************************************
 *
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
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";
static const char *resource_rt = "core.light";
static const char *device_rt = "oic.d.phone";
static const char *device_name = "Galaxy";
static const char *manufacturer = "Samsung";

static pthread_mutex_t app_mutex;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static OC_ATOMIC_INT8_T quit = 0;

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t target_ep;
static bool resource_found = false;

static bool state;
static int power;
static oc_string_t name;

#define OC_IPV6_ADDRSTRLEN (59)
static char address[OC_IPV6_ADDRSTRLEN + 1];
static oc_endpoint_t set_ep;

#define PING_RETRY_COUNT (4)
static size_t ping_count = 0;
static uint16_t ping_timeout = 1;

typedef void (*custom_func_t)(oc_endpoint_t *);

typedef struct
{
  custom_func_t func;
} custom_func_s;

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

static bool
is_resource_found(void)
{
  if (!resource_found) {
    OC_PRINTF("Please discovery resource first!\n");
    return false;
  }

  return true;
}

static void
stop_observe(void)
{
  if (!is_resource_found())
    return;

  OC_PRINTF("Stopping OBSERVE\n");
  if (!oc_stop_observe(a_light, &target_ep)) {
    OC_PRINTF("Please observe start first!\n");
  }
}

static void send_ping(uint16_t timeout_seconds);

#ifdef OC_TCP
static void
pong_received_handler(oc_client_response_t *data)
{
  if (data->code == OC_PING_TIMEOUT) {
    OC_PRINTF("PING timeout!\n");
    ping_count++;
    if (ping_count > PING_RETRY_COUNT) {
      OC_PRINTF("retry over. close connection.\n");
      oc_connectivity_end_session(data->endpoint);
    } else {
      ping_timeout <<= 1;
      OC_PRINTF("PING send again.[retry: %zd, time: %u]\n", ping_count,
                ping_timeout);
      send_ping(ping_timeout);
    }
  } else {
    OC_PRINTF("PONG received:\n");
    OC_PRINTipaddr(*data->endpoint);
    OC_PRINTF("\n");
    ping_count = 0;
  }
}
#endif /* OC_TCP */

static void
send_ping(uint16_t timeout_seconds)
{
  (void)timeout_seconds;
  if (!is_resource_found())
    return;

#ifdef OC_TCP
  if (target_ep.flags & TCP) {
    if (!oc_send_ping(0, &target_ep, timeout_seconds, pong_received_handler,
                      NULL)) {
      OC_PRINTF("oc_send_ping failed\n");
    }
  } else
#endif /* !OC_TCP */
  {
    OC_PRINTF("PING message is not supported\n");
  }
}

static void
parse_payload(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PRINTF("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_PRINTF("%" PRId64 "\n", rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_PRINTF("%s\n", oc_string(rep->value.string));
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static void
observe_response(oc_client_response_t *data)
{
  if (data->observe_option == 0) {
    OC_PRINTF("OBSERVE register success!\n");
  }

  OC_PRINTF("OBSERVE_light:\n");
  parse_payload(data);
}

static void
observe_request(void)
{
  if (!is_resource_found())
    return;

  oc_do_observe(a_light, &target_ep, NULL, &observe_response, LOW_QOS, NULL);
  OC_PRINTF("Sent OBSERVE request\n");
}

static void
post_response(oc_client_response_t *data)
{
  OC_PRINTF("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    OC_PRINTF("POST response: CREATED\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);
}

static void
post_request(void)
{
  if (!is_resource_found())
    return;

  if (oc_init_post(a_light, &target_ep, NULL, &post_response, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, false);
    oc_rep_set_int(root, power, 105);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST request\n");
  } else
    OC_PRINTF("Could not init POST request\n");
}

static void
get_response(oc_client_response_t *data)
{
  OC_PRINTF("GET_light:\n");
  parse_payload(data);
}

static void
get_request(void)
{
  if (!is_resource_found())
    return;

  oc_do_get(a_light, &target_ep, NULL, &get_response, LOW_QOS, NULL);
}

static oc_discovery_flags_t
discovery_handler(const char *anchor, const char *uri, oc_string_array_t types,
                  oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
                  oc_resource_properties_t bm, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;

  (void)anchor;
  (void)iface_mask;
  (void)bm;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      OC_PRINTF("Resource %s hosted at endpoints:\n", a_light);
      if (user_data) {
        custom_func_s *custom = (custom_func_s *)user_data;
        custom->func(endpoint);
      } else {
        OC_PRINTF("custom function is not set!");
        goto exit;
      }

      ret = OC_STOP_DISCOVERY;
      goto exit;
    }
  }

exit:
  return ret;
}

static void
find_first_endpoint(oc_endpoint_t *endpoint)
{
  oc_endpoint_t *ep = endpoint;
  memcpy(&target_ep, ep, sizeof(oc_endpoint_t));
  resource_found = true;
  while (ep != NULL) {
    OC_PRINTipaddr(*ep);
    OC_PRINTF("\n");

    ep = ep->next;
  }
}

static void
find_same_endpoint(oc_endpoint_t *endpoint)
{
  oc_endpoint_t *ep = endpoint;
  while (ep != NULL) {
    OC_PRINTipaddr(*ep);
    OC_PRINTF("\n");

    if (oc_endpoint_compare(&set_ep, ep) == 0) {
      memcpy(&target_ep, ep, sizeof(oc_endpoint_t));
      resource_found = true;
    }

    ep = ep->next;
  }
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

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

static void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  OC_PRINTF("=====================================\n");
  OC_PRINTF("1. Discovery\n");
  OC_PRINTF("2. Discovery with endpoint(%s)\n", address);
  OC_PRINTF("3. Get request\n");
  OC_PRINTF("4. Post request\n");
  OC_PRINTF("5. Observe request\n");
  OC_PRINTF("6. Observe cancel request\n");
  OC_PRINTF("7. Send Ping\n");
  OC_PRINTF("0. Quit\n");
  OC_PRINTF("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
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
  pthread_mutex_destroy(&app_mutex);
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  OC_PRINTF("set remote address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    OC_PRINTF("address: %s\n", address);
  } else {
    OC_PRINTF("error reading remote address\n");
    deinit();
    return -1;
  }

  oc_string_t address_str;
  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &set_ep, NULL) < 0) {
    OC_PRINTF("error parsing remote endpoint address\n");
    deinit();
    return -1;
  }
  set_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
  };

#ifdef OC_STORAGE
  oc_storage_config("./client_multithread_linux_creds");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    OC_PRINTF("oc_main_init failed!(%d)\n", ret);
    deinit();
    return -1;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    OC_PRINTF("Failed to create main thread\n");
    ret = -1;
    goto exit;
  }

  custom_func_s first_func = { .func = find_first_endpoint };
  custom_func_s same_func = { .func = find_same_endpoint };

  int key;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      OC_PRINTF("scanf failed!!!!\n");
      handle_signal(0);
      break;
    }

    pthread_mutex_lock(&app_mutex);
    switch (key) {
    case 1:
      resource_found = false;
      oc_do_ip_discovery(resource_rt, &discovery_handler, &first_func);
      break;
    case 2:
      resource_found = false;
      oc_do_ip_discovery_at_endpoint(resource_rt, &discovery_handler, &set_ep,
                                     &same_func);
      break;
    case 3:
      get_request();
      break;
    case 4:
      post_request();
      break;
    case 5:
      observe_request();
      break;
    case 6:
      stop_observe();
      break;
    case 7:
      ping_count = 0;
      ping_timeout = 1;
      OC_PRINTF("Send PING\n");
      send_ping(ping_timeout);
      break;
    case 0:
      handle_signal(0);
      break;
    default:
      OC_PRINTF("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  OC_PRINTF("pthread_join finish!\n");

exit:
  oc_main_shutdown();
  deinit();
  return ret;
}
