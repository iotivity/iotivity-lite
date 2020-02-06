/****************************************************************************
 *
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
#include "port/oc_clock.h"
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

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
int quit = 0;

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
    printf("Please discovery resource first!\n");
    return false;
  }

  return true;
}

static void
stop_observe(void)
{
  if (!is_resource_found())
    return;

  printf("Stopping OBSERVE\n");
  if (!oc_stop_observe(a_light, &target_ep)) {
    printf("Please observe start first!\n");
  }
}

static void send_ping(uint16_t timeout_seconds);

#ifdef OC_TCP
static void
pong_received_handler(oc_client_response_t *data)
{
  if (data->code == OC_PING_TIMEOUT) {
    printf("PING timeout!\n");
    ping_count++;
    if (ping_count > PING_RETRY_COUNT) {
      printf("retry over. close connection.\n");
      oc_connectivity_end_session(data->endpoint);
    } else {
      ping_timeout <<= 1;
      printf("PING send again.[retry: %zd, time: %u]\n", ping_count,
             ping_timeout);
      send_ping(ping_timeout);
    }
  } else {
    printf("PONG received:\n");
    PRINTipaddr(*data->endpoint);
    printf("\n");
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
      printf("oc_send_ping failed\n");
    }
  } else
#endif /* !OC_TCP */
  {
    printf("PING message is not supported\n");
  }
}

static void
parse_payload(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    printf("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      printf("%d\n", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      printf("%lld\n", rep->value.integer);
      power = (int)rep->value.integer;
      break;
    case OC_REP_STRING:
      printf("%s\n", oc_string(rep->value.string));
      if (oc_string_len(name))
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
    printf("OBSERVE register success!\n");
  }

  printf("OBSERVE_light:\n");
  parse_payload(data);
}

static void
observe_request(void)
{
  if (!is_resource_found())
    return;

  oc_do_observe(a_light, &target_ep, NULL, &observe_response, LOW_QOS, NULL);
  printf("Sent OBSERVE request\n");
}

static void
post_response(oc_client_response_t *data)
{
  printf("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    printf("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_CREATED)
    printf("POST response: CREATED\n");
  else
    printf("POST response code %d\n", data->code);
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
      printf("Sent POST request\n");
    else
      printf("Could not send POST request\n");
  } else
    printf("Could not init POST request\n");
}

static void
get_response(oc_client_response_t *data)
{
  printf("GET_light:\n");
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
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      printf("Resource %s hosted at endpoints:\n", a_light);
      if (user_data) {
        custom_func_s *custom = (custom_func_s *)user_data;
        custom->func(endpoint);
      } else {
        printf("custom function is not set!");
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
    PRINTipaddr(*ep);
    printf("\n");

    ep = ep->next;
  }
}

static void
find_same_endpoint(oc_endpoint_t *endpoint)
{
  oc_endpoint_t *ep = endpoint;
  while (ep != NULL) {
    PRINTipaddr(*ep);
    printf("\n");

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
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=====================================\n");
  printf("1. Discovery\n");
  printf("2. Discovery with endpoint(%s)\n", address);
  printf("3. Get request\n");
  printf("4. Post request\n");
  printf("5. Observe request\n");
  printf("6. Observe cancel request\n");
  printf("7. Send Ping\n");
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

int
main(void)
{
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  printf("set remote address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    printf("address: %s\n", address);
  } else {
    printf("error reading remote address\n");
    return -1;
  }

  oc_string_t address_str;
  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &set_ep, NULL) < 0) {
    printf("error parsing remote endpoint address\n");
    return -1;
  }
  set_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop =
                                          signal_event_loop };

#ifdef OC_STORAGE
  oc_storage_config("./client_multithread_linux_creds");
#endif /* OC_STORAGE */

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    pthread_mutex_destroy(&mutex);
    return -1;
  }

  init = oc_main_init(&handler);
  if (init < 0) {
    printf("oc_main_init failed!(%d)\n", init);
    goto exit;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    init = -1;
    goto exit;
  }

  custom_func_s first_func = { .func = find_first_endpoint };
  custom_func_s same_func = { .func = find_same_endpoint };

  int key;
  while (quit != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      printf("scanf failed!!!!\n");
      quit = 1;
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
      printf("Send PING\n");
      send_ping(ping_timeout);
      break;
    case 0:
      quit = 1;
      handle_signal(0);
      break;
    default:
      printf("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  printf("pthread_join finish!\n");

exit:
  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}
