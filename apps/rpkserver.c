/*
// Copyright (c) 2016 Intel Corporation
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
#include "security/oc_doxm.h"
#include "security/oc_cred.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;

static bool state = false;
int power;
oc_string_t name;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  oc_new_string(&name, "John's Light", 12);
  return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  ++power;

  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  PRINT("POST_light:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      break;
    case OC_REP_INT:
      power = rep->value.integer;
      PRINT("value: %d\n", power);
      break;
    case OC_REP_STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;
  post_light(request, interface, user_data);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource(NULL, "/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_type(res, "core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);
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

void
get_cpubkey_and_token(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token, int *token_len)
{
  if (!cpubkey || !cpubkey_len || !token || !token_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t key[32] = {0x5e, 0x7d, 0xad, 0x29, 0x87, 0x87, 0x5f, 0x42,
                     0x06, 0x0f, 0x37, 0xd4, 0x32, 0x1a, 0xe8, 0xae,
                     0xb0, 0xed, 0x6c, 0x61, 0xb9, 0x21, 0xba, 0x84,
                     0x43, 0x1d, 0x2f, 0x13, 0x07, 0xaa, 0x95, 0xe4
                    };
  uint8_t tkn[8] = "12345678";
  memcpy(cpubkey, key, 32);
  memcpy(token, tkn, 8);
  *cpubkey_len = 32;
  *token_len = 8;
  return;
}

void
get_own_key(uint8_t *priv_key, int *priv_key_len, uint8_t *pub_key, int *pub_key_len)
{
  if (!priv_key || !priv_key_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t prv[32] = {0x50, 0x08, 0xd9, 0xa8, 0x13, 0xb4, 0x2a, 0xc4,
                     0x22, 0xc0, 0xf3, 0xcc, 0xbf, 0x98, 0xf6, 0xb7,
                     0x33, 0xdc, 0x2f, 0xff, 0x58, 0xde, 0xd9, 0x3e,
                     0x84, 0xe0, 0x17, 0x28, 0x63, 0xd6, 0xbb, 0x30
                    };
  uint8_t pub[32] = {0x63, 0x8f, 0x9d, 0x81, 0xba, 0x7d, 0xac, 0xc2,
                     0x43, 0x28, 0xb9, 0x84, 0x8f, 0x26, 0xe8, 0x0e,
                     0x4d, 0x46, 0x3f, 0x6f, 0x92, 0x9c, 0x1e, 0x59,
                     0x0f, 0x38, 0xcd, 0xed, 0x5e, 0xb3, 0xe1, 0x52
                    };
  memcpy(priv_key, prv, 32);
  memcpy(pub_key, pub, 32);
  *priv_key_len = 32;
  *pub_key_len = 32;
  return;
}

int
main(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources =
                                         register_resources };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./rpkserver_creds");
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  oc_sec_doxm_rpk(0);
  oc_sec_set_cpubkey_and_token_cb(get_cpubkey_and_token);
  oc_sec_set_own_key_cb(get_own_key);

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

  oc_main_shutdown();
  return 0;
}
