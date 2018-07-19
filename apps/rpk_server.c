/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_api.h"
#include "port/oc_clock.h"
#include "security/oc_doxm.h"
#include "security/oc_tls.h"
#include "security/oc_rpk.h"
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
post_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
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
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
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

#if defined(OC_SECURITY) && defined(OC_RPK)
void
get_cpubkey_and_token(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token,
                      int *token_len)
{
  if (!cpubkey || !cpubkey_len || !token || !token_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t key[32] = { 0x40, 0x71, 0x28, 0x53, 0xe7, 0x2e, 0xab, 0x64,
                      0xeb, 0x13, 0x24, 0x42, 0x84, 0x00, 0x24, 0x50,
                      0xcc, 0x74, 0x94, 0x21, 0x50, 0x2e, 0x89, 0x5d,
                      0x6c, 0x62, 0xea, 0x6e, 0x33, 0x77, 0x97, 0x41 };
  uint8_t tkn[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
  memcpy(cpubkey, key, 32);
  memcpy(token, tkn, 32);
  *cpubkey_len = 32;
  *token_len = 32;
  return;
}

void
get_own_key(uint8_t *priv_key, int *priv_key_len)
{
  if (!priv_key || !priv_key_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t prv[32] = { 0x28, 0x91, 0xcd, 0x69, 0xb2, 0xe9, 0xe9, 0x39,
                      0xb5, 0xa2, 0x8e, 0xcc, 0x64, 0x37, 0x6e, 0xf4,
                      0xf4, 0x59, 0xc7, 0x8a, 0xfc, 0x20, 0xb9, 0xaa,
                      0x63, 0xdc, 0x54, 0xf4, 0x56, 0x85, 0x70, 0x46 };
  memcpy(priv_key, prv, 32);
  *priv_key_len = 32;
  return;
}
#endif // OC_SECURITY && OC_RPK

int
main(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
#ifdef OC_MFG
  oc_storage_config("./mfgserver_creds");
#elif defined(OC_RPK)
  oc_storage_config("./rpkserver_creds");
#else
  oc_storage_config("./simpleserver_creds");
#endif
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

#ifdef OC_SECURITY
#ifdef OC_MFG
  oc_sec_doxm(0, OC_DOXM_MFG);
#elif defined(OC_RPK)
  oc_sec_doxm(0, OC_DOXM_RPK);
  oc_sec_set_cpubkey_and_token_load(get_cpubkey_and_token);
  oc_sec_set_own_key_load(get_own_key);
#else
  oc_sec_doxm(0, OC_DOXM_JW);
#endif /* OC_MFG */
#endif /* OC_SECURITY */

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
  oc_free_string(&name);
  oc_main_shutdown();
  return 0;
}
