/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "RIHelper.h"

RIHelper *RIHelper::s_riHelperInstance = NULL;
oc_handler_t RIHelper::s_handler;

bool RIHelper::s_isDiscoverResourceSucessfull = false;
bool RIHelper::s_isObserveResourceSuccessfull = false;
bool RIHelper::s_isRequestSucessfull = false;
bool RIHelper::s_lightState = false;
int RIHelper::s_generalQuit = 0;
oc_resource_t *RIHelper::s_pResource = NULL;
oc_endpoint_t *RIHelper::s_pLightEndpoint = NULL;
oc_string_t RIHelper::s_lightName;

pthread_mutex_t RIHelper::s_mutex;
pthread_cond_t RIHelper::s_cv;
struct timespec RIHelper::s_ts;

char RIHelper::s_lightUri[MAX_URI_LENGTH];

RIHelper::RIHelper() {}

RIHelper::~RIHelper() {}

RIHelper *
RIHelper::getInstance(void)
{
  if (s_riHelperInstance == NULL) {
    if (s_riHelperInstance == NULL) {
      s_riHelperInstance = new RIHelper();
    }
  }
  return s_riHelperInstance;
}

int
RIHelper::createResource()
{
  OC_PRINTF("createResource\n");
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handleSignalCb;
  sigaction(SIGINT, &sa, NULL);

  s_handler.init = appInitCb;
  s_handler.signal_event_loop = signalEventLoopCb;
  s_handler.register_resources = registerResourcesCb;
  s_handler.requests_entry = issueRequestsCb;

  oc_set_con_res_announced(false);

  init = oc_main_init(&s_handler);

  return init;
}
int
RIHelper::waitForEvent()
{
  while (s_generalQuit != 1) {
    OC_PRINTF("waitforevent\n");
    oc_main_poll();
    sleep(1);
  }
}

int
RIHelper::initServer()
{
  OC_PRINTF("initServer\n");
  int ret = 0;
  s_handler.init = appInitCb;
  s_handler.signal_event_loop = signalEventLoopCb;
  s_handler.register_resources = registerEmptyResourcesCb;

  ret = oc_main_init(&s_handler);
  return ret;
}

int
RIHelper::initClient()
{
  OC_PRINTF("initClient\n");
  int ret = 0;
  s_handler.init = appInitCb;
  s_handler.signal_event_loop = signalEventLoopCb;
  s_handler.requests_entry = issueRequestsCb;
  ret = oc_main_init(&s_handler);

  return ret;
}

int
RIHelper::appInitCb(void)
{
  OC_PRINTF("appInitCb\n");

  int ret = oc_init_platform(MANUFACTURE_NAME, NULL, NULL);
  ret |= oc_add_device(DEVICE_URI_LIGHT, DEVICE_TYPE_LIGHT, DEVICE_NAME_LIGHT,
                       OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
  return ret;
}

int
RIHelper::appEmptyInitCb(void)
{
  OC_PRINTF("appEmptyInitCb\n");
  return 1;
}
void
RIHelper::issueEmptyRequestsCb(void)
{
  OC_PRINTF("issueEmptyRequestsCb\n");
}

void
RIHelper::registerEmptyResourcesCb(void)
{
  OC_PRINTF("registerEmptyResourcesCb\n");
}

void
RIHelper::signalEventLoopCb(void)
{
  OC_PRINTF("signalEventLoopCb\n");
  pthread_cond_signal(&s_cv);
}

void
RIHelper::issueRequestsCb(void)
{
  OC_PRINTF("issueRequestsCb\n");
}

void
RIHelper::registerResourcesCb(void)
{
  OC_PRINTF("registerResourcesCb\n");

  s_pResource = oc_new_resource(NULL, RESOURCE_URI_LIGHT, 2, 0);
  oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_LIGHT);
  oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_BRIGHT_LIGHT);
  oc_resource_bind_resource_interface(s_pResource, OC_IF_RW);
  oc_resource_set_default_interface(s_pResource, OC_IF_RW);
  oc_resource_set_discoverable(s_pResource, true);
  oc_resource_set_periodic_observable(s_pResource, 1);
  oc_resource_set_request_handler(s_pResource, OC_GET, getLightCb, NULL);
  oc_resource_set_request_handler(s_pResource, OC_PUT, putLightCb, NULL);
  oc_resource_set_request_handler(s_pResource, OC_POST, postLightCb, NULL);
  oc_add_resource(s_pResource);
}
void
RIHelper::unRegisterResources(void)
{
  OC_PRINTF("unRegisterResources\n");
  oc_delete_resource(s_pResource);
  s_pResource = NULL;
}

void
RIHelper::shutDown()
{
  OC_PRINTF("shutDown:\n");
  oc_main_shutdown();
}

void
RIHelper::getLightCb(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
  OC_PRINTF("getLightCb:\n");
  (void)user_data;
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, s_lightState);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  OC_PRINTF("Light state %d\n", s_lightState);
}

void
RIHelper::postLightCb(oc_request_t *request, oc_interface_mask_t interface,
                      void *user_data)
{
  OC_PRINTF("postLightCb:\n");
  (void)interface;
  (void)user_data;
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      OC_PRINTF("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  s_lightState = state;
}

void
RIHelper::putLightCb(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
  postLightCb(request, interface, user_data);
}

/** Client Side **/

oc_event_callback_retval_t
RIHelper::stopObserveClientCb(void *data)
{
  (void)data;
  OC_PRINTF("stopObserveClientCb\n");
  oc_stop_observe(s_lightUri, s_pLightEndpoint);
  s_generalQuit = 1;
  return OC_EVENT_DONE;
}

void
RIHelper::observeLightCb(oc_client_response_t *data)
{
  OC_PRINTF("observeLightCb\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_PRINTF("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PRINTF("%d\n", rep->value.boolean);
      s_lightState = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  s_isObserveResourceSuccessfull = true;
}

void
RIHelper::getLightClientCb(oc_client_response_t *data)
{
  OC_PRINTF("getLightClientCb\n");
  (void)data;
  s_isRequestSucessfull = true;
  s_generalQuit = 1;
}

void
RIHelper::postLightClientCb(oc_client_response_t *data)
{
  OC_PRINTF("postLightClientCb:\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("POST response OK\n");
  else
    OC_PRINTF("POST response code %d\n", data->code);
  s_isRequestSucessfull = true;
  s_generalQuit = 1;
}

void
RIHelper::putLightClientCb(oc_client_response_t *data)
{
  OC_PRINTF("putLightClientCb\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("PUT response OK\n");
  else
    OC_PRINTF("PUT response code %d\n", data->code);
  s_isRequestSucessfull = true;
  s_generalQuit = 1;
}

void
RIHelper::deleteLightClientCb(oc_client_response_t *data)
{
  OC_PRINTF("deleteLightClientCb\n");
  if (data->code == OC_STATUS_CHANGED)
    OC_PRINTF("DELETE response OK\n");
  else
    OC_PRINTF("DELETE response code %d\n", data->code);
  s_isRequestSucessfull = true;
  s_generalQuit = 1;
}

oc_discovery_flags_t
RIHelper::discovery(const char *di, const char *uri, oc_string_array_t types,
                    oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
                    oc_resource_properties_t bm, void *user_data)
{
  (void)di;
  (void)interfaces;
  (void)user_data;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  OC_PRINTF("discovery: %s\n", uri);
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, RESOURCE_TYPE_LIGHT, 10) == 0) {
      strncpy(s_lightUri, uri, uri_len);
      s_lightUri[uri_len] = '\0';
      s_pLightEndpoint = endpoint;

      OC_PRINTF("Resource %s hosted at endpoints:\n", s_lightUri);
      s_generalQuit = 1;
      s_isDiscoverResourceSucessfull = true;
      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

void
RIHelper::discoverResource()
{
  OC_PRINTF("discoverResource:\n");
  s_generalQuit = 0;
  oc_do_ip_discovery(NULL, &discovery, NULL);
}

void
RIHelper::getResource()
{
  OC_PRINTF("getResource:\n");
  s_generalQuit = 0;
  s_isRequestSucessfull = false;
  oc_do_get(s_lightUri, s_pLightEndpoint, NULL, &getLightClientCb, LOW_QOS,
            NULL);
}

void
RIHelper::deleteResource()
{
  OC_PRINTF("deleteResource:\n");
  s_generalQuit = 0;
  s_isRequestSucessfull = false;
  oc_do_delete(s_lightUri, s_pLightEndpoint, NULL, &deleteLightClientCb,
               LOW_QOS, NULL);
}
void
RIHelper::postRequestResource()
{
  OC_PRINTF("postRequestResource:\n");
  s_generalQuit = 0;
  s_isRequestSucessfull = false;
  if (oc_init_post(s_lightUri, s_pLightEndpoint, NULL, &postLightClientCb,
                   LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !s_lightState);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST\n");
  } else
    OC_PRINTF("Could not init POST\n");
}

void
RIHelper::putRequestResource()
{
  OC_PRINTF("putRequestResource:\n");
  s_generalQuit = 0;
  s_isRequestSucessfull = false;
  if (oc_init_put(s_lightUri, s_pLightEndpoint, NULL, &putLightClientCb,
                  LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !s_lightState);
    oc_rep_end_root_object();
    if (oc_do_put())
      OC_PRINTF("Sent PUT request\n");
    else
      OC_PRINTF("Could not send PUT\n");
  } else
    OC_PRINTF("Could not init PUT\n");
}

void
RIHelper::observeResource()
{
  OC_PRINTF("observeResource:\n");
  s_generalQuit = 0;
  oc_do_observe(s_lightUri, s_pLightEndpoint, NULL, &observeLightCb, LOW_QOS,
                NULL);
  oc_set_delayed_callback(NULL, &stopObserveClientCb, 10);
}

void
RIHelper::handleSignalCb(int signal)
{
  (void)signal;
  OC_PRINTF("handleSignalCb:\n");
  signalEventLoopCb();
  s_generalQuit = 1;
}
