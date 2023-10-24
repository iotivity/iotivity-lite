/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "oc_config.h"

#if defined(OC_CLIENT) && defined(OC_TCP)

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_ping_internal.h"
#include "messaging/coap/signal_internal.h"
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_ri.h"

oc_event_callback_retval_t
oc_remove_ping_handler_async(void *data)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)data;

  oc_client_response_t timeout_response;
  timeout_response.code = OC_PING_TIMEOUT;
  timeout_response.endpoint = &cb->endpoint;
  timeout_response.user_data = cb->user_data;
  cb->handler.response(&timeout_response);

  return oc_client_cb_remove_async(cb);
}

bool
oc_send_ping(bool custody, const oc_endpoint_t *endpoint,
             uint16_t timeout_seconds, oc_response_handler_t handler,
             void *user_data)
{
  if (endpoint == NULL || handler == NULL) {
    OC_ERR("oc_send_ping: invalid parameters (endpoint=%s, handler=%s)",
           endpoint != NULL ? "ok" : "null", handler != NULL ? "ok" : "null");
    return false;
  }

  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb =
    oc_ri_alloc_client_cb(OC_PING_URI, endpoint, /*method*/ 0, /*query*/ NULL,
                          client_handler, LOW_QOS, user_data);
  if (cb == NULL) {
    return false;
  }

  if (!coap_send_ping_message(endpoint, custody ? 1 : 0, cb->token,
                              cb->token_len)) {
    oc_client_cb_free(cb);
    return false;
  }

  oc_set_delayed_callback(cb, oc_remove_ping_handler_async, timeout_seconds);
  return true;
}

#endif /* OC_CLIENT && OC_TCP */
