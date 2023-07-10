/****************************************************************************
 *
 * Copyright (c) 2016-2020 Intel Corporation
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
/**
  @file
*/
#ifndef OC_CLIENT_STATE_H
#define OC_CLIENT_STATE_H

#include "messaging/coap/constants.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#ifdef OC_OSCORE
#include "messaging/coap/oscore_constants.h"
#endif /* OC_OSCORE */

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Quality of Service
 *
 */
typedef enum {
  HIGH_QOS = 0, ///< confirmable messages
  LOW_QOS       ///< non-confirmable messages
} oc_qos_t;

/**
 * @brief Client response information
 *
 */
typedef struct
{
  oc_rep_t *payload;       ///< response payload, interpreted as cbor
  const uint8_t *_payload; ///< payload buffer
  size_t _payload_len;     ///< payload buffer length
  oc_endpoint_t *endpoint; ///< endpoint describing the source of the response
  void *client_cb;         ///< callback for the response to the calling client
  void *user_data; ///< user data to be supplied to the callback to the client
  oc_content_format_t content_format; ///< content format of the payload
  oc_status_t code;                   ///< status of the response
  int observe_option;                 ///< observe indication
} oc_client_response_t;

/**
 * @brief discovery flags
 *
 */
typedef enum {
  OC_STOP_DISCOVERY = 0, ///< stop discovering (also no more data)
  OC_CONTINUE_DISCOVERY  ///< continue discovering (more data)
} oc_discovery_flags_t;

/**
 * @brief discovery_all handler
 *
 */
typedef oc_discovery_flags_t (*oc_discovery_all_handler_t)(
  const char *, const char *, oc_string_array_t, oc_interface_mask_t,
  const oc_endpoint_t *, oc_resource_properties_t, bool, void *);

/**
 * @brief discovery handler
 */
typedef oc_discovery_flags_t (*oc_discovery_handler_t)(
  const char *, const char *, oc_string_array_t, oc_interface_mask_t,
  const oc_endpoint_t *, oc_resource_properties_t, void *);

/**
 * @brief client response handler
 */
typedef void (*oc_response_handler_t)(oc_client_response_t *);

/**
 * @brief client handler information
 */
typedef struct oc_client_handler_t
{
  oc_response_handler_t response;           ///< response handler
  oc_discovery_handler_t discovery;         ///< discovery handler
  oc_discovery_all_handler_t discovery_all; ///< discovery all handler
} oc_client_handler_t;

/**
 * @brief client callback information
 *
 */
typedef struct oc_client_cb_t
{
  struct oc_client_cb_t *next;   ///< pointer next callback information
  oc_string_t uri;               ///< the uri
  oc_string_t query;             ///< query parameters
  oc_endpoint_t endpoint;        ///< endpoint
  oc_client_handler_t handler;   ///< handler information
  void *user_data;               ///< user data for the callbacks
  int32_t observe_seq;           ///< observe sequence number
  oc_clock_time_t timestamp;     ///< creation timestamp
  oc_qos_t qos;                  ///< quality of service
  oc_method_t method;            ///< method used
  uint16_t mid;                  ///< CoAP message identifier
  uint8_t token[COAP_TOKEN_LEN]; ///< CoAP token
  uint8_t token_len;             ///< CoAP token lenght
  bool discovery;                ///< discovery call
  bool multicast;                ///< multicast
  bool stop_multicast_receive;   ///< stop receiving multicast
  uint8_t ref_count;             ///< reference counting on this data block
  uint8_t separate;              ///< seperate responses
#ifdef OC_OSCORE
  uint8_t piv[OSCORE_PIV_LEN]; ///< partial IV
  uint8_t piv_len;             ///< lenght of the partial IV
  uint64_t notification_num;   ///< notification number
#endif                         /* OC_OSCORE */
} oc_client_cb_t;

/**
 * @brief allocate the client callback information
 *
 * @param uri the uri to be called (cannot be NULL)
 * @param endpoint the endpoint of the device
 * @param method method to be used
 * @param query the query params to be used
 * @param handler the callback when data arrives
 * @param qos quality of service level
 * @param user_data user data to be provided with the invocation of the callback
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t *oc_ri_alloc_client_cb(const char *uri,
                                      const oc_endpoint_t *endpoint,
                                      oc_method_t method, const char *query,
                                      oc_client_handler_t handler, oc_qos_t qos,
                                      void *user_data) OC_NONNULL(1);

/**
 * @brief retrieve the client callback information
 *
 * @param uri the uri for the callback (cannot be NULL)
 * @param endpoint the endpoint for the callback
 * @param method the used method
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t *oc_ri_get_client_cb(const char *uri,
                                    const oc_endpoint_t *endpoint,
                                    oc_method_t method) OC_NONNULL(1);

/**
 * @brief is the client callback information valid
 *
 * @param client_cb the client callback information
 * @return true is correct
 * @return false is incomplete
 */
bool oc_ri_is_client_cb_valid(const oc_client_cb_t *client_cb);

/**
 * @brief find the client callback info by token
 *
 * @param token the token (cannot be NULL)
 * @param token_len the token lenght
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t *oc_ri_find_client_cb_by_token(const uint8_t *token,
                                              uint8_t token_len) OC_NONNULL(1);

/**
 * @brief find the client callback info by message id (mid)
 *
 * @param mid the message id
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t *oc_ri_find_client_cb_by_mid(uint16_t mid);

/**
 * @brief free the client callback information by endpoint with a specific code
 *
 * @param endpoint the endpoint
 * @param code the propagated code to client callback
 */
void oc_ri_free_client_cbs_by_endpoint_v1(const oc_endpoint_t *endpoint,
                                          oc_status_t code);

/**
 * @brief free the client callback information by endpoint with code
 * OC_CANCELLED
 *
 * @deprecated replaced by oc_ri_free_client_cbs_by_endpoint_v1 in v2.2.5.4
 * @param endpoint the endpoint
 */
void oc_ri_free_client_cbs_by_endpoint(const oc_endpoint_t *endpoint)
  OC_DEPRECATED("replaced by oc_ri_free_client_cbs_by_endpoint_v1 in v2.2.5.4");

/**
 * @brief free the client callback infomation by message id (mid)
 *
 * @param mid the message id
 * @param code the propagated code to client callback
 */
void oc_ri_free_client_cbs_by_mid_v1(uint16_t mid, oc_status_t code);

/**
 * @brief free the client callback infomation by message id (mid) with code
 * OC_CANCELLED
 *
 * @deprecated replaced by oc_ri_free_client_cbs_by_mid_v1 in v2.2.5.4
 * @param mid the message id
 */
void oc_ri_free_client_cbs_by_mid(uint16_t mid)
  OC_DEPRECATED("replaced by oc_ri_free_client_cbs_by_mid_v1 in v2.2.5.4");

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT_STATE_H */
