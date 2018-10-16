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

/**
 *@brief APIs of Iotivity-constrained for resource interface.
 *@file
 */

#ifndef OC_RI_H
#define OC_RI_H

#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "util/oc_etimer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OC_GET = 1, OC_POST, OC_PUT, OC_DELETE } oc_method_t;

/**
 *@brief Types of resource properties.
 */
typedef enum {
  OC_DISCOVERABLE = (1 << 0),
  OC_OBSERVABLE = (1 << 1),
  OC_SECURE = (1 << 4),
  OC_PERIODIC = (1 << 6),
} oc_resource_properties_t;

/**
 *@brief Types of status codes.
 */
typedef enum {
  OC_STATUS_OK = 0,
  OC_STATUS_CREATED,
  OC_STATUS_CHANGED,
  OC_STATUS_DELETED,
  OC_STATUS_NOT_MODIFIED,
  OC_STATUS_BAD_REQUEST,
  OC_STATUS_UNAUTHORIZED,
  OC_STATUS_BAD_OPTION,
  OC_STATUS_FORBIDDEN,
  OC_STATUS_NOT_FOUND,
  OC_STATUS_METHOD_NOT_ALLOWED,
  OC_STATUS_NOT_ACCEPTABLE,
  OC_STATUS_REQUEST_ENTITY_TOO_LARGE,
  OC_STATUS_UNSUPPORTED_MEDIA_TYPE,
  OC_STATUS_INTERNAL_SERVER_ERROR,
  OC_STATUS_NOT_IMPLEMENTED,
  OC_STATUS_BAD_GATEWAY,
  OC_STATUS_SERVICE_UNAVAILABLE,
  OC_STATUS_GATEWAY_TIMEOUT,
  OC_STATUS_PROXYING_NOT_SUPPORTED,
  __NUM_OC_STATUS_CODES__,
  OC_IGNORE
} oc_status_t;

typedef struct oc_separate_response_s oc_separate_response_t;

typedef struct oc_response_buffer_s oc_response_buffer_t;

/**
 *@brief Structure to store oc respnse details.
 */
typedef struct
{
  oc_separate_response_t *separate_response;
  oc_response_buffer_t *response_buffer;
} oc_response_t;

/**
 *@brief Masked value of interfaces.
 */
typedef enum {
  OC_IF_BASELINE = 1 << 1,
  OC_IF_LL = 1 << 2,
  OC_IF_B = 1 << 3,
  OC_IF_R = 1 << 4,
  OC_IF_RW = 1 << 5,
  OC_IF_A = 1 << 6,
  OC_IF_S = 1 << 7,
} oc_interface_mask_t;

/**
 *@brief Types of core resources.
 */
typedef enum {
  OCF_P = 0,
  OCF_RES,
  OCF_CON,
  OCF_INTROSPECTION_WK,
  OCF_INTROSPECTION_DATA,
#ifdef OC_SECURITY
  OCF_SEC_DOXM,
  OCF_SEC_PSTAT,
  OCF_SEC_ACL,
  OCF_SEC_CRED,
#endif
  OCF_D
} oc_core_resource_t;

#define OC_NUM_CORE_RESOURCES_PER_DEVICE (1 + OCF_D)

typedef struct oc_resource_s oc_resource_t;

/**
 *@brief Structure to store oc request details.
 */
typedef struct
{
  oc_endpoint_t *origin;
  oc_resource_t *resource;
  const char *query;
  size_t query_len;
  oc_rep_t *request_payload;
  oc_response_t *response;
} oc_request_t;

/**
 *A function pointer for registering a callback to handle request
 *@param oc_request_t oc_request structure.
 *@param oc_interface_mask_t oc_interface_mask  structure.
 *@param user data.
 */
typedef void (*oc_request_callback_t)(oc_request_t *, oc_interface_mask_t,
                                      void *);

/**
 *@brief Structure to store oc request handler details.
 */
typedef struct oc_request_handler_s
{
  oc_request_callback_t cb;
  void *user_data;
} oc_request_handler_t;

/**
 *@brief Structure to store OC Resource details.
 */
struct oc_resource_s
{
  struct oc_resource_s *next;
  size_t device;
  oc_string_t name;
  oc_string_t uri;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_interface_mask_t default_interface;
  oc_resource_properties_t properties;
  oc_request_handler_t get_handler;
  oc_request_handler_t put_handler;
  oc_request_handler_t post_handler;
  oc_request_handler_t delete_handler;
  uint16_t observe_period_seconds;
  uint8_t num_observers;
};

typedef struct oc_link_s oc_link_t;
typedef struct oc_collection_s oc_collection_t;

/**
 *@brief Types of return value of event callback.
 */
typedef enum {
  OC_EVENT_DONE = 0,
  OC_EVENT_CONTINUE
} oc_event_callback_retval_t;

typedef oc_event_callback_retval_t (*oc_trigger_t)(void *);

/**
 *@brief Structure to store event callback data.
 */
typedef struct oc_event_callback_s
{
  struct oc_event_callback_s *next;
  struct oc_etimer timer;
  oc_trigger_t callback;
  void *data;
} oc_event_callback_t;

/**
 *@brief A function to initialize resource interface.
 */
void oc_ri_init(void);

/**
 *@brief A function to deinitialize resource interface.
 */
void oc_ri_shutdown(void);

/**
 *@brief A function to add callback to be trigerred after particular interval.
 *@param cb_data data to be passed to callback.
 *@param event_callback callback function.
 *@param ticks time interval.
 */
void oc_ri_add_timed_event_callback_ticks(void *cb_data,
                                          oc_trigger_t event_callback,
                                          oc_clock_time_t ticks);

/**
 *@brief A macro to add callback to be trigerred after particular interval.
 *@param cb_data data to be passed to callback.
 *@param event_callback callback function.
 *@param ticks time interval.
 */
#define oc_ri_add_timed_event_callback_seconds(cb_data, event_callback,        \
                                               seconds)                        \
  do {                                                                         \
    oc_ri_add_timed_event_callback_ticks(                                      \
      cb_data, event_callback,                                                 \
      (oc_clock_time_t)seconds *(oc_clock_time_t)OC_CLOCK_SECOND);             \
  } while (0)

/**
 *@brief A function to delete event callback.
 *@param cb_data data to be passed to callback.
 *@param event_callback callback function.
 */
void oc_ri_remove_timed_event_callback(void *cb_data,
                                       oc_trigger_t event_callback);

/**
 *@brief A function to fetch coap status code.
 *@param key oc_status code.
 *@return int coap status code.
 */
int oc_status_code(oc_status_t key);

/**
 *@brief A function to fetch resource with help of uri.
 *@param uri uri of resource.
 *@param uri_len length of uri.
 *@param device device.
 *@return resource OC Resource.
 */
oc_resource_t *oc_ri_get_app_resource_by_uri(const char *uri, size_t uri_len,
                                             size_t device);

/**
 *@brief A function to fetch list of resources present in app.
 *@return resource OC Resource.
 */
oc_resource_t *oc_ri_get_app_resources(void);

#ifdef OC_SERVER

/**
 *@brief A function to allocate memory for particular resource.
 *@return resource OC Resource.
 */
oc_resource_t *oc_ri_alloc_resource(void);

/**
 *@brief A function to add resource to list of app resources.
 *@param resource OC Resource.
 *@return bool Result of add operation.
 *@retval true if add is successful.
 *@retval false if any input parameter is NULL.
 */
bool oc_ri_add_resource(oc_resource_t *resource);

/**
 *@brief A function to delete resource from app resources list.
 *@param resource OC Resource.
 *@return bool Result of delete operation.
 *@retval true if delete is successful.
 *@retval false if any input parameter is NULL.
 */
bool oc_ri_delete_resource(oc_resource_t *resource);

#ifdef OC_MAX_NUM_COLLECTIONS
#define OC_COLLECTIONS
#endif /* OC_MAX_NUM_COLLECTIONS */
#endif /* OC_SERVER */

/**
 *@brief A function to free OC Resource properties.
 *@param resource OC Resource.
 */
void oc_ri_free_resource_properties(oc_resource_t *resource);

/**
 *@brief A function to fetch key value pair in query at particular index.
 *@param query query.
 *@param query_len query length.
 *@param key variable to store key.
 *@param key_len variable to store key length.
 *@param value variable to store value related to key.
 *@param value_len variable to store value length.
 *@param n index to be fetched.
 *@return int  next index in query..
 */
int oc_ri_get_query_nth_key_value(const char *query, size_t query_len,
                                  char **key, size_t *key_len, char **value,
                                  size_t *value_len, size_t n);

/**
 *@brief A function to fetch the value of particular key related to query.
 *@param query query.
 *@param query_len query length.
 *@param key key for which value is required.
 *@param value variable to store value related to key.
 *@return int value length.
 */
int oc_ri_get_query_value(const char *query, size_t query_len, const char *key,
                          char **value);

/**
 *@brief A function to get the masked value of particular interface.
 *@param iface interface for which mask is required.
 *@param if_len interface length
 *@return oc_interface_mask_t masked value of the interface.
 */
oc_interface_mask_t oc_ri_get_interface_mask(char *iface, size_t if_len);
#ifdef __cplusplus
}
#endif

#endif /* OC_RI_H */
