/*
// Copyright (c) 2016-2019 Intel Corporation
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
  @file
*/
#ifndef OC_RI_H
#define OC_RI_H

#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "oc_enums.h"
#include "util/oc_etimer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CoAP methods
 * 
 */
typedef enum { 
  OC_GET = 1,  ///< GET
  OC_POST,     ///< POST
  OC_PUT,      ///< PUT
  OC_DELETE,   ///< DELETE
  OC_FETCH     ///< FETCH
  } oc_method_t;

/**
 * @brief resource properties (bit mask)
 * 
 */
typedef enum {
  OC_DISCOVERABLE = (1 << 0),   ///< discoverable
  OC_OBSERVABLE = (1 << 1),     ///< observable
  OC_SECURE = (1 << 4),         ///< secure
  OC_PERIODIC = (1 << 6),       ///< periodiacal update
  OC_SECURE_MCAST = (1 << 8)    ///< secure multicast (oscore)
} oc_resource_properties_t;

/**
 * @brief response status
 * 
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
  OC_IGNORE,
  OC_PING_TIMEOUT
} oc_status_t;

/**
 * @brief payload content formats
 * 
 */
typedef enum {
  TEXT_PLAIN = 0,
  TEXT_XML = 1,
  TEXT_CSV = 2,
  TEXT_HTML = 3,
  IMAGE_GIF = 21,
  IMAGE_JPEG = 22,
  IMAGE_PNG = 23,
  IMAGE_TIFF = 24,
  AUDIO_RAW = 25,
  VIDEO_RAW = 26,
  APPLICATION_LINK_FORMAT = 40,
  APPLICATION_XML = 41,
  APPLICATION_OCTET_STREAM = 42,
  APPLICATION_RDF_XML = 43,
  APPLICATION_SOAP_XML = 44,
  APPLICATION_ATOM_XML = 45,
  APPLICATION_XMPP_XML = 46,
  APPLICATION_EXI = 47,
  APPLICATION_FASTINFOSET = 48,
  APPLICATION_SOAP_FASTINFOSET = 49,
  APPLICATION_JSON = 50,
  APPLICATION_X_OBIX_BINARY = 51,
  APPLICATION_CBOR = 60,
  APPLICATION_VND_OCF_CBOR = 10000
} oc_content_format_t;

typedef struct oc_separate_response_s oc_separate_response_t;

typedef struct oc_response_buffer_s oc_response_buffer_t;

typedef struct oc_response_t
{
  oc_separate_response_t *separate_response;
  oc_response_buffer_t *response_buffer;
} oc_response_t;

/**
 * @brief interface masks
 * 
 */
typedef enum {
  OC_IF_BASELINE = 1 << 1,   ///< oic.if.baseline
  OC_IF_LL = 1 << 2,         ///< oic.if.ll
  OC_IF_B = 1 << 3,          ///< oic.if.b
  OC_IF_R = 1 << 4,          ///< oic.if.r
  OC_IF_RW = 1 << 5,         ///< oic.if.rw
  OC_IF_A = 1 << 6,          ///< oic.if.a
  OC_IF_S = 1 << 7,          ///< oic.if.s
  OC_IF_CREATE = 1 << 8      ///< oic.if.create
} oc_interface_mask_t;

typedef enum {
  OCF_P = 0,
  /* List of resources on a logical device: start */
  /* List of Device Configuration Resources (DCRs): start */
  OCF_CON,
  OCF_INTROSPECTION_WK,
  OCF_INTROSPECTION_DATA,
#ifdef OC_WKCORE
  WELLKNOWNCORE,
#endif
  OCF_RES,
#ifdef OC_MNT
  OCF_MNT,
#endif /* OC_MNT */
#ifdef OC_CLOUD
  OCF_COAPCLOUDCONF,
#endif /* OC_CLOUD */
#ifdef OC_SOFTWARE_UPDATE
  OCF_SW_UPDATE,
#endif /* OC_SOFTWARE_UPDATE */
#ifdef OC_SECURITY
  OCF_SEC_DOXM,
  OCF_SEC_PSTAT,
  OCF_SEC_ACL,
  OCF_SEC_AEL,
  OCF_SEC_CRED,
  OCF_SEC_SDI,
  OCF_SEC_SP,
#ifdef OC_PKI
  OCF_SEC_CSR,
  OCF_SEC_ROLES,
#endif /* OC_PKI */
#endif /* OC_SECURITY */
  OCF_D
  /* List of Device Configuration Resources (DCRs): end */
  /* List of resources on a logical device: end */
} oc_core_resource_t;

#define OC_NUM_CORE_RESOURCES_PER_DEVICE (1 + OCF_D)

typedef struct oc_resource_s oc_resource_t;

/**
 * @brief request information structure
 * 
 */
typedef struct oc_request_t
{
  oc_endpoint_t *origin;                ///< origin of the request
  oc_resource_t *resource;              ///< resource structure
  const char *query;                    ///< query (as string)
  size_t query_len;                     ///< query lenght
  oc_rep_t *request_payload;            ///< request payload structure
  const uint8_t *_payload;              ///< payload of the request
  size_t _payload_len;                  ///< payload size
  oc_content_format_t content_format;   ///< content format (of the payload in the request)
  oc_content_format_t accept;           ///< accept header 
  oc_response_t *response;              ///< pointer to the response
} oc_request_t;

/**
 * @brief request callback
 * 
 */
typedef void (*oc_request_callback_t)(oc_request_t *, oc_interface_mask_t,
                                      void *);


typedef struct oc_request_handler_s
{
  oc_request_callback_t cb;
  void *user_data;
} oc_request_handler_t;

/**
 * @brief set properties callback
 * 
 */
typedef bool (*oc_set_properties_cb_t)(oc_resource_t *, oc_rep_t *, void *);

/**
 * @brief get properties callback
 * 
 */
typedef void (*oc_get_properties_cb_t)(oc_resource_t *, oc_interface_mask_t,
                                       void *);

/**
 * @brief properties callback structure
 * 
 */
typedef struct oc_properties_cb_t
{
  union {
    oc_set_properties_cb_t set_props;
    oc_get_properties_cb_t get_props;
  } cb;
  void *user_data;
} oc_properties_cb_t;

/**
 * @brief resource structure
 * 
 */
struct oc_resource_s
{
  struct oc_resource_s *next;            ///< next resource
  size_t device;                         ///< device index
  oc_string_t name;                      ///< name of the resource (e.g. "n")
  oc_string_t uri;                       ///< uri of the resource
  oc_string_array_t types;               ///< "rt" types of the resource
  oc_interface_mask_t interfaces;        ///< supported interfaces
  oc_interface_mask_t default_interface; ///< default interface
  oc_resource_properties_t properties;   ///< properties (as bit mask)
  oc_request_handler_t get_handler;      ///< callback for GET
  oc_request_handler_t put_handler;      ///< callback for PUT
  oc_request_handler_t post_handler;     ///< callback for POST
  oc_request_handler_t delete_handler;   ///< callback for DELETE
  oc_properties_cb_t get_properties;     ///< callback for get properties
  oc_properties_cb_t set_properties;     ///< callback for set properties
  double tag_pos_rel[3];                 ///< tag relative position [x,y,z]
  oc_pos_description_t tag_pos_desc;     ///< tag (value) for position description
  oc_enum_t tag_func_desc;               ///< tag (value) for function description
  oc_locn_t tag_locn;                    ///< tag (value) for location desciption
  uint8_t num_observers;                 ///< amount of observers
#ifdef OC_COLLECTIONS
  uint8_t num_links;                     ///< number of links in the collection
#endif /* OC_COLLECTIONS */
  uint16_t observe_period_seconds;       ///< observe period in seconds
};

typedef struct oc_link_s oc_link_t;
typedef struct oc_collection_s oc_collection_t;

typedef enum {
  OC_EVENT_DONE = 0,
  OC_EVENT_CONTINUE
} oc_event_callback_retval_t;

typedef oc_event_callback_retval_t (*oc_trigger_t)(void *);

/**
 * @brief event callback
 * 
 */
typedef struct oc_event_callback_s
{
  struct oc_event_callback_s *next;  ///< next callback
  struct oc_etimer timer;            ///< timer
  oc_trigger_t callback;             ///< callback to be invoked
  void *data;                        ///< data for the callback
} oc_event_callback_t;

/**
 * @brief initialize the resource implementation handler
 * 
 */
void oc_ri_init(void);

/**
 * @brief shut down the resource implementation handler
 * 
 */
void oc_ri_shutdown(void);

/**
 * @brief add timed event callback
 * 
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 * @param ticks time in ticks
 */
void oc_ri_add_timed_event_callback_ticks(void *cb_data,
                                          oc_trigger_t event_callback,
                                          oc_clock_time_t ticks);

#define oc_ri_add_timed_event_callback_seconds(cb_data, event_callback,        \
                                               seconds)                        \
  do {                                                                         \
    oc_ri_add_timed_event_callback_ticks(                                      \
      cb_data, event_callback,                                                 \
      (oc_clock_time_t)seconds *(oc_clock_time_t)OC_CLOCK_SECOND);             \
  } while (0)

/**
 * @brief remove the timed event callback
 * 
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 */
void oc_ri_remove_timed_event_callback(void *cb_data,
                                       oc_trigger_t event_callback);

/**
 * @brief convert the status code to integer
 * 
 * @param key the application level key of the code
 * @return int the CoAP status code 
 */
int oc_status_code(oc_status_t key);

/**
 * @brief retrieve the resource by uri and device indes
 * 
 * @param uri the uri of the resource
 * @param uri_len the lenght of the uri
 * @param device the device index
 * @return oc_resource_t* the resource structure
 */
oc_resource_t *oc_ri_get_app_resource_by_uri(const char *uri, size_t uri_len,
                                             size_t device);

/**
 * @brief retrieve list of resources
 * 
 * @return oc_resource_t* the resource list
 */
oc_resource_t *oc_ri_get_app_resources(void);

#ifdef OC_SERVER
/**
 * @brief allocate a resource strucutre
 * 
 * @return oc_resource_t* 
 */
oc_resource_t *oc_ri_alloc_resource(void);
/**
 * @brief add resource to the system
 * 
 * @param resource the resource to be added to the list of application resources
 * @return true success
 * @return false failure
 */
bool oc_ri_add_resource(oc_resource_t *resource);

/**
 * @brief remove the resource from the list of application resources
 * 
 * @param resource the resource to be removed from the list of application resources
 * @return true success 
 * @return false failure
 */
bool oc_ri_delete_resource(oc_resource_t *resource);
#endif /* OC_SERVER */

/**
 * @brief free the properties of the resource
 * 
 * @param resource the resource
 */
void oc_ri_free_resource_properties(oc_resource_t *resource);

/**
 * @brief retrieve the query value at the nth position
 * 
 * @param query the input query
 * @param query_len the query lenght
 * @param key the key
 * @param key_len the lenght of the key
 * @param value the value belonging to the key
 * @param value_len the lenght of the value
 * @param n the posiition to query
 * @return int 
 */
int oc_ri_get_query_nth_key_value(const char *query, size_t query_len,
                                  char **key, size_t *key_len, char **value,
                                  size_t *value_len, size_t n);

/**
 * @brief retrieve the value of the query parameter "key" 
 * 
 * @param query the input query
 * @param query_len the query lenght
 * @param key the wanted key
 * @param value the returned value
 * @return int the lenght of the value
 */
int oc_ri_get_query_value(const char *query, size_t query_len, const char *key,
                          char **value);

/**
 * @brief retrieve the interface mask from the interface name
 * 
 * @param iface the interface (e.g. "if=oic.if.s")
 * @param if_len the interface lenght
 * @return oc_interface_mask_t the mask value of the interface
 */
oc_interface_mask_t oc_ri_get_interface_mask(char *iface, size_t if_len);

/**
 * @brief checks if the resource is valid
 * 
 * @param resource resource to be tested
 * @return true valid
 * @return false not valid
 */
bool oc_ri_is_app_resource_valid(oc_resource_t *resource);

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_H */
