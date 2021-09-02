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
 * can be translated to HTTP or CoAP.
 */
typedef enum {
  OC_STATUS_OK = 0,                    ///< OK
  OC_STATUS_CREATED,                   ///< Created
  OC_STATUS_CHANGED,                   ///< Changed
  OC_STATUS_DELETED,                   ///< Deleted
  OC_STATUS_NOT_MODIFIED,              ///< Not Modified
  OC_STATUS_BAD_REQUEST,               ///< Bad Request
  OC_STATUS_UNAUTHORIZED,              ///< Unauthorized
  OC_STATUS_BAD_OPTION,                ///< Bad Option
  OC_STATUS_FORBIDDEN,                 ///< Forbidden
  OC_STATUS_NOT_FOUND,                 ///< Not Found
  OC_STATUS_METHOD_NOT_ALLOWED,        ///< Method Not Allowed
  OC_STATUS_NOT_ACCEPTABLE,            ///< Not Acceptable
  OC_STATUS_REQUEST_ENTITY_TOO_LARGE,  ///< Request Entity Too Large
  OC_STATUS_UNSUPPORTED_MEDIA_TYPE,    ///< Unsupported Media Type
  OC_STATUS_INTERNAL_SERVER_ERROR,     ///< Internal Server Error
  OC_STATUS_NOT_IMPLEMENTED,           ///< Not Implemented
  OC_STATUS_BAD_GATEWAY,               ///< Bad Gateway
  OC_STATUS_SERVICE_UNAVAILABLE,       ///< Service Unavailable
  OC_STATUS_GATEWAY_TIMEOUT,           ///< Gateway Timeout
  OC_STATUS_PROXYING_NOT_SUPPORTED,    ///< Proxying not supported
  __NUM_OC_STATUS_CODES__,
  OC_IGNORE,                           ///< Ignore: do not respond to request
  OC_PING_TIMEOUT                      ///< Ping Time out
} oc_status_t;

/**
 * @brief payload content formats
 * 
 * https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#rd-parameters
 * 
 */
typedef enum {
  TEXT_PLAIN = 0,                        ///< text/plain
  TEXT_XML = 1,                          ///< text/xml
  TEXT_CSV = 2,                          ///< text/csv
  TEXT_HTML = 3,                         ///< text/html
  IMAGE_GIF = 21,                        ///< image/gif - not used
  IMAGE_JPEG = 22,                       ///< image/jpeg - not used
  IMAGE_PNG = 23,                        ///< image/png - not used
  IMAGE_TIFF = 24,                       ///< image/tiff - not used
  AUDIO_RAW = 25,                        ///< audio/raw - not used
  VIDEO_RAW = 26,                        ///< video/raw - not used
  APPLICATION_LINK_FORMAT = 40,          ///< application/link-format
  APPLICATION_XML = 41,                  ///< application/xml
  APPLICATION_OCTET_STREAM = 42,         ///< application/octet-stream
  APPLICATION_RDF_XML = 43,              ///< application - not used
  APPLICATION_SOAP_XML = 44,             ///< application/soap - not used
  APPLICATION_ATOM_XML = 45,             ///< application - not used
  APPLICATION_XMPP_XML = 46,             ///< application - not used
  APPLICATION_EXI = 47,                  ///< application/exi
  APPLICATION_FASTINFOSET = 48,          ///< application
  APPLICATION_SOAP_FASTINFOSET = 49,     ///< application
  APPLICATION_JSON = 50,                 ///< application/json
  APPLICATION_X_OBIX_BINARY = 51,        ///< application - not used
  APPLICATION_CBOR = 60,                 ///< application/cbor
  APPLICATION_SENML_JSON = 110,          ///< application/senml+json
  APPLICATION_SENSML_JSON = 111,         ///< application/sensml+json
  APPLICATION_SENML_CBOR = 112,          ///< application/senml+cbor
  APPLICATION_SENSML_CBOR = 113,         ///< application/sensml+cbor
  APPLICATION_SENML_EXI = 114,           ///< application/senml-exi
  APPLICATION_SENSML_EXI = 115,          ///< application/sensml-exi
  APPLICATION_PKCS7_SGK = 280,           ///< application/pkcs7-mime; smime-type=server-generated-key
  APPLICATION_PKCS7_CO = 281,            ///< application/pkcs7-mime; smime-type=certs-only
  APPLICATION_PKCS7_CMC_REQUEST = 282,   ///< application/pkcs7-mime; smime-type=CMC-Request
  APPLICATION_PKCS7_CMC_RESPONSE = 283,  ///< application/pkcs7-mime; smime-type=CMC-Response
  APPLICATION_PKCS8 = 284,               ///< application/pkcs8
  APPLICATION_CRATTRS = 285,             ///< application/csrattrs
  APPLICATION_PKCS10 = 286,              ///< application/pkcs10
  APPLICATION_PKIX_CERT = 287,           ///< application/pkix-cert
  APPLICATION_VND_OCF_CBOR = 10000,      ///< application/vnd.ocf+cbor
  APPLICATION_OSCORE = 10001,            ///< application/oscore
  APPLICATION_VND_OMA_LWM2M_TLV = 11542, ///< application/vnd.oma.lwm2m+tlv
  APPLICATION_VND_OMA_LWM2M_JSON = 11543,///< application/vnd.oma.lwm2m+json
  APPLICATION_VND_OMA_LWM2M_CBOR = 11544 ///< application/vnd.oma.lwm2m+cbor
} oc_content_format_t;

/**
 * @brief seperate response type
 * 
 */
typedef struct oc_separate_response_s oc_separate_response_t;

/**
 * @brief reponse buffer type
 * 
 */
typedef struct oc_response_buffer_s oc_response_buffer_t;

/**
 * @brief response type
 * 
 */
typedef struct oc_response_t
{
  oc_separate_response_t *separate_response;  ///< seperate response
  oc_response_buffer_t *response_buffer;      ///< response buffer
} oc_response_t;

/**
 * @brief interface masks
 * 
 */
typedef enum {
  OC_IF_BASELINE = 1 << 1,        ///< oic.if.baseline
  OC_IF_LL = 1 << 2,              ///< oic.if.ll
  OC_IF_B = 1 << 3,               ///< oic.if.b
  OC_IF_R = 1 << 4,               ///< oic.if.r
  OC_IF_RW = 1 << 5,              ///< oic.if.rw
  OC_IF_A = 1 << 6,               ///< oic.if.a
  OC_IF_S = 1 << 7,               ///< oic.if.s
  OC_IF_CREATE = 1 << 8,          ///< oic.if.create
  OC_IF_W = 1 << 9,               ///< oic.if.w
  OC_IF_STARTUP = 1 << 10,        ///< oic.if.startup
  OC_IF_STARTUP_REVERT = 1 << 11  ///< oic.if.startup.revert
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


/**
 * @brief request handler type
 * 
 */
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

typedef struct oc_resource_defaults_data_t
{
  oc_resource_t *resource;
  oc_interface_mask_t iface_mask;
} oc_resource_defaults_data_t;

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

/**
 * @brief add timed event callback in seconds
 * *
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 * @param seconds time in seconds
 */
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
 * @return int the position of the next key value pair in the query or NULL
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
 * @brief checks if key exist in query
 * 
 * @param[in] query the query to inspect
 * @param[in] query_len the lenght of the query
 * @param[in] key the key to be checked if exist, key is null terminated
 * @return int -1 = not exist
 */
int oc_ri_query_exists(const char* query, size_t query_len, const char* key);

/**
 * @brief check if the nth key exists
 * 
 * @param query the query to inspect
 * @param query_len the lenght of the query
 * @param key the key to be checked if exist, key is not null terminated
 * @param key_len the key length
 * @param n 
 * @return int 
 */
int oc_ri_query_nth_key_exists(const char* query, size_t query_len, char** key,
  size_t* key_len,
  size_t n);

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
