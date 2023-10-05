/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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
#ifndef OC_RI_H
#define OC_RI_H

#include "messaging/coap/constants.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_enums.h"
#include "oc_export.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "port/oc_clock.h"
#include "util/oc_features.h"
#include "util/oc_compiler.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CoAP methods
 *
 */
typedef enum {
  OC_GET = 1, ///< GET
  OC_POST,    ///< POST
  OC_PUT,     ///< PUT
  OC_DELETE,  ///< DELETE
  OC_FETCH    ///< FETCH
} oc_method_t;

/**
 * @brief resource properties (bit mask)
 *
 */
typedef enum {
  OC_DISCOVERABLE = (1 << 0), ///< discoverable
  OC_OBSERVABLE = (1 << 1),   ///< observable
#ifdef OC_HAS_FEATURE_PUSH
  OC_PUSHABLE = (1 << 2), ///< pushable
#endif
  OC_SECURE = (1 << 4),       ///< secure
  OC_PERIODIC = (1 << 6),     ///< periodical update
  OC_SECURE_MCAST = (1 << 8), ///< secure multicast (oscore)
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  OC_ACCESS_IN_RFOTM = (1 << 9) ///< allow access to resource in ready for
                                ///< ownership transfer method(RFOTM) state
#endif
} oc_resource_properties_t;

/**
 * @brief response status
 * can be translated to HTTP or CoAP.
 */
typedef enum {
  OC_STATUS_OK = 0,                   ///< OK
  OC_STATUS_CREATED,                  ///< Created
  OC_STATUS_CHANGED,                  ///< Changed
  OC_STATUS_DELETED,                  ///< Deleted
  OC_STATUS_NOT_MODIFIED,             ///< Not Modified
  OC_STATUS_BAD_REQUEST,              ///< Bad Request
  OC_STATUS_UNAUTHORIZED,             ///< Unauthorized
  OC_STATUS_BAD_OPTION,               ///< Bad Option
  OC_STATUS_FORBIDDEN,                ///< Forbidden
  OC_STATUS_NOT_FOUND,                ///< Not Found
  OC_STATUS_METHOD_NOT_ALLOWED,       ///< Method Not Allowed
  OC_STATUS_NOT_ACCEPTABLE,           ///< Not Acceptable
  OC_STATUS_REQUEST_ENTITY_TOO_LARGE, ///< Request Entity Too Large
  OC_STATUS_UNSUPPORTED_MEDIA_TYPE,   ///< Unsupported Media Type
  OC_STATUS_INTERNAL_SERVER_ERROR,    ///< Internal Server Error
  OC_STATUS_NOT_IMPLEMENTED,          ///< Not Implemented
  OC_STATUS_BAD_GATEWAY,              ///< Bad Gateway
  OC_STATUS_SERVICE_UNAVAILABLE,      ///< Service Unavailable
  OC_STATUS_GATEWAY_TIMEOUT,          ///< Gateway Timeout
  OC_STATUS_PROXYING_NOT_SUPPORTED,   ///< Proxying not supported
  __NUM_OC_STATUS_CODES__,
  OC_IGNORE,          ///< Ignore: do not respond to request
  OC_PING_TIMEOUT,    ///< Ping Time out
  OC_REQUEST_TIMEOUT, ///< Timeout is returned when the timeout is reached for
                      ///< requests created by oc_do_get_with_timeout,
                      ///< oc_do_delete_with_timeout, oc_do_put_with_timeout, or
                      ///< oc_do_post_with_timeout
  OC_CONNECTION_CLOSED,   ///< Connection closed by peer, or client. eg. for
                          ///< invalid TLS handshake
  OC_TRANSACTION_TIMEOUT, ///< Blockwise transaction timed out's
  OC_CANCELLED,           ///< Cancelled: request was cancelled by the client
} oc_status_t;

/**
 * @brief payload content formats
 *
 * https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#rd-parameters
 */
typedef enum {
  TEXT_PLAIN = 0,                    ///< text/plain
  TEXT_XML = 1,                      ///< text/xml
  TEXT_CSV = 2,                      ///< text/csv
  TEXT_HTML = 3,                     ///< text/html
  IMAGE_GIF = 21,                    ///< image/gif - not used
  IMAGE_JPEG = 22,                   ///< image/jpeg - not used
  IMAGE_PNG = 23,                    ///< image/png - not used
  IMAGE_TIFF = 24,                   ///< image/tiff - not used
  AUDIO_RAW = 25,                    ///< audio/raw - not used
  VIDEO_RAW = 26,                    ///< video/raw - not used
  APPLICATION_LINK_FORMAT = 40,      ///< application/link-format
  APPLICATION_XML = 41,              ///< application/xml
  APPLICATION_OCTET_STREAM = 42,     ///< application/octet-stream
  APPLICATION_RDF_XML = 43,          ///< application - not used
  APPLICATION_SOAP_XML = 44,         ///< application/soap - not used
  APPLICATION_ATOM_XML = 45,         ///< application - not used
  APPLICATION_XMPP_XML = 46,         ///< application - not used
  APPLICATION_EXI = 47,              ///< application/exi
  APPLICATION_FASTINFOSET = 48,      ///< application
  APPLICATION_SOAP_FASTINFOSET = 49, ///< application
  APPLICATION_JSON = 50,             ///< application/json
  APPLICATION_X_OBIX_BINARY = 51,    ///< application - not used
  APPLICATION_CBOR = 60,             ///< application/cbor
  APPLICATION_SENML_JSON = 110,      ///< application/senml+json
  APPLICATION_SENSML_JSON = 111,     ///< application/sensml+json
  APPLICATION_SENML_CBOR = 112,      ///< application/senml+cbor
  APPLICATION_SENSML_CBOR = 113,     ///< application/sensml+cbor
  APPLICATION_SENML_EXI = 114,       ///< application/senml-exi
  APPLICATION_SENSML_EXI = 115,      ///< application/sensml-exi
  APPLICATION_PKCS7_SGK =
    280, ///< application/pkcs7-mime; smime-type=server-generated-key
  APPLICATION_PKCS7_CO = 281, ///< application/pkcs7-mime; smime-type=certs-only
  APPLICATION_PKCS7_CMC_REQUEST =
    282, ///< application/pkcs7-mime; smime-type=CMC-Request
  APPLICATION_PKCS7_CMC_RESPONSE =
    283,                   ///< application/pkcs7-mime; smime-type=CMC-Response
  APPLICATION_PKCS8 = 284, ///< application/pkcs8
  APPLICATION_CRATTRS = 285,              ///< application/csrattrs
  APPLICATION_PKCS10 = 286,               ///< application/pkcs10
  APPLICATION_PKIX_CERT = 287,            ///< application/pkix-cert
  APPLICATION_TD_JSON = 432,              ///< application/td+json
  APPLICATION_VND_OCF_CBOR = 10000,       ///< application/vnd.ocf+cbor
  APPLICATION_OSCORE = 10001,             ///< application/oscore
  APPLICATION_VND_OMA_LWM2M_TLV = 11542,  ///< application/vnd.oma.lwm2m+tlv
  APPLICATION_VND_OMA_LWM2M_JSON = 11543, ///< application/vnd.oma.lwm2m+json
  APPLICATION_VND_OMA_LWM2M_CBOR = 11544, ///< application/vnd.oma.lwm2m+cbor

  APPLICATION_NOT_DEFINED = 0xFFFF, ///< not defined
} oc_content_format_t;

/**
 * @brief interface masks
 *
 */
typedef enum {
  OC_IF_BASELINE = 1 << 1,       ///< oic.if.baseline
  OC_IF_LL = 1 << 2,             ///< oic.if.ll
  OC_IF_B = 1 << 3,              ///< oic.if.b
  OC_IF_R = 1 << 4,              ///< oic.if.r
  OC_IF_RW = 1 << 5,             ///< oic.if.rw
  OC_IF_A = 1 << 6,              ///< oic.if.a
  OC_IF_S = 1 << 7,              ///< oic.if.s
  OC_IF_CREATE = 1 << 8,         ///< oic.if.create
  OC_IF_W = 1 << 9,              ///< oic.if.w
  OC_IF_STARTUP = 1 << 10,       ///< oic.if.startup
  OC_IF_STARTUP_REVERT = 1 << 11 ///< oic.if.startup.revert
} oc_interface_mask_t;

typedef enum {
  OCF_P = 0,
#ifdef OC_HAS_FEATURE_PLGD_TIME
  PLGD_TIME,
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  /* List of resources on a logical device: start */
  OCF_CON,
#ifdef OC_INTROSPECTION
  OCF_INTROSPECTION_WK,
  OCF_INTROSPECTION_DATA,
#endif /* OC_INTROSPECTION */
/* List of Device Configuration Resources (DCRs): start */
#ifdef OC_WKCORE
  WELLKNOWNCORE,
#endif
  OCF_RES,
#ifdef OC_MNT
  OCF_MNT,
#endif /* OC_MNT */
#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  OCF_COAPCLOUDCONF,
#endif /* OC_CLIENT &&  OC_SERVER && OC_CLOUD */
#ifdef OC_SOFTWARE_UPDATE
  OCF_SW_UPDATE,
#endif /* OC_SOFTWARE_UPDATE */
/* List of Secure Vertical Resources (SVRs): start */
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
  /* List of Secure Vertical Resources (SVRs): end */
  OCF_D
  /* List of Device Configuration Resources (DCRs): end */
  /* List of resources on a logical device: end */
} oc_core_resource_t;

#define OC_NUM_CORE_RESOURCES_PER_DEVICE (1 + OCF_D)

typedef struct oc_resource_s oc_resource_t;

/**
 * @brief seperate response type
 */
typedef struct oc_separate_response_s oc_separate_response_t;

/**
 * @brief response type
 */
typedef struct oc_response_s oc_response_t;

/**
 * @brief request information structure
 */
typedef struct oc_request_t
{
  const oc_endpoint_t *origin; ///< origin of the request
  oc_resource_t *resource;     ///< resource structure
  const char *query;           ///< query (as string)
  size_t query_len;            ///< query length
  oc_rep_t *request_payload;   ///< request payload structure
  const uint8_t *_payload;     ///< payload of the request
  size_t _payload_len;         ///< payload size
  oc_content_format_t
    content_format; ///< content format (of the payload in the request)
  oc_content_format_t accept; ///< accept header
  oc_response_t *response;    ///< pointer to the response
  oc_method_t method;         ///< method of the request
#ifdef OC_HAS_FEATURE_ETAG
  // TODO: add support for multiple ETags
  // create an iterator for ETags
  const uint8_t *etag;
  uint8_t etag_len;
#endif /* OC_HAS_FEATURE_ETAG */
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
 */
typedef bool (*oc_set_properties_cb_t)(const oc_resource_t *, const oc_rep_t *,
                                       void *);

/**
 * @brief get properties callback
 */
typedef void (*oc_get_properties_cb_t)(const oc_resource_t *,
                                       oc_interface_mask_t, void *);

#ifdef OC_HAS_FEATURE_PUSH
/**
 * @brief application should define this callback which builds updated contents
 * of pushable Resource
 */
typedef void (*oc_payload_callback_t)(void);

#endif /* OC_HAS_FEATURE_PUSH */

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
#if defined(OC_COLLECTIONS)
  oc_properties_cb_t get_properties; ///< callback for get properties
  oc_properties_cb_t set_properties; ///< callback for set properties
#endif
  double tag_pos_rel[3];             ///< tag relative position [x,y,z]
  oc_pos_description_t tag_pos_desc; ///< tag (value) for position description
  oc_enum_t tag_func_desc;           ///< tag (value) for function description
  oc_locn_t tag_locn;                ///< tag (value) for location description
  uint8_t num_observers;             ///< amount of observers
#ifdef OC_COLLECTIONS
  uint8_t num_links; ///< number of links in the collection
#ifdef OC_HAS_FEATURE_PUSH
  oc_payload_callback_t
    payload_builder; ///< callback to build contents of PUSH Notification
#endif
#endif
  uint16_t observe_period_seconds; ///< observe period in seconds
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_ace_permissions_t
    anon_permission_in_rfotm; ///< permissions for anonymous connection in RFOTM
#endif
#ifdef OC_HAS_FEATURE_ETAG
  uint64_t etag; ///< entity tag (ETag) for the resource
#endif
};

typedef struct oc_collection_s oc_collection_t;

typedef enum {
  OC_EVENT_DONE = 0,
  OC_EVENT_CONTINUE
} oc_event_callback_retval_t;

typedef oc_event_callback_retval_t (*oc_trigger_t)(void *);

/**
 * @brief Filtering function used to match scheduled timed events by context
 * data.
 *
 * @param cb_data Data for the timed event callback
 * @param filter_data User data passed from the caller to the filtering function
 *
 * @see oc_ri_remove_timed_event_callback_by_filter
 */
typedef bool (*oc_ri_timed_event_filter_t)(const void *cb_data,
                                           const void *filter_data);

/**
 * @brief Function invoked with timed event context data before the timed event
 * is deallocated.
 *
 * @note Expected use case is for a dynamically allocated context to be
 * deallocated by this callback.
 *
 * @see oc_ri_remove_timed_event_callback_by_filter
 */
typedef void (*oc_ri_timed_event_on_delete_t)(void *cb_data);

/**
 * @brief add timed event callback
 *
 * @param cb_data the timed event callback info
 * @param event_callback the callback (cannot be NULL)
 * @param ticks time in ticks
 */
OC_API
void oc_ri_add_timed_event_callback_ticks(void *cb_data,
                                          oc_trigger_t event_callback,
                                          oc_clock_time_t ticks) OC_NONNULL(2);

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
    oc_ri_add_timed_event_callback_ticks(cb_data, event_callback,              \
                                         (oc_clock_time_t)(seconds) *          \
                                           (oc_clock_time_t)OC_CLOCK_SECOND);  \
  } while (0)

/**
 * @brief check if the timed event callback already exists.
 *
 * Iterate through the list of timed event callbacks and check if a matching
 * item is found. To match:
 * 1) function pointers must be equal
 * 2) the callback info pointers must be equal or ignore_cb_data must be true
 *
 * @param cb_data the timed event callback info
 * @param event_callback the callback (cannot be NULL)
 * @param ignore_cb_data don't compare the timed event callback info pointers
 * @return true matching timed event callback was found
 * @return false otherwise
 */
OC_API
bool oc_ri_has_timed_event_callback(const void *cb_data,
                                    oc_trigger_t event_callback,
                                    bool ignore_cb_data) OC_NONNULL(2);

/**
 * @brief remove the timed event callback by filter
 *
 * @param cb timed event callback (cannot be NULL)
 * @param filter filtering function (cannot be NULL)
 * @param filter_data user data provided to the filtering function
 * @param match_all iterate over all timed events (otherwise the iteration will
 * stop after the first match)
 * @param on_delete function invoked with the context data of the timed event,
 * before the event is deallocated
 *
 * @note if the matched timed event is currently being processed then the \p
 * on_delete callback will be invoked when the processing is finished. So it
 * might occurr some time after the call to
 * oc_ri_remove_timed_event_callback_by_filter has finished.
 *
 * @see oc_ri_timed_event_filter_t
 */
OC_API
void oc_ri_remove_timed_event_callback_by_filter(
  oc_trigger_t cb, oc_ri_timed_event_filter_t filter, const void *filter_data,
  bool match_all, oc_ri_timed_event_on_delete_t on_delete) OC_NONNULL(1, 2);

/**
 * @brief remove the timed event callback
 *
 * @param cb_data timed event callback info
 * @param event_callback timed event callback
 */
OC_API
void oc_ri_remove_timed_event_callback(const void *cb_data,
                                       oc_trigger_t event_callback)
  OC_NONNULL(2);

/**
 * @brief convert the status code to CoAP status code
 *
 * @param key the application level key of the code
 * @return -1 on failure
 * @return CoAP status code (coap_status_t) on success
 */
OC_API
int oc_status_code(oc_status_t key);

/**
 * @brief convert the CoAP status code to status code
 *
 * @param status CoAP status code
 * @return -1 on failure
 * @return status code (oc_status_t) on success
 */
OC_API
int oc_coap_status_to_status(coap_status_t status);

/**
 * @brief Convert the status code to string
 *
 * @param[in] key key the application level key of the code
 * @return CoAP status code in const char *
 * @return Empty string for an invalid log level value
 */
OC_API
const char *oc_status_to_str(oc_status_t key);

/**
 * @brief Convert method to string. It is thread safe.
 *
 * @return Method in const char *.
 * @return Empty string for an invalid log level value
 */
OC_API
const char *oc_method_to_str(oc_method_t method);

/**
 * @brief retrieve the interface mask from the interface name
 *
 * @param iface the interface string (e.g. "oic.if.s", cannot be NULL)
 * @param iface_len length of the interface string
 * @return 0 on failure
 * @return oc_interface_mask_t the mask value of the interface
 */
OC_API
oc_interface_mask_t oc_ri_get_interface_mask(const char *iface,
                                             size_t iface_len) OC_NONNULL();

#ifdef OC_SERVER
/**
 * @brief retrieve the resource by uri and device index
 *
 * @param uri the uri of the resource
 * @param uri_len the length of the uri
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

/**
 * @brief checks if the resource is valid
 *
 * @param resource resource to be tested
 * @return true valid
 * @return false not valid
 */
OC_API
bool oc_ri_is_app_resource_valid(const oc_resource_t *resource);

/**
 * @brief Check if the resource has been scheduled to by deleted by
 * oc_delayed_delete_resource. Such resource should not be used.
 *
 * @param resource resource to be checked
 * @return true resource is about to be deleted
 * @return false otherwise
 *
 * @see oc_delayed_delete_resource
 */
OC_API
bool oc_ri_is_app_resource_to_be_deleted(const oc_resource_t *resource);

/**
 * @brief add resource to the system
 *
 * @param resource the resource to be added to the list of application resources
 * @return true success
 * @return false failure
 */
OC_API
bool oc_ri_add_resource(oc_resource_t *resource);

/**
 * @brief remove the resource from the list of application resources
 *
 * @param resource the resource to be removed from the list of application
 * resources
 * @return true success
 * @return false failure
 */
OC_API
bool oc_ri_delete_resource(oc_resource_t *resource);

/**
 * @brief Callback invoked on resource before it is deleted by
 * oc_delayed_delete_resource.
 *
 * @param resource Resource to be deleted
 */
typedef void (*oc_ri_delete_resource_cb_t)(oc_resource_t *resource);

/**
 * @brief Add to the global list of callbacks invoked by
 * oc_delayed_delete_resource before each resource is deleted.
 *
 * @param cb the callback to be added (cannot be NULL)
 * @return true on success
 * @return false on error
 */
OC_API
bool oc_ri_on_delete_resource_add_callback(oc_ri_delete_resource_cb_t cb)
  OC_NONNULL();

/**
 * @brief Remove callback from the list of callbacks invoked by
 * oc_delayed_delete_resource.
 *
 * @param cb the callback to be removed (cannot be NULL)
 * @return true callback was found and removed
 * @return false callback was not found
 */
OC_API
bool oc_ri_on_delete_resource_remove_callback(oc_ri_delete_resource_cb_t cb)
  OC_NONNULL();

#endif /* OC_SERVER */

/**
 * @brief retrieve the query value at the nth position
 *
 * @param query the input query
 * @param query_len the query length
 * @param[out] key the key (cannot be NULL)
 * @param[out] key_len the length of the key (cannot be NULL)
 * @param[out] value the value belonging to the key
 * @param[out] value_len the length of the value
 * @param n the position to query (must be > 0)
 * @return int the position of the next key value pair in the query
 * @return int -1 on failure
 */
int oc_ri_get_query_nth_key_value(const char *query, size_t query_len,
                                  const char **key, size_t *key_len,
                                  const char **value, size_t *value_len,
                                  size_t n) OC_NONNULL(3, 4);

/**
 * @brief retrieve the value of the query parameter "key"
 *
 * @param query the input query
 * @param query_len the query length
 * @param key the wanted key (cannot be NULL)
 * @param key_len the length of the wanted key
 * @param value the returned value
 * @return -1 if the key is not found
 * @return the length of the value
 */
int oc_ri_get_query_value_v1(const char *query, size_t query_len,
                             const char *key, size_t key_len,
                             const char **value) OC_NONNULL(3);

/**
 * @brief retrieve the value of the query parameter "key"
 *
 * @deprecated replaced by oc_ri_get_query_value_v1 in v2.2.5.9
 */
int oc_ri_get_query_value(const char *query, size_t query_len, const char *key,
                          const char **value) OC_NONNULL(3)
  OC_DEPRECATED("replaced by oc_ri_get_query_value_v1 in v2.2.5.9");

/**
 * @brief Checks if key exist in query
 *
 * @param query the query to inspect
 * @param query_len the length of the query
 * @param key the key to be checked if exist, key is null terminated (cannot
 * be NULL)
 * @param key_len the key length
 * @return true if key exists
 */
bool oc_ri_query_exists_v1(const char *query, size_t query_len, const char *key,
                           size_t key_len) OC_NONNULL(3);

/**
 * @brief Checks if key exist in query
 *
 * @return -1 if key does not exist
 *
 * @deprecated replaced by oc_ri_query_exists_v1 in v2.2.5.9
 */
int oc_ri_query_exists(const char *query, size_t query_len, const char *key)
  OC_NONNULL(3) OC_DEPRECATED("replaced by oc_ri_query_exists_v1 in v2.2.5.9");

/**
 * @brief check if the nth key exists
 *
 * @param query the query to inspect
 * @param query_len the length of the query
 * @param key the key to be checked if exist, key is not null terminated (cannot
 * be NULL)
 * @param key_len the key length (cannot be NULL)
 * @param n index of the key (must be > 0)
 * @return -1 if key does not exist
 * @return >= 0 if key exists and the value is the position of the next key in
 * the query or query_len if it is the last key
 */
int oc_ri_query_nth_key_exists(const char *query, size_t query_len,
                               const char **key, size_t *key_len, size_t n)
  OC_NONNULL(3, 4);

#ifdef __cplusplus
}
#endif

#endif /* OC_RI_H */
