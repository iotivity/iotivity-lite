/* File oc_ri.o */
%module OCRi
%include "enums.swg"
%javaconst(1);
%include "iotivity.swg"
%include "oc_api.i"

%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("iotivity-lite-jni");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}

%{
#include "../../messaging/coap/oc_coap.h"
#include "../../include/oc_ri.h"
%}

%rename (OCStatus) oc_status_t;
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

%rename(OCResponse) oc_response_t;
typedef struct
{
  oc_separate_response_t *separate_response;
  oc_response_buffer_t *response_buffer;
} oc_response_t;

%rename (OCInterfaceMask) oc_interface_mask_t;
typedef enum {
  OC_IF_BASELINE = 1 << 1,
  OC_IF_LL = 1 << 2,
  OC_IF_B = 1 << 3,
  OC_IF_R = 1 << 4,
  OC_IF_RW = 1 << 5,
  OC_IF_A = 1 << 6,
  OC_IF_S = 1 << 7,
} oc_interface_mask_t;

%rename (OCMethod) oc_method_t;
typedef enum { 
  OC_GET = 1,
  OC_POST,
  OC_PUT,
  OC_DELETE
} oc_method_t;

/*
%rename (OCResourceProperties) oc_resource_properties_t;
typedef enum {
  OC_DISCOVERABLE = (1 << 0),
  OC_OBSERVABLE = (1 << 1),
  OC_SECURE = (1 << 4),
  OC_PERIODIC = (1 << 6),
} oc_resource_properties_t;
*/

%rename (OCRequest) oc_request_t;
typedef struct
{
  oc_endpoint_t *origin;
  oc_resource_t *resource;
  const char *query;
  size_t query_len;
  oc_rep_t *request_payload;
  oc_response_t *response;
} oc_request_t;

%rename(OCResource) oc_resource_t;
%rename("%(lowercamelcase)s") default_interface;
// handlers are added to the code using the mainInit function and are not expected to be read by Java code
%ignore get_handler;
%ignore put_handler;
%ignore post_handler;
%ignore delete_handler;
%rename("%(lowercamelcase)s") observe_period_seconds;
%rename("%(lowercamelcase)s") num_observers;
typedef struct
{
  struct oc_resource_t *next;
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
}oc_resource_t;

%rename(OCEventCallbackResult) oc_event_callback_retval_t;
typedef enum {
  OC_EVENT_DONE = 0,
  OC_EVENT_CONTINUE
} oc_event_callback_retval_t;

/***************************************************************
structs from oc_coap
***************************************************************/
// replace all instances of oc_separate_response_s with oc_separate_response_t since parser
// seems to have a problem with typedef that tells the code they are both the same
%rename(OCSeparateResponse) oc_separate_response_t;
/*
 * Currently no known use case that the end user will access this buffer
 * of this must be exposed then work must be done to convert buffer to a java byte[]
 */
%ignore buffer;
typedef struct
{
  OC_LIST_STRUCT(requests);
  int active;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
} oc_separate_response_t;

%rename(OCResponseBuffer) oc_response_buffer_t;
/*
 * Currently no known use case that the end user will access this buffer
 * of this must be exposed then work must be done to convert buffer and buffer_size to a java byte[]
 */
%ignore buffer;
%ignore buffer_size;
typedef struct
{
  uint8_t *buffer;
  uint16_t buffer_size;
  uint16_t response_length;
  int code;
} oc_response_buffer_t;
