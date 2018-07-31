/* File oc_ri.o */
%module ri
%include "enums.swg"
%javaconst(1);
%include "iotivity.swg"
%include "oc_api.i"
%{
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