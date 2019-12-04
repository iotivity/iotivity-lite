/* File oc_ri.o */
%module OCRi
%include "enums.swg"
%javaconst(1);
%include "iotivity.swg"

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

%rename (OCMethod) oc_method_t;
%ignore oc_resource_properties_t;
%rename (OCStatus) oc_status_t;
%rename(OCResponse) oc_response_t;
%rename (separateResponse) oc_response_t::separate_response;
%rename (responseBuffer) oc_response_t::response_buffer;
%ignore oc_interface_mask_t;
%ignore oc_core_resource_t;
%rename (OCRequest) oc_request_t;
%immutable oc_request_t::query;
%rename (queryLen) oc_request_t::query_len;
%rename (requestPayload) oc_request_t::request_payload;
%ignore oc_request_handler_s;

%ignore oc_properties_cb_t;
%ignore oc_properties_cb_t_cb;

%rename(OCResource) oc_resource_s;
%immutable oc_resource_s::next;
%immutable oc_resource_s::device;
%immutable oc_resource_s::name;
%immutable oc_resource_s::uri;
%immutable oc_resource_s::types;
%immutable oc_resource_s::interfaces;
%rename("%(lowercamelcase)s") default_interface;
%immutable oc_resource_s::default_interface;
%immutable oc_resource_s::properties;
// handlers are added to the code using the mainInit function and are not expected to be read by Java code
%ignore oc_resource_s::get_handler;
%ignore oc_resource_s::put_handler;
%ignore oc_resource_s::post_handler;
%ignore oc_resource_s::delete_handler;
%ignore oc_resource_s::get_properties;
%ignore oc_resource_s::set_properties;
%rename(tagPositionRelative) oc_resource_s::tag_pos_rel;
%immutable oc_resource_s::tag_pos_rel;
%rename(tagPositionDescription) oc_resource_s::tag_pos_desc;
%immutable oc_resource_s::tag_pos_desc;
%rename(tagFunctionDescription) oc_resource_s::tag_func_desc;
%immutable oc_resource_s::tag_func_desc;
%rename("%(lowercamelcase)s") num_observers;
%immutable oc_resource_s::num_observers;
%rename("%(lowercamelcase)s") num_links;
%immutable oc_resource_s::num_links;
%rename("%(lowercamelcase)s") observe_period_seconds;
%immutable oc_resource_s::observe_period_seconds;
// get/set properties callbacks are not expected to be read or writen directly to by Java code.
%ignore oc_resource_s::get_properties;
%ignore oc_resource_s::set_properties;

%rename(OCEventCallbackResult) oc_event_callback_retval_t;
%ignore oc_event_callback_s;

%ignore oc_ri_init;
%ignore oc_ri_shutdown;
%ignore oc_ri_add_timed_event_callback_ticks;
%ignore oc_ri_remove_timed_event_callback;
%ignore oc_status_code;
%ignore oc_ri_get_app_resource_by_uri;
%ignore oc_ri_get_app_resources;
%ignore oc_ri_alloc_resource;
%ignore oc_ri_alloc_resource;
%ignore oc_ri_add_resource;
%ignore oc_ri_delete_resource;
%ignore oc_ri_free_resource_properties;
%ignore oc_ri_get_query_nth_key_value;
%ignore oc_ri_get_query_value;
%ignore oc_ri_get_interface_mask;

/***************************************************************
structs from oc_coap
***************************************************************/
/*
 * Currently no known use case that the end user will access this buffer
 * of this must be exposed then work must be done to convert buffer to a java byte[]
 */
%ignore buffer;
%ignore OC_LIST_STRUCT(requests);
%rename(OCSeparateResponse) oc_separate_response_s;
struct oc_separate_response_s
{
  OC_LIST_STRUCT(requests);
  int active;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
};

%rename(OCResponseBuffer) oc_response_buffer_s;
/*
 * Currently no known use case that the end user will access this buffer
 * of this must be exposed then work must be done to convert buffer and buffer_size to a java byte[]
 */
%ignore oc_response_buffer_s::buffer;
%ignore oc_response_buffer_s::buffer_size;
%rename (responseLength) oc_response_buffer_s::response_length;
typedef struct oc_response_buffer_s
{
  uint8_t *buffer;
  uint16_t buffer_size;
  uint16_t response_length;
  int code;
} oc_response_buffer_t;

%include "oc_ri.h"