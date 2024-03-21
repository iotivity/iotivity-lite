/* File oc_endpoint_address.i */
%module OCEndpointAddressUtil

%include "typemaps.i"
%include "iotivity.swg"

%import "oc_uuid.i"

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
#include "oc_iotivity_lite_jni.h"

#include "util/oc_endpoint_address_internal.h"
#include "util/oc_endpoint_address.h"
%}

/*******************Begin oc_endpoint_address.h****************************/

// TODO implement
%ignore oc_endpoint_address_metadata_id_t;
%ignore oc_endpoint_address_metadata_id_view_t;
%ignore oc_endpoint_address_metadata_t;
%ignore oc_endpoint_address_metadata_view_t;
%ignore oc_endpoint_address_view_t;
%ignore oc_endpoint_address_view;
%ignore oc_endpoint_address_make_view_with_uuid;
%ignore oc_endpoint_address_make_view_with_name;

%ignore oc_endpoint_address_uri;
%ignore oc_endpoint_address_set_uuid;
%ignore oc_endpoint_address_uuid;
%ignore oc_endpoint_address_set_name;
%ignore oc_endpoint_address_name;

%ignore oc_endpoint_address_t::next;
%ignore oc_endpoint_address_t::id;
%ignore oc_endpoint_address_t::uri;

%rename(OCEndpointAddress) oc_endpoint_address_t;
%ignore oc_endpoint_address_t::metadata;

%extend oc_endpoint_address_t {
  const char *getUri() {
    const oc_string_t* uri = oc_endpoint_address_uri(self);
    if (uri == NULL) {
      return NULL;
    }
    return oc_string(*uri);
  }

  void setUUID(oc_uuid_t uuid) {
    oc_endpoint_address_set_uuid(self, uuid);
  }

  const oc_uuid_t* getUUID() {
    return oc_endpoint_address_uuid(self);
  }

  void setName(const char* name) {
    oc_endpoint_address_set_name(self, name, strlen(name));
  }

  const char* getName() {
     const oc_string_t* name = oc_endpoint_address_name(self);
      if (name == NULL) {
        return NULL;
      }
      return oc_string(*name);
  }
}

#define OC_API
#define OC_NONNULL(...)
%include "util/oc_endpoint_address.h"

/*******************End oc_endpoint_address.h****************************/


/*******************Begin oc_endpoint_address_internal.h****************************/

%ignore oc_endpoint_address_metadata_type_t;
%ignore oc_endpoint_address_encode;
%ignore on_selected_endpoint_address_change_fn_t;
%ignore oc_endpoint_addresses_on_selected_change_t;

%ignore oc_endpoint_addresses_t;
%ignore oc_endpoint_addresses_init;
%ignore oc_endpoint_addresses_deinit;
%ignore oc_endpoint_addresses_reinit;
%ignore oc_endpoint_addresses_size;
%ignore oc_endpoint_addresses_is_empty;
%ignore oc_endpoint_addresses_contains;
%ignore oc_endpoint_addresses_iterate;
%ignore oc_endpoint_addresses_find;
%ignore oc_endpoint_addresses_add;
%ignore oc_endpoint_addresses_remove;
%ignore oc_endpoint_addresses_remove_by_uri;
%ignore oc_endpoint_addresses_clear;
%ignore oc_endpoint_addresses_select;
%ignore oc_endpoint_addresses_select_by_uri;
%ignore oc_endpoint_addresses_select_next;
%ignore oc_endpoint_addresses_is_selected;
%ignore oc_endpoint_addresses_selected;
%ignore oc_endpoint_addresses_selected_uri;
%ignore oc_endpoint_addresses_selected_uuid;
%ignore oc_endpoint_addresses_selected_name;
%ignore oc_endpoint_addresses_encode;
%ignore oc_endpoint_addresses_set_on_selected_change;
%ignore oc_endpoint_addresses_get_on_selected_change;

%include "util/oc_endpoint_address_internal.h"

/*******************End oc_endpoint_address_internal.h****************************/
