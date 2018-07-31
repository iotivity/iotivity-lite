/* File oc_resource.i */
%module OCResource
%{
#define OC_SERVER=1
#define OC_CLIENT=1

#include "../../include/oc_api.h"

class Resource {
  public:
    Resource(const char *name, const char *url, uint8_t num_resource_types, int device) {
      res = oc_new_resource(name, url, num_resource_types, device);
    }
    
    void bindResourceType(const char *type) {
      oc_resource_bind_resource_type(res, type);
    }
    
    void bindResourceInterface(uint8_t interface) {
      oc_resource_bind_resource_interface(res, interface);
    }
  private:
    oc_resource_t * res;  
};
%}

class Resource {
  public:
    Resource(const char *name, const char *url, uint8_t num_resource_types, int device);
    void bindResourceType(const char *type);
    void bindResourceInterface(uint8_t interface);
};