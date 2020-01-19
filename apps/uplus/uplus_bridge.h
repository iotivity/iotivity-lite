#include "oc_core_res.h"

#define MAX_VODS                              3
#define MAX_VIRTUAL_RT_SIZE                   64
#define MAX_VOD_NAME                          64
#define SPEC_VERSION                          "ocf.2.0.0"
#define DATAMODEL_VERSION                     "ocf.res.1.3.0"
#define SERVER_DATAMODEL_VERSION              "ocf.res.1.3.0,ocf.sh.1.3.0"
#define OC_BRIDGE_DEVICE_TYPE                 "oic.d.bridge"

void 
register_bridge_resources();
int 
uplus_bridge_init(const char *name, const char *platform_name);
oc_device_info_t* 
uplus_add_bridge_device(const char* uri, const char* rt, const char* name);
oc_status_t
uplus_device_post(size_t device_num, oc_rep_value_type_t type, const char *derived_type, void **value);
int
uplus_bridge_main_init(const oc_handler_t *handler);