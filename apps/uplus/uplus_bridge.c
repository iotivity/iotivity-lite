#include "oc_api.h"
#include "uplus_bridge.h"
#include "oc_core_res.h"
#include "../security/oc_doxm.h"
#include "../security/oc_store.h"

static oc_device_info_t* virtual_device_info[MAX_VODS] = {NULL};
static oc_device_info_t* bridge_device_info = NULL;
static oc_platform_info_t* bridge_platform_info;

static int64_t vods_num = 0;

int 
uplus_bridge_init(const char *name, const char *platform_name)
{
    bridge_platform_info = oc_core_init_platform(platform_name, NULL, NULL);
    oc_set_con_res_announced(false);
    bridge_device_info = oc_core_add_new_device("/oic/d", OC_BRIDGE_DEVICE_TYPE, name, SPEC_VERSION, DATAMODEL_VERSION, NULL, NULL);
    return 0;  
} 




static void
get_bridge(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    char di[OC_UUID_LEN];
    oc_sec_doxm_t *bridge_doxm = NULL;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_R:
       
            oc_rep_set_array(root,vods);
            for(int i = 0; i < vods_num; i++){
              
                bridge_doxm = oc_sec_get_doxm(i+1);
                if(bridge_doxm->owned){
                    oc_rep_object_array_begin_item(vods);
                    oc_rep_set_text_string(vods, n, oc_string(virtual_device_info[i]->name));
                    oc_uuid_to_str(&(bridge_doxm->deviceuuid), di, OC_UUID_LEN);
                    oc_rep_set_text_string(vods, di, di);
                    oc_rep_set_text_string(vods, econame, "Uplus");
                    oc_rep_object_array_end_item(vods);
                }
                
            }
            oc_rep_close_array(root,vods);    
            break;
        default:
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
}




oc_status_t 
uplus_device_post(size_t device_num, oc_rep_value_type_t type, const char *derived_type, void **value)
{
    return OC_STATUS_CHANGED;
}


void 
register_bridge_resources()
{
    oc_resource_t *bridge_res = oc_new_resource(NULL, "/vodlist", 1, 0);
    oc_resource_bind_resource_type(bridge_res , "oic.r.vodlist");
    oc_resource_bind_resource_interface(bridge_res , OC_IF_R);
    oc_resource_set_default_interface(bridge_res , OC_IF_R);
    oc_resource_set_discoverable(bridge_res , true);
    oc_resource_set_periodic_observable(bridge_res ,1);
    oc_resource_set_request_handler(bridge_res , OC_GET, get_bridge, NULL);
    oc_add_resource(bridge_res);
}



oc_device_info_t*
uplus_add_bridge_device(const char* uri, const char* rt, const char* name)
{
    printf("add bridge device\n");
    virtual_device_info[vods_num] = oc_core_add_new_device(uri, rt, name, SPEC_VERSION, SERVER_DATAMODEL_VERSION, NULL, NULL);
    oc_resource_t *r = oc_core_get_resource_by_index(OCF_D, oc_core_get_num_devices()-1);
    oc_free_string_array(&(r->types));
    oc_new_string_array(&r->types, 3);
    oc_string_array_add_item(r->types, "oic.wk.d");
    oc_string_array_add_item(r->types, "oic.d.virtual");
    oc_string_array_add_item(r->types, rt);
    vods_num++;
    return virtual_device_info[vods_num-1];
}



void 
uplus_bridge_sec_load(size_t device)
{
#ifdef OC_SECURITY
    oc_sec_load_unique_ids(device);
    oc_sec_load_pstat(device);
    oc_sec_load_doxm(device);
    oc_sec_load_cred(device);
    oc_sec_load_acl(device);
#endif
}



void
uplus_set_vod_discoverable(size_t device)
{
    oc_resource_t *vod_res = NULL;
    vod_res = oc_core_get_resource_by_index(OCF_RES, device);
    oc_resource_set_discoverable(vod_res, false);

}

int
uplus_bridge_main_init(const oc_handler_t *handler)
{
    oc_main_init(handler);
    oc_sec_doxm_t *bridge_doxm = NULL;
    oc_sec_doxm_t *vod_doxm = NULL;
    oc_resource_t *vod_res = NULL;
    bridge_doxm = oc_sec_get_doxm(0);
    if(!bridge_doxm->owned)
    {
        for(int i = 1; i < vods_num+1; i++)
        {
            vod_doxm = oc_sec_get_doxm(i);
            if(!vod_doxm->owned)
            {
                vod_res = oc_core_get_resource_by_index(OCF_RES, i);
                oc_resource_set_discoverable(vod_res, false);
            }
        }
    }
    return 0;
}
