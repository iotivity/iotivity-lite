#include "oc_api.h"
#include "oc_bridge.h"
#include "oc_core_res.h"
#include "virtual_airpurifier_server.h"
#include "pthread.h"

static char *g_airpurifier_operationmode[MAX_AIRPURIFIER_MODES] = {"Auto", "Quiet", "Sleep"};
static char g_airpurifier_mode[10] = "Auto";
static int64_t g_airpurifier_availablelevels[MAX_AIRPURIFIER_LEVELS] = {1,2,3,4,5};
static int64_t g_airpurifier_targetlevel = 1;
static bool g_airpurifier_binary_switch = false;
static size_t g_airpurifier_device_num;
static oc_device_info_t *airpurifier_device_info = NULL;
pthread_mutex_t post_mutex;

uplus_airpurifier g_airpurifier = {.binary_switch = false,
                                   .level = 1,
                                   .mode = "Auto"};

oc_device_info_t*
uplus_airpurifier_init(const char* uri, const char* name)
{   
    airpurifier_device_info = oc_add_bridgee_device(uri, OC_AIRPURIFIER_DEVICE_TYPE, name);
    g_airpurifier_device_num = oc_core_get_num_devices()-1;
    return airpurifier_device_info;
}

static void
get_airpurifier_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    oc_status_t resp = OC_STATUS_OK;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:

        case OC_IF_RW:
            oc_rep_set_boolean(root, value, g_airpurifier.binary_switch);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    printf("get binaryswitch\n");
    oc_send_response(request, resp);
}

static void
post_airpurifier_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    oc_status_t resp = OC_STATUS_CHANGED;
    PRINT("POST_BinarySwitch\n");
    oc_rep_t *rep = request->request_payload;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:

        case OC_IF_RW:
            oc_rep_get_bool(rep, "value", &g_airpurifier_binary_switch);
            bool *temp_binary_switch = &g_airpurifier_binary_switch;
            resp = uplus_device_post(g_airpurifier_device_num, OC_REP_BOOL, DERIVED_BINARY_SWITCH, (void**)&temp_binary_switch);
            PRINT("binaryswitch: %d\n", g_airpurifier_binary_switch);
            oc_rep_set_boolean(root, value, g_airpurifier.binary_switch);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
put_airpurifier_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  post_airpurifier_binary_switch(request, iface_mask, user_data);
}

static void
get_airpurifier_mode(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    oc_string_array_t airpurifier_modes;
    oc_string_array_t airpurifier_operation_mode;
    oc_status_t resp = OC_STATUS_OK;
    printf("get mode\n");
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:

        case OC_IF_RW:
            oc_new_string_array(&airpurifier_modes, (size_t)1);
            oc_string_array_add_item(airpurifier_modes, g_airpurifier.mode);
            oc_rep_set_string_array(root, modes, airpurifier_modes);
            oc_new_string_array(&airpurifier_operation_mode, (size_t)MAX_AIRPURIFIER_MODES);
            for(int i = 0; i< MAX_AIRPURIFIER_MODES; i++)
            {
                oc_string_array_add_item(airpurifier_operation_mode, g_airpurifier_operationmode[i]);
            }
            oc_rep_set_string_array(root, supportedModes, airpurifier_operation_mode);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
post_airpurifier_mode(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    size_t str_len;
    oc_status_t resp = OC_STATUS_CHANGED;
    PRINT("POST_Mode\n");
    oc_rep_t *rep = request->request_payload;
    oc_string_array_t airpurifier_modes;
    oc_rep_start_root_object();
    
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:
            oc_new_string_array(&airpurifier_modes, (size_t)3);
            oc_rep_get_string_array(rep, "modes", &airpurifier_modes, &str_len);
            char* temp_modes=oc_string_array_get_item(airpurifier_modes, 0);
            int i;
            for(i = 0; i< MAX_AIRPURIFIER_MODES; i++)
            {
                if(!strcmp(g_airpurifier_operationmode[i], temp_modes))
                    break;
            }
            if(i == MAX_AIRPURIFIER_MODES)
            {
                resp = OC_STATUS_BAD_REQUEST;
                break;
            }
            strcpy(g_airpurifier_mode, temp_modes);
            resp = uplus_device_post(g_airpurifier_device_num, OC_REP_STRING, DERIVED_MODE, (void**)&g_airpurifier_mode);
            PRINT("mode: %s\n", g_airpurifier_mode);
            oc_new_string_array(&airpurifier_modes, (size_t)1);
            oc_string_array_add_item(airpurifier_modes, g_airpurifier.mode);
            oc_rep_set_string_array(root, modes, airpurifier_modes);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
put_airpurifier_mode(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    post_airpurifier_mode(request, iface_mask, user_data);
}

static void
get_airpurifier_wind_speed(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    oc_status_t resp = OC_STATUS_OK;
    printf("get wind speed\n");
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:
           oc_rep_set_int_array(root, availablelevels,g_airpurifier_availablelevels,
            (int)(sizeof(g_airpurifier_availablelevels)/sizeof(g_airpurifier_availablelevels[0])));
           oc_rep_set_int(root, targetlevel, g_airpurifier.level);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
post_airpurifier_wind_speed(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
    (void)iface_mask;
    (void)user_data;;
    oc_status_t resp = OC_STATUS_CHANGED;
    PRINT("POST_WIND_SPEED\n");
    oc_rep_t *rep = request->request_payload;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:
           oc_rep_get_int(rep, "targetlevel", &g_airpurifier_targetlevel);
           PRINT("target level: %d\n", g_airpurifier_targetlevel);
           int i;
           for(i = 0; i < MAX_AIRPURIFIER_LEVELS; i++)
           {
               if(g_airpurifier_targetlevel == g_airpurifier_availablelevels[i])
                   break;
           }
           if(i == MAX_AIRPURIFIER_LEVELS)
           {
               resp = OC_STATUS_BAD_REQUEST;
               break;
           }
           int64_t * temp_level = &g_airpurifier_targetlevel;
           resp = uplus_device_post(g_airpurifier_device_num, OC_REP_INT, DERIVED_LEVEL, (void**)&temp_level);
           oc_rep_set_int(root, targetlevel, g_airpurifier.level);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;  
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}
static void
put_airpurifier_wind_speed(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    post_airpurifier_wind_speed(request, iface_mask, user_data);
}

void
register_airpurifier_resources(void)
{
    /********************   airpurifier   ******************/
    //binary switch resource
    oc_resource_t *airpurifier_binary_switch_res = oc_new_resource(NULL, "/BinarySwitchResURI", 1, g_airpurifier_device_num);
    oc_resource_bind_resource_type(airpurifier_binary_switch_res, "oic.r.switch.binary");
    oc_resource_bind_resource_interface(airpurifier_binary_switch_res, OC_IF_A);
    oc_resource_set_default_interface(airpurifier_binary_switch_res, OC_IF_A);
    oc_resource_set_discoverable(airpurifier_binary_switch_res, true);
    oc_resource_set_periodic_observable(airpurifier_binary_switch_res,1);
    oc_resource_set_request_handler(airpurifier_binary_switch_res, OC_GET, get_airpurifier_binary_switch, NULL);
    oc_resource_set_request_handler(airpurifier_binary_switch_res, OC_PUT, put_airpurifier_binary_switch, NULL);
    oc_resource_set_request_handler(airpurifier_binary_switch_res, OC_POST, post_airpurifier_binary_switch, NULL);
    oc_add_resource(airpurifier_binary_switch_res);
    //mode resource
    oc_resource_t *airpurifier_mode_res = oc_new_resource(NULL, "/ModeResURI", 1, g_airpurifier_device_num);
    oc_resource_bind_resource_type(airpurifier_mode_res, "oic.r.mode");
    oc_resource_bind_resource_interface(airpurifier_mode_res, OC_IF_A);
    oc_resource_set_default_interface(airpurifier_mode_res, OC_IF_A);
    oc_resource_set_discoverable(airpurifier_mode_res, true);
    oc_resource_set_request_handler(airpurifier_mode_res, OC_GET, get_airpurifier_mode, NULL);
    oc_resource_set_request_handler(airpurifier_mode_res, OC_PUT, put_airpurifier_mode, NULL);
    oc_resource_set_request_handler(airpurifier_mode_res, OC_POST, post_airpurifier_mode, NULL);
    oc_add_resource(airpurifier_mode_res);
    //selectabelevels resource
    oc_resource_t *airpurifier_selectabelevels_res = oc_new_resource(NULL, "/SelectableLevelsResURI", 1, g_airpurifier_device_num);
    oc_resource_bind_resource_type(airpurifier_selectabelevels_res, "oic.r.selectablelevels");;
    oc_resource_bind_resource_interface(airpurifier_selectabelevels_res, OC_IF_A);
    oc_resource_set_default_interface(airpurifier_selectabelevels_res, OC_IF_A);
    oc_resource_set_discoverable(airpurifier_selectabelevels_res, true);
    oc_resource_set_request_handler(airpurifier_selectabelevels_res, OC_GET, get_airpurifier_wind_speed, NULL);
    oc_resource_set_request_handler(airpurifier_selectabelevels_res, OC_PUT, put_airpurifier_wind_speed, NULL);
    oc_resource_set_request_handler(airpurifier_selectabelevels_res, OC_POST, post_airpurifier_wind_speed, NULL);
    oc_add_resource(airpurifier_selectabelevels_res);
  
}

int 
uplus_post_airpurifier(uplus_airpurifier airpurifier)
{
    pthread_mutex_lock(&post_mutex);
    g_airpurifier.binary_switch = airpurifier.binary_switch;
    g_airpurifier.level = airpurifier.level;
    strcpy(g_airpurifier.mode, airpurifier.mode);
    pthread_mutex_unlock(&post_mutex);
    return 0;
}


