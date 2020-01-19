#include "oc_api.h"
#include "uplus_bridge.h"
#include "oc_core_res.h"
#include "virtual_airconditioner_server.h"
#include "pipe0.h"
#include "pthread.h"

static char *g_airconditioner_operationmode[MAX_airconditioner_MODES] = {"Auto", "Quiet", "Sleep"};
static char g_airconditioner_mode[10] = "Auto";
static double g_airconditioner_temperature = 20.0;
static bool g_airconditioner_binary_switch = false;
static size_t g_airconditioner_device_num;
static oc_device_info_t *airconditioner_device_info = NULL;
oc_uuid_t airconditioner_piid;
pthread_mutex_t post_mutex;

uplus_airconditioner g_airconditioner = {.binary_switch = false,
                                   .temperature = 20.0,
                                   .mode = "Auto",
                                   .units = "C"};

const char Airconditioner_devid[33] = "04FA8316D72A";

oc_device_info_t*
uplus_airconditioner_init(const char* uri, const char* name)
{   
    airconditioner_device_info = uplus_add_bridge_device(uri, OC_airconditioner_DEVICE_TYPE, name);
    g_airconditioner_device_num = oc_core_get_num_devices()-1;
    oc_str_to_uuid(AirConditionerID, &airconditioner_piid);
    oc_set_immutable_device_identifier(g_airconditioner_device_num, &airconditioner_piid);
    return airconditioner_device_info;
}

static void
get_airconditioner_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
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
            oc_rep_set_boolean(root, value, g_airconditioner.binary_switch);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
post_airconditioner_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
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
            oc_rep_get_bool(rep, "value", &g_airconditioner_binary_switch);
            bool *temp_binary_switch = &g_airconditioner_binary_switch;
            resp = uplus_device_post(g_airconditioner_device_num, OC_REP_BOOL, DERIVED_BINARY_SWITCH, (void**)&temp_binary_switch);
            if(resp == OC_STATUS_CHANGED)
                g_airconditioner.binary_switch = g_airconditioner_binary_switch;
            PRINT("binaryswitch: %d\n", g_airconditioner_binary_switch);
            oc_rep_set_boolean(root, value, g_airconditioner.binary_switch);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
put_airconditioner_binary_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  post_airconditioner_binary_switch(request, iface_mask, user_data);
}

static void
get_airconditioner_mode(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    oc_string_array_t airconditioner_modes;
    oc_string_array_t airconditioner_operation_mode;
    oc_status_t resp = OC_STATUS_OK;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:

        case OC_IF_RW:
            oc_new_string_array(&airconditioner_modes, (size_t)1);
            oc_string_array_add_item(airconditioner_modes, g_airconditioner.mode);
            oc_rep_set_string_array(root, modes, airconditioner_modes);
            oc_new_string_array(&airconditioner_operation_mode, (size_t)MAX_airconditioner_MODES);
            for(int i = 0; i< MAX_airconditioner_MODES; i++)
            {
                oc_string_array_add_item(airconditioner_operation_mode, g_airconditioner_operationmode[i]);
            }
            oc_rep_set_string_array(root, supportedModes, airconditioner_operation_mode);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
post_airconditioner_mode(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    size_t str_len;
    oc_status_t resp = OC_STATUS_CHANGED;
    PRINT("POST_Mode\n");
    oc_rep_t *rep = request->request_payload;
    oc_string_array_t airconditioner_modes;
    oc_rep_start_root_object();
    
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:
            oc_new_string_array(&airconditioner_modes, (size_t)3);
            oc_rep_get_string_array(rep, "modes", &airconditioner_modes, &str_len);
            char* temp_modes=oc_string_array_get_item(airconditioner_modes, 0);
            int i;
            for(i = 0; i< MAX_airconditioner_MODES; i++)
            {
                if(!strcmp(g_airconditioner_operationmode[i], temp_modes))
                    break;
            }
            if(i == MAX_airconditioner_MODES)
            {
                resp = OC_STATUS_BAD_REQUEST;
                break;
            }
            strcpy(g_airconditioner_mode, temp_modes);
            resp = uplus_device_post(g_airconditioner_device_num, OC_REP_STRING, DERIVED_MODE, (void**)&g_airconditioner_mode);
            if(resp == OC_STATUS_CHANGED)
                 strcpy(g_airconditioner.mode, temp_modes);
            PRINT("mode: %s\n", g_airconditioner_mode);
            oc_new_string_array(&airconditioner_modes, (size_t)1);
            oc_string_array_add_item(airconditioner_modes, g_airconditioner.mode);
            oc_rep_set_string_array(root, modes, airconditioner_modes);
            break;
        default:
            resp = OC_STATUS_BAD_REQUEST;
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
put_airconditioner_mode(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    post_airconditioner_mode(request, iface_mask, user_data);
}


static void
get_airconditioner_temperature(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)user_data;
    oc_status_t resp = OC_STATUS_OK;
    char *temp_units = NULL;
    oc_rep_start_root_object();
    switch(iface_mask)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        case OC_IF_A:
            //
            if(-1!=oc_get_query_value(request, "units", &temp_units))
            {                    
                if(temp_units[0]=='C')
                {
                
                    if(strcmp(g_airconditioner.units, "K")==0)
                    {
                        
                        g_airconditioner.temperature -= 273.15;
                    }
                    if(strcmp(g_airconditioner.units, "F")==0)
                    {
                        g_airconditioner.temperature = (g_airconditioner.temperature-32)*5/9;
                    }
                }
                else if(temp_units[0]=='K')
                {
                    if(strcmp(g_airconditioner.units, "C")==0)
                    {  
                        g_airconditioner.temperature += 273.15;
                    }
                    else if(strcmp(g_airconditioner.units, "F")==0)
                    {
                        g_airconditioner.temperature = (g_airconditioner.temperature-32)*5/9+273.15;
                    }
                }
                else if(temp_units[0]=='F')
                {
                    if(strcmp(g_airconditioner.units, "C")==0)
                    {  
                        g_airconditioner.temperature = g_airconditioner.temperature*9/5+32;
                    }
                    else if(strcmp(g_airconditioner.units, "K")==0)
                    {
                        g_airconditioner.temperature = (g_airconditioner.temperature-273.15)*9/5+32;
                    }
                }
                else
                {
                    resp = OC_STATUS_FORBIDDEN; 
                }
                

                g_airconditioner.units[0] = temp_units[0];
                
            }
            oc_rep_set_double(root, temperature, g_airconditioner.temperature);
            oc_rep_set_text_string(root, units, g_airconditioner.units);


            break;
        default:
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, resp);
}

static void
post_airconditioner_temperature(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    oc_status_t resp = OC_STATUS_CHANGED;
    char *temp_units = NULL;
    size_t units_size = 0;
    PRINT("POST_Temperature\n");
    oc_rep_t *rep = request->request_payload;
    oc_rep_start_root_object();
    if(oc_rep_get_double(rep, "temperature", &g_airconditioner_temperature))
    {
        if(oc_rep_get_string(rep, "units", &temp_units, &units_size))
        {

            if(strcmp(temp_units, "C")&&strcmp(temp_units, "K")&&strcmp(temp_units, "F"))
            {
                
                    resp = OC_STATUS_FORBIDDEN; 
            }
           
        }
        if(resp != OC_STATUS_FORBIDDEN)
        {
            double *temp_temperature = &g_airconditioner_temperature;
            resp = uplus_device_post(g_airconditioner_device_num, OC_REP_DOUBLE, DERIVED_TEMPERATURE, (void**)&temp_temperature);
            if(resp == OC_STATUS_CHANGED)
            {  
                g_airconditioner.temperature = g_airconditioner_temperature;
                if(temp_units)
                    strcpy(g_airconditioner.units, temp_units);
            }    
            PRINT("temperature: %f\n",g_airconditioner_temperature); 
        }
    }
    else{
        resp = OC_STATUS_FORBIDDEN;
    }
    oc_rep_set_double(root, temperature, g_airconditioner.temperature);
    oc_rep_set_text_string(root, units, g_airconditioner.units);
     oc_rep_end_root_object();
    oc_send_response(request, resp);
}

void 
ugw_airconditioner_send(char* name,char* value)
{
    struct msg mym;
    strcpy(mym.devid,Airconditioner_devid);
    strcpy(mym.name,name);
    strcpy(mym.value,value);
    write_pipe(mym);
}



static void
put_airconditioner_temperature(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    post_airconditioner_temperature(request, iface_mask, user_data);
}

void
register_airconditioner_resources(void)
{
    /********************   airconditioner   ******************/
    //binary switch resource
    oc_resource_t *airconditioner_binary_switch_res = oc_new_resource(NULL, "/binaryswitch", 1, g_airconditioner_device_num);
    oc_resource_bind_resource_type(airconditioner_binary_switch_res, "oic.r.switch.binary");
    oc_resource_bind_resource_interface(airconditioner_binary_switch_res, OC_IF_A);
    oc_resource_set_default_interface(airconditioner_binary_switch_res, OC_IF_A);
    oc_resource_set_discoverable(airconditioner_binary_switch_res, true);
    oc_resource_set_periodic_observable(airconditioner_binary_switch_res,1);
    oc_resource_set_request_handler(airconditioner_binary_switch_res, OC_GET, get_airconditioner_binary_switch, NULL);
    oc_resource_set_request_handler(airconditioner_binary_switch_res, OC_PUT, put_airconditioner_binary_switch, NULL);
    oc_resource_set_request_handler(airconditioner_binary_switch_res, OC_POST, post_airconditioner_binary_switch, NULL);
    oc_add_resource(airconditioner_binary_switch_res);
    //mode resource
    oc_resource_t *airconditioner_mode_res = oc_new_resource(NULL, "/ModeResURI", 1, g_airconditioner_device_num);
    oc_resource_bind_resource_type(airconditioner_mode_res, "oic.r.mode");
    oc_resource_bind_resource_interface(airconditioner_mode_res, OC_IF_A);
    oc_resource_set_default_interface(airconditioner_mode_res, OC_IF_A);
    oc_resource_set_discoverable(airconditioner_mode_res, true);
    oc_resource_set_request_handler(airconditioner_mode_res, OC_GET, get_airconditioner_mode, NULL);
    oc_resource_set_request_handler(airconditioner_mode_res, OC_PUT, put_airconditioner_mode, NULL);
    oc_resource_set_request_handler(airconditioner_mode_res, OC_POST, post_airconditioner_mode, NULL);
    oc_add_resource(airconditioner_mode_res);
    //temperature resource
    oc_resource_t *temperature_res = oc_new_resource(NULL, "/temperature", 1, g_airconditioner_device_num);
    oc_resource_bind_resource_type(temperature_res, "oic.r.temperature");
    oc_resource_bind_resource_interface(temperature_res, OC_IF_A);
    oc_resource_set_default_interface(temperature_res, OC_IF_A);
    oc_resource_set_discoverable(temperature_res, true);
    oc_resource_set_periodic_observable(temperature_res,1);
    oc_resource_set_request_handler(temperature_res, OC_GET, get_airconditioner_temperature, NULL);
    oc_resource_set_request_handler(temperature_res, OC_PUT, put_airconditioner_temperature, NULL);
    oc_resource_set_request_handler(temperature_res, OC_POST, post_airconditioner_temperature, NULL);
    oc_add_resource(temperature_res);
  
}
int 
uplus_post_airconditioner(uplus_airconditioner airconditioner)
{
    pthread_mutex_lock(&post_mutex);
    g_airconditioner.binary_switch = airconditioner.binary_switch;
    g_airconditioner.temperature = airconditioner.temperature;
    strcpy(g_airconditioner.mode, airconditioner.mode);
    pthread_mutex_unlock(&post_mutex);
    return 0;
}


