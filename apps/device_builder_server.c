//******************************************************************
//
// Copyright 2017 Open Connectivity Foundation
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=/

/* Application Design
*
* support functions:
* app_init
*  initializes the oic/p and oic/d values.
* register_resources
*  function that registers all endpoints, e.g. sets the RETRIEVE/UPDATE handlers for each end point
*
* main 
*  starts the stack, with the registered resources.
*
* Each endpoint has:
*  global variables for:
*    the property name
*       naming convention: g_<path>_RESOURCE_PROPERTY_NAME_<propertyname>
*    the actual value of the property, which is typed from the json data type
*      naming convention: g_<path>_<propertyname>
*    the path in a variable:
*      naming convention: g_<path>_RESOURCE_ENDPOINT
*    array of interfaces, where by the first will be set as default interface
*      naming convention g_<path>_RESOURCE_INTERFACE
*
*  handlers for the implemented methods (get/post)
*   get_<path>
*     function that is being called when a RETRIEVE is called on <path>
*     set the global variables in the output
*   post_<path>
*     function that is being called when a UPDATE is called on <path>
*     checks the input data
*     if input data is correct
*       updates the global variables
*
*/
/*
 tool_version          : 20171123
 input_file            : ../device_output/out_codegeneration_merged.swagger.json
 version of input_file : v1.1.0-20160519
 title of input_file   : Binary Switch
*/

#include "oc_api.h"
#include "port/oc_clock.h"
#include <signal.h>

#ifdef __linux__
// linux specific code
#include <pthread.h>

#endif

#ifdef WIN32
// windows specific code
#include <windows.h>
static CONDITION_VARIABLE cv;   // event loop variable
static CRITICAL_SECTION cs;     // event loop variable
#endif

#define MAX_STRING 65   // max size of the strings.
volatile int quit = 0;  // stop variable, used by handle_signal

// global variables for path: /3D Printer
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_memorysize[] = "memorysize"; // the name for the attribute
double g_3DPrinter_memorysize = 120.5; // current value of property "memorysize"  This value represents the total memory size of the printer. The unit is MB(Mega Bytes)
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_wanconnected[] = "wanconnected"; // the name for the attribute
bool g_3DPrinter_wanconnected = false; // current value of property "wanconnected" This value indicates the connectivity capability of the 3D printer. If the value is false, the printer does not have network facility to Wide Area Network such as internet and GSM. If the value is true, the printer has network connectivity
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizex[] = "printsizex"; // the name for the attribute
double g_3DPrinter_printsizex = 300.0; // current value of property "printsizex"  This represents the maximum size of printing object in the direction of X-axis. The unit is mm.
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_3dprinttype[] = "3dprinttype"; // the name for the attribute
char g_3DPrinter_3dprinttype[MAX_STRING] = "Digital Light Processing"; // current value of property "3dprinttype" The type of 3D printing technology.
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizez[] = "printsizez"; // the name for the attribute
double g_3DPrinter_printsizez = 250.75; // current value of property "printsizez"  This represents the maximum size of printing object in the direction of Z-axis. The unit is mm.
static char g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizey[] = "printsizey"; // the name for the attribute
double g_3DPrinter_printsizey = 200.5; // current value of property "printsizey"  This represents the maximum size of printing object in the direction of Y-axis. The unit is mm.
// global variables for path: /Audio Controls
static char g_AudioControls_RESOURCE_PROPERTY_NAME_mute[] = "mute"; // the name for the attribute
bool g_AudioControls_mute = false; // current value of property "mute" Mute setting of an audio rendering device
static char g_AudioControls_RESOURCE_PROPERTY_NAME_volume[] = "volume"; // the name for the attribute
int g_AudioControls_volume = 50; // current value of property "volume" Volume setting of an audio rendering device.
// global variables for path: /binaryswitch
static char g_binaryswitch_RESOURCE_PROPERTY_NAME_value[] = "value"; // the name for the attribute
bool g_binaryswitch_value = false; // current value of property "value" Status of the switch
// global variables for path: /humidity
static char g_humidity_RESOURCE_PROPERTY_NAME_desiredHumidity[] = "desiredHumidity"; // the name for the attribute
int g_humidity_desiredHumidity = 40; // current value of property "desiredHumidity" Desired value for Humidity
static char g_humidity_RESOURCE_PROPERTY_NAME_humidity[] = "humidity"; // the name for the attribute
int g_humidity_humidity = 40; // current value of property "humidity" Current sensed value for Humidity// registration data variables for the resources

static char g_3DPrinter_RESOURCE_ENDPOINT[] = "/3D Printer";  // used path for this resource
static char g_3DPrinter_RESOURCE_TYPE[][MAX_STRING] = {"oic.r.printer.3d"}; // rt value (as an array)
int g_3DPrinter_nr_resource_types = 1;
static char g_3DPrinter_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"}; // interface if (as an array) 
int g_3DPrinter_nr_resource_interfaces = 2;

static char g_AudioControls_RESOURCE_ENDPOINT[] = "/Audio Controls";  // used path for this resource
static char g_AudioControls_RESOURCE_TYPE[][MAX_STRING] = {"oic.r.audio"}; // rt value (as an array)
int g_AudioControls_nr_resource_types = 1;
static char g_AudioControls_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"}; // interface if (as an array) 
int g_AudioControls_nr_resource_interfaces = 2;

static char g_binaryswitch_RESOURCE_ENDPOINT[] = "/binaryswitch";  // used path for this resource
static char g_binaryswitch_RESOURCE_TYPE[][MAX_STRING] = {"oic.r.switch.binary"}; // rt value (as an array)
int g_binaryswitch_nr_resource_types = 1;
static char g_binaryswitch_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"}; // interface if (as an array) 
int g_binaryswitch_nr_resource_interfaces = 2;

static char g_humidity_RESOURCE_ENDPOINT[] = "/humidity";  // used path for this resource
static char g_humidity_RESOURCE_TYPE[][MAX_STRING] = {"oic.r.humidity"}; // rt value (as an array)
int g_humidity_nr_resource_types = 1;
static char g_humidity_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"}; // interface if (as an array) 
int g_humidity_nr_resource_interfaces = 2;
/**
* function to set up the device.
*
*/
int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  ret |= oc_add_device("/oic/d", "None", "Binary Switch", 
                       "ocf.1.0.0", // icv value
                       "ocf.res.1.3.0, ocf.sh.1.3.0",  // dmv value
                       NULL, NULL);
  return ret;
}

/**
*  function to convert the interface string definition to the constant
* @param interface the interface string e.g. "oic.if.a"
*/
int convert_if_string(char *interface_name)
{
  if (strcmp(interface_name, "oic.if.baseline") == 0) return OC_IF_BASELINE;
  if (strcmp(interface_name, "oic.if.rw") == 0) return OC_IF_RW;
  if (strcmp(interface_name, "oic.if.r" )== 0) return OC_IF_R;
  if (strcmp(interface_name, "oic.if.s") == 0) return OC_IF_S;
  if (strcmp(interface_name, "oic.if.a") == 0) return OC_IF_A;
  if (strcmp(interface_name, "oic.if.b") == 0) return OC_IF_B;
  //if strcmp(interface_name, "oic.if.lb") == 0) return OC_IF_LB;
  if (strcmp(interface_name, "oic.if.ll") == 0) return OC_IF_LL;
  return OC_IF_A;
}

 
/**
* get method for "/3D Printer" endpoint to intialize the returned values from the global values
* This resource describes the attributes associated with 3D Printer. The type of 3D printing technology is specified by an enumerated string value. The maximum sizes in mm are included for the x, y, and z dimensions. A designation of whether the device is capable of WAN connectivity is represented in a boolean. The memory capacity is captured in MB.
* 
* The print
* Retrieves the current 3D Printer attributes.
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
void
get_3DPrinter(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;  // not used
  
  // TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
  // the calls needs to fill in the global variable before it is returned.
  // alternative is to have a callback from the hardware that sets the global variables
  
  // the current implementation always return everything that belongs to the resource.
  // this kind of implementation is not optimal, but is correct and will pass CTT1.2.2
  
  PRINT("get_3DPrinter: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    /* fall through */
  case OC_IF_A:
  PRINT("   Adding Baseline info\n" );
    oc_process_baseline_interface(request->resource);
    oc_rep_set_double(root, memorysize, g_3DPrinter_memorysize ); 
    PRINT("   %s : %f\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_memorysize, g_3DPrinter_memorysize );
    
    oc_rep_set_boolean(root, wanconnected, g_3DPrinter_wanconnected); 
    PRINT("   %s : %d\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_wanconnected,  g_3DPrinter_wanconnected );
    
    oc_rep_set_double(root, printsizex, g_3DPrinter_printsizex ); 
    PRINT("   %s : %f\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizex, g_3DPrinter_printsizex );
    
    oc_rep_set_text_string(root, 3dprinttype, g_3DPrinter_3dprinttype ); 
    PRINT("   %s : %s\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_3dprinttype, g_3DPrinter_3dprinttype );
    
    oc_rep_set_double(root, printsizez, g_3DPrinter_printsizez ); 
    PRINT("   %s : %f\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizez, g_3DPrinter_printsizez );
    
    oc_rep_set_double(root, printsizey, g_3DPrinter_printsizey ); 
    PRINT("   %s : %f\n", g_3DPrinter_RESOURCE_PROPERTY_NAME_printsizey, g_3DPrinter_printsizey );
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}
 
/**
* get method for "/Audio Controls" endpoint to intialize the returned values from the global values
* This resource defines basic audio control functions.
* The volume is an integer containing a percentage [0,100].
* A volume of 0 (zero) means no sound produced.
* A volume of 100 means maximum sound production.
* The mute control is implemented as a boolean.
* A mute value of true means that the device is muted (no audio).
* A mute value of false means that the device is not muted (audio).
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
void
get_AudioControls(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;  // not used
  
  // TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
  // the calls needs to fill in the global variable before it is returned.
  // alternative is to have a callback from the hardware that sets the global variables
  
  // the current implementation always return everything that belongs to the resource.
  // this kind of implementation is not optimal, but is correct and will pass CTT1.2.2
  
  PRINT("get_AudioControls: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    /* fall through */
  case OC_IF_A:
  PRINT("   Adding Baseline info\n" );
    oc_process_baseline_interface(request->resource);
    oc_rep_set_boolean(root, mute, g_AudioControls_mute); 
    PRINT("   %s : %d\n", g_AudioControls_RESOURCE_PROPERTY_NAME_mute,  g_AudioControls_mute );
    
    oc_rep_set_int(root, volume, g_AudioControls_volume ); 
    PRINT("   %s : %d\n", g_AudioControls_RESOURCE_PROPERTY_NAME_volume, g_AudioControls_volume );
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}
 
/**
* get method for "/binaryswitch" endpoint to intialize the returned values from the global values
* This resource describes a binary switch (on/off).
* The value is a boolean.
* A value of 'true' means that the switch is on.
* A value of 'false' means that the switch is off.
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
void
get_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;  // not used
  
  // TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
  // the calls needs to fill in the global variable before it is returned.
  // alternative is to have a callback from the hardware that sets the global variables
  
  // the current implementation always return everything that belongs to the resource.
  // this kind of implementation is not optimal, but is correct and will pass CTT1.2.2
  
  PRINT("get_binaryswitch: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    /* fall through */
  case OC_IF_A:
  PRINT("   Adding Baseline info\n" );
    oc_process_baseline_interface(request->resource);
    oc_rep_set_boolean(root, value, g_binaryswitch_value); 
    PRINT("   %s : %d\n", g_binaryswitch_RESOURCE_PROPERTY_NAME_value,  g_binaryswitch_value );
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}
 
/**
* get method for "/humidity" endpoint to intialize the returned values from the global values
* This resource describes a sensed or desired humidity.
* The value humidity is an integer describing the percentage measured relative humidity.
* The value desiredHumidity is an integer showing the desired target relative humidity.
* Retrieves the current (relative) humidity level.
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
void
get_humidity(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)user_data;  // not used
  
  // TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
  // the calls needs to fill in the global variable before it is returned.
  // alternative is to have a callback from the hardware that sets the global variables
  
  // the current implementation always return everything that belongs to the resource.
  // this kind of implementation is not optimal, but is correct and will pass CTT1.2.2
  
  PRINT("get_humidity: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    /* fall through */
  case OC_IF_A:
  PRINT("   Adding Baseline info\n" );
    oc_process_baseline_interface(request->resource);
    oc_rep_set_int(root, desiredHumidity, g_humidity_desiredHumidity ); 
    PRINT("   %s : %d\n", g_humidity_RESOURCE_PROPERTY_NAME_desiredHumidity, g_humidity_desiredHumidity );
    
    oc_rep_set_int(root, humidity, g_humidity_humidity ); 
    PRINT("   %s : %d\n", g_humidity_RESOURCE_PROPERTY_NAME_humidity, g_humidity_humidity );
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}
 
/**
* post method for "/Audio Controls" endpoint to assign the returned values to the global values.

* @param requestRep the request representation.
*/
void
post_AudioControls(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("post_AudioControls:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s ", oc_string(rep->name));if (strcmp ( oc_string(rep->name), g_AudioControls_RESOURCE_PROPERTY_NAME_mute) == 0)
    {
      // value exist in payload
      
      if (rep->type != OC_REP_BOOL)
      {
        error_state = true;
        PRINT ("   property 'mute' is not of type bool %d \n", rep->type);
      }
    }
    
    
    if (strcmp ( oc_string(rep->name), g_AudioControls_RESOURCE_PROPERTY_NAME_volume) == 0)
    {
      int value = rep->value.integer;
      // value exist in payload
      
      if (rep->type != OC_REP_INT)
      {
        error_state = true;
        PRINT ("   property 'volume' is not of type int %d \n", rep->type);
      }
      
      if ( value > 100 )
      {
        // check the maximum range
        PRINT ("   property 'volume' value exceed max : 0 >  value: %d \n", value);
        error_state = true;
      }
    } 
    
    
    rep = rep->next;
  }
  if (error_state == false)
  {
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      PRINT("key: (assign) %s ", oc_string(rep->name));
      // no error: assign the variables
      if (strcmp ( oc_string(rep->name), g_AudioControls_RESOURCE_PROPERTY_NAME_mute)== 0)
      {
        // assign mute
        g_AudioControls_mute = rep->value.boolean;
      }if (strcmp ( oc_string(rep->name), g_AudioControls_RESOURCE_PROPERTY_NAME_volume) == 0)
      {
        // assign volume
        g_AudioControls_volume = rep->value.integer;
      }
      rep = rep->next;
    }
    // set the response
    oc_rep_start_root_object();
    //oc_process_baseline_interface(request->resource);
    oc_rep_set_boolean(root, mute, g_AudioControls_mute); 
    
    oc_rep_set_int(root, volume, g_AudioControls_volume ); 
    oc_rep_end_root_object();
    
    // TODO: ACTUATOR add here the code to talk to the HW if one implements an actuator.
    // one can use the global variables as input to those calls
    // the global values have been updated already with the data from the request
    
    oc_send_response(request, OC_STATUS_CHANGED);
  }
  else
  {
    // TODO: add error response, if any
    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
  }
}
 
/**
* post method for "/binaryswitch" endpoint to assign the returned values to the global values.

* @param requestRep the request representation.
*/
void
post_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("post_binaryswitch:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s ", oc_string(rep->name));if (strcmp ( oc_string(rep->name), g_binaryswitch_RESOURCE_PROPERTY_NAME_value) == 0)
    {
      // value exist in payload
      
      if (rep->type != OC_REP_BOOL)
      {
        error_state = true;
        PRINT ("   property 'value' is not of type bool %d \n", rep->type);
      }
    }
    
    
    rep = rep->next;
  }
  if (error_state == false)
  {
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      PRINT("key: (assign) %s ", oc_string(rep->name));
      // no error: assign the variables
      if (strcmp ( oc_string(rep->name), g_binaryswitch_RESOURCE_PROPERTY_NAME_value)== 0)
      {
        // assign value
        g_binaryswitch_value = rep->value.boolean;
      }
      rep = rep->next;
    }
    // set the response
    oc_rep_start_root_object();
    //oc_process_baseline_interface(request->resource);
    oc_rep_set_boolean(root, value, g_binaryswitch_value); 
    oc_rep_end_root_object();
    
    // TODO: ACTUATOR add here the code to talk to the HW if one implements an actuator.
    // one can use the global variables as input to those calls
    // the global values have been updated already with the data from the request
    
    oc_send_response(request, OC_STATUS_CHANGED);
  }
  else
  {
    // TODO: add error response, if any
    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
  }
}
 
/**
* post method for "/humidity" endpoint to assign the returned values to the global values.
* Sets the desired relative humidity level.
* @param requestRep the request representation.
*/
void
post_humidity(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("post_humidity:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s ", oc_string(rep->name));if (strcmp ( oc_string(rep->name), g_humidity_RESOURCE_PROPERTY_NAME_desiredHumidity) == 0)
    {
      int value = rep->value.integer;
      // value exist in payload
      
      if (rep->type != OC_REP_INT)
      {
        error_state = true;
        PRINT ("   property 'desiredHumidity' is not of type int %d \n", rep->type);
      }
      
      if ( value > 100 )
      {
        // check the maximum range
        PRINT ("   property 'desiredHumidity' value exceed max : 0 >  value: %d \n", value);
        error_state = true;
      }
    } 
    
    
    if (strcmp ( oc_string(rep->name), g_humidity_RESOURCE_PROPERTY_NAME_humidity) == 0)
    {
      int value = rep->value.integer;
      // value exist in payload
      
      // check if "humidity" is read only
      error_state = true;
      PRINT ("   property 'humidity' is readOnly \n");
      
      if (rep->type != OC_REP_INT)
      {
        error_state = true;
        PRINT ("   property 'humidity' is not of type int %d \n", rep->type);
      }
      
      if ( value > 100 )
      {
        // check the maximum range
        PRINT ("   property 'humidity' value exceed max : 0 >  value: %d \n", value);
        error_state = true;
      }
    } 
    
    
    rep = rep->next;
  }
  if (error_state == false)
  {
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      PRINT("key: (assign) %s ", oc_string(rep->name));
      // no error: assign the variables
      if (strcmp ( oc_string(rep->name), g_humidity_RESOURCE_PROPERTY_NAME_desiredHumidity) == 0)
      {
        // assign desiredHumidity
        g_humidity_desiredHumidity = rep->value.integer;
      }if (strcmp ( oc_string(rep->name), g_humidity_RESOURCE_PROPERTY_NAME_humidity) == 0)
      {
        // assign humidity
        g_humidity_humidity = rep->value.integer;
      }
      rep = rep->next;
    }
    // set the response
    oc_rep_start_root_object();
    //oc_process_baseline_interface(request->resource);
    oc_rep_set_int(root, desiredHumidity, g_humidity_desiredHumidity ); 
    
    oc_rep_set_int(root, humidity, g_humidity_humidity ); 
    oc_rep_end_root_object();
    
    // TODO: ACTUATOR add here the code to talk to the HW if one implements an actuator.
    // one can use the global variables as input to those calls
    // the global values have been updated already with the data from the request
    
    oc_send_response(request, OC_STATUS_CHANGED);
  }
  else
  {
    // TODO: add error response, if any
    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
  }
}
/**
*  register all the resources
*/
void register_resources(void)
{
  PRINT("register resource with path /3D Printer\n");
  oc_resource_t *res_3DPrinter = oc_new_resource(NULL, g_3DPrinter_RESOURCE_ENDPOINT, g_3DPrinter_nr_resource_types, 0);
  PRINT("     number of resource types: %d\n", g_3DPrinter_nr_resource_types);
  for( int a = 0; a < g_3DPrinter_nr_resource_types; a++ )
  {
    PRINT("     resource type: %s\n", g_3DPrinter_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_3DPrinter,g_3DPrinter_RESOURCE_TYPE[a]);
  }
  for( int a = 0; a < g_3DPrinter_nr_resource_interfaces; a++ )
  {
    oc_resource_bind_resource_interface(res_3DPrinter, convert_if_string(g_3DPrinter_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(res_3DPrinter, convert_if_string(g_3DPrinter_RESOURCE_INTERFACE[0]));  
  PRINT("     default interface: %d (%s)\n", convert_if_string(g_3DPrinter_RESOURCE_INTERFACE[0]), g_3DPrinter_RESOURCE_INTERFACE[0]);
  oc_resource_set_discoverable(res_3DPrinter, true);
  oc_resource_set_periodic_observable(res_3DPrinter, 1);
   
  oc_resource_set_request_handler(res_3DPrinter, OC_GET, get_3DPrinter, NULL);
  oc_add_resource(res_3DPrinter);

  PRINT("register resource with path /Audio Controls\n");
  oc_resource_t *res_AudioControls = oc_new_resource(NULL, g_AudioControls_RESOURCE_ENDPOINT, g_AudioControls_nr_resource_types, 0);
  PRINT("     number of resource types: %d\n", g_AudioControls_nr_resource_types);
  for( int a = 0; a < g_AudioControls_nr_resource_types; a++ )
  {
    PRINT("     resource type: %s\n", g_AudioControls_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_AudioControls,g_AudioControls_RESOURCE_TYPE[a]);
  }
  for( int a = 0; a < g_AudioControls_nr_resource_interfaces; a++ )
  {
    oc_resource_bind_resource_interface(res_AudioControls, convert_if_string(g_AudioControls_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(res_AudioControls, convert_if_string(g_AudioControls_RESOURCE_INTERFACE[0]));  
  PRINT("     default interface: %d (%s)\n", convert_if_string(g_AudioControls_RESOURCE_INTERFACE[0]), g_AudioControls_RESOURCE_INTERFACE[0]);
  oc_resource_set_discoverable(res_AudioControls, true);
  oc_resource_set_periodic_observable(res_AudioControls, 1);
   
  oc_resource_set_request_handler(res_AudioControls, OC_GET, get_AudioControls, NULL);
   
  oc_resource_set_request_handler(res_AudioControls, OC_POST, post_AudioControls, NULL);
  oc_add_resource(res_AudioControls);

  PRINT("register resource with path /binaryswitch\n");
  oc_resource_t *res_binaryswitch = oc_new_resource(NULL, g_binaryswitch_RESOURCE_ENDPOINT, g_binaryswitch_nr_resource_types, 0);
  PRINT("     number of resource types: %d\n", g_binaryswitch_nr_resource_types);
  for( int a = 0; a < g_binaryswitch_nr_resource_types; a++ )
  {
    PRINT("     resource type: %s\n", g_binaryswitch_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_binaryswitch,g_binaryswitch_RESOURCE_TYPE[a]);
  }
  for( int a = 0; a < g_binaryswitch_nr_resource_interfaces; a++ )
  {
    oc_resource_bind_resource_interface(res_binaryswitch, convert_if_string(g_binaryswitch_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(res_binaryswitch, convert_if_string(g_binaryswitch_RESOURCE_INTERFACE[0]));  
  PRINT("     default interface: %d (%s)\n", convert_if_string(g_binaryswitch_RESOURCE_INTERFACE[0]), g_binaryswitch_RESOURCE_INTERFACE[0]);
  oc_resource_set_discoverable(res_binaryswitch, true);
  oc_resource_set_periodic_observable(res_binaryswitch, 1);
   
  oc_resource_set_request_handler(res_binaryswitch, OC_GET, get_binaryswitch, NULL);
   
  oc_resource_set_request_handler(res_binaryswitch, OC_POST, post_binaryswitch, NULL);
  oc_add_resource(res_binaryswitch);

  PRINT("register resource with path /humidity\n");
  oc_resource_t *res_humidity = oc_new_resource(NULL, g_humidity_RESOURCE_ENDPOINT, g_humidity_nr_resource_types, 0);
  PRINT("     number of resource types: %d\n", g_humidity_nr_resource_types);
  for( int a = 0; a < g_humidity_nr_resource_types; a++ )
  {
    PRINT("     resource type: %s\n", g_humidity_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_humidity,g_humidity_RESOURCE_TYPE[a]);
  }
  for( int a = 0; a < g_humidity_nr_resource_interfaces; a++ )
  {
    oc_resource_bind_resource_interface(res_humidity, convert_if_string(g_humidity_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(res_humidity, convert_if_string(g_humidity_RESOURCE_INTERFACE[0]));  
  PRINT("     default interface: %d (%s)\n", convert_if_string(g_humidity_RESOURCE_INTERFACE[0]), g_humidity_RESOURCE_INTERFACE[0]);
  oc_resource_set_discoverable(res_humidity, true);
  oc_resource_set_periodic_observable(res_humidity, 1);
   
  oc_resource_set_request_handler(res_humidity, OC_GET, get_humidity, NULL);
   
  oc_resource_set_request_handler(res_humidity, OC_POST, post_humidity, NULL);
  oc_add_resource(res_humidity);
  

}

#ifdef WIN32
/**
* signal the event loop
*/
void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}
#endif
#ifdef __linux__
/**
* signal the event loop
*/
void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}
#endif

/**
* handle Ctrl-C
* @param signal the captured signal
*/
void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

/**
* main application.
* intializes the global variables
* registers and starts the handler
* handles (in a loop) the next event.
* shuts down the stack
*/
/*int
main(void)
{
int init;

#ifdef WIN32
  // windows specific
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  // install Ctrl-C
  signal(SIGINT, handle_signal);
#endif
#ifdef __linux__
  // linux specific
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  // install Ctrl-C
  sigaction(SIGINT, &sa, NULL);
#endif
  // initialize global variables for endpoint "/3D Printer"
  g_3DPrinter_memorysize = 120.5; // current value of property "memorysize"  This value represents the total memory size of the printer. The unit is MB(Mega Bytes)
  g_3DPrinter_wanconnected = false; // current value of property "wanconnected" This value indicates the connectivity capability of the 3D printer. If the value is false, the printer does not have network facility to Wide Area Network such as internet and GSM. If the value is true, the printer has network connectivity
  g_3DPrinter_printsizex = 300.0; // current value of property "printsizex"  This represents the maximum size of printing object in the direction of X-axis. The unit is mm.
  strcpy(g_3DPrinter_3dprinttype,"Digital Light Processing");  // current value of property "3dprinttype" The type of 3D printing technology.
  g_3DPrinter_printsizez = 250.75; // current value of property "printsizez"  This represents the maximum size of printing object in the direction of Z-axis. The unit is mm.
  g_3DPrinter_printsizey = 200.5; // current value of property "printsizey"  This represents the maximum size of printing object in the direction of Y-axis. The unit is mm.
  
  // initialize global variables for endpoint "/Audio Controls"
  g_AudioControls_mute = false; // current value of property "mute" Mute setting of an audio rendering device
  g_AudioControls_volume = 50; // current value of property "volume" Volume setting of an audio rendering device.
  
  // initialize global variables for endpoint "/binaryswitch"
  g_binaryswitch_value = false; // current value of property "value" Status of the switch
  
  // initialize global variables for endpoint "/humidity"
  g_humidity_desiredHumidity = 40; // current value of property "desiredHumidity" Desired value for Humidity
  g_humidity_humidity = 40; // current value of property "humidity" Current sensed value for Humidity
   
  
  // no oic/con resource.
  oc_set_con_res_announced(false);

  // initializes the handlers structure
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources
#ifdef OC_CLIENT
                                       ,
                                       .requests_entry = 0 
#endif
                                       };
  oc_clock_time_t next_event;
  
  PRINT("file : ../device_output/out_codegeneration_merged.swagger.json\n");
  PRINT("title: Binary Switch\n");

#ifdef OC_SECURITY
  PRINT("intialize secure resources\n");
  oc_storage_config("./device_builder_server_creds/");
#endif*/ /* OC_SECURITY */

  // start the stack
  /*init = oc_main_init(&handler);
  if (init < 0)
    return init;

#ifdef WIN32
  // windows specific loop
  while (quit != 1) {
    next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      SleepConditionVariableCS(&cv, &cs,
                               (DWORD)(next_event / (1000 * OC_CLOCK_SECOND)));
    }
  }
#endif
  
#ifdef __linux__
  // linux specific loop
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
#endif

  // shut down the stack
  oc_main_shutdown();
  return 0;
}*/