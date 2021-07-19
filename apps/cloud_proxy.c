/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright 2017-2021 Open Connectivity Foundation
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

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
* Each resource has:
*  global property variables (per resource path) for:
*    the property name
*       naming convention: g_<path>_RESOURCE_PROPERTY_NAME_<propertyname>
*    the actual value of the property, which is typed from the json data type
*      naming convention: g_<path>_<propertyname>
*  global resource variables (per path) for:
*    the path in a variable:
*      naming convention: g_<path>_RESOURCE_ENDPOINT
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
*  handlers for the proxied device
*  incomming requests from the cloud are handled by:
     - get_resource
          the response from the local device is handled by: get_local_resource_response
     - post_resource
          the response from the local device is handled by: post_local_resource_response
     - delete_resource
          the response from the local device is handled by: delete_local_resource_response
*
*
* PKI SECURITY
*  to install a certificate use MANUFACTORER_PKI compile option
*  - requires to have the header file"pki_certs.h"
*  - this include file can be created with the pki.sh tool in the device builder chain.
*    the sh script creates a Kyrio test certificate with a limited life time.
*    products should not have test certificates.
*    Hence this example is being build without the manufactorer certificate by default.
*
* compile flag PROXY_ALL_DISCOVERED_DEVICES
*   this flag enables that all devices on the network will be proxied.
*
* building on linux (in port/linux):
* make cloud_proxy CLOUD=1 CLIENT=1 OSCORE=0
*
* Usage:
* onboard the cloud_proxy using an OBT
*   configure the ACL for the d2dserverlist (e.g. install ACL for DELETE)
* connect to a cloud using an OBT via a mediator
*   when connected to the cloud, the client part will issue a discovery for all devices on realm and site local scopes
*   devices that are in the d2dserver list will be announced to the cloud
* add a device (one by one) to be proxied, example:
*    POST to /d2dserverlist?di=e0bdc937-cb27-421c-af98-db809a426861
* list the devices that are proxied, example:
*    GET to /d2dserverlist
* delete a device (one by one) that is proxied, example:
*    DELETE to /d2dserverlist?di=e0bdc937-cb27-421c-af98-db809a426861

TODO:
- save the d2dserverlist to disk, read at startup

*/
/*
 tool_version          : 20200103
 input_file            : ../device_output/out_codegeneration_merged.swagger.json
 version of input_file :
 title of input_file   : server_lite_446
*/

#include "oc_api.h"
#include "oc_pki.h"
#include "port/oc_clock.h"
#include <signal.h>

#ifdef OC_CLOUD
#include "oc_cloud.h"
#endif
#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

/* proxy all discovered devices on the network, this is for easier testing*/
//#define PROXY_ALL_DISCOVERED_DEVICES

#ifdef __linux__
/* linux specific code */
#include <pthread.h>
#ifndef NO_MAIN
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
#endif /* NO_MAIN */
#endif

#ifdef WIN32
/* windows specific code */
#include <windows.h>
static CONDITION_VARIABLE cv;   /* event loop variable */
static CRITICAL_SECTION cs;     /* event loop variable */
#endif

#define btoa(x) ((x)?"true":"false")

#define MAX_STRING 30           /* max size of the strings. */
#define MAX_PAYLOAD_STRING 65   /* max size strings in the payload */
#define MAX_ARRAY 10            /* max size of the array */
/* Note: Magic numbers are derived from the resource definition, either from the example or the definition.*/

volatile int quit = 0;          /* stop variable, used by handle_signal */
#define MAX_URI_LENGTH (30)

#define MAX_DISCOVERED_SERVER 100
static oc_endpoint_t* discovered_server[MAX_DISCOVERED_SERVER];

#ifdef PROXY_ALL_DISCOVERED_DEVICES
static int discovered_server_count = 0;
static g_discovery_udn[MAX_PAYLOAD_STRING];
#endif

static const char* cis = "coap+tcp://127.0.0.1:5683";
//static const char* cis = "coap+tcp://128.0.0.4:5683";
static const char* auth_code = "test";
static const char* sid = "00000000-0000-0000-0000-000000000001";
static const char* apn = "plgd";
static const char* device_name = "CloudProxy";


/* global property variables for path: "d2dserverlist" */
static char* g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist = "dis"; /* the name for the attribute */

/* array d2dserverlist  This Property maintains the list of the D2D Device's connection info i.e. {Device ID, Resource URI, end points} */
/* array of objects 
*  di == strlen == zero ==> empty slot
*/
struct _d2dserverlist_d2dserverlist_t
{
  char di[MAX_PAYLOAD_STRING];     /* Format pattern according to IETF RFC 4122. */
  char eps_s[MAX_PAYLOAD_STRING];  /* the OCF Endpoint information of the target Resource */
  char eps[MAX_PAYLOAD_STRING];    /* the OCF Endpoint information of the target Resource */
  char href[MAX_PAYLOAD_STRING];   /* This is the target URI, it can be specified as a Relative Reference or fully-qualified URI. */
};

struct _d2dserverlist_d2dserverlist_t g_d2dserverlist_d2dserverlist[MAX_DISCOVERED_SERVER];

char g_d2dserverlist_di[MAX_PAYLOAD_STRING] = ""; /* current value of property "di" Format pattern according to IETF RFC 4122. */

/* registration data variables for the resources */

/* global resource variables for path: d2dserverlist */
static char* g_d2dserverlist_RESOURCE_ENDPOINT = "d2dserverlist"; /* used path for this resource */
static char* g_d2dserverlist_RESOURCE_TYPE[MAX_STRING] = { "oic.r.d2dserverlist" }; /* rt value (as an array) */
int g_d2dserverlist_nr_resource_types = 1;

/* forward declarations */
void issue_requests(char* udn);
void issue_requests_all(void);

/**
* function to print the returned cbor as JSON
*
* @param rep the cbor representation
* @param print_print nice printing, e.g. nicely indented json
* 
*/
void
print_rep(oc_rep_t* rep, bool pretty_print)
{
  char* json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char*)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  printf("%s\n", json);
  free(json);
}

/**
* function to retrieve the udn from the cloud url
*
* @param url the input url
* @param udn the udn parsed out from the input url
*/
static void url_to_udn(const char* url, char* udn)
{
  strcpy(udn, &url[1]);
  udn[OC_UUID_LEN - 1] = '\0';
}

/**
* function to retrieve the local url from the cloud url
*
* @param url the input url
* @param local_url the local url withoug the udn prefix
*/
static void url_to_local_url(const char* url, char* local_url)
{
  strcpy(local_url, &url[OC_UUID_LEN]);
}

/**
* function to retrieve the udn from the anchor
*
* @param anchor url with udn 
* @param anchor url without the anchor part
*/
static void anchor_to_udn(const char* anchor, char* udn)
{
  strcpy(udn, &anchor[6]);
}


/**
* function to retrieve the index based on udn
* using global discovered_server list
*
* @param udn to check if it is in the list
* @return index, -1 is not in list
*/
static int is_udn_listed_index(char* udn)
{
  PRINT("is_udn_listed_index:  Finding UDN %s \n", udn);

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    if (strcmp(g_d2dserverlist_d2dserverlist[i].di, udn) == 0)
    {
      return i;
    }
  }
  PRINT("None matched\n");
  return -1;
}


/**
* function to find an empty slot in
* the global discovered_server list
*
* @param udn to check if it is in the list
* @return index, -1 full
*/
static int find_empty_slot(void)
{
  PRINT("  Finding empty slot \n");

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    if (strcmp(g_d2dserverlist_d2dserverlist[i].di, "") == 0)
    {
      return i;
    }
  }
  PRINT("no empty slot\n");
  return -1;
}


/**
* function to retrieve the endpoint based on udn
* using global discovered_server list
*
* @param udn to check if it is in the list 
* @return endpoint or NULL (e.g. not in list)
*/
static oc_endpoint_t* is_udn_listed(char* udn)
{
  PRINT("  Finding UDN %s \n", udn);

  //for (int i=0; i<discovered_server_count; i++) {
  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    oc_endpoint_t* ep = discovered_server[i];
    while (ep != NULL) {
      char uuid[OC_UUID_LEN] = { 0 };
      oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);
      PRINT("        uuid %s\n", uuid);
      PRINT("        udn  %s\n", udn);
      PRINT("        endpoint ");
      PRINTipaddr(*ep);
      if (strncmp(uuid, udn, OC_UUID_LEN) == 0) {
        return ep;
      }
      ep = ep->next;
    }
  }
  PRINT("None matched, returning NULL endpoint\n");
  return NULL;
}

/**
* function to set up the device.
*
*/
int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be ocf.2.2.0 (or even higher)
     supplied values are for ocf.2.2.0 */
  ret |= oc_add_device("/oic/d", "oic.d.cloudproxy", "cloud_proxy",
    "ocf.2.2.3", /* icv value */
    "ocf.res.1.3.0, ocf.sh.1.3.0",  /* dmv value */
    NULL, NULL);

#if defined(OC_IDD_API)
  FILE* fp;
  uint8_t* buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read 'cloud_proxy_IDD.cbor'\n"
    "\tIntrospection data not set.\n";
  fp = fopen("./cloud_proxy_IDD.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t*)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      PRINT("\tIntrospection data set 'cloud_proxy_IDD.cbor': %d [bytes]\n", (int)buffer_size);
    }
    else {
      PRINT("%s", introspection_error);
    }
    free(buffer);
  }
  else {
    PRINT("%s", introspection_error);
  }
#else
  PRINT("\t introspection via header file\n");
#endif
  return ret;
}

/**
* helper function to check if the POST input document contains
* the common readOnly properties or the resouce readOnly properties
* @param name the name of the property
* @return the error_status, e.g. if error_status is true, then the input document contains something illegal
*/
/*
static bool
check_on_readonly_common_resource_properties(oc_string_t name, bool error_state)
{
  if (strcmp(oc_string(name), "n") == 0) {
    error_state = true;
    PRINT("   property \"n\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "if") == 0) {
    error_state = true;
    PRINT("   property \"if\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "rt") == 0) {
    error_state = true;
    PRINT("   property \"rt\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    PRINT("   property \"id\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    PRINT("   property \"id\" is ReadOnly \n");
  }
  return error_state;
}
*/


/**
* get method for "d2dserverlist" resource.
* function is called to intialize the return values of the GET method.
* initialisation of the returned values are done from the global property values.
* Resource Description:
* The RETRIEVE operation on this Resource is only allowed for appropriately privileged devices (e.g. Mediator). For all other devices the Cloud Proxy is expected to reject RETRIEVE operation attempts.
*
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
static void
get_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)user_data;  /* variable not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
     the call to the HW needs to fill in the global variable before it returns to this function here.
     alternative is to have a callback from the hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will pass CTT1.2.2 */
  bool error_state = false;

  PRINT("-- Begin get_d2dserverlist: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (array of strings) 'dis' */
    PRINT("   Array of strings : '%s'\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_key(oc_rep_object(root), "dis");
    oc_rep_begin_array(oc_rep_object(root), dis);
    for (int i = 0; i < MAX_ARRAY; i++)
    {
      if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
        oc_rep_add_text_string(dis, g_d2dserverlist_d2dserverlist[i].di);
      }
    }
    oc_rep_end_array(oc_rep_object(root), dis);
    oc_rep_end_root_object();
    break;
  case OC_IF_RW:

    /* property (array of objects) 'd2dserverlist' */
    PRINT("   Array of strings : '%s'\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_key(oc_rep_object(root), "dis");
    oc_rep_begin_array(oc_rep_object(root), dis);
    for (int i = 0; i < MAX_ARRAY; i++)
    {
      if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
        oc_rep_add_text_string(dis, g_d2dserverlist_d2dserverlist[i].di);
      }
    }
    oc_rep_end_array(oc_rep_object(root), dis);
    oc_rep_end_root_object();
    break;

  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  }
  else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End get_d2dserverlist\n");
}

/** 
* check if the di exist in the d2d server list array
* 
* @param di di to be checked (not NULL terminated)
* @param di_len length of di
* @return true : found, false: not found
*/
static bool
if_di_exist(char* di, int di_len)
{
  for (int i = 0; i < MAX_ARRAY; i++) {
    if (strncmp(g_d2dserverlist_d2dserverlist[i].di, di, di_len) == 0) {
      return true;
    }
  }
  return false;
}

/**
*  remove the di from the server list.
*  e.g. blanks the udn.
* 
* @param di di to be checked (not NULL terminated)
* @param len length of di
* @return true : removed, false: not removed
*/
static bool
remove_di(char* di, int len)
{
  for (int i = 0; i < MAX_ARRAY; i++) {
    PRINT("   %s %.*s ", g_d2dserverlist_d2dserverlist[i].di, len, di);
    if (strncmp(g_d2dserverlist_d2dserverlist[i].di, di, len) == 0) {
      strcpy(g_d2dserverlist_d2dserverlist[i].di, "");
      return true;
    }
  }
  return false;
}


/**
*  find the resource with an url that starts with the di
*/
oc_resource_t* find_resource(const char* di)
{
  oc_resource_t* res = oc_ri_get_app_resources();
  while (res != NULL) {
    if ( strncmp(di, oc_string(res->uri), strlen(di)) == 0)
      return res;
    res = res->next;
  }
  return res;
}


/**
*  unregister resources 
*/
static bool
unregister_resources(char* di, int len)
{
  (void)len;
  oc_resource_t* res = NULL;

  res = find_resource(di);
  while (res != NULL)
  {
    // delete the resource
    oc_ri_delete_resource(res);
    // get a next one if exist
    res = find_resource(di);
  }
  return true;
}

/**
* post method for "d2dserverlist" resource.
* The function has as input the request body, which are the input values of the POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property values.
* Resource Description:
* The Mediator provisions the D2DServerList Resource with Device ID of the D2D Device. When the Cloud Proxy receives this request it retrieves '/oic/res' of the D2D Device, and then The Cloud Proxy completes a new entry of 'd2dserver' object with the contents of the RETRIEVE Response and adds it to D2DServerList Resource.
*
* /d2dserverlist?di=00000000-0000-0000-0000-000000000001
* 
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
post_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = true;
  PRINT("-- Begin post_d2dserverlist:\n");
  int stored_index = 0;
  //oc_rep_t* rep = request->request_payload;

  // di is a query param, copy from DELETE.
  bool stored = false;
  char* _di = NULL; /* not null terminated  */

  int _di_len = oc_get_query_value(request, "di", &_di);
  if (_di_len != -1) {
    /* input check  ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ */
    PRINT(" query value 'di': %.*s\n", _di_len, _di);
    if (if_di_exist(_di, _di_len) == false) {
      // di value is not listed yet, so add it
      strncpy(g_d2dserverlist_di, _di, _di_len);
      PRINT(" New di %s\n", g_d2dserverlist_di);
      error_state = false;
      /* store the value */
      for (int i = 0; i < MAX_ARRAY; i++)
      {
        if (strlen(g_d2dserverlist_d2dserverlist[i].di) == 0) {
          strncpy(g_d2dserverlist_d2dserverlist[i].di, _di, _di_len);
          stored_index = i;
          stored = true;
          PRINT(" storing at %d \n", i);
          break;
        }
      }
    }
  }
  /* if the input is ok, then process the input document and assign the global variables */
  if (error_state == false)
  {
      /* set the response */
      PRINT("Set response \n");
      oc_rep_start_root_object();

      /* property (array of objects) 'd2dserverlist' */
      PRINT("   Array of strings : '%s'\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);

      oc_rep_set_key(oc_rep_object(root), "dis");
      oc_rep_begin_array(oc_rep_object(root), dis);
      for (int i = 0; i < MAX_ARRAY; i++)
      {
        if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
          oc_rep_add_text_string(dis, g_d2dserverlist_d2dserverlist[i].di);
        }
      }
      oc_rep_end_array(oc_rep_object(root), dis);
      oc_rep_end_root_object();
      if (stored == true) {
        oc_send_response(request, OC_STATUS_CHANGED);

        /* do a new discovery so that the new device will be added */
        issue_requests(g_d2dserverlist_d2dserverlist[stored_index].di);
      }
      else {
        PRINT("MAX array exceeded, not stored, returing error \n");
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
      }
  }
  else {
    PRINT("  Returning Error \n");
    /* TODO: add error response, if any */
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  PRINT("-- End post_d2dserverlist\n");
}

/**
* delete method for "d2dserverlist" resource.
* Resource Description:
* The Mediator can remove a specific d2dserver entry for maintenance purpose
*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
delete_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)request;
  (void)interfaces;
  (void)user_data;
  bool error_state = true;

  /* query name 'di' type: 'string'*/
  char* _di = NULL; /* not null terminated  */
  int _di_len = oc_get_query_value(request, "di", &_di);
  if (_di_len != -1) {
    /* input check  ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ */

    /* TODO: use the query value to tailer the response*/
    PRINT(" query value 'di': %.*s\n", _di_len, _di);
    if (if_di_exist(_di, _di_len)) {
      // remove it
      PRINT(" FOUND = TRUE \n");
      // remove the resources that are registered..
      bool unregister = unregister_resources(_di, _di_len);
      PRINT(" unregister resources of di: %s\n", btoa(unregister));
      // remove the di of the d2d server list
      bool removed = remove_di(_di, _di_len);
      PRINT(" Removed di: %s\n", btoa(removed));
      error_state = false;
    }
  }
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  }
  else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End delete_d2dserverlist\n");
}

/**
* register all the resources to the stack
* this function registers all application level resources:
* - each resource path is bind to a specific function for the supported methods (GET, POST, PUT)
* - each resource is
*   - secure
*   - observable
*   - discoverable
*   - used interfaces, including the default interface.
*     default interface is the first of the list of interfaces as specified in the input file
*/
void
register_resources(void)
{

  PRINT("Register Resource with local path \"d2dserverlist\"\n");
  oc_resource_t* res_d2dserverlist = oc_new_resource(NULL, g_d2dserverlist_RESOURCE_ENDPOINT, g_d2dserverlist_nr_resource_types, 0);
  PRINT("     number of Resource Types: %d\n", g_d2dserverlist_nr_resource_types);
  for (int a = 0; a < g_d2dserverlist_nr_resource_types; a++) {
    PRINT("     Resource Type: \"%s\"\n", g_d2dserverlist_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_d2dserverlist, g_d2dserverlist_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_d2dserverlist, OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_d2dserverlist, OC_IF_RW); /* oic.if.rw */
  oc_resource_set_default_interface(res_d2dserverlist, OC_IF_RW);
  PRINT("     Default OCF Interface: 'oic.if.rw'\n");
  oc_resource_set_discoverable(res_d2dserverlist, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second */
  //oc_resource_set_periodic_observable(res_d2dserverlist, 1);
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is called.
    this function must be called when the value changes, preferable on an interrupt when something is read from the hardware. */
    /*oc_resource_set_observable(res_d2dserverlist, true); */

  oc_resource_set_request_handler(res_d2dserverlist, OC_DELETE, delete_d2dserverlist, NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_GET, get_d2dserverlist, NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_POST, post_d2dserverlist, NULL);
  // no cloud registration.
  // only local device registration
  oc_add_resource(res_d2dserverlist);
}

#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
void
random_pin_cb(const unsigned char* pin, size_t pin_len, void* data)
{
  (void)data;
  PRINT("\n====================\n");
  PRINT("Random PIN: %.*s\n", (int)pin_len, pin);
  PRINT("====================\n");
}
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */


void
factory_presets_cb(size_t device, void* data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  /* code to include an pki certificate and root trust anchor */
#ifdef MANUFACTORER_PKI
#include "oc_pki.h"
#include "pki_certs.h"
  int credid =
    oc_pki_add_mfg_cert(0, (const unsigned char*)my_cert, strlen(my_cert), (const unsigned char*)my_key, strlen(my_key));
  if (credid < 0) {
    PRINT("ERROR installing PKI certificate\n");
  }
  else {
    PRINT("Successfully installed PKI certificate\n");
  }

  if (oc_pki_add_mfg_intermediate_cert(0, credid, (const unsigned char*)int_ca, strlen(int_ca)) < 0) {
    PRINT("ERROR installing intermediate CA certificate\n");
  }
  else {
    PRINT("Successfully installed intermediate CA certificate\n");
  }

  if (oc_pki_add_mfg_trust_anchor(0, (const unsigned char*)root_ca, strlen(root_ca)) < 0) {
    PRINT("ERROR installing root certificate\n");
  }
  else {
    PRINT("Successfully installed root certificate\n");
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
#endif /* MANUFACTORER_PKI */

#else
  PRINT("No PKI certificates installed\n");
#endif /* OC_SECURITY && OC_PKI */
}


/**
* intializes the global variables
* registers and starts the handler

*/
void
initialize_variables(void)
{
  /* initialize global variables for resource "d2dserverlist" */
  /* initialize array "d2dserverlist" : This Property maintains the list of the D2D Device's connection info i.e. {Device ID, Resource URI, end points} */
  memset((void*)&g_d2dserverlist_d2dserverlist, 0, sizeof(g_d2dserverlist_d2dserverlist));
  memset((void*)discovered_server, 0, sizeof(discovered_server));

  strcpy(g_d2dserverlist_di, "");  /* current value of property "di" Format pattern according to IETF RFC 4122. */

  /* set the flag for NO oic/con resource. */
  oc_set_con_res_announced(false);

}

/**
* check if the resource type is a vertical resource.
* if it is a vertical resource: it will be registered in the cloud
*/
static bool is_vertical(char* resource_type)
{
  int size_rt = (int)strlen(resource_type);
  //PRINT("  is_vertical: %d %s\n", size_rt, resource_type); 

  if (strncmp(resource_type, "oic.d.", 6) == 0)
    return false;

  // these should be false, but they are in the clear, so usefull for debugging.
  if (size_rt == 10 && strncmp(resource_type, "oic.wk.res", 10) == 0)
    return true;
  if (size_rt == 8 && strncmp(resource_type, "oic.wk.p", 8) == 0)
    return true;
  if (size_rt == 8 && strncmp(resource_type, "oic.wk.d", 8) == 0)
    return true;


  if (size_rt == 11 && strncmp(resource_type, "oic.r.roles", 11) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.cred", 10) == 0)
    return false;
  if (size_rt == 11 && strncmp(resource_type, "oic.r.pstat", 11) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.doxm", 10) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.sdi", 9) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.ael", 9) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.csr", 9) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.acl2", 10) == 0)
    return false;
  if (size_rt == 8 && strncmp(resource_type, "oic.r.sp", 8) == 0)
    return false;
  if (size_rt == 20 && strncmp(resource_type, "oic.wk.introspection", 20) == 0)
    return false;
  // add the d2d serverlist
  if (size_rt == 19 && strncmp(resource_type, "oic.r.d2dserverlist", 19) == 0)
    return true; // return false;
  if (size_rt == 19 && strncmp(resource_type, "oic.r.coapcloudconf", 19) == 0)
      return false;

  return true;
}


/**
* Call back for the "GET" to the local device
* note that the user data contains the delayed response information
*/
static void
get_local_resource_response(oc_client_response_t* data)
{
  oc_rep_t * value_list=NULL;
  oc_separate_response_t* delay_response;
 
  delay_response = data->user_data;
 
  PRINT(" get_local_resource_response: \n");
  PRINT(" RESPONSE: " );
  oc_parse_rep(data->_payload, (int) data->_payload_len, &value_list);
  print_rep(value_list, false);
  free(value_list);

  memcpy(delay_response->buffer, data->_payload, (int)data->_payload_len);
  delay_response->len = data->_payload_len;

  oc_send_separate_response(delay_response, data->code);

 // delete the allocated memory in get_resource
  free(delay_response);
}

/**
* Call back for the "GET" from the cloud
* will invoke a GET to the local device
* will respond as a 
*/
static void
get_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)interfaces;
  (void) user_data;
  char query_as_string[MAX_URI_LENGTH * 2]="";
  char url[MAX_URI_LENGTH*2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t* local_server;

  oc_separate_response_t* delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  PRINT(" get_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url );
  PRINT("      local udn: %s\n", local_udn);
  PRINT("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    PRINT("      query    : %s\n", query_as_string);
  }

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);
  oc_do_get(local_url, local_server, query_as_string, &get_local_resource_response, LOW_QOS, delay_response);
  PRINT("       DISPATCHED\n");
}

/**
* Call back for the "POST" to the proxy device
* note that the user data contains the delayed response information
*/
static void
post_local_resource_response(oc_client_response_t* data)
{
  oc_rep_t* value_list = NULL;
  oc_separate_response_t* delay_response;

  delay_response = data->user_data;

  PRINT(" post_local_resource_response: \n");
  PRINT(" RESPONSE: ");
  oc_parse_rep(data->_payload, (int)data->_payload_len, &value_list);
  print_rep(value_list, false);
  free(value_list);

  memcpy(delay_response->buffer, data->_payload, (int)data->_payload_len);
  delay_response->len = data->_payload_len;

  oc_send_separate_response(delay_response, data->code);

  // delete the allocated memory in get_resource
  free(delay_response);
}

/**
* Call back for the "POST" to the proxy device
*/
static void
post_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)request;
  (void)interfaces;
  (void) user_data;

  oc_rep_t* value_list = NULL;
  char query_as_string[MAX_URI_LENGTH * 2] = "";
  char url[MAX_URI_LENGTH * 2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t* local_server;
  const uint8_t* payload = NULL;
  size_t len = 0;
  oc_content_format_t content_format;

  oc_separate_response_t* delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  PRINT(" post_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url);
  PRINT("      local udn: %s\n", local_udn);
  PRINT("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    PRINT("      query    : %s\n", query_as_string);
  }
 
  bool berr  =oc_get_request_payload_raw(request, &payload, &len, &content_format);
  PRINT("      raw buffer ok: %s\n", btoa(berr));

  int err = oc_parse_rep(payload, (int)len, &value_list);
  PRINT("     REQUEST data: %d %d \n", (int) len, err);
  print_rep(value_list, false);
  free(value_list);

  PRINT("     REQUEST 2222: \n");
  print_rep(request->request_payload, false);

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);

  if (oc_init_post(local_url, local_server, query_as_string, &post_local_resource_response, LOW_QOS, delay_response)) {
    // copy over the data
    oc_rep_encode_raw(payload, len);
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST request\n");
  }
  else
    PRINT("Could not init POST request\n");

  PRINT("       DISPATCHED\n");

  // clean up...
  //free(payload);
}

/**
* Call back for the "DELETE" to the local device
* note that the user data contains the delayed response information
*/
static void
delete_local_resource_response(oc_client_response_t* data)
{
  oc_rep_t* value_list = NULL;
  oc_separate_response_t* delay_response;

  delay_response = data->user_data;

  PRINT(" delete_local_resource_response: \n");
  PRINT(" RESPONSE: ");
  oc_parse_rep(data->_payload, (int)data->_payload_len, &value_list);
  print_rep(value_list, false);
  free(value_list);

  memcpy(delay_response->buffer, data->_payload, (int)data->_payload_len);
  delay_response->len = data->_payload_len;

  oc_send_separate_response(delay_response, data->code);

  // delete the allocated memory in get_resource
  //free(delay_response);
}

/**
* Call back for the "DELETE" from the cloud
* will invoke a DELETE to the local device
* will respond as a
*/
static void
delete_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)request;
  (void)interfaces;
  (void) user_data;
  (void)interfaces;
  (void)user_data;
  char query_as_string[MAX_URI_LENGTH * 2] = "";
  char url[MAX_URI_LENGTH * 2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t* local_server;

  oc_separate_response_t* delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  PRINT(" delete_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url);
  PRINT("      local udn: %s\n", local_udn);
  PRINT("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    PRINT("      query    : %s\n", query_as_string);
  }

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);
  oc_do_delete(local_url, local_server, query_as_string, &delete_local_resource_response, LOW_QOS, delay_response);
  PRINT("       DISPATCHED\n");

}

static oc_discovery_flags_t
discovery(const char* anchor, const char* uri, oc_string_array_t types,
  oc_interface_mask_t iface_mask, oc_endpoint_t* endpoint,
  oc_resource_properties_t bm, bool x, void* user_data)
{
  (void)user_data;
  (void)bm;
  (void) x;
  int i;
  char url [MAX_URI_LENGTH];
  char udn[200];
  char udn_url[200];
  int nr_resource_types = 0;
  //bool add_devices = false;

  char* discovered_udn = (char*)user_data;
  
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
 // PRINT("-----DISCOVERYCB %s %s nr_resourcetypes=%zd\n", anchor, uri, oc_string_array_get_allocated_size(types));

  nr_resource_types = (int)oc_string_array_get_allocated_size(types);

  for (i = 0; i < nr_resource_types; i++) {
    char* t = oc_string_array_get_item(types, i);

    if (is_vertical(t)) {
      //oc_string_t ep_string;
      PRINT("  To REGISTER: %s\n", t);

      anchor_to_udn(anchor, udn);
      PRINT("  UDN '%s'\n", udn);

#ifdef PROXY_ALL_DISCOVERED_DEVICES
      //if (if_di_exist(udn, (int)strlen(udn)) == false)
      //{
      //  return OC_CONTINUE_DISCOVERY;
      //}

      if (is_udn_listed(udn) == NULL) {
        // add new server to the list
        PRINT("  ADDING UDN '%s at %d'\n", udn, discovered_server_count);
        if (discovered_server_count < MAX_DISCOVERED_SERVER) {
          // allocate the endpoint
          oc_endpoint_t* copy = (oc_endpoint_t*)malloc(sizeof(oc_endpoint_t));
          // search for the secure endpoint
          oc_endpoint_t* ep = endpoint;  // start of the list
          while ( (ep->flags & SECURED) != 0) {
              ep = ep->next;
          }
          oc_endpoint_copy(copy, ep);
          discovered_server[discovered_server_count++] = copy;
        }
        else {
          PRINT("Discovered server storage limit reached: %d\n", MAX_DISCOVERED_SERVER);
          return OC_CONTINUE_DISCOVERY;
        }

        //strcpy(discovered_udn, udn);
        discovered_udn = udn;
      }
#endif


      PRINT("  Resource %s hosted at endpoints:\n", url);
      oc_endpoint_t* ep = endpoint;
      while (ep != NULL) {
        char uuid[OC_UUID_LEN] = { 0 };
        oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);

        PRINT("di = %s\n", uuid);
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }

      oc_endpoint_t* copy = (oc_endpoint_t*)malloc(sizeof(oc_endpoint_t));
      // search for the secure endpoint
      ep = endpoint;  // start of the list
      while ((ep != NULL) && (ep->flags & SECURED) != 0) {
        ep = ep->next;
      }
      if (ep == NULL) {
        PRINT("  No secure endpoint on UDN '%s'\n", udn);
        return OC_CONTINUE_DISCOVERY;
      }
      // make a copy, so that we can store it in the array to find it back later.
      oc_endpoint_copy(copy, ep);

      /* update the end point, it might have changed*/
      int index = is_udn_listed_index(udn);
      if (index != -1) {
        // add new server to the list
        PRINT("  UPDATING UDN '%s'\n", udn);
        discovered_server[index] = copy;
      }
      else {
        index = find_empty_slot();
        if (index != -1) {
          // add new server to the list
          PRINT("  ADDING UDN '%s'\n", udn);
          discovered_server[index] = copy;
          strcpy(g_d2dserverlist_d2dserverlist[index].di, udn);
        }
        else {
          PRINT("  NO SPACE TO STORE: '%s'\n", udn);
        }
      }

      // make uri as url NULL terminated
      strncpy(url, uri, uri_len);
      url[uri_len] = '\0';

      // make extended url with local UDN as prefix
      strcpy(udn_url, "/");
      strcat(udn_url, udn);
      strcat(udn_url, url);

      if (discovered_udn != NULL && strcmp(discovered_udn, udn) == 0){

        PRINT("   Register Resource with local path \"%s\"\n", udn_url);
        // oc_resource_t* new_resource = oc_new_resource(NULL, udn_url, nr_resource_types, 0);
        oc_resource_t* new_resource = oc_new_resource(udn_url, udn_url, nr_resource_types, 0);
        for (int j = 0; j < nr_resource_types; j++) {
          oc_resource_bind_resource_type(new_resource, oc_string_array_get_item(types, j));
        }

        if (iface_mask & OC_IF_BASELINE) {
          PRINT("   IF BASELINE\n");
          oc_resource_bind_resource_interface(new_resource, OC_IF_BASELINE); /* oic.if.baseline */
        }
        if (iface_mask & OC_IF_R) {
          PRINT("   IF R\n");
          oc_resource_bind_resource_interface(new_resource, OC_IF_R); /* oic.if.r */
          oc_resource_set_default_interface(new_resource, OC_IF_R);
        }
        if (iface_mask & OC_IF_RW) {
          PRINT("   IF RW\n");
          oc_resource_bind_resource_interface(new_resource, OC_IF_RW); /* oic.if.rw */
          oc_resource_set_default_interface(new_resource, OC_IF_RW);
        }
        if (iface_mask & OC_IF_A) {
          PRINT("   IF A\n");
          oc_resource_bind_resource_interface(new_resource, OC_IF_A); /* oic.if.a */
          oc_resource_set_default_interface(new_resource, OC_IF_A);
        }
        if (iface_mask & OC_IF_S) {
          PRINT("   IF S\n");
          oc_resource_bind_resource_interface(new_resource, OC_IF_S); /* oic.if.S */
          oc_resource_set_default_interface(new_resource, OC_IF_S);
        }

        oc_resource_set_request_handler(new_resource, OC_DELETE, delete_resource, NULL);
        oc_resource_set_request_handler(new_resource, OC_GET, get_resource, NULL);
        oc_resource_set_request_handler(new_resource, OC_POST, post_resource, NULL);
        // set resource to not discoverable, so that it does listed in the proxy device
        oc_resource_set_discoverable(new_resource, false);

        oc_add_resource(new_resource);

        int retval = oc_cloud_add_resource(new_resource);
        PRINT("   ADD resource: %d\n", retval);
      }

      //return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

void
issue_requests(char* current_udn)
{
  oc_do_site_local_ipv6_discovery_all(&discovery, current_udn);
  oc_do_realm_local_ipv6_discovery_all(&discovery, current_udn);
  //oc_do_ip_discovery_all(& discovery, NULL);
  //oc_do_ip_discovery("oic.wk.res", &discovery, NULL);
}

void
issue_requests_all(void)
{
  oc_do_site_local_ipv6_discovery_all(&discovery, NULL);
  oc_do_realm_local_ipv6_discovery_all(&discovery, NULL);
  //oc_do_ip_discovery_all(& discovery, NULL);
  //oc_do_ip_discovery("oic.wk.res", &discovery, NULL);
}

#ifndef NO_MAIN

#ifdef WIN32
/**
* signal the event loop (windows version)
* wakes up the main function to handle the next callback
*/
static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}
#endif /* WIN32 */

#ifdef __linux__
/**
* signal the event loop (Linux)
* wakes up the main function to handle the next callback
*/
static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}
#endif /* __linux__ */

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

#ifdef OC_CLOUD
/**
* cloud status handler.
* handler to print out the status of the cloud connection
*/
static void
cloud_status_handler(oc_cloud_context_t* ctx, oc_cloud_status_t status,
  void* data)
{
  (void)data;
  PRINT("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    }
    else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
    /* issue start up request*/
    issue_requests_all();
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    PRINT("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    PRINT("\t\t-Refreshed Token\n");
  }
}
#endif // OC_CLOUD

static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    PRINT("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    PRINT("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len > (long)*buffer_len) {
    PRINT("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  if (fread(buffer, 1, pem_len, fp) < (size_t)pem_len) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}

/** Taken from cloud_server code */
static void
minimal_factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }
}


/**
* main application.
* intializes the global variables
* registers and starts the handler
* handles (in a loop) the next event.
* shuts down the stack
*/
int
main(int argc, char* argv[])
{
  int init;
  oc_clock_time_t next_event;

  memset(&g_d2dserverlist_d2dserverlist, 0, sizeof(g_d2dserverlist_d2dserverlist));

  if (argc > 1) {
    device_name = argv[1];
    PRINT("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    PRINT("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    PRINT("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    PRINT("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    PRINT("apn: %s\n", argv[5]);
  }


#ifdef WIN32
  /* windows specific */
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  /* install Ctrl-C */
  signal(SIGINT, handle_signal);
#endif
#ifdef __linux__
  /* linux specific */
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  /* install Ctrl-C */
  sigaction(SIGINT, &sa, NULL);
#endif

  PRINT("OCF Server name : \"%s\"\n", device_name);

  /*
   The storage folder depends on the build system
   for Windows the projects simpleserver and cloud_server are overwritten, hence the folders should be the same as those targets.
   for Linux (as default) the folder is created in the makefile, with $target as name with _cred as post fix.
  */
#ifdef OC_SECURITY
  PRINT("Intialize Secure Resources\n");
#ifdef OC_CLOUD
  PRINT("\tstorage at './cloud_proxy_creds' \n");
  oc_storage_config("./cloud_proxy_creds");
#endif

  /*intialize the variables */
  initialize_variables();

#endif /* OC_SECURITY */

  /* initializes the handlers structure */
  static const oc_handler_t handler = { .init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources
#ifdef OC_CLIENT
#ifdef PROXY_ALL_DISCOVERED_DEVICES
                                       , .requests_entry = issue_requests_all
#else
                                       , .requests_entry = NULL
#endif
#endif
  };
#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
  /* please enable OC_SECURITY_PIN
    - have display capabilities to display the PIN value
    - server require to implement RANDOM PIN (oic.sec.doxm.rdp) onboarding mechanism
  */
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */

  oc_set_factory_presets_cb(minimal_factory_presets_cb, NULL);
  // oc_set_factory_presets_cb(factory_presets_cb, NULL);

  /* start the stack */
  init = oc_main_init(&handler);

  if (init < 0) {
    PRINT("oc_main_init failed %d, exiting.\n", init);
    return init;
  }

#ifdef OC_CLOUD
  /* get the cloud context and start the cloud */
  oc_cloud_context_t* ctx = oc_cloud_get_context(0);
  if (ctx) {
    int retval;
    PRINT("Start Cloud Manager\n");
    retval = oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    PRINT("   manager status %d\n", retval);
    if (cis) {
      if (argc == 6) {
        int retval;
        /* configure the */
        retval = oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
        PRINT("   config status  %d\n", retval);

        PRINT("Conf Cloud Manager\n");
        PRINT("   cis       %s\n", cis);
        PRINT("   auth_code %s\n", auth_code);
        PRINT("   sid       %s\n", sid);
        PRINT("   apn       %s\n", apn);
      }
      else {
        PRINT("Conf Cloud Manager: waiting to be provisioned by an OBT\n");
      }
    }
  }
#endif 

  PRINT("OCF server \"%s\" running, waiting on incoming connections.\n", device_name);

#ifdef WIN32
  /* windows specific loop */
  while (quit != 1) {
    next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    }
    else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(&cv, &cs,
          (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
#endif

#ifdef __linux__
  /* linux specific loop */
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    }
    else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
#endif

  /* shut down the stack */
#ifdef OC_CLOUD
  PRINT("Stop Cloud Manager\n");
  oc_cloud_manager_stop(ctx);
#endif
  oc_main_shutdown();
  return 0;
}
#endif /* NO_MAIN */
