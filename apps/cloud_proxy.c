/****************************************************************************
 *
 * Copyright 2017-2021 Open Connectivity Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

/* Application Design
 *
 * support functions:
 * app_init
 *  initializes the oic/p and oic/d values.
 * register_resources
 *  function that registers all endpoints, e.g. sets the RETRIEVE/UPDATE
 * handlers for each end point
 *
 * main
 *  starts the stack, with the registered resources.
 *
 * Each resource has:
 *  - global property variables (per resource path) for:
 *    - the property name
 *       naming convention: g_[path]_RESOURCE_PROPERTY_NAME_[propertyname]
 *    - the actual value of the property, which is typed from the json data type
 *      naming convention: g_[path]_[propertyname]
 *  - global resource variables (per path) for:
 *    - the path in a variable:
 *      naming convention: g_[path]_RESOURCE_ENDPOINT
 *
 *  handlers for the implemented methods (get/post):
 *   - get_[path]
 *     function that is being called when a RETRIEVE is called on [path]
 *     set the global variables in the output
 *   - post_[path]
 *     function that is being called when a UPDATE is called on [path]
 *     checks the input data
 *     if input data is correct
 *       updates the global variables
 *
 *
 *  Handlers for the proxied device
 *  incomming requests from the cloud are handled by:
 *    - get_resource
 *         the response from the local device is handled by:
 *         get_local_resource_response
 *    - post_resource
 *         the response from the local device is handled by:
 *         post_local_resource_response
 *    - delete_resource
 *         the response from the local device is handled by:
 *         delete_local_resource_response
 *
 * ## PKI SECURITY
 *  to install a certificate use MANUFACTORER_PKI compile option
 *  - requires to have the header file"pki_certs.h"
 *  - this include file can be created with the pki.sh tool in the device
 *    builder chain.
 *    the sh script creates a Kyrio test certificate with a limited life time.
 *    products should not have test certificates.
 *    Hence this example is being build without the manufactorer certificate by
 *    default.
 *
 * ## IoTivity specific defines
 *
 *  - OC_SECURITY
 *      enable security
 *    - OC_PKI
 *      enable use of PKI, note onboarding is enabled by means of run time code
 *    - OC_SECURITY_PIN
 *      enables Random PIN onboarding,
 *  - OC_CLOUD
 *    enables cloud access
 *  - OC_IDD_API
 *    IDD via API, otherwise use header file to define the IDD
 * - __linux__
 *   build for linux
 * - WIN32
 *   build for windows
 *
 * compile flag PROXY_ALL_DISCOVERED_DEVICES
 *   this flag enables that all devices on the network will be proxied.
 * compile flag  RESET
 *   resets the device at start up, for easy testing with the CTT
 *
 * building on linux (in port/linux):
 * make cloud_proxy CLOUD=1 CLIENT=1 OSCORE=0
 *
 * ## Usage
 *
 * ### onboarding sequence
 *
 * - onboard the cloud_proxy using an OBT
 *   configure the ACE for the d2dserverlist
 *   (e.g. for DeviceSpy this is done automatically except for an ACE for
 *    DELETE)
 * - connect to a cloud using an OBT via a mediator
 *   - set an ACE for coapcloudconfig resource.
 * - install ace for cloud access to the proxy
 *   {"subject": {"uuid": "<CTT_CLOUD_UUID>"}, "permission": 6, "resources":
 *   [{"wc": "*"}]}
 *   so that a cloud client can invoke actions on the links in the RD.
 *
 *   When connected to the cloud, the client part will issue a discovery for all
 *   devices on realm and site local scopes
 *   devices that are in the d2dserver list will be announced to the cloud
 *   note that the resources(links) that listed in oic/res only are posted to
 *   the RD
 *
 * ###  normal operation
 *
 * - add a local device (one by one) to be proxied, example:
 *    POST to /d2dserverlist?di=e0bdc937-cb27-421c-af98-db809a426861
 *    Note that the cloud_proxy client has to be granted access to the local
 *    device
 *    This requires intervention of an OBT to set an ACE on the local device
 * - list the local devices that are proxied, example:
 *    GET to /d2dserverlist
 *    delete a local device (one by one) that is proxied, example:
 *    DELETE to /d2dserverlist?di=e0bdc937-cb27-421c-af98-db809a426861
 *    rescan the network (e.g. update endpoints towards the proxied local
 * devices), example: UPDATE to /d2dserverlist?scan=1
 *
 * TODO:
 * - save the d2dserverlist to disk, read at startup
 */
/*
 tool_version          : 20200103
 input_file            : ../device_output/out_codegeneration_merged.swagger.json
 version of input_file :
 title of input_file   : server_lite_446
*/

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_csr.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "port/oc_clock.h"

#ifdef OC_CLOUD
#include "oc_cloud.h"
#endif /* OC_CLOUD */

#if defined(OC_INTROSPECTION) && defined(OC_IDD_API)
#include "oc_introspection.h"
#endif /* OC_INTROSPECTION && OC_IDD_API */

#include <signal.h>
#include <stdlib.h>

#ifndef DOXYGEN
// Force doxygen to document static inline
#define STATIC static
#endif

/* proxy all discovered devices on the network, this is for easier testing*/
//#define PROXY_ALL_DISCOVERED_DEVICES

/* perform discovery using /oic/sec/doxm, which generates significantly less
 * traffic when compared to /oic/res discovery
 */
//#define OC_DOXM_UUID_FILTER

#ifdef __linux__
/* linux specific code */
#include <pthread.h>
#ifndef NO_MAIN
static pthread_mutex_t mutex;
static pthread_cond_t cv;
#endif /* NO_MAIN */
#endif /* __linux__ */

#ifdef WIN32
/* windows specific code */
#include <windows.h>
static CONDITION_VARIABLE cv; /**< event loop variable */
static CRITICAL_SECTION cs;   /**< event loop variable */
#endif                        /* WIN32 */

#include <stdio.h> /* defines FILENAME_MAX */
#ifdef WIN32
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define btoa(x) ((x) ? "true" : "false")
#define CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

#define MAX_STRING 30         /**< max size of the strings. */
#define MAX_PAYLOAD_STRING 65 /**< max size strings in the payload */
#define MAX_ARRAY 10          /**< max size of the array */
/* Note: Magic numbers are derived from the resource definition, either from the
 * example or the definition.*/

static volatile int quit = 0; /**< stop variable, used by handle_signal */
#define MAX_URI_LENGTH (30)   /**< max size strings in the payload */

#define MAX_DISCOVERED_SERVER                                                  \
  100 /**< amount of local devices that can be stored (during the program) */
STATIC oc_endpoint_t
  *discovered_server[MAX_DISCOVERED_SERVER]; /**< storage of the end ponits */

STATIC const char *cis = "coap+tcp://127.0.0.1:5683";
STATIC const char *auth_code = "test";
STATIC const char *sid = "00000000-0000-0000-0000-000000000001";
STATIC const char *apn = "plgd";
STATIC const char *device_name = "CloudProxy";

STATIC char proxy_di[38];

/** global property variables for path: "d2dserverlist" */
STATIC const char *g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist =
  "dis"; /**< the name for the attribute */

/* array of objects
 *  di == strlen == zero ==> empty slot
 */
struct _d2dserverlist_d2dserverlist_t
{
  char
    di[MAX_PAYLOAD_STRING]; /**< Format pattern according to IETF RFC 4122. */
  char eps_s[MAX_PAYLOAD_STRING]; /**< the OCF Endpoint information of the
                                     target Resource */
  char eps[MAX_PAYLOAD_STRING];  /**< the OCF Endpoint information of the target
                                    Resource */
  char href[MAX_PAYLOAD_STRING]; /**< This is the target URI, it can be
                                    specified as a Relative Reference or
                                    fully-qualified URI. */
};

/** array d2dserverlist  This Property maintains the list of the D2D Device's
 * connection info i.e. {Device ID, Resource URI, end points} */
struct _d2dserverlist_d2dserverlist_t
  g_d2dserverlist_d2dserverlist[MAX_DISCOVERED_SERVER];

char g_d2dserverlist_di[MAX_PAYLOAD_STRING] =
  ""; /**<current value of property "di" Format pattern according to IETF RFC
         4122. */

/* registration data variables for the resources */

/* global resource variables for path: d2dserverlist */
STATIC const char *g_d2dserverlist_RESOURCE_ENDPOINT =
  "d2dserverlist"; /**< used path for this resource */
STATIC const char *g_d2dserverlist_RESOURCE_TYPE[MAX_STRING] = {
  "oic.r.d2dserverlist"
}; /**< rt value (as an array) */
int g_d2dserverlist_nr_resource_types = 1;

/* forward declarations */
void issue_requests(char *udn);
void issue_requests_all(void);

/**
 * function to print the returned cbor as JSON
 *
 * @param rep the cbor representation
 * @param pretty_print nice printing, e.g. nicely indented json
 */
STATIC void
print_rep(oc_rep_t *rep, bool pretty_print)
{
  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  OC_PRINTF("%s\n", json);
  free(json);
}

/**
 * function to retrieve the udn from the cloud url
 *
 * @param url the input url
 * @param udn the udn parsed out from the input url
 */
STATIC void
url_to_udn(const char *url, char *udn)
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
STATIC void
url_to_local_url(const char *url, char *local_url)
{
  strcpy(local_url, &url[OC_UUID_LEN]);
}

/**
 * function to retrieve the udn from the anchor
 *
 * @param anchor url with udn
 * @param[out] udn url without the anchor part
 */
STATIC void
anchor_to_udn(const char *anchor, char *udn)
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
STATIC int
is_udn_listed_index(char *udn)
{
  OC_PRINTF("is_udn_listed_index: Finding UDN %s \n", udn);

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    if (strcmp(g_d2dserverlist_d2dserverlist[i].di, udn) == 0) {
      return i;
    }
  }
  OC_PRINTF("  is_udn_listed_index: None matched\n");
  return -1;
}

/**
 * function to print discovered_server list
 */
STATIC void
list_udn(void)
{
  OC_PRINTF("   list_udn \n");

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
      OC_PRINTF("    %s\n", g_d2dserverlist_d2dserverlist[i].di);
    }
  }
  OC_PRINTF("   - done list_udn \n");
}

/**
 * function to print empty slots in the global discovered_server list
 *
 * @return index, -1 full
 */
STATIC int
find_empty_slot(void)
{
  OC_PRINTF("  find_empty_slot: Finding empty slot \n");

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    if (strcmp(g_d2dserverlist_d2dserverlist[i].di, "") == 0) {
      return i;
    }
  }
  OC_PRINTF("  find_empty_slot: no empty slot\n");
  return -1;
}

/**
 * function to retrieve the endpoint based on udn
 * using global discovered_server list
 *
 * @param udn to check if it is in the list
 * @return endpoint or NULL (e.g. not in list)
 */
STATIC oc_endpoint_t *
is_udn_listed(char *udn)
{
  OC_PRINTF("  is_udn_listed: Finding UDN %s \n", udn);

  for (int i = 0; i < MAX_DISCOVERED_SERVER; i++) {
    oc_endpoint_t *ep = discovered_server[i];
    while (ep != NULL) {
      char uuid[OC_UUID_LEN] = { 0 };
      oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);
      OC_PRINTF("        uuid %s\n", uuid);
      OC_PRINTF("        udn  %s\n", udn);
      OC_PRINTF("        endpoint ");
      OC_PRINTipaddr(*ep);
      if (strncmp(uuid, udn, OC_UUID_LEN) == 0) {
        return ep;
      }
      ep = ep->next;
    }
  }
  OC_PRINTF("  is_udn_listed: None matched, returning NULL endpoint\n");
  return NULL;
}

/**
 * function to set up the device.
 *
 */
STATIC int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be ocf.2.2.0 (or even higher)
     supplied values are for ocf.2.2.0 */
  ret |= oc_add_device("/oic/d", "oic.d.cloudproxy", "cloud_proxy",
                       "ocf.2.2.5",                   /* icv value */
                       "ocf.res.1.3.0, ocf.sh.1.3.0", /* dmv value */
                       NULL, NULL);

#ifdef OC_INTROSPECTION
#ifdef OC_IDD_API
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read 'cloud_proxy_IDD.cbor'\n"
    "\tIntrospection data not set.\n";
  fp = fopen("./cloud_proxy_IDD.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      OC_PRINTF("\tIntrospection data set 'cloud_proxy_IDD.cbor': %d [bytes]\n",
                (int)buffer_size);
    } else {
      OC_PRINTF("%s", introspection_error);
    }
    free(buffer);
  } else {
    OC_PRINTF("%s", introspection_error);
  }
#else  /* !OC_IDD_API */
  OC_PRINTF("\t introspection via header file\n");
#endif /* OC_IDD_API */
#endif /* OC_INTROSPECTION */
  return ret;
}

/**
 * helper function to check if the POST input document contains
 * the common readOnly properties or the resouce readOnly properties
 * @param name the name of the property
 * @return the error_status, e.g. if error_status is true, then the input
 * document contains something illegal
 */
/*
STATIC bool
check_on_readonly_common_resource_properties(oc_string_t name, bool error_state)
{
  if (strcmp(oc_string(name), "n") == 0) {
    error_state = true;
    OC_PRINTF("   property \"n\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "if") == 0) {
    error_state = true;
    OC_PRINTF("   property \"if\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "rt") == 0) {
    error_state = true;
    OC_PRINTF("   property \"rt\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    OC_PRINTF("   property \"id\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    OC_PRINTF("   property \"id\" is ReadOnly \n");
  }
  return error_state;
}
*/

/**
 * get method for "d2dserverlist" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: The RETRIEVE operation on this Resource is only
 * allowed for appropriately privileged devices (e.g. Mediator). For all other
 * devices the Cloud Proxy is expected to reject RETRIEVE operation attempts.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
STATIC void
get_d2dserverlist(oc_request_t *request, oc_interface_mask_t interfaces,
                  void *user_data)
{
  (void)user_data; /* variable not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a
     sensor. the call to the HW needs to fill in the global variable before it
     returns to this function here. alternative is to have a callback from the
     hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will
     pass CTT1.2.2 */
  bool error_state = false;

  OC_PRINTF("-- Begin get_d2dserverlist: interface %d\n", interfaces);
  list_udn();

  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    OC_PRINTF("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (array of strings) 'dis' */
    OC_PRINTF("   Array of strings : '%s'\n",
              g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_key(oc_rep_object(root), "dis");
    oc_rep_begin_array(oc_rep_object(root), dis);
    for (int i = 0; i < MAX_ARRAY; i++) {
      if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
        oc_rep_add_text_string(dis, g_d2dserverlist_d2dserverlist[i].di);
      }
    }
    oc_rep_end_array(oc_rep_object(root), dis);
    oc_rep_end_root_object();
    break;
  case OC_IF_RW:

    /* property (array of objects) 'd2dserverlist' */
    OC_PRINTF("   Array of strings : '%s'\n",
              g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_key(oc_rep_object(root), "dis");
    oc_rep_begin_array(oc_rep_object(root), dis);
    for (int i = 0; i < MAX_ARRAY; i++) {
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
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  OC_PRINTF("-- End get_d2dserverlist\n");
}

/**
 * check if the di exist in the d2d server list array
 *
 * @param di di to be checked (not NULL terminated)
 * @param di_len length of di
 * @return true : found, false: not found
 */
STATIC bool
if_di_exist(const char *di, int di_len)
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
STATIC bool
remove_di(const char *di, int len)
{
  for (int i = 0; i < MAX_ARRAY; i++) {
    OC_PRINTF("   %s %.*s ", g_d2dserverlist_d2dserverlist[i].di, len, di);
    if (strncmp(g_d2dserverlist_d2dserverlist[i].di, di, len) == 0) {
      strcpy(g_d2dserverlist_d2dserverlist[i].di, "");
      return true;
    }
  }
  return false;
}

/**
 * find the resource with an url that starts with the di
 *
 * @param di di to be checked (not NULL terminated)
 * @return return the resource or NULL
 */
STATIC oc_resource_t *
find_resource(const char *di)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res != NULL) {
    if (strncmp(di, oc_string(res->uri), strlen(di)) == 0)
      return res;
    res = res->next;
  }
  return res;
}

/**
 *  unregister resources
 *
 * @param di di to be checked (not NULL terminated)
 * @param len length of di
 */
STATIC bool
unregister_resources(const char *di, int len)
{
  (void)len;
  oc_resource_t *res = NULL;

  res = find_resource(di);
  while (res != NULL) {
    // delete the resource
    oc_ri_delete_resource(res);
    // get a next one if exist
    res = find_resource(di);
  }
  return true;
}

/**
 * post method for "d2dserverlist" resource.
 * The function has as input the request body, which are the input values of the
 * POST method. The input values (as a set) are checked if all supplied values
 * are correct. If the input values are correct, they will be assigned to the
 * global  property values. Resource Description: The Mediator provisions the
 * D2DServerList Resource with Device ID of the D2D Device. When the Cloud Proxy
 * receives this request it retrieves '/oic/res' of the D2D Device, and then The
 * Cloud Proxy completes a new entry of 'd2dserver' object with the contents of
 * the RETRIEVE Response and adds it to D2DServerList Resource.
 *
 * /d2dserverlist?di=00000000-0000-0000-0000-000000000001
 *
 * @param request the request representation.
 * @param interfaces the used interfaces during the request.
 * @param user_data the supplied user data.
 */
STATIC void
post_d2dserverlist(oc_request_t *request, oc_interface_mask_t interfaces,
                   void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = true;
  OC_PRINTF("-- Begin post_d2dserverlist:\n");
  int stored_index = 0;
  // oc_rep_t* rep = request->request_payload;

  // di is a query param, copy from DELETE.
  bool stored = false;
  const char *_di = NULL;   /* not null terminated  */
  const char *_scan = NULL; /* not null terminated  */

  /* do a scan to all devices */
  int _scan_len =
    oc_get_query_value_v1(request, "scan", CHAR_ARRAY_LEN("scan"), &_scan);
  if (_scan_len > 0) {
    OC_PRINTF("   Send multicast discovery\n");
    issue_requests_all();
    oc_send_response(request, OC_STATUS_CHANGED);
    return;
  }

  int _di_len =
    oc_get_query_value_v1(request, "di", CHAR_ARRAY_LEN("di"), &_di);
  if (_di_len != -1) {
    /* input check
     * ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$
     */
    OC_PRINTF("  query value 'di': %.*s\n", _di_len, _di);
    if (if_di_exist(_di, _di_len) == false) {
      // di value is not listed yet, so add it
      strncpy(g_d2dserverlist_di, _di, _di_len);
      OC_PRINTF(" New di %s\n", g_d2dserverlist_di);
      error_state = false;

      stored_index = find_empty_slot();
      if (stored_index >= 0) {
        strncpy(g_d2dserverlist_d2dserverlist[stored_index].di, _di, _di_len);
        stored = true;
        OC_PRINTF(" storing at %d \n", stored_index);
        list_udn();
      } else {
        OC_PRINTF(" full, not stored \n");
        list_udn();
      }
    } else {
      OC_PRINTF(" DI exist, no error, returning existing list\n");
      error_state = false;
      stored = true;
      list_udn();
    }
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    /* set the response */
    OC_PRINTF("Set response \n");
    oc_rep_start_root_object();

    /* property (array of objects) 'd2dserverlist' */
    OC_PRINTF("   Array of strings : '%s'\n",
              g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);

    oc_rep_set_key(oc_rep_object(root), "dis");
    oc_rep_begin_array(oc_rep_object(root), dis);
    for (int i = 0; i < MAX_ARRAY; i++) {
      if (strlen(g_d2dserverlist_d2dserverlist[i].di) > 0) {
        oc_rep_add_text_string(dis, g_d2dserverlist_d2dserverlist[i].di);
        OC_PRINTF("      DI: '%s'\n", g_d2dserverlist_d2dserverlist[i].di);
      }
    }
    oc_rep_end_array(oc_rep_object(root), dis);
    oc_rep_end_root_object();
    if (stored == true) {
      oc_send_response(request, OC_STATUS_CHANGED);

      /* do a new discovery so that the new device will be added */
      issue_requests(g_d2dserverlist_d2dserverlist[stored_index].di);
    } else {
      OC_PRINTF("MAX array exceeded, not stored, returing error \n");
      oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    }
  } else {
    OC_PRINTF("  Returning Error \n");
    /* TODO: add error response, if any */
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  OC_PRINTF("-- End post_d2dserverlist\n");
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
STATIC void
delete_d2dserverlist(oc_request_t *request, oc_interface_mask_t interfaces,
                     void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = true;
  OC_PRINTF("-- Begin delete_d2dserverlist:\n");

  list_udn();

  /* query name 'di' type: 'string'*/
  const char *_di = NULL; /* not null terminated  */
  int _di_len =
    oc_get_query_value_v1(request, "di", CHAR_ARRAY_LEN("di"), &_di);
  if (_di_len != -1) {
    /* input check
     * ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$
     */

    /* TODO: use the query value to tailer the response*/
    OC_PRINTF(" query value 'di': %.*s\n", _di_len, _di);
    if (if_di_exist(_di, _di_len)) {
      // remove it
      OC_PRINTF(" FOUND = TRUE \n");
      // remove the resources that are registered..
      bool unregister = unregister_resources(_di, _di_len);
      OC_PRINTF(" unregister resources of di: %s\n", btoa(unregister));
      // remove the di of the d2d server list
      bool removed = remove_di(_di, _di_len);
      OC_PRINTF(" Removed di: %s\n", btoa(removed));
      error_state = false;
    }
  }
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  OC_PRINTF("-- End delete_d2dserverlist\n");
}

/**
 * register all the resources to the stack
 * this function registers all application level resources:
 * - each resource path is bind to a specific function for the supported methods
 * (GET, POST, PUT)
 * - each resource is
 *   - secure
 *   - observable
 *   - discoverable
 *   - used interfaces, including the default interface.
 *     default interface is the first of the list of interfaces as specified in
 * the input file
 */
STATIC void
register_resources(void)
{

  OC_PRINTF("Register Resource with local path \"d2dserverlist\"\n");
  oc_resource_t *res_d2dserverlist =
    oc_new_resource(NULL, g_d2dserverlist_RESOURCE_ENDPOINT,
                    g_d2dserverlist_nr_resource_types, 0);
  OC_PRINTF("     number of Resource Types: %d\n",
            g_d2dserverlist_nr_resource_types);
  for (int a = 0; a < g_d2dserverlist_nr_resource_types; a++) {
    OC_PRINTF("     Resource Type: \"%s\"\n", g_d2dserverlist_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_d2dserverlist,
                                   g_d2dserverlist_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_d2dserverlist,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_d2dserverlist,
                                      OC_IF_RW); /* oic.if.rw */
  oc_resource_set_default_interface(res_d2dserverlist, OC_IF_RW);
  OC_PRINTF("     Default OCF Interface: 'oic.if.rw'\n");
  oc_resource_set_discoverable(res_d2dserverlist, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second */
  // oc_resource_set_periodic_observable(res_d2dserverlist, 1);
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is
    called. this function must be called when the value changes, preferable on
    an interrupt when something is read from the hardware. */
  /*oc_resource_set_observable(res_d2dserverlist, true); */

  oc_resource_set_request_handler(res_d2dserverlist, OC_DELETE,
                                  delete_d2dserverlist, NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_GET, get_d2dserverlist,
                                  NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_POST,
                                  post_d2dserverlist, NULL);
  // no cloud registration.
  // only local device registration
  oc_add_resource(res_d2dserverlist);
  oc_cloud_add_resource(res_d2dserverlist);

  oc_resource_t *device_resource = oc_core_get_resource_by_index(OCF_D, 0);
  oc_resource_set_observable(device_resource, false);

  oc_resource_t *platform_resource = oc_core_get_resource_by_index(OCF_P, 0);
  oc_resource_set_observable(platform_resource, false);
}

#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
static void
random_pin_cb(const unsigned char *pin, size_t pin_len, void *data)
{
  (void)data;
  OC_PRINTF("\n====================\n");
  OC_PRINTF("Random PIN: %.*s\n", (int)pin_len, pin);
  OC_PRINTF("====================\n");
}
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */

#if 0

static void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  /* code to include an pki certificate and root trust anchor */
#ifdef MANUFACTORER_PKI
#include "oc_pki.h"
#include "pki_certs.h"
  int credid =
    oc_pki_add_mfg_cert(0, (const unsigned char *)my_cert, strlen(my_cert),
                        (const unsigned char *)my_key, strlen(my_key));
  if (credid < 0) {
    OC_PRINTF("ERROR installing PKI certificate\n");
  } else {
    OC_PRINTF("Successfully installed PKI certificate\n");
  }

  if (oc_pki_add_mfg_intermediate_cert(0, credid, (const unsigned char *)int_ca,
                                       strlen(int_ca)) < 0) {
    OC_PRINTF("ERROR installing intermediate CA certificate\n");
  } else {
    OC_PRINTF("Successfully installed intermediate CA certificate\n");
  }

  if (oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)root_ca,
                                  strlen(root_ca)) < 0) {
    OC_PRINTF("ERROR installing root certificate\n");
  } else {
    OC_PRINTF("Successfully installed root certificate\n");
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
#endif /* MANUFACTORER_PKI */

#else
  OC_PRINTF("No PKI certificates installed\n");
#endif /* OC_SECURITY && OC_PKI */
}

#endif

#ifdef OC_SECURITY
/**
 * intializes the global variables
 * registers and starts the handler
 */
STATIC void
initialize_variables(void)
{
  /* initialize global variables for resource "d2dserverlist" */
  /* initialize array "d2dserverlist" : This Property maintains the list of the
   * D2D Device's connection info i.e. {Device ID, Resource URI, end points} */
  memset((void *)&g_d2dserverlist_d2dserverlist, 0,
         sizeof(g_d2dserverlist_d2dserverlist));
  memset((void *)discovered_server, 0, sizeof(discovered_server));

  strcpy(g_d2dserverlist_di, ""); /* current value of property "di" Format
                                     pattern according to IETF RFC 4122. */

  /* set the flag for NO oic/con resource. */
  oc_set_con_res_announced(false);
}
#endif /* OC_SECURITY */

/**
 * check if the resource type is a vertical resource.
 * if it is a vertical resource: it will be registered in the cloud
 *
 * @param resource_type the resource type (rt).
 */
STATIC bool
is_vertical(char *resource_type)
{
  int size_rt = (int)strlen(resource_type);

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
#if defined(OC_SECURITY)
  if (size_rt == 9 && strncmp(resource_type, OCF_SEC_CSR_RT, 9) == 0)
    return false;
#endif /* OC_SECURITY */
  if (size_rt == 10 && strncmp(resource_type, "oic.r.acl2", 10) == 0)
    return false;
  if (size_rt == 8 && strncmp(resource_type, "oic.r.sp", 8) == 0)
    return false;
#ifdef OC_INTROSPECTION
  if (size_rt == 20 &&
      strncmp(resource_type, "oic.wk.introspection", 20) == 0) {
    return false;
  }
#endif /* OC_INTROSPECTION */
  if (size_rt == 19 && strncmp(resource_type, "oic.r.coapcloudconf", 19) == 0)
    return false;

  // add the d2d serverlist
  // if (size_rt == 19 && strncmp(resource_type, "oic.r.d2dserverlist", 19) ==
  // 0)
  //  return true; // return false;

  return true;
}

/**
 * Call back for the "GET" to the local device
 * note that the user data contains the delayed response information
 *
 * @param data the client response
 */
STATIC void
get_local_resource_response(oc_client_response_t *data)
{
  oc_rep_t *value_list = NULL;
  oc_separate_response_t *delay_response;

  delay_response = data->user_data;

  OC_PRINTF(" <== get_local_resource_response: \n");
  OC_PRINTF(" RESPONSE: ");
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
 * Call back for the "GET" from the cloud
 * will invoke a GET to the local device
 *
 * @param request the request
 * @param interfaces The interfaces for the GET call
 * @param user_data the user data supplied with the callback
 */
STATIC void
get_resource(oc_request_t *request, oc_interface_mask_t interfaces,
             void *user_data)
{
  (void)interfaces;
  (void)user_data;
  char query_as_string[MAX_URI_LENGTH * 2] = "";
  char url[MAX_URI_LENGTH * 2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t *local_server;

  oc_separate_response_t *delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  OC_PRINTF(" ==> get_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url);
  OC_PRINTF("      local udn: %s\n", local_udn);
  OC_PRINTF("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    OC_PRINTF("      query    : %s\n", query_as_string);
  }

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);
  oc_do_get(local_url, local_server, query_as_string,
            &get_local_resource_response, LOW_QOS, delay_response);
  OC_PRINTF("       DISPATCHED\n");
}

/**
 * Call back for the "POST" to the proxy device
 * note that the user data contains the delayed response information
 *
 * @param data the client response
 */
STATIC void
post_local_resource_response(oc_client_response_t *data)
{
  oc_rep_t *value_list = NULL;
  oc_separate_response_t *delay_response;

  delay_response = data->user_data;

  OC_PRINTF(" <== post_local_resource_response: \n");
  OC_PRINTF(" RESPONSE: ");
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
 *
 * @param request the request
 * @param interfaces The interfaces for the GET call
 * @param user_data the user data supplied with the callback
 */
STATIC void
post_resource(oc_request_t *request, oc_interface_mask_t interfaces,
              void *user_data)
{
  (void)interfaces;
  (void)user_data;

  oc_rep_t *value_list = NULL;
  char query_as_string[MAX_URI_LENGTH * 2] = "";
  char url[MAX_URI_LENGTH * 2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t *local_server;
  const uint8_t *payload = NULL;
  size_t len = 0;
  oc_content_format_t content_format;

  oc_separate_response_t *delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  OC_PRINTF(" ==> post_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url);
  OC_PRINTF("      local udn: %s\n", local_udn);
  OC_PRINTF("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    OC_PRINTF("      query    : %s\n", query_as_string);
  }

  bool berr =
    oc_get_request_payload_raw(request, &payload, &len, &content_format);
  OC_PRINTF("      raw buffer ok: %s\n", btoa(berr));

  int err = oc_parse_rep(payload, (int)len, &value_list);
  OC_PRINTF("     REQUEST data: %d %d \n", (int)len, err);
  print_rep(value_list, false);
  free(value_list);

  OC_PRINTF("     REQUEST 2222: \n");
  print_rep(request->request_payload, false);

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);

  if (oc_init_post(local_url, local_server, query_as_string,
                   &post_local_resource_response, LOW_QOS, delay_response)) {
    // copy over the data
    oc_rep_encode_raw(payload, len);
    if (oc_do_post())
      OC_PRINTF("Sent POST request\n");
    else
      OC_PRINTF("Could not send POST request\n");
  } else
    OC_PRINTF("Could not init POST request\n");

  OC_PRINTF("       DISPATCHED\n");

  // clean up...
  // free(payload);
}

/**
 * Call back for the "DELETE" to the local device
 * note that the user data contains the delayed response information
 *
 * @param data the client response
 */
STATIC void
delete_local_resource_response(oc_client_response_t *data)
{
  oc_rep_t *value_list = NULL;
  oc_separate_response_t *delay_response;

  delay_response = data->user_data;

  OC_PRINTF(" <== delete_local_resource_response: \n");
  OC_PRINTF(" RESPONSE: ");
  oc_parse_rep(data->_payload, (int)data->_payload_len, &value_list);
  print_rep(value_list, false);
  free(value_list);

  memcpy(delay_response->buffer, data->_payload, (int)data->_payload_len);
  delay_response->len = data->_payload_len;

  oc_send_separate_response(delay_response, data->code);

  // delete the allocated memory in get_resource
  // free(delay_response);
}

/**
 * Call back for the "DELETE" from the cloud
 * will invoke a DELETE to the local device
 *
 * @param request the request
 * @param interfaces The interfaces for the GET call
 * @param user_data the user data supplied with the callback
 */
STATIC void
delete_resource(oc_request_t *request, oc_interface_mask_t interfaces,
                void *user_data)
{
  (void)interfaces;
  (void)user_data;
  char query_as_string[MAX_URI_LENGTH * 2] = "";
  char url[MAX_URI_LENGTH * 2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t *local_server;

  oc_separate_response_t *delay_response = NULL;
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));

  strcpy(url, oc_string(request->resource->uri));
  OC_PRINTF(" ==> delete_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url);
  OC_PRINTF("      local udn: %s\n", local_udn);
  OC_PRINTF("      local url: %s\n", local_url);
  if (request->query_len > 0) {
    strncpy(query_as_string, request->query, request->query_len);
    OC_PRINTF("      query    : %s\n", query_as_string);
  }

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);
  oc_do_delete(local_url, local_server, query_as_string,
               &delete_local_resource_response, LOW_QOS, delay_response);
  OC_PRINTF("       DISPATCHED\n");
}

/**
 * The discovery callback, per discovered resource
 * will invoke a DELETE to the local device
 *
 * @param anchor the anchor of the resource
 * @param uri the uri of the discoverd resource
 * @param types the resource types belonging to the resource
 * @param iface_mask the interfaces supported by the resource
 * @param endpoint the endpoints of the resource
 * @param bm the resource properties
 * @param user_data the user data supplied to callback
 *        this can contain the UDN that is added to the d2dserverlist
 */
STATIC oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, bool more, void *user_data)
{
  (void)bm;
  (void)more;
  int i;
  char url[MAX_URI_LENGTH];
  char this_udn[200];
  char d2d_udn[200] = "";
  char udn_url[200];
  int nr_resource_types = 0;

  strcpy(d2d_udn, "");
  if (user_data != NULL) {
    strcpy(d2d_udn, (char *)user_data);
  }
  anchor_to_udn(anchor, this_udn);

  bool is_added_current_device = false;
  if (strcmp(this_udn, d2d_udn) == 0) {
    is_added_current_device = true;
  }

#ifdef PROXY_ALL_DISCOVERED_DEVICES
  // make sure that the discovered device is handled
  is_added_current_device = true;
  strcpy(d2d_udn, this_udn);
#endif

  OC_PRINTF("  discovery: (cb) '%s' %d (this) '%s'\n", d2d_udn,
            is_added_current_device, this_udn);
  OC_PRINTF("     -- (a) '%s' (uri) '%s'\n", anchor, uri);

  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  nr_resource_types = (int)oc_string_array_get_allocated_size(types);

  for (i = 0; i < nr_resource_types; i++) {
    char *t = oc_string_array_get_item(types, i);

    if (is_vertical(t)) {
      OC_PRINTF("  discovery: To REGISTER resource type: %s\n", t);
      OC_PRINTF("  discovery: Resource %s hosted at endpoints:\n", uri);
      const oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        char uuid[OC_UUID_LEN] = { 0 };
        oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);

        OC_PRINTF("   di = %s\n", uuid);
        OC_PRINTF("      ");
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        ep = ep->next;
      }

      // search for the secure endpoint, so that it can be stored
      ep = endpoint; // start of the list
      while ((ep != NULL) && !(ep->flags & SECURED)) {
        ep = ep->next;
      }
      if (ep != NULL) {
        OC_PRINTF("  discovery secure endpoint on UDN '%s' :\n", this_udn);
        OC_PRINTF("    secure: ");
        OC_PRINTipaddr(*ep);
        OC_PRINTF("\n");
        // make a copy, so that we can store it in the array to find it back
        // later.
        oc_endpoint_t *copy = (oc_endpoint_t *)malloc(sizeof(oc_endpoint_t));
        oc_endpoint_copy(copy, ep);

        /* update the end point, it might have changed*/
        int index = is_udn_listed_index(this_udn);
        if (index != -1) {
          // add new server to the list
          OC_PRINTF("  discovery: UPDATING UDN '%s'\n", this_udn);
          /* free existing endpoint */
          free(discovered_server[index]);
          /* add the newly copied endpoint*/
          discovered_server[index] = copy;
        } else {
          if (is_added_current_device) {
            index = find_empty_slot();
            if (index != -1) {
              // add new server to the list
              OC_PRINTF("  discovery: ADDING UDN '%s'\n", this_udn);
              discovered_server[index] = copy;
              strcpy(g_d2dserverlist_d2dserverlist[index].di, this_udn);
            } else {
              OC_PRINTF("  discovery: NO SPACE TO STORE: '%s'\n", this_udn);
            }
          }
        }
      } /* ep is NULL */

      // make uri as url NULL terminated
      strncpy(url, uri, uri_len);
      url[uri_len] = '\0';

      // make extended url with local UDN as prefix
      strcpy(udn_url, "/");
      strcat(udn_url, this_udn);
      strcat(udn_url, url);

      if (is_added_current_device) {
        OC_PRINTF("   discovery: Register Resource with local path \"%s\"\n",
                  udn_url);
        oc_resource_t *new_resource =
          oc_new_resource(udn_url, udn_url, nr_resource_types, 0);
        for (int j = 0; j < nr_resource_types; j++) {
          oc_resource_bind_resource_type(new_resource,
                                         oc_string_array_get_item(types, j));
        }
        if (iface_mask & OC_IF_BASELINE) {
          OC_PRINTF("   IF BASELINE\n");
          oc_resource_bind_resource_interface(
            new_resource, OC_IF_BASELINE); /* oic.if.baseline */
        }
        if (iface_mask & OC_IF_LL) {
          OC_PRINTF("   IF LL\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_LL); /* oic.if.ll */
          oc_resource_set_default_interface(new_resource, OC_IF_LL);
        }
        if (iface_mask & OC_IF_CREATE) {
          OC_PRINTF("   IF CREATE\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_CREATE); /* oic.if.create */
          // oc_resource_set_default_interface(new_resource, OC_IF_CREATE);
        }
        if (iface_mask & OC_IF_B) {
          OC_PRINTF("   IF B\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_B); /* oic.if.b */
          // oc_resource_set_default_interface(new_resource, OC_IF_B);
        }
        if (iface_mask & OC_IF_R) {
          OC_PRINTF("   IF R\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_R); /* oic.if.r */
          oc_resource_set_default_interface(new_resource, OC_IF_R);
        }
        if (iface_mask & OC_IF_RW) {
          OC_PRINTF("   IF RW\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_RW); /* oic.if.rw */
          oc_resource_set_default_interface(new_resource, OC_IF_RW);
        }
        if (iface_mask & OC_IF_A) {
          OC_PRINTF("   IF A\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_A); /* oic.if.a */
          oc_resource_set_default_interface(new_resource, OC_IF_A);
        }
        if (iface_mask & OC_IF_S) {
          OC_PRINTF("   IF S\n");
          oc_resource_bind_resource_interface(new_resource,
                                              OC_IF_S); /* oic.if.S */
          oc_resource_set_default_interface(new_resource, OC_IF_S);
        }

        /* set the generic callback for the new resource */
        oc_resource_set_request_handler(new_resource, OC_DELETE,
                                        delete_resource, NULL);
        oc_resource_set_request_handler(new_resource, OC_GET, get_resource,
                                        NULL);
        oc_resource_set_request_handler(new_resource, OC_POST, post_resource,
                                        NULL);

        // set resource to not discoverable, so that it does listed in the proxy
        // device
        oc_resource_set_discoverable(new_resource, false);
        // add the resource to the device
        bool add_err = oc_add_resource(new_resource);
        // add the resource to the cloud
        int retval = oc_cloud_add_resource(new_resource);
        OC_PRINTF("   discovery ADDED resource '%s' to cloud : %d\n",
                  (char *)btoa(add_err), retval);

      } /* adding current device, e.g. add the resource to the cloud RD */
    }   /* is vertical */
  }     /* if loop */
  return OC_CONTINUE_DISCOVERY;
}

#ifdef OC_DOXM_UUID_FILTER
static void
doxm_discovery_cb(oc_client_response_t *response)
{
  // a device has responded to the (potentially) UUID-filtered multicast DOXM
  // request. all we need from this request is the IP address of the responder
  oc_do_ip_discovery_all_at_endpoint(discovery, response->endpoint,
                                     response->user_data);
}
#endif /* OC_DOXM_UUID_FILTER */

/**
 * issue a discovery request
 *
 * @param current_udn the current udn as user data for the discovery callback
 */
void
issue_requests(char *current_udn)
{
#ifdef OC_DOXM_UUID_FILTER
  char query[12 + OC_UUID_LEN] = "deviceuuid=";
  strcat(query, current_udn);

  oc_do_site_local_ipv6_multicast("/oic/sec/doxm", query, doxm_discovery_cb,
                                  current_udn);
#else /* !OC_DOXM_UUID_FILTER */
  oc_do_site_local_ipv6_discovery_all(&discovery, current_udn);
  oc_do_realm_local_ipv6_discovery_all(&discovery, current_udn);
#ifdef OC_IPV4
  oc_do_ip_discovery_all(&discovery, current_udn);
#endif /* OC_IPV4 */
#endif /* OC_DOXM_UUID_FILTER */
  // oc_do_ip_discovery_all(& discovery, NULL);
  // oc_do_ip_discovery("oic.wk.res", &discovery, NULL);
}

/**
 * issue a discovery request
 * no user data supplied (e.g. NULL)
 */
void
issue_requests_all(void)
{
  OC_PRINTF("issue_requests_all: Discovery of all devices \n");
#ifdef OC_DOXM_UUID_FILTER
  oc_do_site_local_ipv6_multicast("/oic/sec/doxm", NULL, doxm_discovery_cb,
                                  NULL);
#else /* !OC_DOXM_UUID_FILTER */
  oc_do_site_local_ipv6_discovery_all(&discovery, NULL);
  oc_do_realm_local_ipv6_discovery_all(&discovery, NULL);
#ifdef OC_IPV4
  oc_do_ip_discovery_all(&discovery, NULL);
#endif /* OC_IPV4 */
#endif /* OC_DOXM_UUID_FILTER */
  // oc_do_ip_discovery_all(& discovery, NULL);
  // oc_do_ip_discovery("oic.wk.res", &discovery, NULL);
}

#ifndef NO_MAIN

#ifdef WIN32
/**
 * signal the event loop (windows version)
 * wakes up the main function to handle the next callback
 */
STATIC void
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
STATIC void
signal_event_loop(void)
{
  pthread_cond_signal(&cv);
}
#endif /* __linux__ */

/**
 * handle Ctrl-C
 * @param signal the captured signal
 */
STATIC void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
  signal_event_loop();
}

#ifdef OC_CLOUD
/**
 * cloud status handler.
 * handler to print out the status of the cloud connection
 *
 * @param ctx the cloud context
 * @param status the cloud status
 * @param data the user data supplied to the callback
 */
STATIC void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx != NULL) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
    /* issue start up request*/
    // issue_requests_all();
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    OC_PRINTF("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    OC_PRINTF("\t\t-Refreshed Token\n");
  }

  if (ctx != NULL) {
    const char *at = oc_string(ctx->store.access_token);
    OC_PRINTF("   AC   = %s\n", at != NULL ? at : "");
    const char *ap = oc_string(ctx->store.auth_provider);
    OC_PRINTF("   AP   = %s\n", ap != NULL ? ap : "");
    const char *ci = oc_string(ctx->store.ci_server);
    OC_PRINTF("   CI   = %s\n", ci != NULL ? ci : "");
    const char *uid = oc_string(ctx->store.uid);
    OC_PRINTF("   UUID = %s\n", uid != NULL ? uid : "");
  }
}
#endif // OC_CLOUD

#if defined(OC_SECURITY) && defined(OC_PKI)
/** read certificate in PEM format */
STATIC int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    OC_PRINTF("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    OC_PRINTF("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

/**
 * factory reset callback: resetting device with cloud_ca trust anchors.
 *
 * @param device the device handle
 * @param data the user date
 */
STATIC void
minimal_factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

#ifdef OC_SECURITY
/**
 * callback when the server changes ownership
 *
 * @param device_uuid the new device ID
 * @param device_index the index in the device list
 * @param owned owned/unowned
 */
STATIC void
oc_ownership_status_cb(const oc_uuid_t *device_uuid, size_t device_index,
                       bool owned, void *user_data)
{
  (void)user_data;
  (void)device_index;
  (void)owned;

  char uuid[37] = { 0 };
  oc_uuid_to_str(device_uuid, uuid, OC_UUID_LEN);
  OC_PRINTF(" oc_ownership_status_cb: UUID: '%s'\n", uuid);
}
#endif /* OC_SECURITY */

static void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  OC_PRINTF("Started device with ID: %s\n", buffer);
}

static bool
init(void)
{
#ifdef WIN32
  /* windows specific */
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  /* install Ctrl-C */
  signal(SIGINT, handle_signal);
#endif /* WIN32 */
#ifdef __linux__
  /* linux specific */
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  /* install Ctrl-C */
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
#endif /* __linux__ */
  return true;
}

static void
deinit(void)
{
#ifdef __linux__
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
#endif /* __linux__ */
}

static void
run_loop(void)
{
#ifdef WIN32
  /* windows specific loop */
  while (quit != 1) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    if (next_event_mt == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now_mt = oc_clock_time_monotonic();
      if (now_mt < next_event_mt) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
#endif /* WIN32 */

#ifdef __linux__
  /* linux specific loop */
  while (quit != 1) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    pthread_mutex_lock(&mutex);
    if (next_event_mt == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&cv, &mutex, &next_event);
    }
    pthread_mutex_unlock(&mutex);
  }
#endif /* __linux__ */
}

/**
 * main application.
 * intializes the global variables
 * registers and starts the handler
 * handles (in a loop) the next event.
 * shuts down the stack
 *
 * @param argc the amount of arguments
 * @param argv the arguments
 */
int
main(int argc, char *argv[])
{
  if (!init()) {
    return -1;
  }

  memset(&g_d2dserverlist_d2dserverlist, 0,
         sizeof(g_d2dserverlist_d2dserverlist));

  if (argc > 1) {
    device_name = argv[1];
    OC_PRINTF("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    OC_PRINTF("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    OC_PRINTF("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    OC_PRINTF("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    OC_PRINTF("apn: %s\n", argv[5]);
  }

  char buff[FILENAME_MAX];
  char *retbuf = NULL;
  retbuf = GetCurrentDir(buff, FILENAME_MAX);
  if (retbuf != NULL) {
    OC_PRINTF("Current working dir: %s\n", buff);
  }
  OC_PRINTF("OCF Server name : \"%s\"\n", device_name);

  /*
   The storage folder depends on the build system
   for Windows the projects simpleserver and cloud_server are overwritten, hence
   the folders should be the same as those targets. for Linux (as default) the
   folder is created in the makefile, with $target as name with _cred as post
   fix.
  */
#ifdef OC_SECURITY
  OC_PRINTF("Intialize Secure Resources\n");
#ifdef OC_CLOUD
  OC_PRINTF("\tstorage at './cloud_proxy_creds' \n");
  oc_storage_config("./cloud_proxy_creds");
#endif

  /*intialize the variables */
  initialize_variables();

#endif /* OC_SECURITY */

  /* initializes the handlers structure */
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
#ifdef OC_CLIENT
#ifdef PROXY_ALL_DISCOVERED_DEVICES
    .requests_entry = issue_requests_all,
#else
    .requests_entry = NULL,
#endif
#endif
  };
#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
  /* please enable OC_SECURITY_PIN
    - have display capabilities to display the PIN value
    - server require to implement RANDOM PIN (oic.sec.doxm.rdp) onboarding
    mechanism
  */
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */

  oc_set_factory_presets_cb(minimal_factory_presets_cb, NULL);
  // oc_set_factory_presets_cb(factory_presets_cb, NULL);

  /* start the stack */
  int ret = oc_main_init(&handler);
  if (ret < 0) {
    OC_PRINTF("oc_main_init failed %d, exiting.\n", ret);
    deinit();
    return ret;
  }

#ifdef OC_CLOUD
  /* get the cloud context and start the cloud */
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx) {
    int retval;
    OC_PRINTF("Start Cloud Manager\n");
    retval = oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    OC_PRINTF("   manager status %d\n", retval);
    if (cis) {
      if (argc == 6) {
        int retval;
        /* configure the */
        retval =
          oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
        OC_PRINTF("   config status  %d\n", retval);

        OC_PRINTF("Conf Cloud Manager\n");
        OC_PRINTF("   cis       %s\n", cis);
        OC_PRINTF("   auth_code %s\n", auth_code);
        OC_PRINTF("   sid       %s\n", sid);
        OC_PRINTF("   apn       %s\n", apn);
      } else {
        OC_PRINTF("Conf Cloud Manager: waiting to be provisioned by an OBT\n");
      }
    }
  }
#endif

  oc_uuid_to_str(oc_core_get_device_id(0), proxy_di, OC_UUID_LEN);
  OC_PRINTF(" UUID: '%s'\n", proxy_di);
  display_device_uuid();
#ifdef OC_SECURITY
  oc_add_ownership_status_cb(oc_ownership_status_cb, NULL);
#endif /* OC_SECURITY */

#ifdef RESET
  // reset the device, for easier debugging.
  OC_PRINTF(" RESET DEVICE\n");
  oc_reset();
#endif

  OC_PRINTF("OCF server \"%s\" running, waiting on incoming connections.\n",
            device_name);
  run_loop();

  /* shut down the stack */
#ifdef OC_CLOUD
  OC_PRINTF("Stop Cloud Manager\n");
  oc_cloud_manager_stop(ctx);
#endif
  oc_main_shutdown();
  deinit();
  return 0;
}
#endif /* NO_MAIN */
