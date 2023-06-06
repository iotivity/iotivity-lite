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
 */
/*
 tool_version          : 20200103
 input_file            : ../device_output/out_codegeneration_merged.swagger.json
 version of input_file :
 title of input_file   : server_lite_4209
*/

#include "oc_api.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif /* OC_IDD_API */

#include <signal.h>
#include <stdlib.h>

#ifdef WIN32
/* windows specific code */
#include <windows.h>
static CONDITION_VARIABLE cv; /* event loop variable */
static CRITICAL_SECTION cs;   /* event loop variable */
#endif

#ifdef __linux__
#include <pthread.h>
static pthread_mutex_t mutex;
static pthread_cond_t cv;
#endif /* __linux__ */

#define btoa(x) ((x) ? "true" : "false")

#define MAX_STRING 30         /* max size of the strings. */
#define MAX_PAYLOAD_STRING 65 /* max size strings in the payload */
#define MAX_ARRAY 10          /* max size of the array */
/* Note: Magic numbers are derived from the resource definition, either from the
 * example or the definition.*/

static OC_ATOMIC_INT8_T quit = 0; /* stop variable, used by handle_signal */

/* Resource variables */
static oc_resource_t *res_binaryswitch_both;

/* global property variables for path: "/binaryswitch_both" */
static int g_binaryswitch_both_storage_status =
  0; /* 0=no storage, 1=startup, 2=startup.revert */
static const char *g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value =
  "value"; /* the name for the attribute */
static bool g_binaryswitch_both_value =
  false; /* current value of property "value" The status of the switch. */
/* global property variables for path: "/binaryswitch_revert" */
static int g_binaryswitch_revert_storage_status =
  0; /* 0=no storage, 1=startup, 2=startup.revert */
static const char *g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value =
  "value"; /* the name for the attribute */
static bool g_binaryswitch_revert_value =
  false; /* current value of property "value" The status of the switch. */
/* global property variables for path: "/binaryswitch_startup" */
static int g_binaryswitch_startup_storage_status =
  0; /* 0=no storage, 1=startup, 2=startup.revert */
static const char *g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value =
  "value"; /* the name for the attribute */
static bool g_binaryswitch_startup_value = false;
/* current value of property "value" The status of the switch. */ /* registration
                                                                     data
                                                                     variables
                                                                     for the
                                                                     resources
                                                                   */

/* global resource variables for path: /binaryswitch_both */
static const char *g_binaryswitch_both_RESOURCE_ENDPOINT =
  "/binaryswitch_both"; /* used path for this resource */
static const char *g_binaryswitch_both_RESOURCE_TYPE[MAX_STRING] = {
  "oic.r.switch.binary"
}; /* rt value (as an array) */
static int g_binaryswitch_both_nr_resource_types = 1;
/* global resource variables for path: /binaryswitch_revert */
static const char *g_binaryswitch_revert_RESOURCE_ENDPOINT =
  "/binaryswitch_revert"; /* used path for this resource */
static const char *g_binaryswitch_revert_RESOURCE_TYPE[MAX_STRING] = {
  "oic.r.switch.binary"
}; /* rt value (as an array) */
static int g_binaryswitch_revert_nr_resource_types = 1;
/* global resource variables for path: /binaryswitch_startup */
static const char *g_binaryswitch_startup_RESOURCE_ENDPOINT =
  "/binaryswitch_startup"; /* used path for this resource */
static const char *g_binaryswitch_startup_RESOURCE_TYPE[MAX_STRING] = {
  "oic.r.switch.binary"
}; /* rt value (as an array) */
static int g_binaryswitch_startup_nr_resource_types = 1;

/**
 * function to set up the device.
 *
 */
static int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be ocf.2.2.0 (or even higher)
     supplied values are for ocf.2.2.3 */
  ret |= oc_add_device("/oic/d", "oic.d.light", "server_lite_4209",
                       "ocf.2.2.3",                   /* icv value */
                       "ocf.res.1.3.0, ocf.sh.1.3.0", /* dmv value */
                       NULL, NULL);

#if defined(OC_IDD_API)
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read 'server_introspection.cbor'\n"
    "\tIntrospection data not set.\n";
  FILE *fp = fopen(
    "c:/users/m.trayer/OCF/ResourceDefaults/server_introspection.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      printf(
        "\tIntrospection data set 'server_introspection.cbor': %d [bytes]\n",
        (int)buffer_size);
    } else {
      printf("%s", introspection_error);
    }
    free(buffer);
  } else {
    printf("%s", introspection_error);
  }
#else
  printf("\t introspection via header file\n");
#endif
  return ret;
}

/**
 * helper function to check if the POST input document contains
 * the common readOnly properties or the resouce readOnly properties
 * @param name the name of the property
 * @return the error_status, e.g. if error_status is true, then the input
 * document contains something illegal
 */
static bool
check_on_readonly_common_resource_properties(oc_string_t name, bool error_state)
{
  if (strcmp(oc_string(name), "n") == 0) {
    printf("   property \"n\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "if") == 0) {
    printf("   property \"if\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "rt") == 0) {
    printf("   property \"rt\" is ReadOnly \n");
    return true;
  }
  if (strcmp(oc_string(name), "id") == 0) {
    printf("   property \"id\" is ReadOnly \n");
    return true;
  }
  return error_state;
}

/**
 * get method for "/binaryswitch_both" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: This Resource describes a binary switch
 * (on/off). The Property "value" is a boolean. A value of 'true' means that the
 * switch is on. A value of 'false' means that the switch is off.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_binaryswitch_both(oc_request_t *request, oc_interface_mask_t interfaces,
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
  int oc_status_code = OC_STATUS_OK;

  printf("-- Begin get_binaryswitch_both: interface %d\n", interfaces);
  printf("-- Global storage status: %d\n", g_binaryswitch_both_storage_status);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    printf("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_both_value);
    printf("   %s : %s\n", g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_both_value));
    break;
  case OC_IF_A:

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_both_value);
    printf("   %s : %s\n", g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_both_value));
    break;
  case OC_IF_STARTUP:
    if (g_binaryswitch_both_storage_status != 1) {
      error_state = true;
      break;
    }

#ifdef OC_STORAGE
    /* property (boolean) 'value' */
    {
      bool temp_value;
      long temp_size =
        oc_storage_read("g_binaryswitch_both_value", (uint8_t *)&temp_value,
                        sizeof(temp_value));
      oc_rep_set_boolean(root, value, temp_value);
      printf("   (startup) %s : %s (%ld)\n",
             g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value, btoa(temp_value),
             temp_size);
    }
#endif /* OC_STORAGE */
    break;
  case OC_IF_STARTUP_REVERT:
    if (g_binaryswitch_both_storage_status != 2) {
      error_state = true;
      break;
    }

    oc_status_code = OC_STATUS_NOT_MODIFIED;

    /*
   ** No payload is sent in the Retrieve while in Revert case
  property (boolean) 'value'
    {
     bool temp_value;
     long temp_size;
     temp_size = oc_storage_read("g_binaryswitch_both_value",
  (uint8_t*)&temp_value, sizeof(temp_value)); oc_rep_set_boolean(root, value,
  temp_value); printf("   (startup) %s : %s (%ld)\n",
  g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,  btoa(temp_value),
  temp_size);
    }
  */
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, oc_status_code);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  printf("-- End get_binaryswitch_both\n");
}

/**
 * get method for "/binaryswitch_revert" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: This Resource describes a binary switch
 * (on/off). The Property "value" is a boolean. A value of 'true' means that the
 * switch is on. A value of 'false' means that the switch is off.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_binaryswitch_revert(oc_request_t *request, oc_interface_mask_t interfaces,
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
  int oc_status_code = OC_STATUS_OK;

  printf("-- Begin get_binaryswitch_revert: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    printf("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_revert_value);
    printf("   %s : %s\n", g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_revert_value));
    break;
  case OC_IF_A:

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_revert_value);
    printf("   %s : %s\n", g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_revert_value));
    break;
  case OC_IF_STARTUP_REVERT:
    if (g_binaryswitch_revert_storage_status != 2) {
      error_state = true;
      break;
    }
    oc_status_code = OC_STATUS_NOT_MODIFIED;
    /* No payload is sent for a RETRIEVE in Revert
    {
     bool temp_value;
     long temp_size;
     temp_size = oc_storage_read("g_binaryswitch_revert_value",
    (uint8_t*)&temp_value, sizeof(temp_value));
     // oc_rep_set_boolean(root, value, temp_value);
     printf("   (startup) %s : %s (%ld)\n",
    g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value,  btoa(temp_value),
    temp_size);
    }
  */
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, oc_status_code);
  } else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  printf("-- End get_binaryswitch_revert\n");
}

/**
 * get method for "/binaryswitch_startup" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description: This Resource describes a binary switch
 * (on/off). The Property "value" is a boolean. A value of 'true' means that the
 * switch is on. A value of 'false' means that the switch is off.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_binaryswitch_startup(oc_request_t *request, oc_interface_mask_t interfaces,
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

  printf("-- Begin get_binaryswitch_startup: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    printf("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_startup_value);
    printf("   %s : %s\n", g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_startup_value));
    break;
  case OC_IF_A:

    /* property (boolean) 'value' */
    oc_rep_set_boolean(root, value, g_binaryswitch_startup_value);
    printf("   %s : %s\n", g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value,
           btoa(g_binaryswitch_startup_value));
    break;
  case OC_IF_STARTUP:
    if (g_binaryswitch_startup_storage_status != 1) {
      oc_send_response(request, OC_STATUS_BAD_OPTION);
    }
#ifdef OC_STORAGE
    /* property (boolean) 'value' */
    {
      bool temp_value;
      long temp_size;
      temp_size = oc_storage_read("g_binaryswitch_startup_value",
                                  (uint8_t *)&temp_value, sizeof(temp_value));
      oc_rep_set_boolean(root, value, temp_value);
      printf("   (startup) %s : %s (%ld)\n",
             g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value,
             btoa(temp_value), temp_size);
    }
#endif /* OC_STORAGE */
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
  printf("-- End get_binaryswitch_startup\n");
}

/**
* post method for "/binaryswitch_both" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
post_binaryswitch_both(oc_request_t *request, oc_interface_mask_t interfaces,
                       void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  printf("-- Begin post_binaryswitch_both:\n");
  printf("-- Global storage status: %d\n", g_binaryswitch_both_storage_status);

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  bool var_in_request = false;
  const oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    printf(" required property: 'value' not in request\n");
  }
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    printf("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        printf("   property 'value' is not of type bool %d \n", rep->type);
      }
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    case OC_IF_STARTUP: {
      g_binaryswitch_both_storage_status = 1;
#ifdef OC_STORAGE
      oc_storage_write("g_binaryswitch_both_storage_status",
                       (uint8_t *)&g_binaryswitch_both_storage_status,
                       sizeof(g_binaryswitch_both_storage_status));
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign startup) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* write storage "value" */
          long temp_size = oc_storage_write("g_binaryswitch_both_value",
                                            (uint8_t *)&rep->value.boolean,
                                            sizeof(g_binaryswitch_both_value));
          printf("  storage (startup)  property 'value' : %s (%ld)\n",
                 btoa(rep->value.boolean), temp_size);
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response (startup) \n");
      oc_rep_start_root_object();

      /* property (boolean) 'value' */
      {
        bool temp_value;
        long temp_size =
          oc_storage_read("g_binaryswitch_both_value", (uint8_t *)&temp_value,
                          sizeof(temp_value));
        oc_rep_set_boolean(root, value, temp_value);
        printf("   (startup) %s : %s (%ld)\n",
               g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,
               btoa(temp_value), temp_size);
      }
      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      oc_send_response(request, OC_STATUS_CHANGED);
    } break;
    case OC_IF_STARTUP_REVERT: {
      g_binaryswitch_both_storage_status = 2;
#ifdef OC_STORAGE
      oc_storage_write("g_binaryswitch_both_storage_status",
                       (uint8_t *)&g_binaryswitch_both_storage_status,
                       sizeof(g_binaryswitch_both_storage_status));
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign startup.revert) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* write storage "value" */
          long temp_size = oc_storage_write("g_binaryswitch_both_value",
                                            (uint8_t *)&rep->value.boolean,
                                            sizeof(g_binaryswitch_both_value));
          printf("  storage (startup.revert)  property 'value' : %s (%ld)\n",
                 btoa(rep->value.boolean), temp_size);
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response (startup) \n");
      oc_rep_start_root_object();

      /* property (boolean) 'value' */
      {
        bool temp_value;
        long temp_size =
          oc_storage_read("g_binaryswitch_both_value", (uint8_t *)&temp_value,
                          sizeof(temp_value));
        oc_rep_set_boolean(root, value, temp_value);
        printf("   (startup.revert) %s : %s (%ld)\n",
               g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,
               btoa(temp_value), temp_size);
      }
      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      oc_send_response(request, OC_STATUS_CHANGED);
    } break;
    default: {
#ifdef OC_STORAGE
      if (g_binaryswitch_both_storage_status == 2) {
        /* write the properties to the storage */
        const oc_rep_t *rep = request->request_payload;
        while (rep != NULL) {
          printf("key: (assign startup default) %s \n", oc_string(rep->name));
          /* no error: assign the variables */

          if (strcmp(oc_string(rep->name),
                     g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
            /* write storage "value" */
            long temp_size = oc_storage_write(
              "g_binaryswitch_both_value", (uint8_t *)&rep->value.boolean,
              sizeof(g_binaryswitch_both_value));
            printf("  storage (startup default)  property 'value' : %s (%ld)\n",
                   btoa(rep->value.boolean), temp_size);
          }
          rep = rep->next;
        }
      } /* g_binaryswitch_both_storage_status */
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* assign "value" */
          printf("  property 'value' : %s\n", btoa(rep->value.boolean));
          g_binaryswitch_both_value = rep->value.boolean;
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response for default interface \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */
      printf("   %s : %s", g_binaryswitch_both_RESOURCE_PROPERTY_NAME_value,
             btoa(g_binaryswitch_both_value));
      oc_rep_set_boolean(root, value, g_binaryswitch_both_value);
      // oc_storage_write("g_binaryswitch_both_value",
      // (uint8_t*)&g_binaryswitch_both_value,
      // sizeof(g_binaryswitch_both_value));

      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
         actuator. one can use the global variables as input to those calls
         the global values have been updated already with the data from the
         request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    printf("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  printf("-- End post_binaryswitch_both\n");
}

/**
* post method for "/binaryswitch_revert" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
post_binaryswitch_revert(oc_request_t *request, oc_interface_mask_t interfaces,
                         void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  printf("-- Begin post_binaryswitch_revert:\n");

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  bool var_in_request = false;
  const oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    printf(" required property: 'value' not in request\n");
  }
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    printf("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        printf("   property 'value' is not of type bool %d \n", rep->type);
      }
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    case OC_IF_STARTUP_REVERT: {
      g_binaryswitch_revert_storage_status = 2;
#ifdef OC_STORAGE
      oc_storage_write("g_binaryswitch_revert_storage_status",
                       (uint8_t *)&g_binaryswitch_revert_storage_status,
                       sizeof(g_binaryswitch_revert_storage_status));
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign startup) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* write storage "value" */
          long temp_size = oc_storage_write(
            "g_binaryswitch_revert_value", (uint8_t *)&rep->value.boolean,
            sizeof(g_binaryswitch_revert_value));
          printf("  storage (startup.revert)  property 'value' : %s (%ld)\n",
                 btoa(rep->value.boolean), temp_size);
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response (startup) \n");
      oc_rep_start_root_object();

      /* property (boolean) 'value' */
      {
        bool temp_value;
        long temp_size =
          oc_storage_read("g_binaryswitch_revert_value", (uint8_t *)&temp_value,
                          sizeof(temp_value));
        oc_rep_set_boolean(root, value, temp_value);
        printf("   (startup) %s : %s (%ld)\n",
               g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value,
               btoa(temp_value), temp_size);
      }
      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      oc_send_response(request, OC_STATUS_CHANGED);
    } break;
    default: {
#ifdef OC_STORAGE
      if (g_binaryswitch_revert_storage_status == 2) {
        /* write the properties to the storage */
        const oc_rep_t *rep = request->request_payload;
        while (rep != NULL) {
          printf("key: (assign startup) %s \n", oc_string(rep->name));
          /* no error: assign the variables */

          if (strcmp(oc_string(rep->name),
                     g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value) == 0) {
            /* write storage "value" */
            long temp_size = oc_storage_write(
              "g_binaryswitch_revert_value", (uint8_t *)&rep->value.boolean,
              sizeof(g_binaryswitch_revert_value));
            printf("  storage (startup.revert)  property 'value' : %s (%ld)\n",
                   btoa(rep->value.boolean), temp_size);
          }
          rep = rep->next;
        }
      } /* g_binaryswitch_revert_storage_status */
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* assign "value" */
          printf("  property 'value' : %s\n", btoa(rep->value.boolean));
          g_binaryswitch_revert_value = rep->value.boolean;
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */
      printf("   %s : %s", g_binaryswitch_revert_RESOURCE_PROPERTY_NAME_value,
             btoa(g_binaryswitch_revert_value));
      oc_rep_set_boolean(root, value, g_binaryswitch_revert_value);
      oc_storage_write("g_binaryswitch_revert_value",
                       (uint8_t *)&g_binaryswitch_revert_value,
                       sizeof(g_binaryswitch_revert_value));

      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
       actuator. one can use the global variables as input to those calls the
       global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    printf("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  printf("-- End post_binaryswitch_revert\n");
}

/**
* post method for "/binaryswitch_startup" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
post_binaryswitch_startup(oc_request_t *request, oc_interface_mask_t interfaces,
                          void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  printf("-- Begin post_binaryswitch_startup:\n");

  /* loop over the request document for each required input field to check if
   * all required input fields are present */
  bool var_in_request = false;
  const oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false) {
    error_state = true;
    printf(" required property: 'value' not in request\n");
  }
  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    printf("key: (check) %s \n", oc_string(rep->name));

    error_state =
      check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        printf("   property 'value' is not of type bool %d \n", rep->type);
      }
    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    switch (interfaces) {
    case OC_IF_STARTUP: {
      g_binaryswitch_startup_storage_status = 1;
#ifdef OC_STORAGE
      oc_storage_write("g_binaryswitch_startup_storage_status",
                       (uint8_t *)&g_binaryswitch_startup_storage_status,
                       sizeof(g_binaryswitch_startup_storage_status));
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign startup) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* write storage "value" */
          long temp_size = oc_storage_write(
            "g_binaryswitch_startup_value", (uint8_t *)&rep->value.boolean,
            sizeof(g_binaryswitch_startup_value));
          printf("  storage (startup.revert)  property 'value' : %s (%ld)\n",
                 btoa(rep->value.boolean), temp_size);
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response (startup) \n");
      oc_rep_start_root_object();

      /* property (boolean) 'value' */
      {
        bool temp_value;
        long temp_size =
          oc_storage_read("g_binaryswitch_startup_value",
                          (uint8_t *)&temp_value, sizeof(temp_value));
        oc_rep_set_boolean(root, value, temp_value);
        printf("   (startup) %s : %s (%ld)\n",
               g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value,
               btoa(temp_value), temp_size);
      }
      oc_rep_end_root_object();
#endif /* OC_STORAGE */
      oc_send_response(request, OC_STATUS_CHANGED);
    } break;
    default: {
      /* loop over all the properties in the input document */
      const oc_rep_t *rep = request->request_payload;
      while (rep != NULL) {
        printf("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name),
                   g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value) == 0) {
          /* assign "value" */
          printf("  property 'value' : %s\n", btoa(rep->value.boolean));
          g_binaryswitch_startup_value = rep->value.boolean;
        }
        rep = rep->next;
      }
      /* set the response */
      printf("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */
      printf("   %s : %s", g_binaryswitch_startup_RESOURCE_PROPERTY_NAME_value,
             btoa(g_binaryswitch_startup_value));
      oc_rep_set_boolean(root, value, g_binaryswitch_startup_value);

      oc_rep_end_root_object();
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an
       actuator. one can use the global variables as input to those calls the
       global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  } else {
    printf("  Returning Error \n");
    /* TODO: add error response, if any */
    // oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  printf("-- End post_binaryswitch_startup\n");
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
static void
register_resources(void)
{
  printf("Register Resource with local path \"/binaryswitch_both\"\n");
  res_binaryswitch_both =
    oc_new_resource(NULL, g_binaryswitch_both_RESOURCE_ENDPOINT,
                    g_binaryswitch_both_nr_resource_types, 0);
  printf("     number of Resource Types: %d\n",
         g_binaryswitch_both_nr_resource_types);
  for (int a = 0; a < g_binaryswitch_both_nr_resource_types; a++) {
    printf("     Resource Type: \"%s\"\n",
           g_binaryswitch_both_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_binaryswitch_both,
                                   g_binaryswitch_both_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_binaryswitch_both,
                                      OC_IF_A); /* oic.if.a */
  oc_resource_bind_resource_interface(res_binaryswitch_both,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_binaryswitch_both,
                                      OC_IF_STARTUP); /* oic.if.startup */
  oc_resource_bind_resource_interface(
    res_binaryswitch_both, OC_IF_STARTUP_REVERT); /* oic.if.startup.revert */
  oc_resource_set_default_interface(res_binaryswitch_both, OC_IF_A);
  printf("     Default OCF Interface: 'oic.if.a'\n");
  oc_resource_set_discoverable(res_binaryswitch_both, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second
  oc_resource_set_periodic_observable(res_binaryswitch_both, 1); */
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is
    called. this function must be called when the value changes, preferable on
    an interrupt when something is read from the hardware. */
  oc_resource_set_observable(res_binaryswitch_both, true);

  oc_resource_set_request_handler(res_binaryswitch_both, OC_GET,
                                  get_binaryswitch_both, NULL);

  oc_resource_set_request_handler(res_binaryswitch_both, OC_POST,
                                  post_binaryswitch_both, NULL);

  oc_add_resource(res_binaryswitch_both);

  printf("Register Resource with local path \"/binaryswitch_revert\"\n");
  oc_resource_t *res_binaryswitch_revert =
    oc_new_resource(NULL, g_binaryswitch_revert_RESOURCE_ENDPOINT,
                    g_binaryswitch_revert_nr_resource_types, 0);
  printf("     number of Resource Types: %d\n",
         g_binaryswitch_revert_nr_resource_types);
  for (int a = 0; a < g_binaryswitch_revert_nr_resource_types; a++) {
    printf("     Resource Type: \"%s\"\n",
           g_binaryswitch_revert_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_binaryswitch_revert,
                                   g_binaryswitch_revert_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_binaryswitch_revert,
                                      OC_IF_A); /* oic.if.a */
  oc_resource_bind_resource_interface(res_binaryswitch_revert,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(
    res_binaryswitch_revert, OC_IF_STARTUP_REVERT); /* oic.if.startup.revert */
  oc_resource_set_default_interface(res_binaryswitch_revert, OC_IF_A);
  printf("     Default OCF Interface: 'oic.if.a'\n");
  oc_resource_set_discoverable(res_binaryswitch_revert, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second
  oc_resource_set_periodic_observable(res_binaryswitch_revert, 1); */
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is
    called. this function must be called when the value changes, preferable on
    an interrupt when something is read from the hardware. */
  oc_resource_set_observable(res_binaryswitch_revert, true);

  oc_resource_set_request_handler(res_binaryswitch_revert, OC_GET,
                                  get_binaryswitch_revert, NULL);
  oc_resource_set_request_handler(res_binaryswitch_revert, OC_POST,
                                  post_binaryswitch_revert, NULL);

  oc_add_resource(res_binaryswitch_revert);

  printf("Register Resource with local path \"/binaryswitch_startup\"\n");
  oc_resource_t *res_binaryswitch_startup =
    oc_new_resource(NULL, g_binaryswitch_startup_RESOURCE_ENDPOINT,
                    g_binaryswitch_startup_nr_resource_types, 0);
  printf("     number of Resource Types: %d\n",
         g_binaryswitch_startup_nr_resource_types);
  for (int a = 0; a < g_binaryswitch_startup_nr_resource_types; a++) {
    printf("     Resource Type: \"%s\"\n",
           g_binaryswitch_startup_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_binaryswitch_startup,
                                   g_binaryswitch_startup_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_binaryswitch_startup,
                                      OC_IF_A); /* oic.if.a */
  oc_resource_bind_resource_interface(res_binaryswitch_startup,
                                      OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_binaryswitch_startup,
                                      OC_IF_STARTUP); /* oic.if.startup */
  oc_resource_set_default_interface(res_binaryswitch_startup, OC_IF_A);
  printf("     Default OCF Interface: 'oic.if.a'\n");
  oc_resource_set_discoverable(res_binaryswitch_startup, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second */
  /* oc_resource_set_periodic_observable(res_binaryswitch_startup, 1); */
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is
    called. this function must be called when the value changes, preferable on
    an interrupt when something is read from the hardware. */
  oc_resource_set_observable(res_binaryswitch_startup, true);

  oc_resource_set_request_handler(res_binaryswitch_startup, OC_GET,
                                  get_binaryswitch_startup, NULL);
  oc_resource_set_request_handler(res_binaryswitch_startup, OC_POST,
                                  post_binaryswitch_startup, NULL);

  oc_add_resource(res_binaryswitch_startup);
}

/**
static void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
#include "oc_pki.h"
#include "pki_certs.h"
  int credid =
    oc_pki_add_mfg_cert(0, (const unsigned char *)my_cert, strlen(my_cert),
                        (const unsigned char *)my_key, strlen(my_key));
  if (credid < 0) {
    printf("ERROR installing PKI certificate\n");
  } else {
    printf("Successfully installed PKI certificate\n");
  }

  if (oc_pki_add_mfg_intermediate_cert(0, credid, (const unsigned char *)int_ca,
                                       strlen(int_ca)) < 0) { printf("ERROR
installing intermediate CA certificate\n"); } else { printf("Successfully
installed intermediate CA certificate\n");
  }

  if (oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)root_ca,
                                  strlen(root_ca)) < 0) {
    printf("ERROR installing root certificate\n");
  } else {
    printf("Successfully installed root certificate\n");
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
#else
  printf("No PKI certificates installed\n");
#endif
}
*/

/**
 * intializes the global variables
 * registers and starts the handler
 */
static void
initialize_variables(void)
{
/* initialize global variables for resource "/binaryswitch_both" */
#ifdef OC_STORAGE
  oc_storage_read("g_binaryswitch_both_storage_status",
                  (uint8_t *)&g_binaryswitch_both_storage_status,
                  sizeof(g_binaryswitch_both_storage_status));
#endif /* OC_STORAGE */
  g_binaryswitch_both_value =
    false; /* current value of property "value" The status of the switch. */
#ifdef OC_STORAGE
  long ret_size = oc_storage_read("g_binaryswitch_both_value",
                                  (uint8_t *)&g_binaryswitch_both_value,
                                  sizeof(g_binaryswitch_both_value));

  if (ret_size != sizeof(g_binaryswitch_both_value)) {
    printf(" could not read store g_binaryswitch_both_value : %ld\n", ret_size);
  }
  /* initialize global variables for resource "/binaryswitch_revert" */
  oc_storage_read("g_binaryswitch_revert_storage_status",
                  (uint8_t *)&g_binaryswitch_revert_storage_status,
                  sizeof(g_binaryswitch_revert_storage_status));
#endif /* OC_STORAGE */
  g_binaryswitch_revert_value =
    false; /* current value of property "value" The status of the switch. */
#ifdef OC_STORAGE
  ret_size = oc_storage_read("g_binaryswitch_revert_value",
                             (uint8_t *)&g_binaryswitch_revert_value,
                             sizeof(g_binaryswitch_revert_value));
  if (ret_size != sizeof(g_binaryswitch_revert_value)) {
    printf(" could not read store g_binaryswitch_revert_value : %ld\n",
           ret_size);
  }
  /* initialize global variables for resource "/binaryswitch_startup" */
  oc_storage_read("g_binaryswitch_startup_storage_status",
                  (uint8_t *)&g_binaryswitch_startup_storage_status,
                  sizeof(g_binaryswitch_startup_storage_status));
#endif /* OC_STORAGE */
  g_binaryswitch_startup_value =
    false; /* current value of property "value" The status of the switch. */
#ifdef OC_STORAGE
  ret_size = oc_storage_read("g_binaryswitch_startup_value",
                             (uint8_t *)&g_binaryswitch_startup_value,
                             sizeof(g_binaryswitch_startup_value));
  if (ret_size != sizeof(g_binaryswitch_startup_value)) {
    printf(" could not read store g_binaryswitch_startup_value : %ld\n",
           ret_size);
  }
#endif /* OC_STORAGE */
  /* set the flag for NO oic/con resource. */
  oc_set_con_res_announced(false);
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
  pthread_cond_signal(&cv);
}
#endif /* __linux__ */

/**
 * handle Ctrl-C
 * @param signal the captured signal
 */
static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

static bool
init(void)
{
#ifdef _WIN32
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  signal(SIGINT, handle_signal);
#else
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    printf("pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
#endif /* _WIN32 */
  return true;
}

static void
deinit(void)
{
#ifndef WIN32
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
#endif /* !WIN32 */
}

static void
run_loop(void)
{
#ifdef WIN32
  while (OC_ATOMIC_LOAD8(quit) != 1) {
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
  while (OC_ATOMIC_LOAD8(quit) != 1) {
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
 */
int
main(void)
{
  if (!init()) {
    return -1;
  }

  printf("Used input file : "
         "\"../device_output/out_codegeneration_merged.swagger.json\"\n");
  printf("OCF Server name : \"server_lite_4209\"\n");

#ifdef OC_STORAGE
  /*
   The storage folder depends on the build system
   for Windows the projects simpleserver and cloud_server are overwritten, hence
   the folders should be the same as those targets. for Linux (as default) the
   folder is created in the makefile, with $target as name with _cred as post
   fix.
  */
  printf("\tstorage at './simpleserver_creds' \n");
  oc_storage_config("./simpleserver_creds/");
#endif /* OC_STORAGE */

  /*intialize the variables */
  initialize_variables();

  /* initializes the handlers structure */
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
#ifdef OC_CLIENT
    .requests_entry = 0,
#endif /* OC_CLIENT */
  };

  // oc_set_factory_presets_cb(factory_presets_cb, NULL);

  /* start the stack */
  int ret = oc_main_init(&handler);
  if (ret < 0) {
    printf("oc_main_init failed %d, exiting.\n", ret);
    deinit();
    return ret;
  }

  printf("OCF server \"server_lite_4209\" running, waiting on incoming "
         "connections.\n");
  run_loop();
  /* shut down the stack */
  oc_main_shutdown();
  deinit();
  return 0;
}

#endif /* NO_MAIN */
