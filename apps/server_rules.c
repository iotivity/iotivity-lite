/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright 2017-2019 Open Connectivity Foundation
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

#include "oc_api.h"
#include "oc_collection.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include <signal.h>

#ifdef __linux__
/* linux specific code */
#include <pthread.h>
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
#endif

#ifdef WIN32
/* windows specific code */
#include <windows.h>
static CONDITION_VARIABLE cv; /* event loop variable */
static CRITICAL_SECTION cs;   /* event loop variable */
#endif

#define MAX_STRING 30         /* max size of the strings. */
#define MAX_PAYLOAD_STRING 65 /* max size strings in the payload */
#define MAX_ARRAY 10          /* max size of the array */

volatile int quit = 0; /* stop variable, used by handle_signal */

/* global property variables for path: "/binaryswitch" */
static char g_binaryswitch_RESOURCE_PROPERTY_NAME_value[] = "value";
bool g_binaryswitch_value = false;
static char g_binaryswitch_RESOURCE_INTERFACE[][MAX_STRING] = {
  "oic.if.a", "oic.if.baseline"
};
int g_binaryswitch_nr_resource_interfaces = 2;

/* global property variables for path: "/audio" */
bool g_audio_mute = false;
int g_audio_volume = 50;

/* global resource variables for path: /audio */
static char g_audio_RESOURCE_INTERFACE[][MAX_STRING] = { "oic.if.a",
                                                         "oic.if.baseline" };
int g_audio_nr_resource_interfaces = 2;

/* global resource variables for path: /scenemember1 */
static char g_scenemember_RESOURCE_INTERFACE[][MAX_STRING] = {
  "oic.if.baseline"
};
int g_scenemember_nr_resource_interfaces = 1;
static oc_string_array_t scenemem_link_param_if;
static oc_string_array_t scenemem_link_param_rt;

/* global property variables for path: /ruleaction and /scenecollection */
static oc_string_t lastscene;
static oc_string_t ra_lastscene;
static oc_string_array_t scenevalues;
static oc_string_array_t scenecol_link_param_if;
static oc_string_array_t scenecol_link_param_rt;

/* global resource variables for path: /ruleaction */
static char g_ruleaction_RESOURCE_INTERFACE[][MAX_STRING] = {
  "oic.if.rw", "oic.if.baseline"
};
int g_ruleaction_nr_resource_interfaces = 2;

/* global property variables for path: /ruleexpression */
static oc_string_t rule;
static bool ruleresult = false;
static bool ruleenable = false;
static bool actionenable = false;

/* global resource variables for path: /ruleexpression */
static char g_ruleexpression_RESOURCE_INTERFACE[][MAX_STRING] = {
  "oic.if.rw", "oic.if.baseline"
};
int g_ruleexpression_nr_resource_interfaces = 2;

/* Resource pointers needed for providing notifications when rules execute
 */
oc_resource_t *res_ruleexpression;
oc_resource_t *res_audio;

/**
 * function to set up the device.
 *
 */
static int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be OCF1.3.1 or OCF2.0.0 (or even higher)
     supplied values are for OCF1.3.1 */
  ret |= oc_add_device("/oic/d", "oic.d.stb", "Set Top Box",
                       "ocf.2.0.0",                   /* icv value */
                       "ocf.res.1.3.0, ocf.sh.1.3.0", /* dmv value */
                       NULL, NULL);
  oc_new_string(&rule, "(switch:value = true)", 21);
  oc_new_string(&lastscene, "normalaudio", 12);
  oc_new_string(&ra_lastscene, "loudaudio", 9);
  oc_new_string_array(&scenevalues, (size_t)2);
  oc_string_array_add_item(scenevalues, oc_string(lastscene));
  oc_string_array_add_item(scenevalues, oc_string(ra_lastscene));
  oc_new_string_array(&scenecol_link_param_if, (size_t)2);
  oc_string_array_add_item(scenecol_link_param_if, "oic.if.rw");
  oc_string_array_add_item(scenecol_link_param_if, "oic.if.baseline");
  oc_new_string_array(&scenecol_link_param_rt, (size_t)1);
  oc_string_array_add_item(scenecol_link_param_rt, "oic.wk.scenecollection");
  oc_new_string_array(&scenemem_link_param_if, (size_t)2);
  oc_string_array_add_item(scenemem_link_param_if, "oic.if.a");
  oc_string_array_add_item(scenemem_link_param_if, "oic.if.baseline");
  oc_new_string_array(&scenemem_link_param_rt, (size_t)1);
  oc_string_array_add_item(scenemem_link_param_rt, "oic.r.audio");
  return ret;
}

/**
 * helper function to convert the interface string definition to the constant
 * defintion used by the stack.
 * @param interface the interface string e.g. "oic.if.a"
 * @return the stack constant for the interface
 */
static int
convert_if_string(char *interface_name)
{
  if (strcmp(interface_name, "oic.if.baseline") == 0)
    return OC_IF_BASELINE; /* baseline interface */
  if (strcmp(interface_name, "oic.if.rw") == 0)
    return OC_IF_RW; /* read write interface */
  if (strcmp(interface_name, "oic.if.r") == 0)
    return OC_IF_R; /* read interface */
  if (strcmp(interface_name, "oic.if.s") == 0)
    return OC_IF_S; /* sensor interface */
  if (strcmp(interface_name, "oic.if.a") == 0)
    return OC_IF_A; /* actuator interface */
  if (strcmp(interface_name, "oic.if.b") == 0)
    return OC_IF_B; /* batch interface */
  if (strcmp(interface_name, "oic.if.ll") == 0)
    return OC_IF_LL; /* linked list interface */
  return OC_IF_A;
}

static void
invoke_rule_action()
{
  /*
   * Set lastscene on the target scenecollection
   */
  if (actionenable) {
    lastscene = ra_lastscene;
    g_audio_volume = 60;
    oc_notify_observers(res_audio);
  }
}

static void
rule_notify_expression()
{
  /*
   * rule expression value has changed
   */
  if (ruleenable) {
    /*
     * rule is enabled
     */
    if (g_binaryswitch_value) {
      ruleresult = true;
    } else {
      ruleresult = false;
    }

    oc_notify_observers(res_ruleexpression);

    if (actionenable && ruleresult) {
      invoke_rule_action();
    }
  } else {
    ruleresult = false;
  }
}

/**
 * get method for "/binaryswitch" resource.
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
get_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                 void *user_data)
{
  (void)user_data; /* not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a
     sensor. the call to the HW needs to fill in the global variable before it
     returns to this function here. alternative is to have a callback from the
     hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will
     pass CTT1.2.2 */

  PRINT("get_binaryswitch: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_A:
    /* property "value" */
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    PRINT("   %s : %d\n", g_binaryswitch_RESOURCE_PROPERTY_NAME_value,
          g_binaryswitch_value); /* not handled value */
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
* post method for "/binaryswitch" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param requestRep the request representation.
*/
static void
post_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces,
                  void *user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("post_binaryswitch:\n");
  oc_rep_t *rep = request->request_payload;
  /* loop over the request document to check if all inputs are ok */
  while (rep != NULL) {
    PRINT("key: (check) %s \n", oc_string(rep->name));
    if (strcmp(oc_string(rep->name),
               g_binaryswitch_RESOURCE_PROPERTY_NAME_value) == 0) {
      /* property "value" of type boolean exist in payload */
      if (rep->type != OC_REP_BOOL) {
        error_state = true;
        PRINT("   property 'value' is not of type bool %d \n", rep->type);
      }
    }

    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global
   * variables */
  if (error_state == false) {
    /* loop over all the properties in the input document */
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
      PRINT("key: (assign) %s \n", oc_string(rep->name));
      /* no error: assign the variables */
      if (strcmp(oc_string(rep->name),
                 g_binaryswitch_RESOURCE_PROPERTY_NAME_value) == 0) {
        /* assign "value" */
        g_binaryswitch_value = rep->value.boolean;
      }
      rep = rep->next;
    }
    /* set the response */
    PRINT("Set response \n");
    oc_rep_start_root_object();
    /*oc_process_baseline_interface(request->resource); */
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    oc_rep_end_root_object();

    rule_notify_expression();

    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    /* TODO: add error response, if any */
    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
  }
}

/**
 * get method for "/audio" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description:
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_audio(oc_request_t *request, oc_interface_mask_t interfaces,
          void *user_data)
{
  (void)user_data; /* not used */

  PRINT("get_audio: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_A:
    oc_rep_set_int(root, volume, g_audio_volume);
    oc_rep_set_boolean(root, mute, g_audio_mute);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
* post method for "/audio" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param requestRep the request representation.
*/
static void
post_audio(oc_request_t *request, oc_interface_mask_t interfaces,
           void *user_data)
{
  (void)interfaces;
  (void)user_data;
  PRINT("post_audio:\n");
  oc_rep_t *rep = request->request_payload;

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      g_audio_mute = rep->value.boolean;
      PRINT("value: %d\n", g_audio_mute);
      break;
    case OC_REP_INT:
      g_audio_volume = (int)rep->value.integer;
      PRINT("value: %d\n", g_audio_volume);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }

  oc_send_response(request, OC_STATUS_CHANGED);
}

/**
 * get method for "/scenemember1" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description:
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_scenemember(oc_request_t *request, oc_interface_mask_t interfaces,
                void *user_data)
{
  (void)user_data; /* not used */

  PRINT("get_scenemember: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);

    // "link" Property
    oc_rep_set_object(root, link);
    oc_rep_set_text_string(link, href, "/audio");
    oc_rep_set_string_array(link, rt, scenemem_link_param_rt);
    oc_rep_set_string_array(link, if, scenemem_link_param_if);
    oc_rep_close_object(root, link);

    // SceneMappings array
    oc_rep_set_array(root, SceneMappings);
    oc_rep_object_array_begin_item(SceneMappings);
    oc_rep_set_text_string(SceneMappings, scene, "normalaudio");
    oc_rep_set_text_string(SceneMappings, memberProperty, "volume");
    oc_rep_set_text_string(SceneMappings, memberValue, "40");
    oc_rep_object_array_end_item(SceneMappings);
    oc_rep_object_array_begin_item(SceneMappings);
    oc_rep_set_text_string(SceneMappings, scene, oc_string(ra_lastscene));
    oc_rep_set_text_string(SceneMappings, memberProperty, "volume");
    oc_rep_set_text_string(SceneMappings, memberValue, "60");
    oc_rep_object_array_end_item(SceneMappings);
    oc_rep_close_array(root, SceneMappings);

    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
 * get method for "/ruleexpression" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description:
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_ruleexpression(oc_request_t *request, oc_interface_mask_t interfaces,
                   void *user_data)
{
  (void)user_data; /* not used */

  PRINT("get_ruleexpression: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, ruleresult, ruleresult);
    oc_rep_set_boolean(root, ruleenable, ruleenable);
    oc_rep_set_boolean(root, actionenable, actionenable);
    oc_rep_set_text_string(root, rule, oc_string(rule));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
* post method for "/ruleexpression" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param requestRep the request representation.
*/
static void
post_ruleexpression(oc_request_t *request, oc_interface_mask_t interfaces,
                    void *user_data)
{
  (void)interfaces;
  (void)user_data;

  PRINT("post_ruleexpression:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    printf("  %s :", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "ruleenable", 10) == 0) {
        ruleenable = rep->value.boolean;
        /* If the rule has been newly enabled evaluate the rule expression */
        if (ruleenable) {
          rule_notify_expression();
        }
      } else if (oc_string_len(rep->name) == 12 &&
                 memcmp(oc_string(rep->name), "actionenable", 12) == 0) {
        actionenable = rep->value.boolean;
      } else if (oc_string_len(rep->name) == 10 &&
                 memcmp(oc_string(rep->name), "ruleresult", 10) == 0) {
        /* Attempt to set the result, verify rule is disabled and actions are
         * enabled */
        if (!ruleenable && actionenable) {
          ruleresult = rep->value.boolean;
          if (ruleresult) {
            invoke_rule_action();
          }
        } else {
          // Invalid state for setting ruleresult by a client; fail the request
          oc_send_response(request, OC_STATUS_METHOD_NOT_ALLOWED);
          return;
          break;
        }
      }
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }

  oc_send_response(request, OC_STATUS_CHANGED);
}

/**
 * get method for "/ruleaction" resource.
 * function is called to intialize the return values of the GET method.
 * initialisation of the returned values are done from the global property
 * values. Resource Description:
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void
get_ruleaction(oc_request_t *request, oc_interface_mask_t interfaces,
               void *user_data)
{
  (void)user_data; /* not used */

  PRINT("get_ruleaction: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_text_string(root, scenevalue, "loudaudio");
    oc_rep_set_object(root, link);
    oc_rep_set_text_string(link, href, "/scenecollection1");
    oc_rep_set_string_array(link, rt, scenecol_link_param_rt);
    oc_rep_set_string_array(link, if, scenecol_link_param_if);
    oc_rep_close_object(root, link);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

/**
* post method for "/ruleaction" resource.
* The function has as input the request body, which are the input values of the
POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property
values.
* Resource Description:

*
* @param requestRep the request representation.
*/
static void
post_ruleaction(oc_request_t *request, oc_interface_mask_t interfaces,
                void *user_data)
{
  (void)interfaces;
  (void)user_data;
  PRINT("post_ruleaction:\n");
  /* TODO: loop over the request document to check if all inputs are ok
  bool error_state = false;
  oc_rep_t *rep = request->request_payload;
  */

  oc_send_response(request, OC_STATUS_CHANGED);
}

/**
 * Callbacks for handling Collection level Properties on Scene Collection
 */
bool
set_scenecol_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)resource;
  (void)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_string_len(rep->name) == 9 &&
          memcmp(oc_string(rep->name), "lastScene", 9) == 0) {
        lastscene = rep->value.string;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

void
get_scenecol_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)resource;
  (void)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_rep_set_text_string(root, lastScene, oc_string(lastscene));
    oc_rep_set_string_array(root, sceneValues, scenevalues);
    break;
  default:
    break;
  }
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
 *   - used interfaces (from the global variables).
 */
static void
register_resources(void)
{

  PRINT("Register Resource with local path \"/binaryswitch\"\n");
  oc_resource_t *res_binaryswitch =
    oc_new_resource("Binary Switch", "/binaryswitch", 1, 0);
  oc_resource_bind_resource_type(res_binaryswitch, "oic.r.switch.binary");
  for (int a = 0; a < g_binaryswitch_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(
      res_binaryswitch,
      convert_if_string(g_binaryswitch_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(
    res_binaryswitch, convert_if_string(g_binaryswitch_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_binaryswitch, true);
  oc_resource_set_periodic_observable(res_binaryswitch, 1);
  oc_resource_set_request_handler(res_binaryswitch, OC_GET, get_binaryswitch,
                                  NULL);
  oc_resource_set_request_handler(res_binaryswitch, OC_POST, post_binaryswitch,
                                  NULL);
  oc_add_resource(res_binaryswitch);

  PRINT("Register Resource with local path \"/audio\"\n");
  res_audio = oc_new_resource("Audio", "/audio", 1, 0);
  oc_resource_bind_resource_type(res_audio, "oic.r.audio");
  for (int a = 0; a < g_audio_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(
      res_audio, convert_if_string(g_audio_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(
    res_audio, convert_if_string(g_audio_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_audio, true);
  oc_resource_set_periodic_observable(res_audio, 1);
  oc_resource_set_request_handler(res_audio, OC_GET, get_audio, NULL);
  oc_resource_set_request_handler(res_audio, OC_POST, post_audio, NULL);
  oc_add_resource(res_audio);

  PRINT("Register Resource with local path \"/scenemember1\"\n");
  oc_resource_t *res_scenemember1 =
    oc_new_resource("Scene Member 1", "/scenemember1", 1, 0);
  oc_resource_bind_resource_type(res_scenemember1, "oic.wk.scenemember");
  for (int a = 0; a < g_scenemember_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(
      res_scenemember1, convert_if_string(g_scenemember_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(
    res_scenemember1, convert_if_string(g_scenemember_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_scenemember1, true);
  oc_resource_set_periodic_observable(res_scenemember1, 1);
  oc_resource_set_request_handler(res_scenemember1, OC_GET, get_scenemember,
                                  NULL);
  oc_add_resource(res_scenemember1);

  /**
  PRINT("Register Resource with local path \"/scenemember2\"\n");
  oc_resource_t* res_scenemember2 = oc_new_resource("Scene Member 2",
  "/scenemember2", 1, 0); oc_resource_bind_resource_type(res_scenemember2,
  "oic.wk.scenemember"); for (int a = 0; a <
  g_scenemember_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(res_scenemember2,
  convert_if_string(g_scenemember_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(res_scenemember2,
  convert_if_string(g_scenemember_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_scenemember2, true);
  oc_resource_set_periodic_observable(res_scenemember2, 1);
  oc_resource_set_request_handler(res_scenemember2, OC_GET, get_scenemember,
  NULL); oc_add_resource(res_scenemember2);
  */

  PRINT("Register Resource with local path \"/scenecollection1\"\n");
  oc_resource_t *res_scenecol1 =
    oc_new_collection("Scene Collection 1", "/scenecollection1", 1, 0);
  oc_resource_bind_resource_type(res_scenecol1, "oic.wk.scenecollection");
  oc_resource_set_discoverable(res_scenecol1, true);

  oc_link_t *sm1 = oc_new_link(res_scenemember1);
  oc_collection_add_link(res_scenecol1, sm1);

  oc_collection_add_supported_rt(res_scenecol1, "oic.wk.scenemember");
  oc_resource_set_properties_cbs(res_scenecol1, get_scenecol_properties, NULL,
                                 set_scenecol_properties, NULL);
  oc_add_collection(res_scenecol1);

  PRINT("Register Resource with local path \"/scenelist\"\n");
  oc_resource_t *res_scenelist =
    oc_new_collection("Scene List", "/scenelist", 1, 0);
  oc_resource_bind_resource_type(res_scenelist, "oic.wk.scenelist");
  oc_resource_set_discoverable(res_scenelist, true);

  oc_link_t *sc1 = oc_new_link(res_scenecol1);
  oc_collection_add_link(res_scenelist, sc1);

  oc_collection_add_supported_rt(res_scenelist, "oic.wk.scenecollection");

  oc_add_collection(res_scenelist);

  PRINT("Register Resource with local path \"/ruleexpression\"\n");
  res_ruleexpression =
    oc_new_resource("Rule Expression", "/ruleexpression", 1, 0);
  oc_resource_bind_resource_type(res_ruleexpression, "oic.r.rule.expression");
  for (int a = 0; a < g_ruleexpression_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(
      res_ruleexpression,
      convert_if_string(g_ruleexpression_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(
    res_ruleexpression,
    convert_if_string(g_ruleexpression_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_ruleexpression, true);
  oc_resource_set_periodic_observable(res_ruleexpression, 1);
  oc_resource_set_request_handler(res_ruleexpression, OC_GET,
                                  get_ruleexpression, NULL);
  oc_resource_set_request_handler(res_ruleexpression, OC_POST,
                                  post_ruleexpression, NULL);
  oc_add_resource(res_ruleexpression);

  PRINT("Register Resource with local path \"/ruleaction\"\n");
  oc_resource_t *res_ruleaction =
    oc_new_resource("Rule Action", "/ruleaction", 1, 0);
  oc_resource_bind_resource_type(res_ruleaction, "oic.r.rule.action");
  for (int a = 0; a < g_ruleaction_nr_resource_interfaces; a++) {
    oc_resource_bind_resource_interface(
      res_ruleaction, convert_if_string(g_ruleaction_RESOURCE_INTERFACE[a]));
  }
  oc_resource_set_default_interface(
    res_ruleaction, convert_if_string(g_ruleaction_RESOURCE_INTERFACE[0]));
  oc_resource_set_discoverable(res_ruleaction, true);
  oc_resource_set_periodic_observable(res_ruleaction, 1);
  oc_resource_set_request_handler(res_ruleaction, OC_GET, get_ruleaction, NULL);
  oc_resource_set_request_handler(res_ruleaction, OC_POST, post_ruleaction,
                                  NULL);
  oc_add_resource(res_ruleaction);

  PRINT("Register Resource with local path \"/ruleinputcollection\"\n");
  oc_resource_t *res_ruleinputcol =
    oc_new_collection("Rule Input Collection", "/ruleinputcollection", 1, 0);
  // Remove batch from the set of supported interafaces
  res_ruleinputcol->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_resource_bind_resource_type(res_ruleinputcol,
                                 "oic.r.rule.inputcollection");
  oc_resource_set_discoverable(res_ruleinputcol, true);

  oc_link_t *ric1 = oc_new_link(res_binaryswitch);
  // Replace the default rel array with ["hosts"] with just "ruleinput"
  oc_free_string_array(&(ric1->rel));
  oc_new_string_array(&ric1->rel, 3);
  oc_link_add_rel(ric1, "ruleinput");
  oc_link_add_link_param(ric1, "anchor", "switch");
  oc_link_set_interfaces(ric1, OC_IF_A);
  oc_collection_add_link(res_ruleinputcol, ric1);

  oc_add_collection(res_ruleinputcol);

  PRINT("Register Resource with local path \"/ruleactioncollection\"\n");
  oc_resource_t *res_ruleactioncol =
    oc_new_collection("Rule Action Collection", "/ruleactioncollection", 1, 0);
  // Remove batch from the set of supported interafaces
  res_ruleactioncol->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_resource_bind_resource_type(res_ruleactioncol,
                                 "oic.r.rule.actioncollection");
  oc_resource_set_discoverable(res_ruleactioncol, true);

  oc_link_t *rac1 = oc_new_link(res_ruleaction);
  oc_collection_add_link(res_ruleactioncol, rac1);

  oc_collection_add_supported_rt(res_ruleactioncol, "oic.r.rule.action");

  oc_add_collection(res_ruleactioncol);

  PRINT("Register Resource with local path \"/rule\"\n");
  oc_resource_t *res_rule = oc_new_collection("Rule", "/rule", 1, 0);
  // Remove batch from the set of supported interafaces
  res_rule->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_resource_bind_resource_type(res_rule, "oic.r.rule");
  oc_resource_set_discoverable(res_rule, true);

  oc_link_t *r1 = oc_new_link(res_ruleexpression);
  oc_collection_add_link(res_rule, r1);

  oc_link_t *r2 = oc_new_link(res_ruleinputcol);
  oc_collection_add_link(res_rule, r2);

  oc_link_t *r3 = oc_new_link(res_ruleactioncol);
  oc_collection_add_link(res_rule, r3);

  oc_collection_add_supported_rt(res_rule, "oic.r.rule.expression");
  oc_collection_add_supported_rt(res_rule, "oic.r.rule.input");
  oc_collection_add_supported_rt(res_rule, "oic.r.rule.actioncollection");

  oc_add_collection(res_rule);
}

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
#endif
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
int
main(void)
{
  int init;

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
  /* initialize global variables for resource "/binaryswitch" */
  g_binaryswitch_value =
    false; /* current value of property "value" The status of the switch. */
  /* set the flag for oic/con resource. */
  oc_set_con_res_announced(true);

  /* initializes the handlers structure */
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = register_resources
#ifdef OC_CLIENT
                                        ,
                                        .requests_entry = 0
#endif
  };
  oc_clock_time_t next_event;

  PRINT("OCF Server name : \"Rules Test Server\"\n");

#ifdef OC_SECURITY
  PRINT("Intialize Secure Resources\n");
  oc_storage_config("./device_builder_server_creds/");
#endif /* OC_SECURITY */

  /* start the stack */
  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  PRINT("OCF server \"Rules Test Server\" running, waiting on incomming "
        "connections.\n");

#ifdef WIN32
  /* windows specific loop */
  while (quit != 1) {
    next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
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
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
#endif

  /* free up strings */
  oc_free_string(&rule);
  oc_free_string(&lastscene);

  /* shut down the stack */
  oc_main_shutdown();
  return 0;
}