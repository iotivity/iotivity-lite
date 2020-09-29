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
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include <signal.h>

#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

/* linux specific code */
#include <pthread.h>
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;

#define MAX_STRING 65 /* max size of the strings. */

typedef struct scenemappings_t
{
  struct scenemappings_t *next;
  char scene[MAX_STRING];
  char key[MAX_STRING];
  char value[MAX_STRING];
} scenemappings_t;
OC_MEMB(smap_s, scenemappings_t, 1);
OC_LIST(smap);

volatile int quit = 0; /* stop variable, used by handle_signal */

/* global property variables for path: "/binaryswitch" */
bool g_binaryswitch_value = false;

/* global property variables for path: "/audio" */
bool g_audio_mute = false;
int g_audio_volume = 50;

/* global property variables for path: /ruleaction and /scenecollection */
char lastscene[MAX_STRING];
char ra_lastscene[MAX_STRING];
static oc_string_array_t scenevalues;

/* global property variables for path: /ruleexpression */
char rule[MAX_STRING];
static bool ruleresult = false;
static bool ruleenable = false;
static bool actionenable = false;

/* Resource handles */
/* Used as input to rule */
oc_resource_t *res_binaryswitch;
/* Specification of the rule */
oc_resource_t *res_ruleexpression;
/* Used in the rule action */
oc_resource_t *res_audio;
/* Collection of Scene Members. Records the "lastscene" following a rule action
 */
oc_resource_t *res_scenecol1;

static pthread_t toggle_switch_thread;

static oc_event_callback_retval_t
set_scene(void *data)
{
  (void)data;
  scenemappings_t *sm = (scenemappings_t *)oc_list_head(smap);
  while (sm) {
    if (strcmp(sm->scene, lastscene) == 0) {
      if (strcmp(sm->key, "volume") == 0) {
        sscanf(sm->value, "%d", &g_audio_volume);
        oc_notify_observers(res_audio);
        break;
      }
    }
    sm = sm->next;
  }
  return OC_EVENT_DONE;
}

static void
perform_rule_action(void)
{
  /*
   * Set lastscene on the target scenecollection
   */
  if (actionenable) {
    strcpy(lastscene, ra_lastscene);
    set_scene(NULL);
  }
}

static void
rule_notify_and_eval(void)
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
      perform_rule_action();
    }
  } else {
    ruleresult = false;
  }
}

oc_define_interrupt_handler(toggle_switch)
{
  if (res_binaryswitch) {
    oc_notify_observers(res_binaryswitch);
    rule_notify_and_eval();
  }
}

/**
 * function to set up the device.
 *
 */
static int
app_init(void)
{
  oc_activate_interrupt_handler(toggle_switch);
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be OCF1.3.1 or OCF2.0.0 (or even higher)
     supplied values are for OCF1.3.1 */
  ret |= oc_add_device("/oic/d", "oic.d.stb", "Set Top Box",
                       "ocf.2.2.0",                   /* icv value */
                       "ocf.res.1.3.0, ocf.sh.1.3.0", /* dmv value */
                       NULL, NULL);
  strcpy(rule, "(switch:value = true)");
  strcpy(lastscene, "normalaudio");
  strcpy(ra_lastscene, "loudaudio");
  oc_new_string_array(&scenevalues, (size_t)2);
  oc_string_array_add_item(scenevalues, lastscene);
  oc_string_array_add_item(scenevalues, ra_lastscene);
  scenemappings_t *sm = (scenemappings_t *)oc_memb_alloc(&smap_s);
  if (sm) {
    strcpy(sm->scene, "normalaudio");
    strcpy(sm->key, "volume");
    sprintf(sm->value, "%f", 40.0);
    oc_list_add(smap, sm);
  }
  sm = (scenemappings_t *)oc_memb_alloc(&smap_s);
  if (sm) {
    strcpy(sm->scene, "loudaudio");
    strcpy(sm->key, "volume");
    sprintf(sm->value, "%d", 60);
    oc_list_add(smap, sm);
  }
#if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read server_certification_tests_IDD.cbor\n"
    "\tIntrospection data not set for device.\n";
  fp = fopen("./server_rules_IDD.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      PRINT("\tIntrospection data set for device.\n");
    } else {
      PRINT("%s", introspection_error);
    }
    free(buffer);
  } else {
    PRINT("%s", introspection_error);
  }
#endif
  return ret;
}

static void *
toggle_switch_resource(void *data)
{
  (void)data;
  while (quit != 1) {
    char c = getchar();
    if (quit != 1) {
      getchar();
      if (c == 48) {
        g_binaryswitch_value = false;
      } else {
        g_binaryswitch_value = true;
      }
      oc_signal_interrupt_handler(toggle_switch);
    }
  }
  return NULL;
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
     hardware that sets the global variables. */

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
    PRINT("   value : %d\n", g_binaryswitch_value); /* not handled value */
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
    if (memcmp(oc_string(rep->name), "value", 5) == 0) {
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
      if (memcmp(oc_string(rep->name), "value", 5) == 0) {
        /* assign "value" */
        g_binaryswitch_value = rep->value.boolean;
      }
      rep = rep->next;
    }
    /* set the response */
    PRINT("Set response \n");
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, value, g_binaryswitch_value);
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_CHANGED);
    rule_notify_and_eval();
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
    oc_rep_set_text_string(link, href, oc_string(res_audio->uri));
    oc_rep_set_string_array(link, rt, res_audio->types);
    oc_core_encode_interfaces_mask(oc_rep_object(link), res_audio->interfaces);
    oc_rep_close_object(root, link);

    // SceneMappings array
    oc_rep_set_array(root, SceneMappings);
    scenemappings_t *sm = (scenemappings_t *)oc_list_head(smap);
    while (sm) {
      oc_rep_object_array_begin_item(SceneMappings);
      oc_rep_set_text_string(SceneMappings, scene, sm->scene);
      oc_rep_set_text_string(SceneMappings, memberProperty, sm->key);
      oc_rep_set_text_string(SceneMappings, memberValue, sm->value);
      oc_rep_object_array_end_item(SceneMappings);
      sm = sm->next;
    }
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
    oc_rep_set_text_string(root, rule, rule);
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
          rule_notify_and_eval();
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
            perform_rule_action();
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
    oc_rep_set_text_string(root, scenevalue, ra_lastscene);
    oc_rep_set_object(root, link);
    oc_rep_set_text_string(link, href, "/scenecollection1");
    oc_rep_set_string_array(link, rt, res_scenecol1->types);
    oc_core_encode_interfaces_mask(oc_rep_object(link),
                                   res_scenecol1->interfaces);
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
  oc_rep_t *rep = request->request_payload;
  while (rep) {
    if (rep->type == OC_REP_STRING && oc_string_len(rep->name) == 10 &&
        memcmp(oc_string(rep->name), "scenevalue", 10) == 0) {
      size_t i;
      bool match = false;
      for (i = 0; i < oc_string_array_get_allocated_size(scenevalues); i++) {
        const char *sv = oc_string_array_get_item(scenevalues, i);
        if (strlen(sv) == oc_string_len(rep->value.string) &&
            memcmp(sv, oc_string(rep->value.string),
                   oc_string_len(rep->value.string)) == 0) {
          match = true;
          break;
        }
      }
      if (!match) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
      }
      strcpy(ra_lastscene, oc_string(rep->value.string));
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
    rep = rep->next;
  }

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
        size_t i;
        bool match = false;
        for (i = 0; i < oc_string_array_get_allocated_size(scenevalues); i++) {
          const char *sv = oc_string_array_get_item(scenevalues, i);
          if (strlen(sv) == oc_string_len(rep->value.string) &&
              memcmp(sv, oc_string(rep->value.string),
                     oc_string_len(rep->value.string)) == 0) {
            match = true;
            break;
          }
        }
        if (!match) {
          return false;
        }
        strcpy(lastscene, oc_string(rep->value.string));
        oc_set_delayed_callback(NULL, &set_scene, 0);
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
    oc_rep_set_text_string(root, lastScene, lastscene);
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
  res_binaryswitch = oc_new_resource("Binary Switch", "/binaryswitch", 1, 0);
  oc_resource_bind_resource_type(res_binaryswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res_binaryswitch, OC_IF_A);
  oc_resource_set_default_interface(res_binaryswitch, OC_IF_A);
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
  oc_resource_bind_resource_interface(res_audio, OC_IF_A);
  oc_resource_set_default_interface(res_audio, OC_IF_A);
  oc_resource_set_discoverable(res_audio, true);
  oc_resource_set_periodic_observable(res_audio, 1);
  oc_resource_set_request_handler(res_audio, OC_GET, get_audio, NULL);
  oc_resource_set_request_handler(res_audio, OC_POST, post_audio, NULL);
  oc_add_resource(res_audio);

  PRINT("Register Resource with local path \"/scenemember1\"\n");
  oc_resource_t *res_scenemember1 =
    oc_new_resource("Scene Member 1", "/scenemember1", 1, 0);
  oc_resource_bind_resource_type(res_scenemember1, "oic.wk.scenemember");
  oc_resource_set_discoverable(res_scenemember1, true);
  oc_resource_set_periodic_observable(res_scenemember1, 1);
  oc_resource_set_request_handler(res_scenemember1, OC_GET, get_scenemember,
                                  NULL);
  oc_add_resource(res_scenemember1);

  PRINT("Register Collection with local path \"/scenecollection1\"\n");
  res_scenecol1 =
    oc_new_collection("Scene Collection 1", "/scenecollection1", 1, 0);
  // Remove batch from the set of supported interafaces
  res_scenecol1->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_resource_bind_resource_type(res_scenecol1, "oic.wk.scenecollection");
  oc_resource_set_discoverable(res_scenecol1, true);

  oc_link_t *sm1 = oc_new_link(res_scenemember1);
  oc_collection_add_link(res_scenecol1, sm1);

  oc_collection_add_mandatory_rt(res_scenecol1, "oic.wk.scenemember");
  oc_collection_add_supported_rt(res_scenecol1, "oic.wk.scenemember");
  oc_resource_set_properties_cbs(res_scenecol1, get_scenecol_properties, NULL,
                                 set_scenecol_properties, NULL);
  oc_add_collection(res_scenecol1);

  PRINT("Register Collection with local path \"/scenelist\"\n");
  oc_resource_t *res_scenelist =
    oc_new_collection("Scene List", "/scenelist", 1, 0);
  oc_resource_bind_resource_type(res_scenelist, "oic.wk.scenelist");
  oc_resource_set_discoverable(res_scenelist, true);
  // Remove batch from the set of supported interafaces
  res_scenelist->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_link_t *sc1 = oc_new_link(res_scenecol1);
  oc_collection_add_link(res_scenelist, sc1);

  oc_collection_add_mandatory_rt(res_scenelist, "oic.wk.scenecollection");
  oc_collection_add_supported_rt(res_scenelist, "oic.wk.scenecollection");

  oc_add_collection(res_scenelist);

  PRINT("Register Resource with local path \"/ruleexpression\"\n");
  res_ruleexpression =
    oc_new_resource("Rule Expression", "/ruleexpression", 1, 0);
  oc_resource_bind_resource_type(res_ruleexpression, "oic.r.rule.expression");
  oc_resource_bind_resource_interface(res_ruleexpression, OC_IF_RW);
  oc_resource_set_default_interface(res_ruleexpression, OC_IF_RW);
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
  oc_resource_bind_resource_interface(res_ruleaction, OC_IF_RW);
  oc_resource_set_default_interface(res_ruleaction, OC_IF_RW);
  oc_resource_set_discoverable(res_ruleaction, true);
  oc_resource_set_periodic_observable(res_ruleaction, 1);
  oc_resource_set_request_handler(res_ruleaction, OC_GET, get_ruleaction, NULL);
  oc_resource_set_request_handler(res_ruleaction, OC_POST, post_ruleaction,
                                  NULL);
  oc_add_resource(res_ruleaction);

  PRINT("Register Collection with local path \"/ruleinputcollection\"\n");
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

  //oc_collection_add_mandatory_rt(res_ruleinputcol, "oic.r.switch.binary");
  oc_collection_add_supported_rt(res_ruleinputcol, "oic.r.switch.binary");
  oc_add_collection(res_ruleinputcol);

  PRINT("Register Collection with local path \"/ruleactioncollection\"\n");
  oc_resource_t *res_ruleactioncol =
    oc_new_collection("Rule Action Collection", "/ruleactioncollection", 1, 0);
  // Remove batch from the set of supported interafaces
  res_ruleactioncol->interfaces = OC_IF_BASELINE | OC_IF_LL;
  oc_resource_bind_resource_type(res_ruleactioncol,
                                 "oic.r.rule.actioncollection");
  oc_resource_set_discoverable(res_ruleactioncol, true);

  oc_link_t *rac1 = oc_new_link(res_ruleaction);
  oc_collection_add_link(res_ruleactioncol, rac1);

  oc_collection_add_mandatory_rt(res_ruleactioncol, "oic.r.rule.action");
  oc_collection_add_supported_rt(res_ruleactioncol, "oic.r.rule.action");

  oc_add_collection(res_ruleactioncol);

  PRINT("Register Collection with local path \"/rule\"\n");
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

  oc_collection_add_mandatory_rt(res_rule, "oic.r.rule.expression");
  oc_collection_add_mandatory_rt(res_rule, "oic.r.rule.inputcollection");
  oc_collection_add_mandatory_rt(res_rule, "oic.r.rule.actioncollection");

  oc_collection_add_supported_rt(res_rule, "oic.r.rule.expression");
  oc_collection_add_supported_rt(res_rule, "oic.r.rule.inputcollection");
  oc_collection_add_supported_rt(res_rule, "oic.r.rule.actioncollection");

  oc_add_collection(res_rule);
}

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
 * Display UUID of device
 */
void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  PRINT("Started device with ID: %s\n", buffer);
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

  /* linux specific */
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  /* install Ctrl-C */
  sigaction(SIGINT, &sa, NULL);
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
  oc_storage_config("./server_rules_creds");
#endif /* OC_SECURITY */
  oc_set_max_app_data_size(13312);

  if (pthread_create(&toggle_switch_thread, NULL, &toggle_switch_resource,
                     NULL) != 0) {
    return -1;
  }

  /* start the stack */
  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  oc_resource_t *con_resource = oc_core_get_resource_by_index(OCF_CON, 0);
  oc_resource_set_observable(con_resource, false);

  display_device_uuid();
  PRINT("OCF server \"Rules Test Server\" running, waiting on incomming "
        "connections.\n");

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

  /* free up strings and scenemappings */
  oc_free_string_array(&scenevalues);
  scenemappings_t *sm = (scenemappings_t *)oc_list_pop(smap);
  while (sm) {
    oc_memb_free(&smap_s, sm);
    sm = (scenemappings_t *)oc_list_pop(smap);
  }

  /* shut down the stack */
  oc_main_shutdown();
  pthread_join(toggle_switch_thread, NULL);

  return 0;
}
