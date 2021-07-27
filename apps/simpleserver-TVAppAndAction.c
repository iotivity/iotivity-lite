/*
// Copyright (c) 2016 Intel Corporation
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
*/

#include "oc_api.h"
#include "port/oc_clock.h"
#include <signal.h>
#include <windows.h>

int quit = 0;

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

static bool state = false;
int power;
oc_string_t name;
oc_string_array_t my_supportedactions;

/* global property variables for path: "/binaryswitch" */
bool g_binaryswitch_value = false;

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.2.2.3",
                       "ocf.res.1.3.0, ocf.sh.1.3.0", NULL, NULL);
  oc_new_string(&name, "John's Light", 12);
  oc_new_string_array(&my_supportedactions, (size_t)19);
  oc_string_array_add_item(my_supportedactions, "arrowup");
  oc_string_array_add_item(my_supportedactions, "arrowdown");
  oc_string_array_add_item(my_supportedactions, "arrowleft");
  oc_string_array_add_item(my_supportedactions, "arrowright");
  oc_string_array_add_item(my_supportedactions, "enter");
  oc_string_array_add_item(my_supportedactions, "return");
  oc_string_array_add_item(my_supportedactions, "exit");
  oc_string_array_add_item(my_supportedactions, "home");
  oc_string_array_add_item(my_supportedactions, "1");
  oc_string_array_add_item(my_supportedactions, "2");
  oc_string_array_add_item(my_supportedactions, "3");
  oc_string_array_add_item(my_supportedactions, "4");
  oc_string_array_add_item(my_supportedactions, "5");
  oc_string_array_add_item(my_supportedactions, "6");
  oc_string_array_add_item(my_supportedactions, "7");
  oc_string_array_add_item(my_supportedactions, "8");
  oc_string_array_add_item(my_supportedactions, "9");
  oc_string_array_add_item(my_supportedactions, "0");
  oc_string_array_add_item(my_supportedactions, "-");

  #if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read 'server_introspection.cbor'\n"
    "\tIntrospection data not set.\n";
  fp = fopen("c:/users/m.trayer/OCF/TVApps/server_introspection.cbor",
             "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      PRINT(
        "\tIntrospection data set 'server_introspection.cbor': %d [bytes]\n",
        (int)buffer_size);
    } else {
      PRINT("%s", introspection_error);
    }
    free(buffer);
  } else {
    PRINT("%s", introspection_error);
  }
#else
  PRINT("\t introspection via header file\n");
#endif
  return ret;
}

bool
verify_action_in_supported_set(char* action, int action_len) {
	bool rc = false;
	size_t i;

	for (i = 0; i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
		const char* sv = oc_string_array_get_item(my_supportedactions, i);
		PRINT("Action compare. Supported action %s against received action %s \n", sv, action);
		if (strlen(sv) == action_len &&
			memcmp(sv, action, action_len) == 0) {
			rc = true;
			break;
		}
	}

	return rc;
}

static void
get_binaryswitch(oc_request_t* request, oc_interface_mask_t interfaces,
	void* user_data)
{
	(void)user_data; /* not used */

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
post_binaryswitch(oc_request_t* request, oc_interface_mask_t interfaces,
	void* user_data)
{
	(void)interfaces;
	(void)user_data;
	bool error_state = false;
	PRINT("post_binaryswitch:\n");
	oc_rep_t* rep = request->request_payload;
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
		oc_rep_t* rep = request->request_payload;
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
	}
	else {
		/* TODO: add error response, if any */
		oc_send_response(request, OC_STATUS_NOT_MODIFIED);
	}
}

static void
get_remotecontrol(oc_request_t* request, oc_interface_mask_t iface_mask,
	void* user_data)
{
	(void)user_data;

	/* Check if query string includes action selectio, it is does, reject the request. */
	char* action = NULL;
	int action_len = -1;
	oc_init_query_iterator();
	bool rc = oc_iterate_query_get_values(request, "action", &action, &action_len);

	if (action_len > 0) {
		// An action parm was received
		//
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
		return;
	}

	PRINT("GET_remotecontrol:\n");
	oc_rep_start_root_object();
	switch (iface_mask) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
	case OC_IF_A:
		oc_rep_set_key(oc_rep_object(root), "supportedactions");
		oc_rep_begin_array(oc_rep_object(root), supportedactions);
	    for (size_t i = 0; i < oc_string_array_get_allocated_size(my_supportedactions); i++) {
			oc_rep_add_text_string(supportedactions, oc_string_array_get_item(my_supportedactions,i));
		}
		oc_rep_end_array(oc_rep_object(root), supportedactions);
		oc_rep_end_root_object();
		break;
	default:
		break;
	}
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);
}

static void
post_remotecontrol(oc_request_t* request, oc_interface_mask_t iface_mask,
	void* user_data)
{
	(void)iface_mask;
	(void)user_data;
	PRINT("POST_remotecontrol:\n");
	char* query = request->query;
	int query_len = request->query_len;

	/* Check if query string includes action selection. */
	char* action = NULL;
	int action_len = -1;
	oc_init_query_iterator();
	bool rc = oc_iterate_query_get_values(request, "action", &action, &action_len);

	if (action_len > 0) {
		PRINT("POST action length = %d \n", action_len);
		PRINT("POST action string actual size %d \n", strlen(action));
		PRINT("POST action received raw = %s \n", action);

		// Validate that the action requests is in the set
		//
		action[action_len] = "\0";
		bool valid_action = verify_action_in_supported_set(action, action_len);

		// Build response with selected action
		//
		if (valid_action) {
			oc_rep_start_root_object();
			oc_rep_set_key(oc_rep_object(root), "selectedactions");
			oc_rep_begin_array(oc_rep_object(root), selectedactions);
			oc_rep_add_text_string(selectedactions, action);
			oc_rep_end_array(oc_rep_object(root), selectedactions);
			oc_rep_end_root_object();
			oc_send_response(request, OC_STATUS_CHANGED);
		}
		else {
			oc_send_response(request, OC_STATUS_BAD_REQUEST);
		}
	}
	else {
		PRINT("POST no action received \n");
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
	}
}

static void
register_resources(void)
{
	PRINT("Register Resource with local path \"/binaryswitch\"\n");
	oc_resource_t* res = oc_new_resource("Binary Switch", "/binaryswitch", 1, 0);
	oc_resource_bind_resource_type(res, "oic.r.switch.binary");
	oc_resource_bind_resource_interface(res, OC_IF_A);
	oc_resource_set_default_interface(res, OC_IF_A);
	oc_resource_set_discoverable(res, true);
	oc_resource_set_request_handler(res, OC_GET, get_binaryswitch, NULL);
	oc_resource_set_request_handler(res, OC_POST, post_binaryswitch, NULL);
	oc_add_resource(res);

    PRINT("Register Resource with local path \"/remotecontrol\"\n");
    oc_resource_t* res2 = oc_new_resource("Remote Control", "/remotecontrol", 1, 0);
    oc_resource_bind_resource_type(res2, "oic.r.remotecontrol");
    oc_resource_bind_resource_interface(res2, OC_IF_A);
    oc_resource_set_default_interface(res2, OC_IF_A);
    oc_resource_set_discoverable(res2, true);
    oc_resource_set_request_handler(res2, OC_GET, get_remotecontrol, NULL);
    oc_resource_set_request_handler(res2, OC_POST, post_remotecontrol, NULL);
    oc_add_resource(res2);
}

static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}

void
handle_signal(int signal)
{
  signal_event_loop();
  quit = 1;
}

int
main(void)
{
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);

  int init;

  signal(SIGINT, handle_signal);

  /* initialize global variables for resource "/binaryswitch" */
  g_binaryswitch_value = false;

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources,
                                        .requests_entry = 0 };

  oc_clock_time_t next_event;

#ifdef OC_STORAGE
  oc_storage_config("./simpleserver_creds/");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

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

  oc_main_shutdown();
  return 0;
}
