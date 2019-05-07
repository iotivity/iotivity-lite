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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#include <luna-service2/lunaservice.h>
#include <glib.h>
#include <pbnjson.h>
#include <PmLogLib.h>

static LSHandle *pLsHandle = NULL;
static GMainLoop *mainloop = NULL;

PmLogContext gLogContext;
PmLogContext gLogLibContext;

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;

static bool state = false;
int power;
oc_string_t name;

pthread_t threadId_server;
oc_resource_t *res;

oc_define_interrupt_handler(observe)
{
	oc_notify_observers(res);
}

static int
app_init(void)
{
	oc_activate_interrupt_handler(observe);
	int ret = oc_init_platform("webOS", NULL, NULL);
	ret |= oc_add_device("/oic/d", "oic.d.light", "webOS Lamp", "ocf.2.0.0",
			"ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);
	oc_new_string(&name, "webOS Light", 11);
	return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)user_data;
	++power;

	PRINT("GET_light:\n");
	oc_rep_start_root_object();
	switch (iface_mask) {
		case OC_IF_BASELINE:
			PRINT("OC_IF_BASELINE\n");
			oc_process_baseline_interface(request->resource);
			/* fall through */
		case OC_IF_RW:
			oc_rep_set_boolean(root, value, state);
			//oc_rep_set_int(root, power, power);
			oc_rep_set_text_string(root, n, oc_string(name));
			break;
		case OC_IF_A:
			PRINT("OC_IF_A\n");
			oc_rep_set_boolean(root, value, state);
			//oc_rep_set_int(root, power, power);
			oc_rep_set_text_string(root, n, oc_string(name));
			break;
		default:
			break;
	}
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)iface_mask;
	(void)user_data;
	PRINT("POST_light:\n");
	oc_rep_t *rep = request->request_payload;
	while (rep != NULL) {
		PRINT("key: %s ", oc_string(rep->name));
		switch (rep->type) {
			case OC_REP_BOOL:
				state = rep->value.boolean;
				PRINT("value: %d\n", state);
				break;
			case OC_REP_INT:
				power = (int)rep->value.integer;
				PRINT("value: %d\n", power);
				break;
			case OC_REP_STRING:
				oc_free_string(&name);
				oc_new_string(&name, oc_string(rep->value.string),
						oc_string_len(rep->value.string));
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

static void
put_light(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
	(void)iface_mask;
	(void)user_data;
	post_light(request, iface_mask, user_data);
}

static void
register_resources(void)
{
	res = oc_new_resource("ssm", "/binaryswitch", 1, 0);
	//oc_resource_bind_resource_type(res, "core.light");
	oc_resource_bind_resource_type(res, "oic.r.switch.binary");
	//oc_resource_bind_resource_type(res, "core.brightlight");
	//oc_resource_bind_resource_interface(res, OC_IF_RW);
	oc_resource_bind_resource_interface(res, OC_IF_BASELINE);
	oc_resource_bind_resource_interface(res, OC_IF_A);
	//oc_resource_set_default_interface(res, OC_IF_RW);
	oc_resource_set_default_interface(res, OC_IF_A);
	//oc_resource_set_default_interface(res, OC_IF_BASELINE);
	oc_resource_set_discoverable(res, true);
	oc_resource_set_periodic_observable(res, 1);
	oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
	oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
	oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
	oc_set_con_res_announced(false);
	oc_create_introspection_resource(0);
	oc_add_resource(res);
}

static void
signal_event_loop(void)
{
	pthread_mutex_lock(&mutex);
	PRINT("signal_event_loop\n");
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mutex);
	PRINT("signal_event_loop exit\n");
}

void
handle_signal(int signal)
{
	(void)signal;
	signal_event_loop();
	PRINT("handle_signal\n");
	quit = 1;
}

void *serverStarter(gpointer user_data)
{
	oc_clock_time_t next_event;
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
}

int
main(void)
{
	struct timespec timeout;
	LSError lserror;
	LSErrorInit(&lserror);
	(void) PmLogGetContext("OCSERVERBASICOPS", &gLogContext);
	(void) PmLogGetContext("OCSERVERBASICOPS-LIB", &gLogLibContext);
	PmLogSetLibContext(gLogLibContext);

	mainloop = g_main_loop_new(NULL, FALSE);

	// Initialize g_main_loop
	if (!mainloop) {
		PRINT("Failed to create main loop");
		return 0;
	}

	PRINT("OCServer is starting...\n");

	if (!LSRegister("org.ocf.webossample.simpleserver", &pLsHandle, &lserror)) {
		PRINT("Failed to register LS Handle");
		LSErrorLog(gLogContext, "LS_SRVC_ERROR", &lserror);
		return 0;
	}

	if (!LSGmainAttach(pLsHandle, mainloop, &lserror)) {
		PRINT("Failed to attach main loop: %s", &lserror);
		LSErrorLog(gLogContext, "LS_SRVC_ATTACH_ERROR", &lserror);
		return 0;
	}

	int init;
	struct sigaction sa;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);

	static const oc_handler_t handler = {.init = app_init,
		.signal_event_loop = signal_event_loop,
		.register_resources =
			register_resources };

#ifdef OC_SECURITY
	oc_storage_config("./simpleserver_creds");
#endif /* OC_SECURITY */

	init = oc_main_init(&handler);
	if (init < 0)
		return init;

	pthread_create(&threadId_server, NULL, serverStarter, (void *)NULL);

	char input[10] = {0};
	uint8_t j = 0;

	while (!quit)
	{
		printf("\n");
		printf("*********************************\n");
		printf("********** webOS Light **********\n");
		printf("*********************************\n");
		printf("Control the light locally:\n");
		printf("1: turn on the switch\n");
		printf("2: turn off the switch\n");
		printf("3: show current status\n");
		printf("99: quit the menu\n");
		printf("*********************************\n");
		printf("Select your choice: ");
		char * ret = fgets(input, sizeof(input), stdin);
		switch (atoi(input))
		{
			case 1:
				printf("Power up...\n");
				state = true;
				oc_signal_interrupt_handler(observe);
				j = 0;

				break;
			case 2:
				printf("Power down...\n");
				state = false;
				j = 0;
				break;

			case 3:
				printf("\n*****************************************************\n");
				printf("*****************************************************\n");
				break;
			case 99:
				quit = true;
				break;
			default:
				printf("Invalid selection...\n");
				break;
		}
	}

	oc_free_string(&name);
	oc_main_shutdown();
	return 0;
}
