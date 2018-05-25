/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "CloudHelper.h"

CloudHelper *CloudHelper::s_riHelperInstance = NULL;
oc_handler_t CloudHelper::s_handler;

bool CloudHelper::s_isDiscoverResourceSucessfull = false;
bool CloudHelper::s_isObserveResourceSuccessfull = false;
bool CloudHelper::s_isRequestSucessfull = false;
bool CloudHelper::s_lightState = false;
int CloudHelper::s_generalQuit = 0;
oc_resource_t *CloudHelper::s_pResource1 = NULL;
oc_resource_t *CloudHelper::s_pResource2 = NULL;

oc_endpoint_t *CloudHelper::s_pLightEndpoint = NULL;
oc_endpoint_t CloudHelper::s_cloudEndpoint;

oc_string_t CloudHelper::s_lightName;

pthread_mutex_t CloudHelper::s_mutex;
pthread_cond_t CloudHelper::s_cv;
struct timespec CloudHelper::s_ts;

char CloudHelper::s_lightUri[MAX_URI_LENGTH];

oc_link_t *CloudHelper::link1;
oc_link_t *CloudHelper::link2;

oc_string_t CloudHelper::uid;
oc_string_t CloudHelper::access_token;

CloudHelper::CloudHelper() {
}

CloudHelper::~CloudHelper() {
}

CloudHelper *CloudHelper::getInstance(void) {
	if (s_riHelperInstance == NULL) {
		if (s_riHelperInstance == NULL) {
			s_riHelperInstance = new CloudHelper();
		}
	}
	return s_riHelperInstance;
}

int CloudHelper::createResource() {
	PRINT("createResource\n");
	int init = 0;

	s_handler.init = appInitCb;
	s_handler.signal_event_loop = signalEventLoopCb;
	s_handler.register_resources = registerResourcesCb;
	s_handler.requests_entry = issueRequestsCb;

	oc_set_con_res_announced(false);

	init = oc_main_init(&s_handler);

	return init;
}
int CloudHelper::waitForEvent() {
	int count = 0;
	while (s_generalQuit != 1 && count != 30) {
		PRINT("waitforevent\n");
		oc_main_poll();
		sleep(1);
		count++;
	}

}

int CloudHelper::appInitCb(void) {
	PRINT("appInitCb\n");

	int ret = oc_init_platform(MANUFACTURE_NAME, NULL, NULL);
	ret |= oc_add_device(DEVICE_URI_LIGHT, DEVICE_TYPE_LIGHT, DEVICE_NAME_LIGHT,
			OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
	return ret;
}

void CloudHelper::signalEventLoopCb(void) {
	PRINT("signalEventLoopCb\n");
	pthread_mutex_lock(&s_mutex);
	pthread_cond_signal(&s_cv);
	pthread_mutex_unlock(&s_mutex);
}

void CloudHelper::issueRequestsCb(void) {
	PRINT("issueRequestsCb\n");
}

void CloudHelper::registerResourcesCb(void) {
	PRINT("registerResourcesCb\n");

	s_pResource1 = oc_new_resource(NULL, RESOURCE_URI_LIGHT, 1, 0);
	oc_resource_bind_resource_type(s_pResource1, RESOURCE_TYPE_LIGHT);
	oc_resource_bind_resource_interface(s_pResource1, OC_IF_RW);
	oc_resource_set_default_interface(s_pResource1, OC_IF_RW);
	oc_resource_set_discoverable(s_pResource1, true);
	oc_resource_set_request_handler(s_pResource1, OC_GET, getLightCb, NULL);
	oc_add_resource(s_pResource1);

	s_pResource2 = oc_new_resource(NULL, RESOURCE_URI_FAN, 1, 0);
	oc_resource_bind_resource_type(s_pResource2, RESOURCE_TYPE_LIGHT);
	oc_resource_bind_resource_interface(s_pResource2, OC_IF_RW);
	oc_resource_set_default_interface(s_pResource2, OC_IF_RW);
	oc_resource_set_discoverable(s_pResource2, true);
	oc_resource_set_request_handler(s_pResource2, OC_GET, getLightCb, NULL);
	oc_add_resource(s_pResource2);
}
void CloudHelper::unRegisterResources(void) {
	PRINT("unRegisterResources\n");
	oc_delete_resource(s_pResource1);
	oc_delete_resource(s_pResource2);
	s_pResource1 = NULL;
	s_pResource2 = NULL;
}

void CloudHelper::shutDown() {
	PRINT("shutDown:\n");
	oc_main_shutdown();
}

void CloudHelper::getLightCb(oc_request_t *request,
		oc_interface_mask_t interface, void *user_data) {
	PRINT("getLightCb:\n");
	(void) user_data;
	oc_rep_start_root_object();
	switch (interface) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
		/* fall through */
	case OC_IF_RW:
		oc_rep_set_boolean(root, state, s_lightState);
		break;
	default:
		break;
	}
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);
	PRINT("Light state %d\n", s_lightState);
}

/** Client Side **/

oc_event_callback_retval_t CloudHelper::stopObserveClientCb(void *data) {
	(void) data;
	PRINT("stopObserveClientCb\n");
	oc_stop_observe(s_lightUri, s_pLightEndpoint);
	s_generalQuit = 1;
	return OC_EVENT_DONE;
}

void CloudHelper::observeLightCb(oc_client_response_t *data) {
	PRINT("observeLightCb\n");
	oc_rep_t *rep = data->payload;
	while (rep != NULL) {
		PRINT("key %s, value ", oc_string(rep->name));
		switch (rep->type) {
		case OC_REP_BOOL:
			PRINT("%d\n", rep->value.boolean);
			s_lightState = rep->value.boolean;
			break;
		default:
			break;
		}
		rep = rep->next;
	}
	s_isObserveResourceSuccessfull = true;
}

void CloudHelper::getLightClientCb(oc_client_response_t *data) {
	PRINT("getLightClientCb\n");
	(void) data;
	s_isRequestSucessfull = true;
	s_generalQuit = 1;
}

void CloudHelper::postLightClientCb(oc_client_response_t *data) {
	PRINT("postLightClientCb:\n");
	if (data->code == OC_STATUS_CHANGED)
		PRINT("POST response OK\n");
	else
		PRINT("POST response code %d\n", data->code);
	s_isRequestSucessfull = true;
	s_generalQuit = 1;
}

void CloudHelper::putLightClientCb(oc_client_response_t *data) {
	PRINT("putLightClientCb\n");
	if (data->code == OC_STATUS_CHANGED)
		PRINT("PUT response OK\n");
	else
		PRINT("PUT response code %d\n", data->code);
	s_isRequestSucessfull = true;
	s_generalQuit = 1;
}

void CloudHelper::deleteLightClientCb(oc_client_response_t *data) {
	PRINT("deleteLightClientCb\n");
	if (data->code == OC_STATUS_CHANGED)
		PRINT("DELETE response OK\n");
	else
		PRINT("DELETE response code %d\n", data->code);
	s_isRequestSucessfull = true;
	s_generalQuit = 1;
}

oc_discovery_flags_t CloudHelper::discovery(const char *di, const char *uri,
		oc_string_array_t types, oc_interface_mask_t interfaces,
		oc_endpoint_t *endpoint, oc_resource_properties_t bm, void *user_data) {
	(void) di;
	(void) interfaces;
	(void) user_data;
	(void) bm;
	int i;
	int uri_len = strlen(uri);
	uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
	PRINT("discovery: %s\n", uri);
	for (i = 0; i < (int) oc_string_array_get_allocated_size(types); i++) {
		char *t = oc_string_array_get_item(types, i);
		if (strlen(t) == 10 && strncmp(t, RESOURCE_TYPE_LIGHT, 10) == 0) {
			strncpy(s_lightUri, uri, uri_len);
			s_lightUri[uri_len] = '\0';
			s_pLightEndpoint = endpoint;

			PRINT("Resource %s hosted at endpoints:\n", s_lightUri);
			s_generalQuit = 1;
			s_isDiscoverResourceSucessfull = true;
			return OC_STOP_DISCOVERY;
		}
	}
	oc_free_server_endpoints(endpoint);
	return OC_CONTINUE_DISCOVERY;
}

void CloudHelper::discoverResource() {
	PRINT("discoverResource:\n");
	s_generalQuit = 0;
	oc_do_ip_discovery(NULL, &discovery, NULL);
}

void CloudHelper::getResource() {
	PRINT("getResource:\n");
	s_generalQuit = 0;
	s_isRequestSucessfull = false;
	oc_do_get(s_lightUri, s_pLightEndpoint, NULL, &getLightClientCb, LOW_QOS,
	NULL);
}

void CloudHelper::deleteResource() {
	PRINT("deleteResource:\n");
	s_generalQuit = 0;
	s_isRequestSucessfull = false;
	oc_do_delete(s_lightUri, s_pLightEndpoint, NULL, &deleteLightClientCb,
			LOW_QOS,
			NULL);
}
void CloudHelper::postRequestResource() {
	PRINT("postRequestResource:\n");
	s_generalQuit = 0;
	s_isRequestSucessfull = false;
	if (oc_init_post(s_lightUri, s_pLightEndpoint, NULL, &postLightClientCb,
			LOW_QOS,
			NULL)) {
		oc_rep_start_root_object();
		oc_rep_set_boolean(root, state, !s_lightState);
		oc_rep_end_root_object();
		if (oc_do_post())
			PRINT("Sent POST request\n");
		else
			PRINT("Could not send POST\n");
	} else
		PRINT("Could not init POST\n");
}

void CloudHelper::putRequestResource() {
	PRINT("putRequestResource:\n");
	s_generalQuit = 0;
	s_isRequestSucessfull = false;
	if (oc_init_put(s_lightUri, s_pLightEndpoint, NULL, &putLightClientCb,
			LOW_QOS,
			NULL)) {
		oc_rep_start_root_object();
		oc_rep_set_boolean(root, state, !s_lightState);
		oc_rep_end_root_object();
		if (oc_do_put())
			PRINT("Sent PUT request\n");
		else
			PRINT("Could not send PUT\n");
	} else
		PRINT("Could not init PUT\n");
}

void CloudHelper::observeResource() {
	PRINT("observeResource:\n");
	s_generalQuit = 0;
	oc_do_observe(s_lightUri, s_pLightEndpoint, NULL, &observeLightCb, LOW_QOS,
	NULL);
	oc_set_delayed_callback(NULL, &stopObserveClientCb, 10);
}

void CloudHelper::handleSignalCb(int signal) {
	(void) signal;
	PRINT("handleSignalCb:\n");
	signalEventLoopCb();
	s_generalQuit = 1;
}

static void CloudHelper::cloudPostResponseCb(oc_client_response_t *data) {
	if (data->code == OC_STATUS_CHANGED)
		printf("POST response: CHANGED\n");
	else if (data->code == OC_STATUS_CREATED)
		printf("POST response: CREATED\n");
	else
		printf("POST response code %d\n", data->code);

	parsePayload(data);
	s_isRequestSucessfull = 1;
	s_generalQuit = 1;
}

static void CloudHelper::parsePayload(oc_client_response_t *data) {
	oc_rep_t *rep = data->payload;
	while (rep != NULL) {
		printf("key %s, value ", oc_string(rep->name));
		switch (rep->type) {
		case OC_REP_BOOL:
			printf("%d\n", rep->value.boolean);
			break;
		case OC_REP_INT:
			printf("%d\n", rep->value.integer);
			break;
		case OC_REP_STRING:
			printf("%s\n", oc_string(rep->value.string));
			if (strncmp("uid", oc_string(rep->name), oc_string_len(rep->name))
					== 0) {
				if (oc_string_len(uid))
					oc_free_string(&uid);
				oc_new_string(&uid, oc_string(rep->value.string),
						oc_string_len(rep->value.string));
			} else if (strncmp("accesstoken", oc_string(rep->name),
					oc_string_len(rep->name)) == 0) {
				if (oc_string_len(access_token))
					oc_free_string(&access_token);
				oc_new_string(&access_token, oc_string(rep->value.string),
						oc_string_len(rep->value.string));
			}
			break;
		default:
			printf("NULL\n");
			break;
		}
		rep = rep->next;
	}
}

bool CloudHelper::ocSignUpWithAuth(const char *provier, const char *address,
		const char *auth_code) {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;

	if (strlen(address) != 0) {
		oc_string_t address_str;
		oc_new_string(&address_str, address, strlen(address));

		oc_string_to_endpoint(&address_str, &s_cloudEndpoint, NULL);
		oc_free_string(&address_str);

	}

	return oc_sign_up_with_auth(&s_cloudEndpoint, provier, auth_code, 0,
			cloudPostResponseCb,
			NULL);
}

bool CloudHelper::ocSignInWithAuth() {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;

	return oc_sign_in(&s_cloudEndpoint, oc_string(uid), oc_string(access_token),
			0, cloudPostResponseCb, NULL);
}

bool CloudHelper::ocSignInWithAuth(bool endpoint, const char *luid,
		const char *laccess_token, bool cb) {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;

	if (endpoint)
		return oc_sign_in(NULL, oc_string(uid), oc_string(access_token), 0,
				cloudPostResponseCb, NULL);
	else if (cb)
		return oc_sign_in(&s_cloudEndpoint, oc_string(uid),
				oc_string(access_token), 0, NULL, NULL);
	else
		return oc_sign_in(&s_cloudEndpoint, luid, laccess_token, 0,
				cloudPostResponseCb, NULL);
}

bool CloudHelper::ocSignOutWithAuth() {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;
	return oc_sign_out(&s_cloudEndpoint, oc_string(access_token), 0,
			cloudPostResponseCb, NULL);
}

bool CloudHelper::ocSignOutWithAuth(bool endpoint, const char *laccess_token,
		bool cb) {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;
	if (endpoint)
		return oc_sign_out(NULL, oc_string(access_token), 0,
				cloudPostResponseCb, NULL);
	else if (cb)
		return oc_sign_out(&s_cloudEndpoint, oc_string(access_token), 0, NULL,
				NULL);
	else
		return oc_sign_out(&s_cloudEndpoint, laccess_token, 0,
				cloudPostResponseCb, NULL);

}

bool CloudHelper::ocSignUp() {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;
	return oc_sign_up(&s_cloudEndpoint, "github", oc_string(uid),
			oc_string(access_token), 0, cloudPostResponseCb, NULL);
}

bool CloudHelper::ocSignUp(bool endpoint, const char *lauthprovider,
		const char *luid, const char *laccess_token, bool cb) {
	s_generalQuit = 0;
	s_isRequestSucessfull = 0;

	if (endpoint)
		return oc_sign_up(NULL, "github", oc_string(uid),
				oc_string(access_token), 0, cloudPostResponseCb, NULL);
	else if (cb)
		return oc_sign_up(&s_cloudEndpoint, "github", oc_string(uid),
				oc_string(access_token), 0, NULL, NULL);
	else
		return oc_sign_up(&s_cloudEndpoint, lauthprovider, luid, laccess_token,
				0, cloudPostResponseCb, NULL);
}
