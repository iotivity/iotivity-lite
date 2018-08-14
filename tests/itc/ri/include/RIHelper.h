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

#ifndef INCLUDE_TESTCASE_RI_RIHELPER_H_
#define INCLUDE_TESTCASE_RI_RIHELPER_H_

#include "oc_uuid.h"
#include "oc_api.h"
#include "port/oc_clock.h"

#include <gtest/gtest.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define MANUFACTURE_NAME  "Samsung"
#define MAX_URI_LENGTH (30)

//resource types
constexpr char RESOURCE_TYPE_LIGHT[] { "core.light" };
constexpr char RESOURCE_TYPE_BRIGHT_LIGHT[] { "core.brightlight" };
constexpr char RESOURCE_TYPE_FAN[] { "core.fan" };
constexpr char RESOURCE_TYPE_TEMPERATURE[] { "oic.r.temperature" };
constexpr char RESOURCE_TYPE_PLATFORM[] { "oic.wk.p" };
constexpr char RESOURCE_TYPE_DEVICE[] { "oic.wk.d" };
constexpr char RESOURCE_URI_LIGHT[] { "/a/light" };
constexpr char RESOURCE_URI_FAN[] { "/a/fan" };
constexpr char RESOURCE_INTERFACE_DEFAULT[] { "oc.if.a" };
constexpr char RESOURCE_INTERFACE_RW[] { "core.rw" };

constexpr char DEVICE_URI_LIGHT[] { "/oic/d" };
constexpr char DEVICE_TYPE_LIGHT[] { "oic.d.light" };
constexpr char DEVICE_NAME_LIGHT[] { "Lamp" };
constexpr char OCF_SPEC_VERSION[] { "ocf.1.0.0" };
constexpr char OCF_DATA_MODEL_VERSION[] { "ocf.res.1.0.0" };

constexpr char KEY_TEMPERATURE[] { "temperature" };
constexpr char KEY_UNITS[] { "units" };
constexpr char KEY_HOUR[] { "x.samsung.hour" };

constexpr char KEY_DEVICE_NAME[] { "n" };
constexpr char KEY_SPEC_VERSION[] { "lcv" };

constexpr char KEY_PLATFORM_ID[] { "pi" };
constexpr char KEY_MANUFACTURER_NAME[] { "mnmn" };
constexpr char KEY_MANUFACTURER_URL[] { "mnml" };
constexpr char KEY_MODEL_NUMBER[] { "mnmo" };
constexpr char KEY_DATE_OF_MANUFACTURE[] { "mndt" };
constexpr char KEY_PLATFORM_VERSION[] { "mnpv" };
constexpr char KEY_OPERATING_SYSTEM[] { "mnos" };
constexpr char KEY_HARDWARE_VERSION[] { "mnhw" };
constexpr char KEY_FIRMWARE_VERSION[] { "mnfv" };
constexpr char KEY_SUPPORT_URL[] { "mnsl" };
constexpr char KEY_SYSTEM_TIME[] { "st" };

class RIHelper {
private:
	oc_request_t *serverrequest;

	static RIHelper *s_riHelperInstance;
	static oc_handler_t s_handler;
	static bool s_lightState;
	static oc_string_t s_lightName;
	static oc_resource_t *s_pResource;
	static oc_endpoint_t *s_pLightEndpoint;
	static int s_generalQuit;
	static pthread_mutex_t s_mutex;
	static pthread_cond_t s_cv;
	static struct timespec s_ts;
	static char s_lightUri[MAX_URI_LENGTH];

public:
	static bool s_isDiscoverResourceSucessfull;
	static bool s_isObserveResourceSuccessfull;
	static bool s_isRequestSucessfull;

	RIHelper();
	virtual ~RIHelper();

	//server
	int initServer();
	void sendRequestRespons(oc_status_t response_code);
	static void unRegisterResources(void);

	//server callback
	static void registerResourcesCb(void);
	static void registerEmptyResourcesCb(void);
	static void issueEmptyRequestsCb(void);
	static void getLightCb(oc_request_t *, oc_interface_mask_t, void *);
	static void postLightCb(oc_request_t *, oc_interface_mask_t, void *);
	static void putLightCb(oc_request_t *, oc_interface_mask_t, void *);

	//client
	int initClient();
	void observeResource();
	void getResource();
	void deleteResource();
	void postRequestResource();
	void putRequestResource();
	void discoverResource();

	//client callback
	static void issueRequestsCb(void);
	static oc_discovery_flags_t discovery(const char *, const char *,
			oc_string_array_t, oc_interface_mask_t, oc_endpoint_t *,
			oc_resource_properties_t, void *);
	static void observeLightCb(oc_client_response_t *);
	static void postLightClientCb(oc_client_response_t *);
	static oc_event_callback_retval_t stopObserveClientCb(void *);
	static void handleSignalCb(int signal);
	static void putLightClientCb(oc_client_response_t *data);
	static void deleteLightClientCb(oc_client_response_t *data);
	static void getLightClientCb(oc_client_response_t *data);

	//general
	static RIHelper *getInstance(void);
	static int appInitCb(void);
	static int appEmptyInitCb(void);
	static void signalEventLoopCb(void);

	int createResource();
	void shutDown();
	int waitForEvent();

};
#endif

