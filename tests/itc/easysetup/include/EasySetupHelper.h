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

#ifndef INCLUDE_TESTCASE_EASYSETUP_HELPER_H_
#define INCLUDE_TESTCASE_EASYSETUP_HELPER_H_

extern "C" {
    #include "cloud_access.h"
    #include "oc_api.h"
    #include "port/oc_clock.h"
    #include "rd_client.h"
    #include "easysetup.h"
    #include "es_common.h"
}

#include <gtest/gtest.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define MANUFACTURE_NAME  "Samsung"
#define MAX_URI_LENGTH (30)
#define OC_IPV6_ADDRSTRLEN (46)

#define STR_USERPROPERTY_KEY_INT "x.user.property.int"
#define USERPROPERTY_KEY_INT x.user.property.int
#define USERPROPERTY_KEY_STR x.user.property.str

#define set_custom_property_str(object, key, value)                            \
  oc_rep_set_text_string(object, key, value)
#define set_custom_property_int(object, key, value)                            \
  oc_rep_set_int(object, key, value)

#define MAXLEN_STRING 100
#define TIMEOUT 30

typedef struct
{
    int user_value_int; /**< User-specific property in WiFi Resource **/
    char user_value_str[MAXLEN_STRING]; /**< User-specific property in DevConf
     Resource **/
} user_properties_t;

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

class EasySetupHelper
{
    private:
        oc_request_t *serverrequest;

        static EasySetupHelper *s_easySetupHelperInstance;
        static oc_handler_t s_handler;
        static bool s_lightState;

        static oc_resource_t *s_pResource;

        static int s_generalQuit;
        static pthread_mutex_t s_mutex;
        static pthread_cond_t s_cv;
        static struct timespec s_ts;

        static es_provisioning_callbacks_s easyset_callbacks_handler;
        static user_properties_t s_useProperties;

    public:

        static bool s_iswifiProvinAppCbSucessfull;
        static bool s_isdevConfProInAppCbSucessfull;
        static bool s_iscloudConfProvinAppCBSucessfull;

        EasySetupHelper();
        virtual ~EasySetupHelper();

        //server
        void sendRequestRespons(oc_status_t response_code);
        static void unRegisterResources(void);

        //server callback
        static void registerResourcesCb(void);
        static void getLightCb(oc_request_t *, oc_interface_mask_t, void *);
        static void postLightCb(oc_request_t *, oc_interface_mask_t, void *);

        //client callback
        static void issueRequestsCb(void);

        //general
        static EasySetupHelper *getInstance(void);
        static int appInitCb(void);
        static void signalEventLoopCb(void);

        int createResource();
        void shutDown();
        int waitForEvent();

        //easy setup server
        bool easySetupInitEnrollee(bool isSecured, bool isResourceMask,
                                   bool isHandlerNull);
        bool easySetupCallbackforUserData(bool isCallbackNull);
        bool setDeviceInfo(bool isDevicePropertyNull);
        bool stopEasySetup();

        void setUserProperties();

        static void cloudConfProvinAppCB(es_coap_cloud_conf_data *event_data);
        static void devConfProInAppCb(es_dev_conf_data *event_data);
        static void wifiProvinAppCb(es_wifi_conf_data *event_data);
        static void writeUserDataCb(oc_rep_t *payload, char *resourceType);
        static void readUserDataCb(oc_rep_t *payload, char *resourceType,
                                   void **userdata);
};
#endif

