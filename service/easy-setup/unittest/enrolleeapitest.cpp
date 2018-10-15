/* *****************************************************************
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

#include <cstdlib>
#include <string>
#include <gtest/gtest.h>

#include "easysetup.h"

#define DEVICE_URI "/oic/d"
#define DEVICE_TYPE "oic.d.light"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "TEST_DEVICE"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

/** Callback functions for SetUserData API Test */
static void free_userdata_cb_test(void* userdata, char* resource_type)
{
    (void)resource_type;
    (void)userdata;
}

static void read_userdata_cb_test(oc_rep_t* payload, char* resource_type, void** userdata)
{
    (void)resource_type;
    (void)payload;
    (void)userdata;
}

static void write_userdata_cb_test(oc_rep_t* payload, char* resource_type)
{
    (void)resource_type;
    (void)payload;
}

/** Test Class for Enrollee API Test, this is the entry point. */
class TestESEnrolleeAPI: public testing::Test
{
   private:
        static oc_handler_t s_handler;
        static es_provisioning_callbacks_s es_api_callbacks;

        static int appInit(void)
        {
            int result = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            result |= oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                                    OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            return result;
        }

        static void registerResources(void)
        {
            bool is_secure = false;

            es_resource_mask_e resourcem_mask = (es_resource_mask_e) (ES_WIFICONF_RESOURCE |
                ES_COAPCLOUDCONF_RESOURCE |
                ES_DEVCONF_RESOURCE);

            es_api_callbacks.wifi_prov_cb = wifi_prov_cb_test;
            es_api_callbacks.dev_conf_prov_cb = dev_conf_prov_cb_test;
            es_api_callbacks.cloud_data_prov_cb = cloud_conf_prov_cb_test;

            es_init_enrollee(is_secure, resourcem_mask, es_api_callbacks);
        }

        static void signalEventLoop(void)
        {
        }

        static void requestsEntry(void)
        {
        }

        static void wifi_prov_cb_test(es_wifi_conf_data *wifi_prov_data)
        {
            (void)wifi_prov_data;
        }

        static void dev_conf_prov_cb_test(es_dev_conf_data *dev_prov_data)
        {
            (void)dev_prov_data;
        }

        static void cloud_conf_prov_cb_test(es_coap_cloud_conf_data *cloud_prov_data)
        {
            (void)cloud_prov_data;
        }

    protected:
        virtual void SetUp()
        {
            s_handler.init = appInit;
            s_handler.signal_event_loop = signalEventLoop;
            s_handler.register_resources = registerResources;
            s_handler.requests_entry = requestsEntry;

            int initResult = oc_main_init(&s_handler);

            ASSERT_TRUE((initResult == 0));
        }

        virtual void TearDown()
        {
            es_terminate_enrollee();
            oc_main_shutdown();
        }
};

/** Static member definitions. */
oc_handler_t TestESEnrolleeAPI::s_handler;
es_provisioning_callbacks_s TestESEnrolleeAPI::es_api_callbacks;

/** Positive Test Cases Start Here */
TEST_F(TestESEnrolleeAPI, SetDeviceProperty_P)
{
    es_device_property device_property = {
        {
            {WIFI_11G, WIFI_11N, WIFI_11AC, WiFi_EOF },
            WIFI_5G
        },
        {
         {0}
        }
    };

    oc_new_string(&device_property.DevConf.device_name, DEVICE_NAME, strlen(DEVICE_NAME));

    es_result_e ret = es_set_device_property(&device_property);

    EXPECT_TRUE((ES_OK == ret));
}

TEST_F(TestESEnrolleeAPI, GetState_P)
{
    es_enrollee_state es_state_get_val = es_get_state();

    // ES_STATE_EOF is the state just after init until es_set_state() gets invoked.
    EXPECT_TRUE((es_state_get_val == ES_STATE_EOF));
}

TEST_F(TestESEnrolleeAPI, SetState_P)
{
    es_enrollee_state es_state_set_val = ES_STATE_INIT;

    // Set State
    es_result_e ret = es_set_state(es_state_set_val);

    EXPECT_TRUE((ES_OK == ret));

    // Verify same state is returned by get API.
    es_enrollee_state es_state_get_val = es_get_state();

    EXPECT_TRUE((es_state_get_val == es_state_set_val));
}

TEST_F(TestESEnrolleeAPI, SetErrorCode_P)
{
    es_error_code es_error_code_val = ES_ERRCODE_NO_ERROR;
    es_result_e ret;

    ret = es_set_error_code(es_error_code_val);

    EXPECT_TRUE((ES_OK == ret));
}

TEST_F(TestESEnrolleeAPI, SetUserDataCallbacks_P)
{
    es_result_e ret;

    ret = es_set_callback_for_userdata(read_userdata_cb_test,
        write_userdata_cb_test,
        free_userdata_cb_test);

    EXPECT_TRUE((ES_OK == ret));
}

/** Positive Test Cases End Here */

