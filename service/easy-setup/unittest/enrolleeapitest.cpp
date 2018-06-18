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

#include <cstdlib>
#include <string>
#include <gtest/gtest.h>

extern "C" {
    #include "easysetup.h"
}

#define MAX_WAIT_TIME 10
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

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

static void
wifi_prov_cb_test(es_wifi_conf_data *wifi_prov_data)
{
}

static void
dev_conf_prov_cb_test(es_dev_conf_data *dev_prov_data)
{
}

static void
cloud_conf_prov_cb_test(es_coap_cloud_conf_data *cloud_prov_data)
{
}


class TestESEnrolleeAPI: public testing::Test
{
   private:
        static oc_handler_t s_handler;
        static es_provisioning_callbacks_s es_api_callbacks;

    protected:
        static int appInit(void)
        {
            int result = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            result |= oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                                    OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            return result;
        }

        static void registerResources(void)
        {
            es_resource_mask_e resourcem_mask = ES_WIFICONF_RESOURCE |
                ES_COAPCLOUDCONF_RESOURCE |
                ES_DEVCONF_RESOURCE;

            es_api_callbacks.wifi_prov_cb = wifi_prov_cb_test;
            es_api_callbacks.dev_conf_prov_cb = dev_conf_prov_cb_test;
            es_api_callbacks.cloud_data_prov_cb = cloud_conf_prov_cb_test;
            es_init_enrollee(true, resourcem_mask, es_api_callbacks);
        }

        static void signalEventLoop(void)
        {
            //pthread_mutex_lock(&s_mutex);
            //pthread_cond_signal(&s_cv);
            //pthread_mutex_unlock(&s_mutex);
        }

        static void requestsEntry(void)
        {
        }

        virtual void SetUp()
        {
            s_handler.init = appInit;
            s_handler.signal_event_loop = signalEventLoop;
            s_handler.register_resources = registerResources;
            s_handler.requests_entry = requestsEntry;

            int initResult = oc_main_init(&s_handler);
        }

        virtual void TearDown()
        {
            es_terminate_enrollee();
        }
};

TEST(TestESEnrolleeAPI, SetDeviceProperty_P)
{
    char *device_name = "TEST_DEVICE";

    es_device_property device_property = {
        {
            {WIFI_11G, WIFI_11N, WIFI_11AC, WiFi_EOF },
            WIFI_5G
        },
        {
         {0}
        }
    };

    oc_new_string(&device_property.DevConf.device_name, device_name, strlen(device_name));

    es_result_e ret = es_set_device_property(&device_property);

    EXPECT_TRUE((ES_OK == ret));
}

TEST(TestESEnrolleeAPI, SetAndGetState_P)
{
    es_enrollee_state es_state_set_val = ES_STATE_INIT;

    es_set_state(es_state_set_val);

    es_enrollee_state es_state_get_val = ES_STATE_EOF;

    es_state_get_val = es_get_state();

    EXPECT_TRUE((es_state_get_val == es_state_set_val));
}

TEST(TestESEnrolleeAPI, SetErrorCode_P)
{
    es_error_code es_error_code_val = ES_ERRCODE_NO_ERROR;
    es_result_e ret;

    ret = es_set_error_code(es_error_code_val);

    EXPECT_TRUE((ES_OK == ret));
}

TEST(TestESEnrolleeAPI, SetUserDataCallbacks_P)
{
    es_result_e ret;

    ret = es_set_callback_for_userdata(read_userdata_cb_test,
        write_userdata_cb_test,
        free_userdata_cb_test);

    EXPECT_TRUE((ES_OK == ret));
}


