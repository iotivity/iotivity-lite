/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_fota_manager.h"
    #include "oc_ri.h"
    #include "oc_api.h"
    #include "sttestcommon.h"
    extern int st_fota_manager_start(void);
    extern void st_fota_manager_stop(void);
}

#define device_index 0

static bool
st_fota_cmd_handler(fota_cmd_t cmd)
{
    (void)cmd;
    return true;
}

class TestSTFotaManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

TEST_F(TestSTFotaManager, st_fota_manager_start)
{
    int ret = st_fota_manager_start();
    st_fota_manager_stop();
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTFotaManager, st_fota_manager_stop)
{
    char uri[10] = "/firmware";
    oc_resource_t *resource = NULL;
    st_fota_manager_start();
    st_fota_manager_stop();
    resource = oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
    EXPECT_EQ(NULL, resource);
}

TEST_F(TestSTFotaManager, st_fota_set_state)
{
    // Given
    st_fota_manager_start();

    // When
    st_error_t ret = st_fota_set_state(FOTA_STATE_DOWNLOADING);
    st_fota_manager_stop();

    // Then
    EXPECT_EQ(ST_ERROR_NONE, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_state_fail)
{
    // Given
    st_fota_manager_start();

    // When
    st_error_t ret = st_fota_set_state(FOTA_STATE_IDLE);
    st_fota_manager_stop();

    // Then
    EXPECT_NE(ST_ERROR_NONE, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_fw_info)
{
    // Given
    char ver[4] = "1.0";
    char uri[23] = "http://www.samsung.com";

    // When
    st_error_t ret = st_fota_set_fw_info(ver, uri);

    // Then
    EXPECT_EQ(ST_ERROR_NONE, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_fw_info_fail)
{
    // Given
    char *ver = NULL;
    char uri[23] = "http://www.samsung.com";

    // When
    st_error_t ret = st_fota_set_fw_info(ver, uri);

    // Then
    EXPECT_NE(ST_ERROR_NONE, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_result)
{
    // Given

    // When
    st_error_t ret = st_fota_set_result(FOTA_RESULT_SUCCESS);

    // Then
    EXPECT_EQ(ST_ERROR_NONE, ret);
}

TEST_F(TestSTFotaManager, st_register_fota_cmd_handler)
{
    // Given
    st_fota_manager_start();

    // When
    bool ret = st_register_fota_cmd_handler(st_fota_cmd_handler);
    st_fota_manager_stop();

    // Then
    EXPECT_TRUE(ret);
}

TEST_F(TestSTFotaManager, st_register_fota_cmd_handler_fail)
{
    // Given
    st_fota_manager_start();
    st_register_fota_cmd_handler(st_fota_cmd_handler);

    // When
    bool ret = st_register_fota_cmd_handler(st_fota_cmd_handler);
    st_fota_manager_stop();

    // Then
    EXPECT_FALSE(ret);
}

TEST_F(TestSTFotaManager, st_unregister_fota_cmd_handler)
{
    // Given
    st_fota_manager_start();
    st_register_fota_cmd_handler(st_fota_cmd_handler);

    // When
    st_unregister_fota_cmd_handler();
    bool ret = st_register_fota_cmd_handler(st_fota_cmd_handler);
    st_fota_manager_stop();

    // Then
    EXPECT_TRUE(ret);
}

#define OC_RSRVD_FIRMWARE_URI "/firmware"
#define MAX_WAIT_TIME 10
#define DEVICE_URI "/oic/d"
#define DEVICE_TYPE "oic.d.light"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define DEVICE_NUM 0
#define OCF_SPEC_VERSION "core.1.1.0"
#define OCF_DATA_MODEL_VERSION "res.1.1.0"

class TestSTFotaManagerHandler: public testing::Test
{
    public:
        static oc_handler_t handler;
        static pthread_mutex_t mutex;
        static pthread_cond_t cv;
        static bool isResourceDiscovered;
        static bool isCallbackReceived;
        static oc_endpoint_t *LightEndpoint;
        static oc_status_t status;

        static oc_discovery_flags_t onResourceDiscovered(const char *di, const char *uri,
                oc_string_array_t types, oc_interface_mask_t interfaces,
                oc_endpoint_t *endpoint, oc_resource_properties_t bm, void *user_data)
        {
            (void)di;
            (void)types;
            (void)interfaces;
            (void)bm;
            (void)user_data;
            std::string discoveredResourceUri = std::string(uri);
            if (discoveredResourceUri.compare(OC_RSRVD_FIRMWARE_URI) == 0)
            {
                PRINT("Switch Resource Discovered...\n");
                LightEndpoint = endpoint;
                isResourceDiscovered = true;
                return OC_STOP_DISCOVERY;
            }

            oc_free_server_endpoints(endpoint);
            return OC_CONTINUE_DISCOVERY;
        }

        static void onPostResponse(oc_client_response_t *data)
        {
            EXPECT_EQ(OC_STATUS_CHANGED, data->code); 
            isCallbackReceived = true;
        }

        static void waitForEvent(int waitTime)
        {
            oc_clock_time_t next_event;
            (void)next_event;
            while (waitTime && !isCallbackReceived && !isResourceDiscovered)
            {
                PRINT("Waiting for callback....\n");
                next_event = oc_main_poll();
                sleep(1);
                waitTime--;
            }
        }

        static int appInit(void)
        {
            int result = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            result |= oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                                    OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            return result;
        }

        static void signalEventLoop(void)
        {
            pthread_mutex_lock(&mutex);
            pthread_cond_signal(&cv);
            pthread_mutex_unlock(&mutex);
        }

        static void registerResources(void)
        {
            st_fota_manager_start();
        }

    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }

        static void SetUpTestCase(){
            
            handler.init = appInit;
            handler.signal_event_loop = signalEventLoop;
            handler.register_resources = registerResources;

            oc_main_init(&handler);
            get_wildcard_acl_policy();
            ASSERT_TRUE(oc_do_ip_discovery(NULL, onResourceDiscovered, NULL)) << "oc_do_ip_discovery() returned failure.";

            waitForEvent(MAX_WAIT_TIME);
            ASSERT_TRUE(isResourceDiscovered) << " Unable to discover Switch Resource";
        }
        
        static void TearDownTestCase()
        {
            st_fota_manager_stop();
            oc_main_shutdown();
            reset_storage();
        }
};

bool TestSTFotaManagerHandler::isCallbackReceived = false;
bool TestSTFotaManagerHandler::isResourceDiscovered = false;
oc_endpoint_t *TestSTFotaManagerHandler::LightEndpoint = nullptr;
oc_handler_t TestSTFotaManagerHandler::handler;
pthread_mutex_t TestSTFotaManagerHandler::mutex;
pthread_cond_t TestSTFotaManagerHandler::cv;

TEST_F(TestSTFotaManagerHandler, fota_cmd_handler)
{
    bool init_success, post_success = false;
    isCallbackReceived = false;
    isResourceDiscovered = false;

    init_success = oc_init_post(OC_RSRVD_FIRMWARE_URI, LightEndpoint, NULL, onPostResponse, LOW_QOS, NULL);
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, update, "Init");
    oc_rep_end_root_object();
    post_success = oc_do_post();

    EXPECT_TRUE(init_success);
    EXPECT_TRUE(post_success);

    waitForEvent(MAX_WAIT_TIME);
    EXPECT_TRUE(isCallbackReceived);
}