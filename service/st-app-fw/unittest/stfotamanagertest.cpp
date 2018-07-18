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
    #include "st_manager.h"
    #include "st_fota_manager.h"
    #include "st_data_manager.h"
    #include "oc_ri.h"
    #include "oc_api.h"
    #include "sttestcommon.h"
    int st_fota_manager_start(void);
    void st_fota_manager_stop(void);

    extern unsigned char st_device_def[];
    extern unsigned int st_device_def_len;
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
            st_unregister_fota_cmd_handler();
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

TEST_F(TestSTFotaManager, st_register_fota_cmd_handler_fail_already_registered)
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

TEST_F(TestSTFotaManager, st_register_fota_cmd_handler_fail_null_param)
{
    // Given
    st_fota_manager_start();

    // When
    bool ret = st_register_fota_cmd_handler(NULL);
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

static st_mutex_t mutex, p_mutex;
static st_cond_t cv, p_cv;
static bool isCallbackReceived;
static oc_status_t status;
static st_thread_t t = NULL;
 
class TestSTFotaManagerHandler: public testing::Test
{
    public:

        static void
        st_status_handler(st_status_t status)
        {
            if (status == ST_STATUS_EASY_SETUP_PROGRESSING ||
                status == ST_STATUS_EASY_SETUP_DONE) {
                st_mutex_lock(mutex);
                st_cond_signal(cv);
                st_mutex_unlock(mutex);
            }
        }

        static
        void *st_manager_func(void *data)
        {
            (void)data;
            st_error_t ret = st_manager_start();
            EXPECT_EQ(ST_ERROR_NONE, ret);

            return NULL;
        }

        static oc_endpoint_t *
        get_endpoint(void)
        {
            oc_endpoint_t *eps = oc_connectivity_get_endpoints(0);

            while (eps && ((eps->flags & transport_flags::TCP) ||
                        (eps->flags & transport_flags::IPV6))) {
                eps = eps->next;
            }

            EXPECT_NE(NULL, eps);

            return eps;
        }

        static void onPostResponse(oc_client_response_t *data)
        {
            status = data->code;
            isCallbackReceived = true;
            st_mutex_lock(p_mutex);
            st_cond_signal(p_cv);
            st_mutex_unlock(p_mutex);
        }

    protected:
        virtual void SetUp()
        {
            mutex = st_mutex_init();
            cv = st_cond_init();
            st_manager_initialize();
            st_set_device_profile(st_device_def, st_device_def_len);
            st_register_status_handler(st_status_handler);
            t = st_thread_create(st_manager_func, "TEST", 0, NULL);
            test_wait_until(mutex, cv, 5);
#ifdef OC_SECURITY
            oc_storage_config("./st_things_creds");
#endif /* OC_SECURITY */
            reset_storage();
            get_wildcard_acl_policy();
            p_mutex = st_mutex_init();
            p_cv = st_cond_init();
        }

        virtual void TearDown()
        {
            st_manager_stop();
            st_thread_destroy(t);
            st_manager_deinitialize();
            reset_storage();
            st_unregister_fota_cmd_handler();
            st_cond_destroy(cv);
            st_mutex_destroy(mutex);
            st_mutex_destroy(p_mutex);
            st_cond_destroy(p_cv);
            p_cv = NULL;
            p_mutex = NULL;
        }
};

TEST_F(TestSTFotaManagerHandler, fota_cmd_handler)
{
    bool init_success, post_success = false;
    isCallbackReceived = false;

    st_register_fota_cmd_handler(st_fota_cmd_handler);

    oc_endpoint_t *ep = get_endpoint();
    init_success = oc_init_post(OC_RSRVD_FIRMWARE_URI, ep, NULL, onPostResponse, LOW_QOS, NULL);
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, update, "Init");
    oc_rep_end_root_object();
    post_success = oc_do_post();

    EXPECT_TRUE(init_success);
    EXPECT_TRUE(post_success);

    test_wait_until(p_mutex, p_cv, 5);
    EXPECT_TRUE(isCallbackReceived);
    EXPECT_EQ(OC_STATUS_CHANGED, status);
}

TEST_F(TestSTFotaManagerHandler, fota_cmd_handler_fail_not_registered)
{
    bool init_success, post_success = false;
    isCallbackReceived = false;

    oc_endpoint_t *ep = get_endpoint();
    init_success = oc_init_post(OC_RSRVD_FIRMWARE_URI, ep, NULL, onPostResponse, LOW_QOS, NULL);
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, update, "Init");
    oc_rep_end_root_object();
    post_success = oc_do_post();

    EXPECT_TRUE(init_success);
    EXPECT_TRUE(post_success);

    test_wait_until(p_mutex, p_cv, 5);
    EXPECT_TRUE(isCallbackReceived);
    EXPECT_EQ(OC_STATUS_BAD_REQUEST, status);
}