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
#include <pthread.h>

extern "C"{
    #include "st_data_manager.h"
    #include "st_resource_manager.h"
    #include "st_manager.h"
    #include "oc_api.h"
    #include "oc_ri.h"
    #include "oc_rep.h"
    #include "st_port.h"
    #include "st_types.h"
    #include "sttestcommon.h"
    #include "sc_easysetup.h"
    #include "messaging/coap/observe.h"
    int st_register_resources(int device);

    extern unsigned char st_device_def[];
    extern unsigned int st_device_def_len;
}

static int device_index = 0;
static bool request_handled;

static bool
resource_handler(st_request_t *request)
{
    (void)request;
    return true;
}

class TestSTResourceManager: public testing::Test
{
    private:
        static oc_handler_t s_handler;
        static int appInit(void)
        {
            int result = oc_init_platform("Samsung", NULL, NULL);
            result |= oc_add_device("/oic/d", "oic.d.light", "Light",
                                    "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
            return result;
        }

        static void signalEventLoop(void)
        {
            return;
        }

    protected:
        virtual void SetUp()
        {
            st_set_device_profile(st_device_def, st_device_def_len);
            s_handler.init = appInit;
            s_handler.signal_event_loop = signalEventLoop;
            int initResult = oc_main_init(&s_handler);
            ASSERT_TRUE((initResult == 0));
        }

        virtual void TearDown()
        {
            st_free_device_profile();
            oc_main_shutdown();
        }
};
oc_handler_t TestSTResourceManager::s_handler;

TEST_F(TestSTResourceManager, st_register_resources)
{
    char uri[26] = "/capability/switch/main/0";
    oc_resource_t *resource = NULL;
    st_data_mgr_info_load();
    st_register_resources(device_index);
    resource = oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
    EXPECT_STREQ(uri, oc_string(resource->uri));
    deinit_provisioning_info_resource();
    st_data_mgr_info_free();
}

TEST_F(TestSTResourceManager, st_register_resources_fail)
{
    int ret = st_register_resources(device_index);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTResourceManager, st_register_resource_handler)
{
    st_error_t ret = st_register_resource_handler(resource_handler, resource_handler);
    EXPECT_EQ(ST_ERROR_NONE, ret);
}

TEST_F(TestSTResourceManager, st_register_resource_handler_fail)
{
    st_error_t ret = st_register_resource_handler(NULL, NULL);
    EXPECT_EQ(ST_ERROR_INVALID_PARAMETER, ret);
}

static void onGetRequest(oc_request_t *request,
                                 oc_interface_mask_t interface, void *user_data)
{
    (void) interface;
    (void) user_data;

    request_handled = true;
    oc_send_response(request, OC_STATUS_OK);
}

TEST_F(TestSTResourceManager, st_notify_back)
{
    // Given
    request_handled = false;
    char uri[26] = "/capability/test/main/0";
    oc_resource_t *resource = oc_new_resource(NULL, uri, 1, 0);

    oc_resource_bind_resource_type(resource, "core.light");
    oc_resource_set_observable(resource, true);
    oc_resource_set_request_handler(resource, OC_GET, onGetRequest, NULL);
    oc_add_resource(resource);

    oc_endpoint_t *endpoint = oc_new_endpoint();

    coap_packet_t request;
    coap_packet_t response;
    request.code = COAP_GET;
    request.uri_path = uri;
    request.uri_path_len = strlen(uri);
    memset(request.token, 0, COAP_TOKEN_LEN) ;
    request.token_len = COAP_TOKEN_LEN;
    SET_OPTION(&request, COAP_OPTION_OBSERVE);
    request.observe = 0;
    response.code = COAP_NO_ERROR;
#ifdef OC_BLOCK_WISE
    int observe = coap_observe_handler(&request, &response, resource, 10, endpoint);
#else  /* OC_BLOCK_WISE */
    int observe = coap_observe_handler(&request, &response, resource, endpoint);
#endif /* !OC_BLOCK_WISE */

    EXPECT_EQ(0, observe);
    oc_free_endpoint(endpoint);

    // When
    st_error_t ret = st_notify_back(uri);
    EXPECT_EQ(true, request_handled);
    EXPECT_EQ(ST_ERROR_NONE, ret);
    oc_delete_resource(resource);
}

TEST_F(TestSTResourceManager, st_notify_back_fail_null)
{
    // Given
    char *uri = NULL;

    // When
    st_error_t ret = st_notify_back(uri);

    // Then
    EXPECT_EQ(ST_ERROR_INVALID_PARAMETER, ret);
}

TEST_F(TestSTResourceManager, st_notify_back_fail)
{
    // Given
    char uri[26] = "/capability/switch/main/1";

    // When
    st_error_t ret = st_notify_back(uri);

    // Then
    EXPECT_EQ(ST_ERROR_OPERATION_FAILED, ret);
}

#define RESOURCE_URI "/capability/switch/main/0"

static st_mutex_t mutex, g_mutex, p_mutex;
static st_cond_t cv, g_cv, p_cv;
static bool isCallbackReceived;
static oc_endpoint_t *ep;
#ifndef STATE_MODEL
static st_thread_t t = NULL;
#endif

class TestSTResourceManagerHandler: public testing::Test
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

        static void onGetResponse(oc_client_response_t *data)
        {
            (void) data;
            isCallbackReceived = true;
            st_mutex_lock(g_mutex);
            st_cond_signal(g_cv);
            st_mutex_unlock(g_mutex);
        }

        static void onPostResponse(oc_client_response_t *data)
        {
            (void) data;
            EXPECT_EQ(OC_STATUS_CHANGED, data->code);
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
#ifdef STATE_MODEL
            st_manager_start();
#else
            t = st_thread_create(st_manager_func, "TEST", 0, NULL);
            test_wait_until(mutex, cv, 5);
#endif

#ifdef OC_SECURITY
            oc_storage_config("./st_things_creds");
#endif /* OC_SECURITY */
            reset_storage();
            get_wildcard_acl_policy();
            ep = get_endpoint();
        }

        virtual void TearDown()
        {
            st_manager_stop();
#ifndef STATE_MODEL
            st_thread_destroy(t);
#endif
            st_register_status_handler(st_status_handler);
            st_manager_deinitialize();
            reset_storage();
            st_cond_destroy(cv);
            st_mutex_destroy(mutex);
        }
};

TEST_F(TestSTResourceManagerHandler, Get_Request)
{
    bool isSuccess = false;
    isCallbackReceived = false;
    g_mutex = st_mutex_init();
    g_cv = st_cond_init();
    isSuccess = oc_do_get(RESOURCE_URI, ep, NULL, onGetResponse, HIGH_QOS, NULL);

    EXPECT_TRUE(isSuccess);
    test_wait_until(g_mutex, g_cv, 5);
    EXPECT_TRUE(isCallbackReceived);

    st_mutex_destroy(g_mutex);
    st_cond_destroy(g_cv);
    g_cv = NULL;
    g_mutex = NULL;
}

TEST_F(TestSTResourceManagerHandler, Post_Request)
{
    bool init_success, post_success = false;
    isCallbackReceived = false;
    p_mutex = st_mutex_init();
    p_cv = st_cond_init();

    init_success = oc_init_post(RESOURCE_URI, ep, NULL, onPostResponse, LOW_QOS, NULL);
    oc_rep_start_root_object();
    oc_rep_set_int(root, power, 105);
    oc_rep_end_root_object();
    post_success = oc_do_post();

    EXPECT_TRUE(init_success);
    EXPECT_TRUE(post_success);

    test_wait_until(p_mutex, p_cv, 5);
    EXPECT_TRUE(isCallbackReceived);
    st_cond_destroy(p_cv);
    st_mutex_destroy(p_mutex);
    p_cv = NULL;
    p_mutex = NULL;
}
