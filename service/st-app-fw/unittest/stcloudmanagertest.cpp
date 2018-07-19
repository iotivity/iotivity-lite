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
    #include "st_cloud_manager.h"
    #include "st_manager.h"
    #include "st_resource_manager.h"
    #include "st_store.h"
    #include "st_port.h"
    #include "sttestcommon.h"
    #include "es_common.h"

    extern unsigned char st_device_def[];
    extern unsigned int st_device_def_len;
}

typedef enum {
  CM_NO_ERROR,
  CM_REFRESH,
  CM_RESET,
  CM_RETRY,
  CM_FAIL
} cm_test_case_t;

static int device_index = 0;
st_store_t *store_info = NULL;
void cloud_manager_handler_test(st_cloud_manager_status_t status)
{
    (void) status;
}

class TestSTCloudManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};


TEST_F(TestSTCloudManager, st_cloud_manager_start_store_info_fail)
{
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTCloudManager, st_cloud_manager_start)
{
    st_store_t *store_info = st_store_get_info();
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    st_cloud_manager_stop(0);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTCloudManager, st_cloud_manager_check_connection)
{
    char url[28] = "coap://www.samsung.com:5683";
    oc_string_t ci_server;
    oc_new_string(&ci_server, url, strlen(url));
    int ret = st_cloud_manager_check_connection(&ci_server);
    oc_free_string(&ci_server);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTCloudManager, st_cloud_manager_check_connection_fail)
{
    int ret = st_cloud_manager_check_connection(NULL);
    EXPECT_EQ(-1, ret);
}

static st_mutex_t mutex = NULL;
static st_cond_t cv = NULL;
static st_thread_t t = NULL;
static bool is_stack_ready = false;
static bool is_st_app_ready = false;
static bool is_reset_handled = false;
static bool is_stop_handled = false;
static cm_test_case_t test_case_type = CM_NO_ERROR;

/*
{
    "status": true,
    "accesspoint": {
        "ssid": "wifi_ssid",
        "pwd": "wifi_pw"
    },
    "cloudinfo": {
        "ci_server": "coap://224.0.1.187:5683",
        "auth_provider": "https://auth.iotivity.org",
        "uid": "1234567890",
        "access_token": "xxxxxxxxxx",
        "refresh_token": "yyyyyyyyyy",
        "status": 0
    }
}
*/
#ifdef OC_SECURITY
static uint8_t st_info[] = {
  0xa3, 0x66, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0xf5, 0x6b, 0x61, 0x63,
  0x63, 0x65, 0x73, 0x73, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0xa2, 0x64, 0x73,
  0x73, 0x69, 0x64, 0x69, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x73, 0x73, 0x69,
  0x64, 0x63, 0x70, 0x77, 0x64, 0x67, 0x77, 0x69, 0x66, 0x69, 0x5f, 0x70,
  0x77, 0x69, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x6e, 0x66, 0x6f, 0xa6,
  0x69, 0x63, 0x69, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x77, 0x63,
  0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x32, 0x32, 0x34, 0x2e, 0x30, 0x2e,
  0x31, 0x2e, 0x31, 0x38, 0x37, 0x3a, 0x35, 0x36, 0x38, 0x33, 0x6d, 0x61,
  0x75, 0x74, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72,
  0x78, 0x19, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x61, 0x75,
  0x74, 0x68, 0x2e, 0x69, 0x6f, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x2e,
  0x6f, 0x72, 0x67, 0x63, 0x75, 0x69, 0x64, 0x6a, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x6c, 0x61, 0x63, 0x63, 0x65, 0x73,
  0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x6a, 0x78, 0x78, 0x78, 0x78,
  0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x6d, 0x72, 0x65, 0x66, 0x72, 0x65,
  0x73, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x6a, 0x79, 0x79, 0x79,
  0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x66, 0x73, 0x74, 0x61, 0x74,
  0x75, 0x73, 0x00
};
static int st_info_len = 207;
#endif /* OC_SECURITY */

static bool
find_tcp_endpoint(void)
{
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(0);
    while (ep) {
        oc_string_t ep_str;
        if (!(ep->flags & transport_flags::SECURED) &&
            (ep->flags & transport_flags::TCP) &&
            (ep->flags & transport_flags::IPV4) &&
            oc_endpoint_to_string(ep, &ep_str) == 0) {
            st_store_t *st_info = st_store_get_info();
            if (oc_string(st_info->cloudinfo.ci_server)) {
                oc_free_string(&st_info->cloudinfo.ci_server);
            }
            oc_new_string(&st_info->cloudinfo.ci_server,
                            oc_string(ep_str), oc_string_len(ep_str));
            oc_free_string(&ep_str);
            return true;
        }
        ep = ep->next;
    }
    return false;
}

static void
st_status_handler(st_status_t status)
{
    if (status <= ST_STATUS_WIFI_CONNECTING && !is_stack_ready) {
        ASSERT_TRUE(find_tcp_endpoint());
        is_stack_ready = true;
        st_mutex_lock(mutex);
        st_cond_signal(cv);
        st_mutex_unlock(mutex);
    } else {
        if (status == ST_STATUS_RESET) {
            is_reset_handled = true;
        } else if (status == ST_STATUS_STOP) {
            is_stop_handled = true;
        } else if (status == ST_STATUS_DONE) {
            is_st_app_ready = true;
        } else {
            return;
        }
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
    if(test_case_type == CM_FAIL)
        EXPECT_EQ(ST_ERROR_OPERATION_FAILED, ret);
    else
        EXPECT_EQ(ST_ERROR_NONE, ret);

    return NULL;
}

static
void set_st_store_info(void)
{
#ifdef OC_SECURITY
    oc_storage_write("st_info", st_info, st_info_len);
#endif /* OC_SECURITY */
}

static oc_event_callback_retval_t
disconnect_handler(void *data)
{
    oc_endpoint_t *ep = (oc_endpoint_t *)data;

    //After sign up, disconnect session to connect re-direct server.
    OC_LOGipaddr(*ep);
    oc_connectivity_end_session(ep);
    free(ep);
    return OC_EVENT_DONE;
}

static void
sign_up_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
    (void)interface;
    (void)user_data;
    oc_rep_t *rep = request->request_payload;
    int len = 0;
    char *access_token = NULL;
    bool ret = oc_rep_get_string(rep, "accesstoken", &access_token, &len);
    ASSERT_TRUE(ret);

    st_store_t *st_info = st_store_get_info();
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, accesstoken, oc_string(st_info->cloudinfo.access_token));
    oc_rep_set_text_string(root, redirecturi, oc_string(st_info->cloudinfo.ci_server));
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_CHANGED);

    oc_endpoint_t *ep = (oc_endpoint_t *)malloc(sizeof(oc_endpoint_t));
    memcpy(ep, request->origin, sizeof(oc_endpoint_t));
    oc_set_delayed_callback(ep, disconnect_handler, 2);
}

static void
sign_in_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
    (void)interface;
    (void)user_data;
    oc_rep_t *rep = request->request_payload;
    int len = 0;
    char *access_token = NULL;
    bool ret = oc_rep_get_string(rep, "accesstoken", &access_token, &len);
    ASSERT_TRUE(ret);
    bool is_login;
    ret = oc_rep_get_bool(rep, "login", &is_login);
    ASSERT_TRUE(ret);
    EXPECT_TRUE(is_login);

    switch(test_case_type){
    case CM_NO_ERROR:
        oc_send_response(request, OC_STATUS_CHANGED);
        break;
    case CM_REFRESH:
        test_case_type = CM_NO_ERROR;
        oc_rep_start_root_object();
        oc_rep_set_int(root, code, 4);
        oc_rep_end_root_object();
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        break;
    case CM_RESET:
        test_case_type = CM_NO_ERROR;
        oc_rep_start_root_object();
        oc_rep_set_int(root, code, 200);
        oc_rep_end_root_object();
        oc_send_response(request, OC_STATUS_NOT_FOUND);
        break;
    case CM_RETRY:
        test_case_type = CM_NO_ERROR;
        oc_rep_start_root_object();
        oc_rep_set_int(root, code, 0);
        oc_rep_end_root_object();
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
        break;
    case CM_FAIL:
        oc_rep_start_root_object();
        oc_rep_set_int(root, code, 5);
        oc_rep_end_root_object();
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        break;
    }
}

static void
refresh_token_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                            void *user_data)
{
    (void)interface;
    (void)user_data;
    oc_rep_t *rep = request->request_payload;
    int len = 0;
    char *refresh_token = NULL;
    bool ret = oc_rep_get_string(rep, "refreshtoken", &refresh_token, &len);
    ASSERT_TRUE(ret);

    st_store_t *st_info = st_store_get_info();
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, accesstoken, oc_string(st_info->cloudinfo.access_token));
    oc_rep_set_text_string(root, refreshtoken, refresh_token);
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
device_profile_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                            void *user_data)
{
    (void)interface;
    (void)user_data;

    //TODO: check validity?

    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
rd_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                void *user_data)
{
    (void)interface;
    (void)user_data;

    //TODO: check validity?

    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
ping_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                 void *user_data)
{
    (void)interface;
    (void)user_data;

    int inarray[4] = { 1, 2, 4, 8 };
    oc_rep_start_root_object();
    oc_rep_set_int_array(root, inarray, inarray, 4);
    oc_rep_end_root_object();

    oc_send_response(request, OC_STATUS_OK);
}

static void
ping_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                  void *user_data)
{
    (void)interface;
    (void)user_data;

    //TODO: check validity?

    oc_send_response(request, OC_STATUS_NOT_MODIFIED);
}

static
void register_cloud_resources(void)
{
    oc_resource_t *res = oc_new_resource(NULL, "/oic/account", 1, 0);
    oc_resource_bind_resource_interface(res, OC_IF_BASELINE);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res, true);
    oc_resource_set_request_handler(res, OC_POST, sign_up_post_handler, NULL);
    oc_add_resource(res);

    oc_resource_t *res1 = oc_new_resource(NULL, "/oic/account/session", 1, 0);
    oc_resource_bind_resource_interface(res1, OC_IF_BASELINE);
    oc_resource_set_discoverable(res1, true);
    oc_resource_set_observable(res1, true);
    oc_resource_set_request_handler(res1, OC_POST, sign_in_post_handler, NULL);
    oc_add_resource(res1);

    oc_resource_t *res2 = oc_new_resource(NULL, "/oic/account/tokenrefresh", 1, 0);
    oc_resource_bind_resource_interface(res2, OC_IF_BASELINE);
    oc_resource_set_discoverable(res2, true);
    oc_resource_set_observable(res2, true);
    oc_resource_set_request_handler(res2, OC_POST, refresh_token_post_handler, NULL);
    oc_add_resource(res2);

    oc_resource_t *res3 = oc_new_resource(NULL, "/oic/account/profile/device", 1, 0);
    oc_resource_bind_resource_interface(res3, OC_IF_BASELINE);
    oc_resource_set_discoverable(res3, true);
    oc_resource_set_observable(res3, true);
    oc_resource_set_request_handler(res3, OC_POST, device_profile_post_handler, NULL);
    oc_add_resource(res3);

    oc_resource_t *res4 = oc_new_resource(NULL, "/oic/rd", 1, 0);
    oc_resource_bind_resource_interface(res4, OC_IF_BASELINE);
    oc_resource_set_discoverable(res4, true);
    oc_resource_set_observable(res4, true);
    oc_resource_set_request_handler(res4, OC_POST, rd_post_handler, NULL);
    oc_add_resource(res4);

    oc_resource_t *res5 = oc_new_resource(NULL, "/oic/ping", 1, 0);
    oc_resource_bind_resource_interface(res5, OC_IF_BASELINE);
    oc_resource_set_discoverable(res5, true);
    oc_resource_set_observable(res5, true);
    oc_resource_set_request_handler(res5, OC_GET, ping_get_handler, NULL);
    oc_resource_set_request_handler(res5, OC_POST, ping_post_handler, NULL);
    oc_add_resource(res5);
}

class TestSTCloudManager_cb: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            is_stack_ready = false;
            mutex = st_mutex_init();
            cv = st_cond_init();
            reset_storage();
            st_manager_initialize();
            st_register_status_handler(st_status_handler);
            st_set_device_profile(st_device_def, st_device_def_len);
            set_st_store_info();
            t = st_thread_create(st_manager_func, "TEST", 0, NULL);
            test_wait_until(mutex, cv, 5);
            get_wildcard_acl_policy();
            register_cloud_resources();
        }

        virtual void TearDown()
        {
            st_manager_stop();
            st_thread_destroy(t);
            st_manager_deinitialize();
            reset_storage();
            st_cond_destroy(cv);
            st_mutex_destroy(mutex);
            cv = NULL;
            mutex = NULL;
        }
};

#ifndef JENKINS_BLOCK
#ifdef OC_SECURITY
TEST_F(TestSTCloudManager_cb, cloud_manager_normal_test)
{
    is_st_app_ready = false;
    int ret = test_wait_until(mutex, cv, 20);
    ASSERT_EQ(0, ret);

    EXPECT_TRUE(is_st_app_ready);
}

TEST_F(TestSTCloudManager_cb, cloud_manager_token_expired)
{
    is_st_app_ready = false;
    test_case_type = CM_REFRESH;
    int ret = test_wait_until(mutex, cv, 30);
    ASSERT_EQ(0, ret);

    EXPECT_TRUE(is_st_app_ready);
}

TEST_F(TestSTCloudManager_cb, cloud_manager_device_not_found)
{
    is_reset_handled = false;
    test_case_type = CM_RESET;
    int ret = test_wait_until(mutex, cv, 30);
    ASSERT_EQ(0, ret);

    EXPECT_TRUE(is_reset_handled);
}

TEST_F(TestSTCloudManager_cb, DISABLED_cloud_manager_internal_server_error)
{
    is_st_app_ready = false;
    test_case_type = CM_RETRY;
    int ret = test_wait_until(mutex, cv, 80);
    ASSERT_EQ(0, ret);

    EXPECT_TRUE(is_st_app_ready);
}

TEST_F(TestSTCloudManager_cb, cloud_manager_authorization_fail)
{
    is_stop_handled = false;
    test_case_type = CM_FAIL;
    int ret = test_wait_until(mutex, cv, 20);
    ASSERT_EQ(0, ret);

    EXPECT_TRUE(is_stop_handled);
}
#endif /* OC_SECURITY */
#endif /* JENKINS_BLOCK */