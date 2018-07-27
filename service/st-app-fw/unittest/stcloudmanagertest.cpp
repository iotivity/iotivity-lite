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
//Secure Info
{
    "salt": "6cc68d2aa6af1a7ae5d1966f489d41a2d7ca4459bbacca9b25b2918dd55e0d37",
    "iv": "cecf45964f995b974ca41c6ea42b2700",
    "data_len": 168,
    "encrypted_len": 176
}

//encrypted data

{
    "status": true,
    "cloudstatus": 0,
    "data": h'447A1B341EECF5CC1442421C26DB1C95BFC8B020B2F825F0FF5D9EAF66B1C428052B9BB795185725AC693EFEE1BBA6168D90758484F4DDCC090438943272E6B0D387F5BD143E3252B57F4CB11EED5930418E89C02945B02E2A59778A07C35CB88765B7C8DF39A2241931BFFBE5289E3BB1E2A074841B07E7572B700C80558AE3738305A5DE83F3F6C95189613DCA0502A2A6F3AA446C236DA3A61F8674E14B8B16015F752241DD752CA7A3BA35CC743F'
}

//Cloud and accesspoint info(Encrypted as data)
{
    "ssid": "wifi_ssid",
    "pwd": "wifi_pw",
    "ci_server": "coap://224.0.1.187:5683",
    "auth_provider": "https://auth.iotivity.org",
    "uid": "1234567890",
    "access_token": "xxxxxxxxxx",
    "refresh_token": "yyyyyyyyyy"
}
*/

#ifdef OC_SECURITY
static uint8_t st_info[] = {
0xA3, 0x66, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0xF5, 0x6B, 0x63, 0x6C,
0x6F, 0x75, 0x64, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x00, 0x64, 0x64,
0x61, 0x74, 0x61, 0x58, 0xB0, 0x7C, 0x0B, 0x42, 0xD4, 0x04, 0x9A, 0xB4,
0x02, 0x55, 0xCE, 0x5D, 0x78, 0x21, 0x57, 0x95, 0x0B, 0xAA, 0x67, 0xAC,
0x97, 0xCB, 0x34, 0x79, 0x89, 0x24, 0x00, 0x62, 0xFA, 0x46, 0x5C, 0x79,
0x67, 0x2E, 0x12, 0x13, 0xFE, 0x34, 0x18, 0x3C, 0x92, 0x3B, 0x2A, 0x75,
0x3F, 0x4E, 0xFC, 0x0C, 0xE9, 0x35, 0xB9, 0x4F, 0x22, 0xF8, 0x13, 0x70,
0x9D, 0xD0, 0xDE, 0x40, 0xEB, 0x46, 0x43, 0x32, 0xF2, 0xAE, 0x20, 0xAA,
0x9A, 0x31, 0x75, 0x8E, 0xF4, 0xC9, 0x5B, 0xE6, 0xC5, 0x6C, 0x8A, 0xB4,
0xAA, 0x29, 0xE7, 0x6B, 0x44, 0x0B, 0x89, 0x89, 0xC5, 0x3A, 0xE4, 0x40,
0xD5, 0x49, 0x2D, 0xEA, 0x79, 0x79, 0x4D, 0x3C, 0xF5, 0xEA, 0x64, 0xF1,
0x69, 0xC3, 0x9B, 0xD4, 0xD0, 0x4C, 0x0C, 0x3A, 0x64, 0x89, 0x30, 0x61,
0x4A, 0xB2, 0xBD, 0xD1, 0x23, 0x69, 0xDA, 0x30, 0x84, 0x3C, 0xCB, 0x55,
0x08, 0xD7, 0x67, 0xFB, 0x19, 0x8C, 0x35, 0xD3, 0x2B, 0x01, 0x94, 0xD9,
0xCE, 0xC4, 0x97, 0x0E, 0xE4, 0x27, 0x4B, 0x73, 0xDF, 0x87, 0x24, 0x04,
0xB7, 0x6E, 0x3B, 0x3F, 0x33, 0x8F, 0xA0, 0x21, 0x37, 0x82, 0x2C, 0xE5,
0x72, 0x6E, 0x3C, 0x10, 0xC8, 0x58, 0xC8, 0xDA, 0xDE, 0x08, 0x68, 0x10,
0x29
};
static int st_info_len = 205;

static uint8_t st_info_secure[] = {
0XBF, 0X64, 0X73, 0X61, 0X6C, 0X74, 0X58, 0X20, 0X6C, 0XC6, 0X8D, 0X2A,
0XA6, 0XAF, 0X1A, 0X7A, 0XE5, 0XD1, 0X96, 0X6F, 0X48, 0X9D, 0X41, 0XA2,
0XD7, 0XCA, 0X44, 0X59, 0XBB, 0XAC, 0XCA, 0X9B, 0X25, 0XB2, 0X91, 0X8D,
0XD5, 0X5E, 0X0D, 0X37, 0X62, 0X69, 0X76, 0X50, 0XCE, 0XCF, 0X45, 0X96,
0X4F, 0X99, 0X5B, 0X97, 0X4C, 0XA4, 0X1C, 0X6E, 0XA4, 0X2B, 0X27, 0X00,
0X68, 0X64, 0X61, 0X74, 0X61, 0X5F, 0X6C, 0X65, 0X6E, 0X18, 0XA8, 0X6D,
0X65, 0X6E, 0X63, 0X72, 0X79, 0X70, 0X74, 0X65, 0X64, 0X5F, 0X6C, 0X65,
0X6E, 0X18, 0XB0, 0XFF
};
static int st_info_secure_len = 87;
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

#ifdef STATE_MODEL
static void
st_status_handler(st_status_t status)
{
    if (status == ST_STATUS_WIFI_CONNECTION_CHECKING && !is_stack_ready)
    {
        ASSERT_TRUE(find_tcp_endpoint());
        is_stack_ready = true;
    }
    else {
        if (status == ST_STATUS_EASY_SETUP_PROGRESSING && is_stack_ready) {
            is_reset_handled = true;
        } else if (status == ST_STATUS_STOP) {
            is_stop_handled = true;
        } else if (status == ST_STATUS_DONE) {
            is_st_app_ready = true;
        } else {
            return;
        }
    }
    st_mutex_lock(mutex);
    st_cond_signal(cv);
    st_mutex_unlock(mutex);
}

#else
static void
st_status_handler(st_status_t status)
{
    if (status <= ST_STATUS_WIFI_CONNECTING && !is_stack_ready) {
        ASSERT_TRUE(find_tcp_endpoint());
        is_stack_ready = true;
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
    }
    st_mutex_lock(mutex);
    st_cond_signal(cv);
    st_mutex_unlock(mutex);
}


static
void *st_manager_func(void *data)
{
    (void)data;
    st_error_t ret = st_manager_run_loop();
    if(test_case_type != CM_FAIL)
        EXPECT_EQ(ST_ERROR_NONE, ret);
    else
        EXPECT_EQ(ST_ERROR_OPERATION_FAILED, ret);

    return NULL;
}
#endif

static
void set_st_store_info(void)
{
#ifdef OC_SECURITY
    oc_storage_write("st_info", st_info, st_info_len);
    oc_storage_write("st_info_secure", st_info_secure, st_info_secure_len);
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
            st_manager_start();
#ifndef STATE_MODEL
            t = st_thread_create(st_manager_func, "TEST", 0, NULL);
            test_wait_until(mutex, cv, 5);
#endif /* !STATE_MODEL */
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
    test_case_type = CM_NO_ERROR;
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