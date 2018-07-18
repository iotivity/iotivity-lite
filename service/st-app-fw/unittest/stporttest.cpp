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
    #include "st_port.h"
    #include "st_process.h"
    #include "st_manager.h"
    #include "st_easy_setup.h"
    #include "st_data_manager.h"
    #include "st_device_profile.h"
    #include "st_device_def.h"
}

#define SOFT_AP_PWD "1111122222"
#define SOFT_AP_CHANNEL (6)
static const char *device_name;
static const char *manufacturer;
static const char *sid;

st_cond_t cv = NULL;
st_mutex_t st_mutex = NULL;
st_specification_t *spec_info = NULL;

static void *thread_test(void *data){
    (void)data;
    st_mutex_lock(st_mutex);
    st_cond_wait(cv, st_mutex);
    st_print_log("thread_test Entered.\n");
    st_mutex_unlock(st_mutex);
    pthread_exit(NULL);
    return NULL;
}

class TestSTPort: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            st_set_device_profile(st_device_def, st_device_def_len);
            st_data_mgr_info_load();
            spec_info = st_data_mgr_get_spec_info();
            device_name = oc_string(spec_info->device.device_name);
            manufacturer = oc_string(spec_info->platform.manufacturer_name);
            sid = oc_string(spec_info->platform.model_number);
        }

        virtual void TearDown()
        {
            st_data_mgr_info_free();
            st_unset_device_profile();
        }
};

class TestSTPort_Thread: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            st_mutex = st_mutex_init();
            cv = st_cond_init();
        }

        virtual void TearDown()
        {
            st_mutex_destroy(st_mutex);
            st_cond_destroy(cv);
        }
};

TEST_F(TestSTPort, st_port_specific_init)
{
    int ret = st_port_specific_init();
    EXPECT_EQ(0, ret);
    st_port_specific_destroy();
}

TEST_F(TestSTPort, st_mutex_init)
{
    st_mutex = st_mutex_init();
    EXPECT_NE(NULL, st_mutex);
    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_mutex_destroy)
{
    st_mutex = st_mutex_init();
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort, st_mutex_destroy_fail)
{
    st_mutex = NULL;
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_mutex_lock)
{
    st_mutex = st_mutex_init();
    int ret_lock = st_mutex_lock(st_mutex);
    EXPECT_NE(-1, ret_lock);

    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(16, ret_relock);

    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_mutex_unlock)
{
    st_mutex = st_mutex_init();
    st_mutex_lock(st_mutex);
    int ret_unlock = st_mutex_unlock(st_mutex);
    EXPECT_NE(-1, ret_unlock);

    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(0, ret_relock);

    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_cond_init)
{
    cv = st_cond_init();
    EXPECT_NE(NULL, cv);
    st_cond_destroy(cv);
}

TEST_F(TestSTPort, st_cond_destroy)
{
    cv = st_cond_init();
    int ret = st_cond_destroy(cv);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort, st_cond_wait_fail)
{
    cv, st_mutex = NULL;
    int ret = st_cond_wait(cv, st_mutex);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_cond_timedwait_fail)
{
    cv = st_cond_init();
    oc_clock_time_t waiting = 1;
    st_mutex = NULL;
    int ret = st_cond_timedwait(cv, st_mutex, waiting);
    EXPECT_EQ(-1, ret);
    st_cond_signal(cv);
    st_cond_destroy(cv);
}

TEST_F(TestSTPort, st_cond_signal)
{
    pthread_t tid;
    st_mutex = st_mutex_init();
    cv = st_cond_init();
    pthread_create(&tid, NULL, thread_test, 0);
    sleep(1);
    int ret = st_cond_signal(cv);
    int ret_join = pthread_join(tid, 0);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, ret_join);
}

TEST_F(TestSTPort_Thread, st_thread_create_stacksize_fail)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", -1, NULL);
    EXPECT_EQ(NULL, ret_thread);
}

TEST_F(TestSTPort_Thread, st_thread_create_handler_fail)
{
    st_thread_t ret_thread = st_thread_create(NULL, "test", -1, NULL);
    EXPECT_EQ(NULL, ret_thread);
}

TEST_F(TestSTPort_Thread, st_thread_destroy_O)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", 0, NULL);
    sleep(1);
    pthread_cond_broadcast((pthread_cond_t *)cv);
    int ret = st_thread_destroy(ret_thread);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort_Thread, st_thread_destroy_fail)
{
    int ret = st_thread_destroy(NULL);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort_Thread, st_thread_cancel_fail)
{
    int ret = st_thread_cancel(NULL);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_turn_on_soft_AP_and_st_turn_off_soft_AP)
{
    char ssid[MAX_SSID_LEN + 1];
    EXPECT_EQ(0, st_gen_ssid(ssid, device_name, manufacturer, sid));
    st_turn_on_soft_AP(ssid, SOFT_AP_PWD, SOFT_AP_CHANNEL);
    sleep(1);
    st_turn_off_soft_AP();
}

TEST_F(TestSTPort, st_connect_wifi)
{
    char ssid[MAX_SSID_LEN + 1];
    EXPECT_EQ(0, st_gen_ssid(ssid, device_name, manufacturer, sid));
    st_connect_wifi(ssid, SOFT_AP_PWD);
}

#ifdef MOCK_WIFI_SCAN
TEST_F(TestSTPort, st_scan_wifi_mock)
{
    st_wifi_ap_t *scanlist = NULL;
    st_wifi_scan(&scanlist);
    st_wifi_ap_t *ap_test = scanlist;
    int cnt = 3;
    while(cnt--){
        char name[15];
        sprintf(name, "iot_home_%d", cnt);
        EXPECT_STREQ(name, ap_test->ssid);
        EXPECT_STREQ("00:11:22:33:44:55", ap_test->mac_addr);
        EXPECT_STREQ("15", ap_test->channel);
        EXPECT_STREQ("38", ap_test->max_bitrate);
        EXPECT_STREQ("-10", ap_test->rssi);
        EXPECT_STREQ("WPA2", ap_test->sec_type);
        EXPECT_STREQ("AES", ap_test->enc_type);
        ap_test = ap_test->next;
    }
    st_wifi_free_scan_list(scanlist);
}
#endif

TEST_F(TestSTPort, st_wifi_set_cache_and_st_wifi_get_cache_and_st_wifi_clear_cache)
{
    st_wifi_ap_t *ap_list, *ap_list_cache = NULL;
    st_wifi_scan(&ap_list);
    st_wifi_set_cache(ap_list);
    ap_list_cache = st_wifi_get_cache();

    EXPECT_NE(NULL, ap_list_cache);
    EXPECT_EQ(ap_list, ap_list_cache);

    st_wifi_clear_cache();
    EXPECT_EQ(NULL, st_wifi_get_cache());
}

TEST_F(TestSTPort, st_wifi_free_scan_list)
{
    st_wifi_ap_t *ap_test =  (st_wifi_ap_t*) calloc(1, sizeof(st_wifi_ap_t));
    int len = 7;
    ap_test->ssid = (char*) calloc(len+1, sizeof(char));
    strncpy(ap_test->ssid, "abcdefg", len);
    st_wifi_free_scan_list(ap_test);

    EXPECT_STRNE("abcdefg", ap_test->ssid);
}