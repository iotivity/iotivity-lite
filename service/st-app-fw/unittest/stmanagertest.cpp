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
    #include "st_process.h"
    #include "st_port.h"
    #include "sttestcommon.h"

    extern unsigned char st_device_def[];
    extern unsigned int st_device_def_len;
}

static st_mutex_t mutex = NULL;
static st_cond_t cv = NULL;

#ifdef OC_SECURITY
static bool otm_confirm_handler_test(void)
{
    return true;
}
static void
rpk_cpubkey_and_token_handler(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token,
                              int *token_len)
{
    return;
}
static void
rpk_priv_key_handler(uint8_t *priv_key, int *priv_key_len)
{
    return;
}
#endif

static void st_status_handler_test(st_status_t status)
{
    if (status == ST_STATUS_WIFI_CONNECTING ||
        status == ST_STATUS_EASY_SETUP_START) {
        st_mutex_lock(mutex);
        st_cond_signal(cv);
        st_mutex_unlock(mutex);
    }
}
static
void *st_manager_func(void *data)
{
    (void)data;
    st_manager_run_loop();
    // st_error_t ret = st_manager_start();
    // EXPECT_EQ(ST_ERROR_NONE, ret);

    return NULL;
}

class TestSTManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            mutex = st_mutex_init();
            cv = st_cond_init();
            reset_storage();
            st_set_device_profile(st_device_def, st_device_def_len);
        }

        virtual void TearDown()
        {
            reset_storage();
            st_cond_destroy(cv);
            st_mutex_destroy(mutex);
            cv = NULL;
            mutex = NULL;
        }
};

TEST_F(TestSTManager, st_manager_initialize)
{
    st_error_t ret = st_manager_initialize();
    EXPECT_EQ(ST_ERROR_NONE, ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_initialize_fail_dueto_callingtwice)
{
    st_error_t ret;
    st_manager_initialize();
    ret=st_manager_initialize();
    EXPECT_EQ(ST_ERROR_STACK_ALREADY_INITIALIZED, ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_start_fail_dueto_excluding_init)
{
    st_error_t st_error_ret = st_manager_start();
    EXPECT_EQ(ST_ERROR_STACK_NOT_INITIALIZED, st_error_ret);
}

TEST_F(TestSTManager, st_manager_start)
{
    st_error_t st_error_ret = st_manager_initialize();
    EXPECT_EQ(ST_ERROR_NONE, st_error_ret);

    st_register_status_handler(st_status_handler_test);
    st_manager_start();
    st_thread_t t = st_thread_create(st_manager_func, "TEST", 0, NULL);

    int ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);
    st_manager_stop();
    st_thread_destroy(t);
    st_manager_stop();
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_reset)
{
    int st_error_ret = st_manager_initialize();
    EXPECT_EQ(ST_ERROR_NONE, st_error_ret);

    st_register_status_handler(st_status_handler_test);
    st_manager_start();
    st_thread_t t = st_thread_create(st_manager_func, "TEST", 0, NULL);
    int ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);

    st_sleep(1);

    st_manager_reset();
    ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);
    st_manager_stop();
    st_thread_destroy(t);
    st_manager_stop();
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_stop_fail_dueto_excluding_init)
{
    st_error_t st_error_ret = st_manager_stop();
    EXPECT_EQ(ST_ERROR_STACK_NOT_INITIALIZED, st_error_ret);
}

TEST_F(TestSTManager, st_manager_stop_fail_dueto_excluding_start)
{
    st_error_t st_error_ret;
    st_manager_initialize();
    st_error_ret = st_manager_stop();
    EXPECT_EQ(ST_ERROR_STACK_NOT_STARTED, st_error_ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_stop_fail_dueto_callingtwice)
{
    st_error_t st_error_ret;

    st_manager_initialize();
    st_register_status_handler(st_status_handler_test);
    st_thread_t t = st_thread_create(st_manager_func, "TEST", 0, NULL);

    test_wait_until(mutex, cv, 5);

    st_manager_stop();
    st_thread_destroy(t);
    st_manager_stop();
    st_error_ret=st_manager_stop();
    EXPECT_EQ(ST_ERROR_STACK_NOT_STARTED, st_error_ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_reset_fail_dueto_excluding_init)
{
    int st_error_ret = st_manager_reset();
    EXPECT_EQ(ST_ERROR_STACK_NOT_INITIALIZED, st_error_ret);
}

TEST_F(TestSTManager, st_manager_deinitialize)
{
    st_error_t st_error_ret;
    st_manager_initialize();
    st_error_ret = st_manager_deinitialize();
    EXPECT_EQ(ST_ERROR_NONE, st_error_ret);
}

TEST_F(TestSTManager, st_manager_deinitialize_fail_dueto_excluding_init)
{
    st_error_t st_error_ret;
    st_error_ret = st_manager_deinitialize();
    EXPECT_EQ(ST_ERROR_STACK_NOT_INITIALIZED,st_error_ret);
}

TEST_F(TestSTManager, st_manager_deinitialize_fail_dueto_callingtwice)
{
    st_error_t st_error_ret;
    st_manager_initialize();
    st_manager_deinitialize();
    st_error_ret = st_manager_deinitialize();
    EXPECT_EQ(ST_ERROR_STACK_NOT_INITIALIZED,st_error_ret);
}

#ifdef OC_SECURITY
TEST_F(TestSTManager, st_register_otm_confirm_handler)
{
    bool ret = st_register_otm_confirm_handler(otm_confirm_handler_test);
    EXPECT_TRUE(ret);
    st_unregister_otm_confirm_handler();
}
#endif

TEST_F(TestSTManager, st_register_status_handler)
{
    bool ret = st_register_status_handler(st_status_handler_test);
    EXPECT_TRUE(ret);
    st_unregister_status_handler();
}

#ifdef OC_SECURITY
TEST_F(TestSTManager, st_register_rpk_handler)
{
    bool ret = st_register_rpk_handler(rpk_cpubkey_and_token_handler,
                                       rpk_priv_key_handler);
    EXPECT_TRUE(ret);
    st_unregister_rpk_handler();
}
#endif