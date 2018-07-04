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
    int ret = st_fota_set_state(FOTA_STATE_DOWNLOADING);
    st_fota_manager_stop();

    // Then
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_state_fail)
{
    // Given
    st_fota_manager_start();

    // When
    int ret = st_fota_set_state(FOTA_STATE_IDLE);
    st_fota_manager_stop();

    // Then
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_fw_info)
{
    // Given
    char ver[4] = "1.0";
    char uri[23] = "http://www.samsung.com";

    // When
    int ret = st_fota_set_fw_info(ver, uri);

    // Then
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_fw_info_fail)
{
    // Given
    char *ver = NULL;
    char uri[23] = "http://www.samsung.com";

    // When
    int ret = st_fota_set_fw_info(ver, uri);

    // Then
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTFotaManager, st_fota_set_result)
{
    // Given

    // When
    int ret = st_fota_set_result(FOTA_RESULT_SUCCESS);

    // Then
    EXPECT_EQ(0, ret);
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
