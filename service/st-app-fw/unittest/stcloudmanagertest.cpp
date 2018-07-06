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
    #include "st_resource_manager.h"
    #include "st_store.h"
    #include "es_common.h"
}

static int device_index = 0;
st_store_t *store_info = NULL;
void cloud_manager_handler_test(st_cloud_manager_status_t status){
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
    char *url = "coap://www.samsung.com:5683";
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