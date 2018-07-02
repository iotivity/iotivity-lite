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
    #include "st_data_manager.h"
    #include "st_resource_manager.h"
    #include "oc_api.h"
    #include "oc_ri.h"
    #include "st_port.h"
    #include "oc_signal_event_loop.h"
}

static int device_index = 0;
static bool
resource_handler(oc_request_t *request)
{
    (void)request;
    return true;
}

class TestSTResourceManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

TEST_F(TestSTResourceManager, st_register_resources)
{
    char *uri = "/capability/switch/main/0";
    oc_resource_t *resource = NULL;
    st_data_mgr_info_load();
    int ret = st_register_resources(device_index);
    resource = oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(uri, oc_string(resource->uri));
    st_data_mgr_info_free();
}

TEST_F(TestSTResourceManager, st_register_resource_handler)
{
    int ret = st_register_resource_handler(resource_handler, resource_handler);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTResourceManager, st_register_resource_handler_fail)
{
    int ret = st_register_resource_handler(NULL, NULL);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTResourceManager, st_notify_back)
{
    // Given
    char *uri = "/capability/switch/main/0";
    oc_resource_t *resource = oc_new_resource(NULL, uri, 1, 0);
    oc_resource_bind_resource_type(resource, "core.light");
    oc_add_resource(resource);

    // When
    int ret = st_notify_back(uri);
    oc_delete_resource(resource);

    // Then
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTResourceManager, st_notify_back_fail_null)
{
    // Given
    char *uri = NULL;

    // When
    int ret = st_notify_back(uri);

    // Then
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTResourceManager, st_notify_back_fail)
{
    // Given
    char *uri = "/capability/switch/main/1";

    // When
    int ret = st_notify_back(uri);

    // Then
    EXPECT_EQ(-1, ret);
}