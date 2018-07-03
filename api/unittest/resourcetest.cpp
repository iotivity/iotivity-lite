/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include <cstdlib>
#include <string>
#include <stdio.h>
#include <gtest/gtest.h>

extern "C" {
    #include "config.h"
    #include "oc_ri.h"
    #include "oc_api.h"
    #include "oc_collection.h"
}
#define OBSERVERPERIODSECONDS_N (0)
#define OBSERVERPERIODSECONDS_P (1)
#define INTERFACE_TYPES (1)
#define DEVICE_COUNT (0)

static bool isCallbackReceived;

class TestResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
        }
        virtual void TearDown()
        {
        }
};

static void onGet(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
        {
            (void)request;
            (void)interface;
            (void)user_data;
            isCallbackReceived = true;
        }

TEST_F(TestResource, NewResource_P)
{
    oc_resource_t *res;
    res = oc_new_resource("roomlights", "/a/light", INTERFACE_TYPES, DEVICE_COUNT);
    EXPECT_EQ(OC_IF_BASELINE, res->interfaces);
    oc_delete_resource(res);
}

TEST_F(TestResource, NewCollectionTest_P)
{
    oc_resource_t *collection;
    collection = oc_new_collection("roomlights","/lights", INTERFACE_TYPES, DEVICE_COUNT);
    EXPECT_EQ(OC_IF_LL, collection->default_interface);
    oc_delete_resource(res);
}

TEST_F(TestResource, AddResource_P)
{
    oc_resource_t *res;
    bool add_resource;
    res = oc_new_resource("roomlights", "/a/light", INTERFACE_TYPES, DEVICE_COUNT);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
    oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
    add_resource = oc_add_resource(res);
    ASSERT_TRUE(add_resource);
    oc_delete_resource(res);
}

TEST_F(TestResource, AddResource_N)
{
    oc_resource_t *res;
    bool add_resource;
    res = oc_new_resource("roomlights", "/a/light", INTERFACE_TYPES, DEVICE_COUNT)
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_N);
    oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
    add_resource = oc_add_resource(res);
    ASSERT_FALSE(add_resource);
    oc_delete_resource(res);
}

TEST_F(TestResource, FreeResourceProperties_P)
{
    oc_resource_t *res;
    res = oc_new_resource("roomlights", "/a/light", INTERFACE_TYPES, DEVICE_COUNT);
    oc_ri_free_resource_properties(res);
    EXPECT_EQ(0,oc_string_len(res->name));
}


TEST_F(TestResource, ProcessBaseLineInTest_P)
{
    oc_resource_t *res;
    res = oc_new_resource("roomlights", "/lights", INTERFACE_TYPES, DEVICE_COUNT)
    oc_process_baseline_interface(res);
    EXPECT_LT(0, oc_string_len(res->name));
    oc_delete_resource(res);
}
