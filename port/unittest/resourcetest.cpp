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
static bool s_isCallbackReceived;

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
            s_isCallbackReceived = true;
        }

TEST_F(TestResource, NewResource_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
    EXPECT_EQ(OC_IF_BASELINE, s_pResource->interfaces);
}

TEST_F(TestResource, NewCollectionTest_P)
{
    oc_resource_t *collection = oc_new_collection("roomlights","/lights", 1, 0);
    EXPECT_EQ(OC_IF_LL, collection->default_interface);
}

TEST_F(TestResource, Add_Resource_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
                  oc_resource_set_discoverable(s_pResource, true);
                  oc_resource_set_periodic_observable(s_pResource, 1);
                  oc_resource_set_request_handler(s_pResource, OC_GET, onGet, NULL);
             bool add_resource = oc_add_resource(s_pResource);
             ASSERT_TRUE(add_resource);
}

TEST_F(TestResource, Add_Resource_N)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
                  oc_resource_set_discoverable(s_pResource, true);
                  oc_resource_set_periodic_observable(s_pResource, 0);
                  oc_resource_set_request_handler(s_pResource, OC_GET, onGet, NULL);
             bool add_resource = oc_add_resource(s_pResource);
             ASSERT_FALSE(add_resource);
}

TEST_F(TestResource, CollectionGetLinkTest_P)
{
    oc_resource_t *collection =  oc_new_collection("roomlights","/lights", 1, 0);
    oc_link_t *get_links = oc_collection_get_links(collection);
    EXPECT_EQ(NULL,get_links);
}

TEST_F(TestResource, Free_Resource_Propertie_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
    oc_ri_free_resource_properties(s_pResource);
    EXPECT_EQ(0,oc_string_len(s_pResource->name));
}
