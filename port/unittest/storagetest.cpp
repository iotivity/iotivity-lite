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
    #include "port/oc_storage.h"
    #include "config.h"
    #include "oc_ri.h"
    #include "oc_api.h"
    #include "oc_collection.h"
}

#define STORAGE_CONFIG "./simpleserver_creds"
/* ./simple_len_cert folder is not exist */
#define STORAGE_CONFIG_N "./simple_len_cert"
static uint8_t buf[OC_MAX_APP_DATA_SIZE] = "AAFFBB";
static uint8_t buf2[OC_MAX_APP_DATA_SIZE] = "";
static bool s_isCallbackReceived;

class TestStorage: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_storage_config(STORAGE_CONFIG);
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


TEST_F(TestStorage, StorageConfigTest_P)
{
    int ret = oc_storage_config(STORAGE_CONFIG);
    EXPECT_EQ(0, ret);
}

TEST_F(TestStorage, StorageConfigTest_N)
{
    int ret = oc_storage_config("NEGATIVE_TEST_CASE_FOR_STORAGE_CONFIG_NEGATIVE_TEST_CASE_FOR_STORAGE_CONFIG_NEGATIVE");
    ASSERT_EQ(-ENOENT, ret);
}

TEST_F(TestStorage, StorageWriteRead_P)
{
    oc_storage_write(STORAGE_CONFIG, buf, OC_MAX_APP_DATA_SIZE);
    oc_storage_read(STORAGE_CONFIG, buf2, OC_MAX_APP_DATA_SIZE);
    EXPECT_EQ(0,strcmp(buf,buf2));
}

TEST_F(TestStorage, StorageWriteRead_N)
{
    long ret_write = oc_storage_write(STORAGE_CONFIG_N, buf, OC_MAX_APP_DATA_SIZE);
    EXPECT_EQ(-EINVAL, ret_write);
    long ret_read = oc_storage_read(STORAGE_CONFIG_N, buf2, OC_MAX_APP_DATA_SIZE);
    EXPECT_EQ(-EINVAL, ret_read)<< "Invalid Folder able to read and write";
}

TEST_F(TestStorage, NewResource_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
    EXPECT_EQ(OC_IF_BASELINE, s_pResource->interfaces);
}

TEST_F(TestStorage, NewCollectionTest_P)
{
    oc_resource_t *collection = oc_new_collection("roomlights","/lights", 1, 0);
    EXPECT_EQ(OC_IF_LL, collection->default_interface);
}

TEST_F(TestStorage, Add_Resource_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
                  oc_resource_set_discoverable(s_pResource, true);
                  oc_resource_set_periodic_observable(s_pResource, 1);
                  oc_resource_set_request_handler(s_pResource, OC_GET, onGet, NULL);
             bool add_resource = oc_add_resource(s_pResource);
             ASSERT_TRUE(add_resource);
}

TEST_F(TestStorage, Add_Resource_N)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
                  oc_resource_set_discoverable(s_pResource, true);
                  oc_resource_set_periodic_observable(s_pResource, 0);
                  oc_resource_set_request_handler(s_pResource, OC_GET, onGet, NULL);
             bool add_resource = oc_add_resource(s_pResource);
             ASSERT_FALSE(add_resource);
}

TEST_F(TestStorage, CollectionGetLinkTest_P)
{
    oc_resource_t *collection =  oc_new_collection("roomlights","/lights", 1, 0);
    oc_link_t *get_links = oc_collection_get_links(collection);
    EXPECT_EQ(NULL,get_links);
}

TEST_F(TestStorage, Free_Resource_Propertie_P)
{
    oc_resource_t *s_pResource = oc_new_resource("roomlights", "/a/light", 1, 0);
    oc_ri_free_resource_properties(s_pResource);
    EXPECT_EQ(0,oc_string_len(s_pResource->name));
}


