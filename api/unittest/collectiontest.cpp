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
    #include "port/linux/config.h"
    #include "oc_ri.h"
    #include "oc_api.h"
    #include "oc_collection.h"
    #include "oc_endpoint.h"
    #include "util/oc_memb.h" 
    #include "port/oc_connectivity.h"
}
#define RESOURCE_URI "/LightResourceURI"
#define RESOURCE_NAME "roomlights"
#define DEVICE 0

class TestCollection: public testing::Test
{
    protected:
        virtual void SetUp()
        {
        }
        virtual void TearDown()
        {
        }
};

TEST_F(TestCollection, CheckCollectionTest_P)
{
    oc_resource_t *pResource; 
    bool collection;
    pResource = oc_new_resource(NULL, RESOURCE_URI, 1, 0);
    collection = oc_check_if_collection(pResource);
    ASSERT_FALSE(collection);
}

TEST_F(TestCollection, AllocateCollectionTest_P)
{
    oc_collection_t *collection;

    collection = oc_collection_alloc();
    EXPECT_NE(NULL, collection);
}

TEST_F(TestCollection, CollectionFreeTest_P)
{
    oc_collection_t *collection;

    collection = oc_collection_alloc();
    oc_collection_free(collection);
    EXPECT_EQ(NULL, collection);
}

TEST_F(TestCollection, GetCollectionByUriTest_N)
{
    oc_collection_t *collection;
    
    collection = oc_get_collection_by_uri(RESOURCE_URI, strlen(RESOURCE_URI), DEVICE);
    EXPECT_EQ(NULL, collection);
    oc_collection_free(collection);
}

TEST_F(TestCollection, CollectionGetAllTest_N)
{
    oc_collection_t *collection;

    collection = oc_collection_get_all();
    EXPECT_EQ(NULL, collection);
}

TEST_F(TestCollection, NewEndPointTest_P)
{
    oc_endpoint_t *endpoint;

    endpoint = oc_new_endpoint();
    EXPECT_NE(NULL, endpoint);
}

TEST_F(TestCollection, EndpointCompareTest_N)
{
    oc_endpoint_t *endpoint1;
    oc_endpoint_t *endpoint2;
    int endpoint;

    endpoint1 = oc_new_endpoint();
    endpoint2 = oc_new_endpoint();
    endpoint = oc_endpoint_compare(endpoint1, endpoint2);
    EXPECT_EQ(-1, endpoint);
}

TEST_F(TestCollection, EndpointCompareAddressTest_N)
{
    oc_endpoint_t *endpoint1;
    oc_endpoint_t *endpoint2;
    int endpoint;

    endpoint1 = oc_new_endpoint();
    endpoint2 = oc_new_endpoint();
    endpoint = oc_endpoint_compare_address(endpoint1, endpoint2);
    EXPECT_EQ(-1, endpoint);
}



