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
    #include "oc_core_res.h"
}
#define RESOURCE_URI "/oic/d"
#define DEVICE 0

class TestCollection: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_core_init();
            oc_ri_init();
        }
        virtual void TearDown()
        {
            oc_main_shutdown();
            oc_ri_shutdown();
        }
};

TEST_F(TestCollection, CheckIfCollection_N)
{
    oc_resource_t *col;
    bool chk_collection;

    col = oc_new_collection(NULL, RESOURCE_URI, 1, 0);
    chk_collection = oc_check_if_collection(col);
    EXPECT_EQ(chk_collection, 0);

    oc_delete_collection(col);
}


TEST_F(TestCollection, CheckIfCollection_P)
{
    oc_resource_t *col;
    bool chk_collection;

    col = oc_new_collection(NULL, RESOURCE_URI, 1, 0);
    oc_add_collection(col);
    chk_collection = oc_check_if_collection(col);
    EXPECT_EQ(chk_collection, 1);

    oc_delete_collection(col);
}

TEST_F(TestCollection, CollectionAlloc_P)
{
    oc_collection_t *collection;

    collection = oc_collection_alloc();
    EXPECT_NE(NULL, collection);

    oc_collection_free((oc_collection_t*)collection);
}

TEST_F(TestCollection, GetCollectionByUri_P)
{
    oc_collection_t *collection;
    oc_resource_t *col;

    col = oc_new_collection(NULL, RESOURCE_URI, 1, 0);
    oc_add_collection(col);
    collection = oc_get_collection_by_uri(RESOURCE_URI, strlen(RESOURCE_URI), DEVICE);

    EXPECT_NE(NULL, collection);
    oc_delete_collection(col);
    oc_collection_free(collection);
}

TEST_F(TestCollection, GetCollectionByUri_N)
{
    oc_collection_t *collection;

    collection = oc_get_collection_by_uri(RESOURCE_URI, strlen(RESOURCE_URI), DEVICE);
    EXPECT_EQ(NULL, collection);
    oc_collection_free(collection);
}

TEST_F(TestCollection, NewEndPoint_P)
{
    oc_endpoint_t *endpoint;

    endpoint = oc_new_endpoint();
    EXPECT_NE(NULL, endpoint);
    oc_free_endpoint(endpoint);
}




