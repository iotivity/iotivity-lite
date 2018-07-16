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
    #include "oc_api.h"
    #include "oc_ri.h"
 }
#define RESOURCE_URI "/LightResourceURI"
#define RESOURCE_NAME "roomlights"

class TestRetroIntrospection: public testing::Test
{
    protected:
        virtual void SetUp()
        {
        }
        virtual void TearDown()
        {
        }
};

TEST_F(TestRetroIntrospection, RiGetAppResource_N)
{
    oc_resource_t *res;

    res = oc_ri_get_app_resources();
    EXPECT_EQ(0, res);
}

TEST_F(TestRetroIntrospection, RiAllocResource_P)
{
    oc_resource_t *res;

    res = oc_ri_alloc_resource();
    EXPECT_NE(0, res);
}

TEST_F(TestRetroIntrospection, RiFreeResourceProperties_P)
{
    oc_resource_t *res;

    res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
    oc_ri_free_resource_properties(res);
    EXPECT_EQ(0,oc_string_len(res->name));
    oc_delete_resource(res);
}


