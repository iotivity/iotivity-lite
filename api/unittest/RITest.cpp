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
    #include "oc_helpers.h"
 }

#define RESOURCE_URI "/LightResourceURI"
#define RESOURCE_NAME "roomlights"
#define OBSERVERPERIODSECONDS_P 1

class TestOcRi: public testing::Test
{
    protected:
        virtual void SetUp()
        {
          oc_ri_init();
        }
        virtual void TearDown()
        {
          oc_ri_shutdown();
        }
};

static void onGet(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
        (void)request;
        (void)interface;
        (void)user_data;
}

TEST_F(TestOcRi, GetAppResourceByUriTest_P)
{
    oc_resource_t *res;
    oc_resource_t *res1;

    res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
    oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
    oc_ri_add_resource(res);

    res1 = oc_ri_get_app_resource_by_uri(RESOURCE_URI, strlen(RESOURCE_URI),0);
    EXPECT_NE(res1, NULL);
    oc_ri_delete_resource(res);
    oc_ri_delete_resource(res1);
}


TEST_F(TestOcRi, GetAppResourceByUriTest_N)
{
    oc_resource_t *res1;

    res1 = oc_ri_get_app_resource_by_uri(RESOURCE_URI, strlen(RESOURCE_URI),0);
    EXPECT_EQ(res1, NULL);
}

TEST_F(TestOcRi, RiGetAppResourceTest_P)
{
    oc_resource_t *res;
    oc_resource_t *res1;

    res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
    oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
    oc_ri_add_resource(res);
    res1 = oc_ri_get_app_resources();
    EXPECT_NE(0, res1);
    oc_delete_resource(res);
    oc_ri_delete_resource(res1);

}

TEST_F(TestOcRi, RiGetAppResourceTest_N)
{
    oc_resource_t *res;

    res = oc_ri_get_app_resources();
    EXPECT_EQ(0, res);
}

TEST_F(TestOcRi, RiAllocResourceTest_P)
{
    oc_resource_t *res;

    res = oc_ri_alloc_resource();
    EXPECT_NE(0, res);
    oc_ri_delete_resource(res);
}

TEST_F(TestOcRi, RiDeleteResourceTest_P)
{
    oc_resource_t *res;
    bool del_check;

    res = oc_ri_alloc_resource();
    del_check = oc_ri_delete_resource(res);
    ASSERT_TRUE(del_check);
}

TEST_F(TestOcRi, RiFreeResourcePropertiesTest_P)
{
    oc_resource_t *res;

    res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
    oc_ri_free_resource_properties(res);
    EXPECT_EQ(0,oc_string_len(res->name));
}

TEST_F(TestOcRi, RiAddResourceTest_P)
{
    oc_resource_t *res;
    bool res_check;

    res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
    oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
    res_check = oc_ri_add_resource(res);
    ASSERT_TRUE(res_check);
    oc_ri_delete_resource(res);
}
