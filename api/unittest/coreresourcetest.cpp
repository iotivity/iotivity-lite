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

#include "oc_core_res.h"
#include "oc_api.h"
#include "oc_helpers.h"

#define DEVICE_URI "/oic/d"
#define DEVICE_TYPE "oic.d.light"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

class TestCoreResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_core_init();
            oc_random_init();
        }
        virtual void TearDown()
        {
            oc_core_shutdown();
            oc_random_destroy();
        }
};

TEST_F(TestCoreResource, InitPlatform_P)
{
    int oc_platform_info;

    oc_platform_info = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
    EXPECT_EQ(0, oc_platform_info);
}

TEST_F(TestCoreResource, CoreInitPlatform_P)
{
    oc_platform_info_t *oc_platform_info;

    oc_platform_info = oc_core_init_platform(MANUFACTURER_NAME, NULL, NULL);
    EXPECT_EQ(strlen(MANUFACTURER_NAME), oc_string_len(oc_platform_info->mfg_name));
}

TEST_F(TestCoreResource, CoreDevice_P)
{
    int numcoredevice;
    oc_device_info_t *addcoredevice;

    addcoredevice = oc_core_add_new_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                          OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
    ASSERT_NE(addcoredevice, NULL);
    numcoredevice = oc_core_get_num_devices();
    EXPECT_EQ(1, numcoredevice);
    oc_connectivity_shutdown(0);
}

TEST_F(TestCoreResource, CoreGetResource_P)
{
    oc_core_init_platform(MANUFACTURER_NAME, NULL, NULL);

    char uri[] = "/oic/p";
    oc_resource_t *res = oc_core_get_resource_by_uri(uri, 0);

    ASSERT_NE(res, NULL);
    EXPECT_EQ(strlen(uri), oc_string_len(res->uri));
}
