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
    #include "oc_core_res.h"
    #include "oc_api.h"
    #include "oc_helpers.h"
    #include "oc_uuid.h"
 }
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"
#define RESOURCE_URI "/LightResourceURI"
static int numcoredevice;
static oc_device_info_t *addcoredevice;

class TestCoreResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
        }
        virtual void TearDown()
        {
            oc_core_init();
        }
};

TEST_F(TestCoreResource, NewResourceTest_P)
{
    int oc_platform_info;
    oc_platform_info = oc_init_platform("Apple", NULL, NULL);
    EXPECT_EQ(0, oc_platform_info);
}

TEST_F(TestCoreResource, NewCoreResourceTest_P)
{
    oc_platform_info_t *oc_platform_info;
    oc_platform_info = oc_core_init_platform("Apple", NULL, NULL);
    std::cout<< oc_string_len(oc_platform_info->mfg_name);
    std::cout << "\n";
    EXPECT_NE(0, oc_string_len(oc_platform_info->mfg_name));
}

TEST_F(TestCoreResource, AddNewCoreResourceNameTest_P1)
{
    
    addcoredevice = oc_core_add_new_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                          OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
    numcoredevice = oc_core_get_num_devices();
    EXPECT_NE(0, oc_string_len(addcoredevice->name));
}

TEST_F(TestCoreResource, CoreGetNumDevicesTest_P)
{
    EXPECT_EQ(1, numcoredevice);
}

