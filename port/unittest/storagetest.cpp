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
    #include <config.h>
    }
    
#define SVR_TAG_MAX (32)
#define SVR_TAG_N_MAX (100)
#define STORAGE_CONFIG_LONG "./IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices_IOTIVITY_CONSTRAINED_LITE_Sample_Test_devices"
#define STORAGE_CONFIG "./simpleserver_creds"
#define STORAGE_CONFIG_N "./simple_len_sert"
uint8_t buf[OC_MAX_APP_DATA_SIZE] = "uuuuuu";
uint8_t buf2[OC_MAX_APP_DATA_SIZE] = "0000000000000000000000000000";
char svr_tag[SVR_TAG_MAX];

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

TEST(TestStorage_config, StorageConfigTest_P)
{
    int ret = oc_storage_config(STORAGE_CONFIG);
    EXPECT_EQ(0, ret);
}

TEST(TestStorage_config, StorageConfigTest_N)
{
    int ret = oc_storage_config("./Sample_Test_device_exceeds_more_than_defined_64bit_to_mkae_the_test_fail");
    ASSERT_EQ(-ENOENT, ret);
}

TEST_F(TestStorage, StorageReadWrite_P)
{  
    long ret = oc_storage_write(STORAGE_CONFIG, buf, OC_MAX_APP_DATA_SIZE);
    EXPECT_NE(0, ret);
    long ret1 = oc_storage_read(STORAGE_CONFIG, buf2, OC_MAX_APP_DATA_SIZE);
    EXPECT_NE(0, ret1);
}

TEST_F(TestStorage, StorageReadWrite_N)
{  
    long ret = oc_storage_write(STORAGE_CONFIG_N, buf, OC_MAX_APP_DATA_SIZE);
    EXPECT_EQ(-EINVAL, ret);
    long ret1 = oc_storage_read(STORAGE_CONFIG_N, buf2, OC_MAX_APP_DATA_SIZE);
    EXPECT_EQ(-EINVAL, ret1);
}