/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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
#include "gtest/gtest.h"

extern "C" {
    #include "oc_acl.h"
    #include "oc_api.h"
    #include "oc_cred.h"
    #include "oc_doxm.h"
    #include <config.h>
}

#define DEVICE_MAX_NUM 2
#define INVALID_BOUND 3
#define DEVICE_NUM 1
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"


class TestAclOperational: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            
            oc_sec_acl_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                          OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
        }

        virtual void TearDown()
        {
        }
};

TEST_F(TestAclOperational, GetAclTest_P)
{
    oc_sec_acl_t *aclist;
    aclist = oc_sec_get_acl(DEVICE_MAX_NUM);
    EXPECT_NE(0, aclist) << "Able to get the value from the acl list";
}

TEST_F(TestAclOperational, GetAclTest_N)
{
    oc_sec_acl_t *errorCode_More =oc_sec_get_acl(INVALID_BOUND) ;
    EXPECT_NE(0, errorCode_More) << "Failed to get the value from the acl list";
}

TEST_F(TestAclOperational, EncodeAclTest_P)
{
    bool errorCode_false =  oc_sec_encode_acl(DEVICE_NUM);
    EXPECT_EQ(true, errorCode_false) << "Properly Encode the subject of the device";
}

TEST_F(TestAclOperational, GetCredsTest_P)
{
    oc_sec_creds_t *errorCode_false =  oc_sec_get_creds(DEVICE_NUM);
    std::cout << errorCode_false->rowneruuid.id;
    EXPECT_NE(0, errorCode_false) << "Properly Encode the subject of the device";
}

TEST_F(TestAclOperational, GetDoxmTest_P)
{
    oc_sec_doxm_t *errorCode_false =  oc_sec_get_doxm(DEVICE_MAX_NUM);
    EXPECT_NE(0, errorCode_false) << "Properly Encode the subject of the device";
}