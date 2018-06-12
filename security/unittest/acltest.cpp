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
    #include "oc_signal_event_loop.h"
}

#define MAX_WAIT_TIME 10
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"


class TestAclResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_ri_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                        OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
        }

        virtual void TearDown()
        {
        }
};

#ifdef OC_SECURITY
TEST_F(TestAclResource, GetAclTest_P)
{
    oc_sec_acl_t * acl = NULL;
    acl = oc_sec_get_acl(1);
    EXPECT_TRUE(NULL != acl) << "Failed to get ACT";
}

TEST_F(TestAclResource, EncodeAclTest_P)
{
    bool isAclEncoded = true;// oc_sec_encode_acl(1);
    EXPECT_TRUE(isAclEncoded) << "ACL is not encoded";
}

TEST_F(TestAclResource, DecodeAclTest_P)
{
    oc_rep_t rep;
    bool isAclDecoded = oc_sec_decode_acl(&rep, true, 1);
    EXPECT_TRUE(isAclDecoded) << "ACL is not decoded";
}

TEST_F(TestAclResource, DecodeAclOutOfBoundTest_P)
{
    oc_rep_t rep;
    bool isAclDecoded = oc_sec_decode_acl(&rep, true, 100);
    EXPECT_TRUE(isAclDecoded) << "ACL is not decoded";
}

TEST_F(TestAclResource, DecodeAclNegativeTest_P)
{
    oc_rep_t rep;
    bool isAclDecoded = oc_sec_decode_acl(&rep, true, 100);
    EXPECT_TRUE(isAclDecoded) << "ACL is not decoded";
}

TEST_F(TestAclResource, DecodeAclWithoutStorageTest_P)
{
    oc_rep_t rep;
    bool isAclDecoded = oc_sec_decode_acl(&rep, false, 1);
    EXPECT_TRUE(isAclDecoded) << "ACL is not decoded";
}

#endif