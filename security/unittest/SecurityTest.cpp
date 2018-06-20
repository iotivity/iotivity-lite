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
#include "gtest/gtest.h"

extern "C" {
    #include "oc_acl.h"
    #include "oc_api.h"
    #include "oc_cred.h"
    #include "oc_doxm.h"
    #include "config.h"
    #include "oc_uuid.h"
    #include "oc_core_res.h"
    #include "oc_ri.h"
    #include "oc_pstat.h"
}
#define DEVICE_MAX_NUM 2
#define INVALID_DEVICE_MAX_NUM 3
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
#define OC_MAX_NUM_DEVICE 2

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
    oc_sec_acl_t *aclist_p;
    aclist = oc_sec_get_acl(DEVICE_MAX_NUM);
    EXPECT_NE(0, aclist_p);
}

TEST_F(TestAclOperational, GetAclTest_N)
{
    oc_sec_acl_t *aclist_n =oc_sec_get_acl(INVALID_BOUND) ;
    EXPECT_EQ(0, aclist_n) << "Failed to get the value from the acl list";
}

TEST_F(TestAclOperational, EncodeAclTest_P)
{
    bool encode_acl =  oc_sec_encode_acl(DEVICE_NUM);
    ASSERT_TRUE(encode_acl) << encode_acl;
}

TEST_F(TestAclOperational, GetCredsTest_P)
{
    oc_sec_creds_t *get_creds =  oc_sec_get_creds(DEVICE_NUM);
    EXPECT_NE(0, get_creds);
}

TEST_F(TestAclOperational, GetDoxmTest_P)
{
    oc_sec_doxm_t *get_doxm =  oc_sec_get_doxm(DEVICE_MAX_NUM);
    EXPECT_NE(0, get_doxm);
}

TEST_F(TestAclOperational, GetDeviceIdTest_P)
{
    oc_uuid_t *deviceuuid =  oc_core_get_device_id(DEVICE_NUM);
    EXPECT_NE(0, deviceuuid->id);

}

TEST_F(TestAclOperational, GetDeviceInfoTest_P)
{
    oc_device_info_t *deviceinfo =  oc_core_get_device_info(DEVICE_NUM);
    EXPECT_NE(0, deviceinfo) << "Properly get the device info";
}

TEST_F(TestAclOperational, GetResourceByIndexTest_P)
{
    oc_resource_t *res_index =  oc_core_get_resource_by_index(OCF_CON,DEVICE_MAX_NUM);
    EXPECT_NE(0, res_index);
}

TEST_F(TestAclOperational, InitPlatformP)
{
  int _init_plat = oc_init_platform("Samsung", NULL, NULL);
  EXPECT_EQ(0, init_plat);
}

TEST_F(TestAclOperational, GetConRes_P)
{
    bool announce = true;
    oc_set_con_res_announced(announce);
    bool get_con_announce = oc_get_con_res_announced();
    ASSERT_TRUE(get_announce)<<get_con_announce;
  }