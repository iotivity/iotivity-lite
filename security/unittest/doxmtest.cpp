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
    #include "oc_doxm.h"
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
#define UUID "12345678123412341234123456789012"


class TestDoxmResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_ri_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                        OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            oc_sec_doxm_init();
        }

        virtual void TearDown()
        {
            oc_sec_doxm_free();
        }
};

#ifdef OC_SECURITY
TEST_F(TestDoxmResource, GetDoxmTest_P)
{
    oc_sec_doxm_t *doxm = NULL;
    doxm = oc_sec_get_doxm(1);
    EXPECT_TRUE(NULL != doxm) << "Failed to get Doxm";
}

TEST_F(TestDoxmResource, GetDoxmOutOfBoundTest_N)
{
    oc_sec_doxm_t *doxm = NULL;
    doxm = oc_sec_get_doxm(100);
    EXPECT_TRUE(NULL != doxm) << "Failed to get Doxm";
}

TEST_F(TestDoxmResource, GetDoxmNegativeTest_N)
{
    oc_sec_doxm_t *doxm = NULL;
    doxm = oc_sec_get_doxm(-1);
    EXPECT_TRUE(NULL != doxm) << "Failed to get Doxm";
}

TEST_F(TestDoxmResource, DecodeDoxmTest_P)
{
    oc_rep_t rep;
    memset(&rep, 0, sizeof(oc_rep_t));
    bool isDoxmDecoded = oc_sec_decode_doxm(&rep, false, 1);
    EXPECT_FALSE(isDoxmDecoded) << "DOXM is not decoded";
}

#endif