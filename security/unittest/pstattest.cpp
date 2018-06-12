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
    #include "oc_pstat.h"
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


class TestPstatResource: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_ri_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                        OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            oc_sec_pstat_init();
        }

        virtual void TearDown()
        {
            oc_sec_pstat_free();
        }
};

#ifdef OC_SECURITY
TEST_F(TestPstatResource, GetPstatTest_P)
{
    oc_sec_pstat_t *pstat = NULL;
    pstat = oc_sec_get_pstat(1);
    EXPECT_TRUE(NULL != pstat) << "Failed to get Pstat";
}

TEST_F(TestPstatResource, GetPstatOutOfBoundTest_N)
{
    oc_sec_pstat_t *pstat = NULL;
    pstat = oc_sec_get_pstat(100);
    EXPECT_TRUE(NULL != pstat) << "Failed to get Pstat";
}

TEST_F(TestPstatResource, GetPstatNegativeTest_N)
{
    oc_sec_pstat_t *pstat = NULL;
    pstat = oc_sec_get_pstat(-1);
    EXPECT_TRUE(NULL != pstat) << "Failed to get Pstat";
}

TEST_F(TestPstatResource, DecodePstatTest_P)
{
    oc_rep_t rep;
    memset(&rep, 0, sizeof(oc_rep_t));
    bool isPstatDecoded = oc_sec_decode_pstat(&rep, false, 1);
    EXPECT_FALSE(isPstatDecoded) << "DOXM is not decoded";
}

TEST_F(TestPstatResource, PstatOperationalTest_N)
{
    bool isOperational = oc_sec_is_operational(0);
    EXPECT_FALSE(isOperational) << "Failed to get Pstat";
}

#endif