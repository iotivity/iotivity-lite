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
#include <string>
#include <gtest/gtest.h>

extern "C" {
    #include "port/oc_clock.h"
}

class TestClock: public testing::Test
{
    protected:
        virtual void SetUp()
        {
        }

        virtual void TearDown()
        {
        }
};

TEST_F(TestClock, oc_clock_time)
{
    oc_clock_time_t timestamp = oc_clock_time();
    EXPECT_NE(0, timestamp);
}

TEST_F(TestClock, oc_clock_seconds)
{
    long time_seconds = oc_clock_seconds();
    EXPECT_NE(0, time_seconds);
}

TEST_F(TestClock, oc_clock_wait)
{
    oc_clock_time_t wait_time = 1 * (OC_CLOCK_SECOND / 1000);
    oc_clock_time_t prev_stamp = oc_clock_time();
    oc_clock_wait(wait_time);
    oc_clock_time_t cur_stamp = oc_clock_time();

    int seconds = (cur_stamp - prev_stamp) / OC_CLOCK_SECOND;
    EXPECT_EQ(1, seconds);
}
