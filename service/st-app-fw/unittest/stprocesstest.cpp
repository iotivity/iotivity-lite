/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <gtest/gtest.h>
#include <cstdlib>

#include "st_process.h"

class TestSTProcess: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

static void *
st_process_func(void *data)
{
    (void)data;
    int ret = st_process_start();
    EXPECT_EQ(0, ret);

    return NULL;
}

TEST_F(TestSTProcess, st_process_init)
{
    int ret = st_process_init();
    EXPECT_EQ(0, ret);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_start)
{
    st_process_init();
    st_thread_t t = st_thread_create(st_process_func, "TEST", 0, NULL);
    st_process_stop();
    st_thread_destroy(t);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_stop)
{
    st_process_init();
    st_thread_t t = st_thread_create(st_process_func, "TEST", 0, NULL);
    int ret = st_process_stop();
    EXPECT_EQ(0, ret);
    st_thread_destroy(t);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_already_stopped)
{
    st_process_init();
    st_thread_t t = st_thread_create(st_process_func, "TEST", 0, NULL);
    st_process_stop();
    st_thread_destroy(t);
    int ret = st_process_stop();
    EXPECT_EQ(0, ret);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_destroy)
{
    st_process_init();
    st_thread_t t = st_thread_create(st_process_func, "TEST", 0, NULL);
    st_process_stop();
    st_thread_destroy(t);
    int ret = st_process_destroy();
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTProcess, st_process_destroy_fail)
{
    st_process_init();
    st_thread_t t = st_thread_create(st_process_func, "TEST", 0, NULL);
    int ret = st_process_destroy();
    EXPECT_EQ(-1, ret);
    st_process_stop();
    st_thread_destroy(t);
    st_process_destroy();
}

