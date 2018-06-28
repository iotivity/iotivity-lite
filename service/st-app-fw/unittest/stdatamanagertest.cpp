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

extern "C"{
    #include "st_data_manager.h"
}

class TestSTDataManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

TEST_F(TestSTDataManager, st_data_mgr_info_load)
{
    int ret = st_data_mgr_info_load();
    EXPECT_EQ(0, ret);
    st_data_mgr_info_free();
}

TEST_F(TestSTDataManager, st_data_mgr_get_spec_info)
{
    st_data_mgr_info_load();
    st_specification_t *ret;
    ret = st_data_mgr_get_spec_info();
    EXPECT_NE(NULL, ret);
    st_data_mgr_info_free();
}

TEST_F(TestSTDataManager, st_data_mgr_get_spec_info_fail)
{
    st_specification_t *ret;
    ret = st_data_mgr_get_spec_info();
    EXPECT_EQ(NULL, ret);
}

TEST_F(TestSTDataManager, st_data_mgr_get_resource_info)
{
    st_data_mgr_info_load();
    st_resource_info_t *ret;
    ret = st_data_mgr_get_resource_info();
    EXPECT_NE(NULL, ret);
    st_data_mgr_info_free();
}

TEST_F(TestSTDataManager, st_data_mgr_get_resource_info_fail)
{
    st_resource_info_t *ret;
    ret = st_data_mgr_get_resource_info();
    EXPECT_EQ(NULL, ret);
}

TEST_F(TestSTDataManager, st_data_mgr_get_rsc_type_info)
{
    st_data_mgr_info_load();
    st_resource_type_t *ret;
    ret = st_data_mgr_get_rsc_type_info("x.com.st.powerswitch");
    EXPECT_NE(NULL, ret);
    st_data_mgr_info_free();
}

TEST_F(TestSTDataManager, st_data_mgr_get_rsc_type_info_fail)
{
    st_resource_type_t *ret;
    ret = st_data_mgr_get_rsc_type_info("x.com.st.powerswitch");
    EXPECT_EQ(NULL, ret);
}