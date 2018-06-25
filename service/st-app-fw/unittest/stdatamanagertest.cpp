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