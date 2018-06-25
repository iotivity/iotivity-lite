#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_manager.h"
    #include "st_store.h"
    #include "st_cloud_manager.h"
}

class TestSTStore: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            
        }

        virtual void TearDown()
        {
            st_store_info_initialize();
        }
};

TEST_F(TestSTStore, st_store_load)
{
    int ret = st_store_load();
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTStore, st_store_dump)
{
    st_manager_initialize();
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    st_store_dump();
    st_store_info_initialize();
    st_store_load();

    EXPECT_EQ(store_info->status, true);
    st_process_start();
    st_process_stop();
    st_process_destroy();
    st_port_specific_destroy();
}

TEST_F(TestSTStore, st_store_info_initialize)
{
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    st_store_info_initialize();
    
    EXPECT_EQ(store_info->status, false);
}

TEST_F(TestSTStore, st_store_get_info)
{
    st_store_t *store_info = NULL;
    store_info = st_store_get_info();
    EXPECT_NE(store_info, NULL);
}