#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_process.h"
}

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

TEST_F(TestSTProcess, st_process_init)
{
    int ret = st_process_init();
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTProcess, st_process_start)
{
    st_process_init();
    int ret = st_process_start();
    EXPECT_EQ(ret, 0);
    st_process_stop();
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_stop_O)
{
    st_process_init();
    st_process_start();
    int ret = st_process_stop();
    EXPECT_EQ(ret, 0);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_stop_X)
{
    st_process_init();
    st_process_start();
    st_process_stop();
    int ret = st_process_stop();
    EXPECT_EQ(ret, -1);
    st_process_destroy();
}

TEST_F(TestSTProcess, st_process_destroy_O)
{
    st_process_init();
    st_process_start();
    st_process_stop();
    int ret = st_process_destroy();
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTProcess, st_process_destroy_X)
{
    st_process_init();
    st_process_start();
    int ret = st_process_destroy();
    EXPECT_EQ(ret, -1);
    st_process_stop();
    st_process_destroy();
}

