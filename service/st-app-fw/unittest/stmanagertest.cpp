#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_manager.h"
    #include "st_process.h"
    #include "st_port.h"
}

static bool otm_confirm_handler_test(void){}
static void st_status_handler_test(st_status_t status)
{
    (void)status;
}

class TestSTManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            
        }

        virtual void TearDown()
        {
        
        }
};

TEST_F(TestSTManager, st_manager_initialize)
{
    int ret = st_manager_initialize();
    EXPECT_EQ(ret, 0);
    st_process_start();
    st_process_stop();
    st_process_destroy();
    st_port_specific_destroy();
}

TEST_F(TestSTManager, st_register_otm_confirm_handler)
{
    bool ret = st_register_otm_confirm_handler(otm_confirm_handler_test);
    EXPECT_EQ(ret, true);
    st_unregister_otm_confirm_handler();
}

TEST_F(TestSTManager, st_register_status_handler)
{
    bool ret = st_register_status_handler(st_status_handler_test);
    EXPECT_EQ(ret, true);
    st_unregister_status_handler();
}