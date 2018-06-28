#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_manager.h"
    #include "st_process.h"
    #include "st_port.h"
    void st_manager_quit(void);
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
    EXPECT_EQ(0, ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_quit)
{
    st_manager_quit();
}

#ifdef OC_SECURITY
TEST_F(TestSTManager, st_register_otm_confirm_handler)
{
    bool ret = st_register_otm_confirm_handler(otm_confirm_handler_test);
    EXPECT_EQ(true, ret);
    st_unregister_otm_confirm_handler();
}
#endif

TEST_F(TestSTManager, st_register_status_handler)
{
    bool ret = st_register_status_handler(st_status_handler_test);
    EXPECT_EQ(true, ret);
    st_unregister_status_handler();
}