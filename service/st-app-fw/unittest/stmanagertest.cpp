#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_manager.h"
    #include "st_process.h"
    #include "st_port.h"
    #include "sttestcommon.h"
    void st_manager_quit(void);
}

static st_mutex_t mutex = NULL;
static st_cond_t cv = NULL;

#ifdef OC_SECURITY
static bool otm_confirm_handler_test(void){}
#endif
static void st_status_handler_test(st_status_t status)
{
    if (status == ST_STATUS_EASY_SETUP_DONE ||
        status == ST_STATUS_EASY_SETUP_PROGRESSING) {
        st_mutex_lock(mutex);
        st_cond_signal(cv);
        st_mutex_unlock(mutex);
    }
}
static
void *st_manager_func(void *data)
{
    (void)data;
    int ret = st_manager_start();
    EXPECT_EQ(0, ret);

    return NULL;
}

class TestSTManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            mutex = st_mutex_init();
            cv = st_cond_init();
            reset_storage();
        }

        virtual void TearDown()
        {
            reset_storage();
            st_cond_destroy(cv);
            st_mutex_destroy(mutex);
            cv = NULL;
            mutex = NULL;
        }
};

TEST_F(TestSTManager, st_manager_initialize)
{
    int ret = st_manager_initialize();
    EXPECT_EQ(0, ret);
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_start)
{
    int ret = st_manager_initialize();
    EXPECT_EQ(0, ret);

    st_register_status_handler(st_status_handler_test);
    st_thread_t t = st_thread_create(st_manager_func, "TEST", 0, NULL);

    ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);
    st_manager_quit();
    st_thread_destroy(t);
    st_manager_stop();
    st_manager_deinitialize();
}

TEST_F(TestSTManager, st_manager_reset)
{
    int ret = st_manager_initialize();
    EXPECT_EQ(0, ret);

    st_register_status_handler(st_status_handler_test);
    st_thread_t t = st_thread_create(st_manager_func, "TEST", 0, NULL);
    ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);

    st_sleep(1);

    st_manager_reset();
    ret = test_wait_until(mutex, cv, 5);
    EXPECT_EQ(0, ret);
    st_manager_quit();
    st_thread_destroy(t);
    st_manager_stop();
    st_manager_deinitialize();
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