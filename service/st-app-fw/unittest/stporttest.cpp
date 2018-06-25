#include <gtest/gtest.h>
#include <cstdlib>
#include <pthread.h>

extern "C"{
    #include "st_port.h"
    #include "st_process.h"
    #include "st_manager.h"
}

st_cond_t cv = NULL;
st_mutex_t st_mutex = NULL;

static void *thread_test(void *data){
    st_mutex_lock(st_mutex);
    st_cond_wait(cv, st_mutex);
    st_print_log("thread_test Entered.\n");
    st_mutex_unlock(st_mutex);
    pthread_exit(NULL);
    return NULL;
}

class TestSTPort: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

class TestSTPort_Thread: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            st_mutex = st_mutex_init();
            cv = st_cond_init();
        }

        virtual void TearDown()
        {
            st_mutex_destroy(st_mutex);
            st_cond_destroy(cv);
        }
};

TEST_F(TestSTPort, st_port_specific_init)
{
    int ret = st_port_specific_init();
    EXPECT_EQ(0, ret);
    st_port_specific_destroy();
}

TEST_F(TestSTPort, st_mutex_init)
{
    st_mutex = st_mutex_init();
    EXPECT_NE(NULL, st_mutex);
    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_mutex_destroy)
{
    st_mutex = st_mutex_init();
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort, st_mutex_destroy_fail)
{
    st_mutex = NULL;
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_mutex_lock)
{
    st_mutex = st_mutex_init();
    int ret_lock = st_mutex_lock(st_mutex);
    EXPECT_NE(-1, ret_lock);

    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(16, ret_relock);

    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_mutex_unlock)
{
    st_mutex = st_mutex_init();
    st_mutex_lock(st_mutex);
    int ret_unlock = st_mutex_unlock(st_mutex);
    EXPECT_NE(-1, ret_unlock);

    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(0, ret_relock);

    st_mutex_destroy(st_mutex);
}

TEST_F(TestSTPort, st_cond_init)
{
    cv = st_cond_init();
    EXPECT_NE(NULL, cv);
    st_cond_destroy(cv);
}

TEST_F(TestSTPort, st_cond_destroy)
{
    cv = st_cond_init();
    int ret = st_cond_destroy(cv);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort, st_cond_wait_fail)
{
    cv, st_mutex = NULL;
    int ret = st_cond_wait(cv, st_mutex);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_cond_timedwait_fail)
{
    cv = st_cond_init();
    oc_clock_time_t waiting = 1;
    st_mutex = NULL;
    int ret = st_cond_timedwait(cv, st_mutex, waiting);
    EXPECT_EQ(-1, ret);
    st_cond_signal(cv);
    st_cond_destroy(cv);
}

TEST_F(TestSTPort, st_cond_signal)
{
    pthread_t tid;
    st_mutex = st_mutex_init();
    cv = st_cond_init();
    pthread_create(&tid, NULL, thread_test, 0);
    sleep(1);
    int ret = st_cond_signal(cv);
    int ret_join = pthread_join(tid, 0);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, ret_join);
}

TEST_F(TestSTPort_Thread, st_thread_create_stacksize_fail)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", -1, NULL);
    EXPECT_EQ(NULL, ret_thread);
}

TEST_F(TestSTPort_Thread, st_thread_create_handler_fail)
{
    st_thread_t ret_thread = st_thread_create(NULL, "test", -1, NULL);
    EXPECT_EQ(NULL, ret_thread);
}

TEST_F(TestSTPort_Thread, st_thread_destroy_O)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", 0, NULL);
    sleep(1);
    pthread_cond_broadcast((pthread_cond_t *)cv);
    int ret = st_thread_destroy(ret_thread);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTPort_Thread, st_thread_destroy_fail)
{
    int ret = st_thread_destroy(NULL);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort_Thread, st_thread_cancel_fail)
{
    int ret = st_thread_cancel(NULL);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTPort, st_free_wifi_scan_list)
{
    st_wifi_ap_t *ap_test =  (st_wifi_ap_t*) calloc(1, sizeof(st_wifi_ap_t));
    int len = 7;
    ap_test->ssid = (char*) calloc(len+1, sizeof(char));
    strncpy(ap_test->ssid, "abcdefg", len);
    st_free_wifi_scan_list(ap_test);

    EXPECT_STRNE("abcdefg", ap_test->ssid);
}