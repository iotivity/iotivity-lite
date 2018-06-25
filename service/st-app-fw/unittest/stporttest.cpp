#include <gtest/gtest.h>
#include <cstdlib>
#include <pthread.h>

extern "C"{
    #include "st_port.h"
    #include "st_process.h"
}

st_cond_t cv = NULL;
st_mutex_t st_mutex = NULL;
//static st_process_data_t g_process_data;

static void *thread_test(void *data){
    pthread_mutex_lock((pthread_mutex_t *)st_mutex);
    pthread_cond_wait((pthread_cond_t *)cv, (pthread_mutex_t *)st_mutex);
    st_print_log("thread entered.\n");
    pthread_mutex_unlock((pthread_mutex_t *)st_mutex);
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
            st_mutex_destroy(st_mutex);
            st_cond_destroy(cv);
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
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTPort, st_mutex_init)
{
    st_mutex = st_mutex_init();
    EXPECT_NE(st_mutex, NULL);
}

TEST(TestSTPort_destroy, st_mutex_destroy_O)
{
    st_mutex = st_mutex_init();
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(ret, 0);
}

TEST(TestSTPort_destroy, st_mutex_destroy_X)
{
    st_mutex = NULL;
    int ret = st_mutex_destroy(st_mutex);
    EXPECT_EQ(ret, -1);
}

TEST_F(TestSTPort, st_mutex_lock)
{
    st_mutex = st_mutex_init();
    int ret_lock = st_mutex_lock(st_mutex);
    EXPECT_NE(ret_lock, -1);
    
    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(ret_relock, 16);
}

TEST_F(TestSTPort, st_mutex_unlock)
{
    st_mutex = st_mutex_init();
    st_mutex_lock(st_mutex);
    int ret_unlock = st_mutex_unlock(st_mutex); 
    EXPECT_NE(ret_unlock, -1);
    
    int ret_relock = pthread_mutex_trylock((pthread_mutex_t *)st_mutex);
    EXPECT_EQ(ret_relock, 0);
}

TEST_F(TestSTPort, st_cond_init)
{
    st_mutex = st_mutex_init();
    cv = st_cond_init();
    EXPECT_NE(cv, NULL);
}

TEST(TestSTPort_cond, st_cond_destroy)
{
    cv = st_cond_init();
    int ret = st_cond_destroy(cv);
    EXPECT_EQ(ret, 0);
}

TEST(TestSTPort_cond, st_cond_wait_X)
{
    cv, st_mutex = NULL;
    int ret = st_cond_wait(cv, st_mutex);
    EXPECT_EQ(ret, -1);
}

TEST(TestSTPort_cond, st_cond_timedwait_X)
{
    cv = st_cond_init();
    oc_clock_time_t waiting = 1;
    st_mutex = NULL;
    int ret = st_cond_timedwait(cv, st_mutex, waiting);
    EXPECT_EQ(ret, -1);
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
    int ret = st_cond_signal((pthread_cond_t *)cv);
    pthread_join(tid, 0);
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTPort_Thread, st_thread_create_stacksize_X)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", -1, NULL);
    EXPECT_EQ(ret_thread, NULL);
}

TEST_F(TestSTPort_Thread, st_thread_create_handler_X)
{
    st_thread_t ret_thread = st_thread_create(NULL, "test", -1, NULL);
    EXPECT_EQ(ret_thread, NULL);
}

TEST_F(TestSTPort_Thread, st_thread_destroy_O)
{
    st_thread_t ret_thread = st_thread_create(thread_test, "test", 0, NULL);
    pthread_cond_broadcast((pthread_cond_t *)cv);
    int ret = st_thread_destroy(ret_thread);
    EXPECT_EQ(ret, 0);
}


TEST_F(TestSTPort_Thread, st_thread_destroy_X)
{
    int ret = st_thread_destroy(NULL);
    EXPECT_EQ(ret, -1);
}

TEST_F(TestSTPort_Thread, st_thread_cancel_X)
{
    int ret = st_thread_cancel(NULL);
    EXPECT_EQ(ret, -1);
}

/*
TEST(TestSTPort_cond, st_cond_destroy)
{
    //pthread_t tid;
    //st_mutex = st_mutex_init();
    cv = st_cond_init();
    //pthread_create(&tid, NULL, thread_test,0);
    //sleep(2);
    //pthread_cond_signal((pthread_cond_t *)cv);
    int ret = st_cond_destroy(cv);
    //int ret = pthread_cond_destroy((pthread_cond_t *)cv);
    //st_print_log("loggljdlfj: %d\n", ret);
    EXPECT_EQ(ret, 0);
}*/
