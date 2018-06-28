#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_cloud_manager.h"
    #include "st_resource_manager.h"
    #include "st_store.h"
    #include "es_common.h"
}

static int device_index = 0;
st_store_t *store_info = NULL;
void cloud_manager_handler_test(st_cloud_manager_status_t status){
    (void) status;
}

class TestSTCloudManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};


TEST_F(TestSTCloudManager, st_cloud_manager_start_store_info_fail)
{
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestSTCloudManager, st_cloud_manager_start)
{
    st_store_t *store_info = st_store_get_info();
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    EXPECT_EQ(0, ret);
    st_cloud_manager_stop(0);
}

TEST_F(TestSTCloudManager, st_cloud_manager_check_connection)
{
    char *url = "coap://www.samsung.com:5683";
    oc_string_t ci_server;
    oc_new_string(&ci_server, url, strlen(url));
    int ret = st_cloud_manager_check_connection(&ci_server);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTCloudManager, st_cloud_manager_check_connection_fail)
{
    int ret = st_cloud_manager_check_connection(NULL);
    EXPECT_EQ(-1, ret);
}