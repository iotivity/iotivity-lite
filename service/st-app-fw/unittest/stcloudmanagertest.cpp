#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_cloud_manager.h"
    #include "st_resource_manager.h"
    #include "st_store.h"
    #include "es_common.h"
}

static int device_index = 0;
typedef void (*st_cloud_manager_cb_t)(st_cloud_manager_status_t status);
es_enrollee_state en_state = ES_STATE_EOF;
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


TEST_F(TestSTCloudManager, st_cloud_manager_start_store_info_X)
{
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    EXPECT_EQ(ret, -1);
}

TEST_F(TestSTCloudManager, st_cloud_manager_start_O)
{
    st_store_t *store_info = st_store_get_info();
    int ret = st_cloud_manager_start(store_info, device_index, cloud_manager_handler_test);
    EXPECT_EQ(ret, 0);
    st_cloud_manager_stop(0);
}