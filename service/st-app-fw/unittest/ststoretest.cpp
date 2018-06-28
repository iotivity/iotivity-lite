#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_manager.h"
    #include "st_store.h"
    #include "st_cloud_manager.h"
    #include "port/oc_storage.h"
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
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTStore, st_store_dump)
{
    oc_storage_config("./st_things_creds");
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    oc_new_string(&store_info->accesspoint.ssid, "ssid", strlen("ssid"));
    oc_new_string(&store_info->accesspoint.pwd, "pwd", strlen("pwd"));
    oc_new_string(&store_info->cloudinfo.ci_server, "ci_server", strlen("ci_server"));
    oc_new_string(&store_info->cloudinfo.auth_provider, "auth_provider", strlen("auth_provider"));
    oc_new_string(&store_info->cloudinfo.uid, "uid", strlen("uid"));
    oc_new_string(&store_info->cloudinfo.access_token, "access_token", strlen("access_token"));
    oc_new_string(&store_info->cloudinfo.refresh_token, "refresh_token", strlen("refresh_token"));
    st_store_dump();
    st_store_info_initialize();
    st_store_load();

    EXPECT_TRUE(store_info->status);
}

TEST_F(TestSTStore, st_store_dump_async)
{
    st_store_dump_async();
}

TEST_F(TestSTStore, st_store_info_initialize)
{
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    st_store_info_initialize();

    EXPECT_FALSE(store_info->status);
}

TEST_F(TestSTStore, st_store_get_info)
{
    st_store_t *store_info = NULL;
    store_info = st_store_get_info();
    EXPECT_NE(NULL, store_info);
}