/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <gtest/gtest.h>
#include <cstdlib>

#include "oc_api.h"
#include "st_manager.h"
#include "st_store.h"
#include "st_cloud_manager.h"
#include <oc_random.h>

static void
signal_event_loop(void)
{
}

static int
app_init(void)
{
  int ret = oc_init_platform("Samsung", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

class TestSTStore: public testing::Test
{
    protected:
        oc_handler_t handler = {.init = app_init,
                            .signal_event_loop = signal_event_loop,
                            .register_resources = NULL };

        virtual void SetUp()
        {
            oc_main_init(&handler);

        }

        virtual void TearDown()
        {
            st_store_info_initialize();
            oc_main_shutdown();
        }
};

#ifdef OC_SECURITY
TEST_F(TestSTStore, st_store_load)
{
    int ret = st_store_load();
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTStore, st_store_dump)
{
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
#endif /* OC_SECURITY */