/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_api.h"
#include "oc_config.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_store_internal.h"
#include "oc_collection.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "tests/gtest/Device.h"

#include <filesystem>
#include <gtest/gtest.h>

#define ACCESS_TOKEN ("access_token")
#define AUTH_PROVIDER ("auth_provider")
#define CI_SERVER ("ci_server")
#define DEVICE (1234)
#define EXPIRES_IN (5678)
#define REFRESH_TOKEN ("refresh_token")
#define SID ("sid")
#define STATUS (OC_CLOUD_LOGGED_IN)
#define UID ("uid")
#define CPS (OC_CPS_READYTOREGISTER)
#define CLOUD_STORAGE ("storage_cloud")

#define DEFAULT_CLOUD_CIS ("coaps+tcp://127.0.0.1")
#define DEFAULT_CLOUD_SID ("00000000-0000-0000-0000-000000000000")

class TestCloudStore : public testing::Test {
public:
  static oc_cloud_context_t s_context;

  static void validateDefaults(const oc_cloud_store_t *store)
  {
    EXPECT_STREQ(DEFAULT_CLOUD_CIS, oc_string(store->ci_server));
    EXPECT_EQ(nullptr, oc_string(store->auth_provider));
    EXPECT_EQ(nullptr, oc_string(store->uid));
    EXPECT_EQ(nullptr, oc_string(store->access_token));
    EXPECT_EQ(nullptr, oc_string(store->refresh_token));
    EXPECT_STREQ(DEFAULT_CLOUD_SID, oc_string(store->sid));
    EXPECT_EQ(0, store->expires_in);
    EXPECT_EQ(0, store->status);
    EXPECT_EQ(0, store->cps);
  }

#ifdef OC_STORAGE
  static void compareStores(const oc_cloud_store_t *s1,
                            const oc_cloud_store_t *s2)
  {
    EXPECT_STREQ(oc_string(s1->ci_server), oc_string(s2->ci_server));
    EXPECT_STREQ(oc_string(s1->auth_provider), oc_string(s2->auth_provider));
    EXPECT_STREQ(oc_string(s1->uid), oc_string(s2->uid));
    EXPECT_STREQ(oc_string(s1->access_token), oc_string(s2->access_token));
    EXPECT_STREQ(oc_string(s1->refresh_token), oc_string(s2->refresh_token));
    EXPECT_STREQ(oc_string(s1->sid), oc_string(s2->sid));
    EXPECT_EQ(s1->expires_in, s2->expires_in);
    EXPECT_EQ(s1->device, s2->device);
    EXPECT_EQ(s1->cps, s2->cps);
    EXPECT_EQ(s1->status, s2->status);
  }
#endif /* OC_STORAGE */

  static void freeStore(oc_cloud_store_t *store)
  {
    oc_free_string(&store->ci_server);
    oc_free_string(&store->auth_provider);
    oc_free_string(&store->uid);
    oc_free_string(&store->access_token);
    oc_free_string(&store->refresh_token);
    oc_free_string(&store->sid);
  }

  static void SetUpTestCase()
  {
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc_storage_config(CLOUD_STORAGE));
#endif /* OC_STORAGE */
    ASSERT_TRUE(oc::TestDevice::StartServer());
    memset(&s_context, 0, sizeof(s_context));
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#ifdef OC_STORAGE
    EXPECT_EQ(0, oc_storage_reset());
    for (const auto &entry :
         std::filesystem::directory_iterator(CLOUD_STORAGE)) {
      std::filesystem::remove_all(entry.path());
    }
#endif /* OC_STORAGE */
  }

  void SetUp() override
  {
    oc_new_string(&m_store.ci_server, CI_SERVER, strlen(CI_SERVER));
    oc_new_string(&m_store.auth_provider, AUTH_PROVIDER, strlen(AUTH_PROVIDER));
    oc_new_string(&m_store.uid, UID, strlen(UID));
    oc_new_string(&m_store.access_token, ACCESS_TOKEN, strlen(ACCESS_TOKEN));
    oc_new_string(&m_store.refresh_token, REFRESH_TOKEN, strlen(REFRESH_TOKEN));
    oc_new_string(&m_store.sid, SID, strlen(SID));
    m_store.expires_in = EXPIRES_IN;
    m_store.device = DEVICE;
    m_store.cps = CPS;
    m_store.status = STATUS;
  }

  void TearDown() override
  {
    freeStore(&m_store);
#ifdef OC_STORAGE
    for (const auto &entry :
         std::filesystem::directory_iterator(CLOUD_STORAGE)) {
      std::filesystem::remove_all(entry.path());
    }
#endif /* OC_STORAGE */
    oc::TestDevice::Reset();
  }

  oc_cloud_store_t m_store;
};

oc_cloud_context_t TestCloudStore::s_context;

TEST_F(TestCloudStore, dump_async)
{
  cloud_store_dump_async(&m_store);
  oc::TestDevice::PoolEvents(1);

  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  store1.device = m_store.device;
#ifdef OC_STORAGE
  EXPECT_EQ(0, cloud_store_load(&store1));
  compareStores(&m_store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_NE(0, cloud_store_load(&store1));
  validateDefaults(&store1);
#endif /* OC_STORAGE */

  freeStore(&store1);
}

TEST_F(TestCloudStore, load_defaults)
{
  oc_cloud_store_t store;
  memset(&store, 0, sizeof(store));
  EXPECT_NE(0, cloud_store_load(&store));

  validateDefaults(&store);
  freeStore(&store);
}

TEST_F(TestCloudStore, dump)
{
#ifdef OC_STORAGE
  EXPECT_LE(0, cloud_store_dump(&m_store));
#else  /* !OC_STORAGE */
  EXPECT_NE(0, cloud_store_dump(&m_store));
#endif /* OC_STORAGE */
  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  store1.device = m_store.device;
#ifdef OC_STORAGE
  EXPECT_EQ(0, cloud_store_load(&store1));
  compareStores(&m_store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_NE(0, cloud_store_load(&store1));
  validateDefaults(&store1);
#endif /* OC_STORAGE */

  freeStore(&store1);
}
