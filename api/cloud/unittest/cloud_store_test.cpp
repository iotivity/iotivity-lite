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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_collection.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <string_view>

using namespace std::chrono_literals;

static constexpr std::string_view access_token = "access_token";
static constexpr std::string_view auth_provider = "auth_provider";
static constexpr std::string_view ci_server = "ci_server";
static constexpr std::string_view refresh_token = "refresh_token";
static constexpr std::string_view sid = "sid";
static constexpr std::string_view uid = "uid";
static constexpr size_t kDevice = 1234;
static constexpr int64_t kExpiresIn = 5678;
static constexpr oc_cloud_status_t kStatus = OC_CLOUD_LOGGED_IN;
static constexpr oc_cps_t kCps = OC_CPS_READYTOREGISTER;
static constexpr std::string_view kCloudStoragePath = "storage_cloud";

class TestCloudStore : public testing::Test {
public:
  static void clean()
  {
#ifdef OC_STORAGE
    for (const auto &entry :
         std::filesystem::directory_iterator(kCloudStoragePath.data())) {
      std::filesystem::remove_all(entry.path());
    }
#endif /* OC_STORAGE */
  }

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

  static void validateDefaults(const oc_cloud_store_t *store)
  {
    oc_cloud_store_t def{};
    cloud_store_initialize(&def);
    compareStores(&def, store);
    freeStore(&def);
  }

  static oc_cloud_store_t makeStore()
  {
    oc_cloud_store_t store;
    memset(&store, 0, sizeof(store));
    oc_new_string(&store.ci_server, ci_server.data(), ci_server.length());
    oc_new_string(&store.auth_provider, auth_provider.data(),
                  auth_provider.length());
    oc_new_string(&store.uid, uid.data(), uid.length());
    oc_new_string(&store.access_token, access_token.data(),
                  access_token.length());
    oc_new_string(&store.refresh_token, refresh_token.data(),
                  refresh_token.length());
    oc_new_string(&store.sid, sid.data(), sid.length());
    store.expires_in = kExpiresIn;
    store.device = kDevice;
    store.cps = kCps;
    store.status = kStatus;
    return store;
  }

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
    clean();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc_storage_config(kCloudStoragePath.data()));
#endif /* OC_STORAGE */
  }

  static void TearDownTestCase()
  {
#ifdef OC_STORAGE
    EXPECT_EQ(0, oc_storage_reset());
#endif /* OC_STORAGE */
    clean();
  }

  void TearDown() override
  {
    clean();
  }
};

TEST_F(TestCloudStore, Decode_FailUnknownProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, plgd, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_FALSE(cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, Decode_FailUnknownIntProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, plgd, 42);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_FALSE(cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, Decode_FailUnknownStringProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, plgd, "plgd");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_FALSE(cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, LoadDefaults)
{
  oc_cloud_store_t store{};
  EXPECT_FALSE(cloud_store_load(&store));

  validateDefaults(&store);
  freeStore(&store);
}

TEST_F(TestCloudStore, DumpAndLoad)
{
  oc_cloud_store_t store = makeStore();
  ASSERT_LT(0, cloud_store_dump(&store));

  oc_cloud_store_t store2{};
  store2.device = store.device;
  ASSERT_TRUE(cloud_store_load(&store2));
  compareStores(&store, &store2);

  freeStore(&store2);
  freeStore(&store);
}

class TestCloudStoreWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    TestCloudStore::clean();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc_storage_config(kCloudStoragePath.data()));
#endif /* OC_STORAGE */
    ASSERT_TRUE(oc::TestDevice::StartServer());
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#ifdef OC_STORAGE
    EXPECT_EQ(0, oc_storage_reset());
#endif /* OC_STORAGE */
  }

  void SetUp() override
  {
    m_store = TestCloudStore::makeStore();
  }

  void TearDown() override
  {
    TestCloudStore::freeStore(&m_store);
    TestCloudStore::clean();
    oc::TestDevice::Reset();
  }

  oc_cloud_store_t m_store;
};

TEST_F(TestCloudStoreWithServer, DumpAsync)
{
  cloud_store_dump_async(&m_store);
  oc::TestDevice::PoolEventsMsV1(50ms);

  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  store1.device = m_store.device;
#ifdef OC_STORAGE
  ASSERT_TRUE(cloud_store_load(&store1));
  TestCloudStore::compareStores(&m_store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_FALSE(cloud_store_load(&store1));
  TestCloudStore::validateDefaults(&store1);
#endif /* OC_STORAGE */

  TestCloudStore::freeStore(&store1);
}

TEST_F(TestCloudStoreWithServer, Dump)
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
  ASSERT_TRUE(cloud_store_load(&store1));
  TestCloudStore::compareStores(&m_store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_FALSE(cloud_store_load(&store1));
  TestCloudStore::validateDefaults(&store1);
#endif /* OC_STORAGE */

  TestCloudStore::freeStore(&store1);
}
