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
#include "api/oc_event_callback_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_collection.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <map>

using namespace std::chrono_literals;

static constexpr std::string_view access_token = "access_token";
static constexpr std::string_view auth_provider = "auth_provider";
static constexpr std::string_view ci_server = "ci_server";
static constexpr std::string_view refresh_token = "refresh_token";
static constexpr oc_uuid_t sid{ { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
                                  0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                  0xCD, 0xEF } };
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

  static void compareEndpoints(const oc_cloud_endpoints_t &eps1,
                               const oc_cloud_endpoints_t &eps2)
  {
    std::map<std::string, oc_cloud_endpoint_t, std::less<>> e1{};
    std::map<std::string, oc_cloud_endpoint_t, std::less<>> e2{};
    oc_cloud_endpoint_t *eps = nullptr;
    if (eps1.endpoints != nullptr) {
      eps = static_cast<oc_cloud_endpoint_t *>(oc_list_head(eps1.endpoints));
    }
    while (eps != nullptr) {
      e1[oc_string(eps->uri)] = *eps;
      eps = eps->next;
    }
    eps = nullptr;
    if (eps2.endpoints != nullptr) {
      eps = static_cast<oc_cloud_endpoint_t *>(oc_list_head(eps2.endpoints));
    }
    while (eps != nullptr) {
      e2[oc_string(eps->uri)] = *eps;
      eps = eps->next;
    }

    EXPECT_EQ(e1.size(), e2.size());
    if (e1.size() != e2.size()) {
      return;
    }

    for (const auto &[key, value] : e1) {
      auto it = e2.find(key);
      EXPECT_NE(e2.end(), it);
      EXPECT_STREQ(oc_string(value.uri), oc_string(it->second.uri));
      EXPECT_TRUE(oc_uuid_is_equal(value.id, it->second.id));
    }
  }

  static void compareStores(const oc_cloud_store_t *s1,
                            const oc_cloud_store_t *s2)
  {
    compareEndpoints(s1->ci_servers, s2->ci_servers);
    EXPECT_STREQ(oc_string(s1->auth_provider), oc_string(s2->auth_provider));
    EXPECT_STREQ(oc_string(s1->uid), oc_string(s2->uid));
    EXPECT_STREQ(oc_string(s1->access_token), oc_string(s2->access_token));
    EXPECT_STREQ(oc_string(s1->refresh_token), oc_string(s2->refresh_token));
    EXPECT_EQ(s1->expires_in, s2->expires_in);
    EXPECT_EQ(s1->device, s2->device);
    EXPECT_EQ(s1->cps, s2->cps);
    EXPECT_EQ(s1->status, s2->status);
  }

  static void validateDefaults(const oc_cloud_store_t *store)
  {
    oc_cloud_store_t def{};
    oc_cloud_store_initialize(&def, nullptr, nullptr);
    compareStores(&def, store);
    freeStore(&def);
  }

  static oc_cloud_store_t makeStore()
  {
    oc_cloud_store_t store;
    memset(&store, 0, sizeof(store));
    oc_cloud_endpoints_init(
      &store.ci_servers, nullptr, nullptr,
      oc_string_view(ci_server.data(), ci_server.length()), sid);
    oc_new_string(&store.auth_provider, auth_provider.data(),
                  auth_provider.length());
    oc_new_string(&store.uid, uid.data(), uid.length());
    oc_new_string(&store.access_token, access_token.data(),
                  access_token.length());
    oc_new_string(&store.refresh_token, refresh_token.data(),
                  refresh_token.length());
    store.expires_in = kExpiresIn;
    store.device = kDevice;
    store.cps = kCps;
    store.status = kStatus;
    return store;
  }

  static void freeStore(oc_cloud_store_t *store)
  {
    oc_cloud_endpoints_deinit(&store->ci_servers);
    oc_free_string(&store->auth_provider);
    oc_free_string(&store->uid);
    oc_free_string(&store->access_token);
    oc_free_string(&store->refresh_token);
  }

  static void SetUpTestCase()
  {
    clean();
    oc_random_init();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc_storage_config(kCloudStoragePath.data()));
#endif /* OC_STORAGE */
  }

  static void TearDownTestCase()
  {
#ifdef OC_STORAGE
    EXPECT_EQ(0, oc_storage_reset());
#endif /* OC_STORAGE */
    oc_random_destroy();
    clean();
  }

  void TearDown() override
  {
    // selecting a cloud server schedules a storage dump, which we need to
    // remove to avoid a leak
    oc_event_callbacks_shutdown();
    clean();
  }
};

TEST_F(TestCloudStore, Decode_ServersArray)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  std::string key{ "x.org.iotivity.servers" };
  oc_rep_encode_text_string(oc_rep_object(root), key.c_str(), key.length());
  oc_rep_begin_array(oc_rep_object(root), servers);
  oc_rep_object_array_begin_item(servers);
  // missing uri -> item skipped
  oc_rep_set_text_string(servers, id, "00000000-0000-0000-0000-000000000000");
  oc_rep_object_array_end_item(servers);
  oc_rep_object_array_begin_item(servers);
  // missing id -> item skipped
  oc_rep_set_text_string(servers, uri, "coaps://plgd.dev");
  oc_rep_object_array_end_item(servers);
  oc_rep_object_array_begin_item(servers);
  // invalid id -> item skipped
  oc_rep_set_text_string(servers, uri, "coaps://plgd.dev");
  oc_rep_set_text_string(servers, id, "invalid");
  oc_rep_object_array_end_item(servers);
  // valid
  oc_rep_object_array_begin_item(servers);
  oc_rep_set_text_string(servers, uri, "coaps://plgd.dev");
  oc_rep_set_text_string(servers, id, "00000000-0000-0000-0000-000000000000");
  oc_rep_object_array_end_item(servers);
  // duplicate -> item skipped
  oc_rep_object_array_begin_item(servers);
  oc_rep_set_text_string(servers, uri, "coaps://plgd.dev");
  oc_rep_set_text_string(servers, id, "00000000-0000-0000-0000-000000000000");
  oc_rep_object_array_end_item(servers);
  oc_rep_end_array(oc_rep_object(root), servers);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_TRUE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, Decode_FailUnknownProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, plgd, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_FALSE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
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
  EXPECT_FALSE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
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
  EXPECT_FALSE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, Decode_FailUnknownObjectArrayProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  std::string key{ "key" };
  oc_rep_encode_text_string(oc_rep_object(root), key.c_str(), key.length());
  oc_rep_begin_array(oc_rep_object(root), plgd);
  oc_rep_object_array_begin_item(plgd);
  oc_rep_set_text_string(plgd, plgd, "dev");
  oc_rep_object_array_end_item(plgd);
  oc_rep_end_array(oc_rep_object(root), plgd);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  EXPECT_FALSE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, Decode_FailInvalidSid)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, ci_server, "coaps://plgd.dev");
  oc_rep_set_text_string(root, sid, "non-UUID");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_cloud_store_t store{};
  // invalid sid resuls in a warning, not an error
  EXPECT_TRUE(oc_cloud_store_decode(pool.ParsePayload().get(), &store));
  freeStore(&store);
}

TEST_F(TestCloudStore, LoadDefaults)
{
  oc_cloud_store_t store{};
  EXPECT_FALSE(oc_cloud_store_load(&store));

  validateDefaults(&store);
  freeStore(&store);
}

TEST_F(TestCloudStore, DumpAndLoad)
{
  oc_cloud_store_t store = makeStore();
  ASSERT_LT(0, oc_cloud_store_dump(&store));

  oc_cloud_store_t store2{};
  store2.device = store.device;
  ASSERT_TRUE(oc_cloud_store_load(&store2));
  compareStores(&store, &store2);

  freeStore(&store2);
  freeStore(&store);
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestCloudStore, DumpAndLoad_MultipleEndpoints)
{
  oc_cloud_store_t store = makeStore();
  oc_uuid_t id{};
  oc_gen_uuid(&id);
  ASSERT_TRUE(
    oc_cloud_endpoint_add(&store.ci_servers, OC_STRING_VIEW("/test/1"), id));
  oc_gen_uuid(&id);
  ASSERT_TRUE(
    oc_cloud_endpoint_add(&store.ci_servers, OC_STRING_VIEW("/test/2"), id));
  ASSERT_LT(0, oc_cloud_store_dump(&store));

  oc_cloud_store_t store2{};
  store2.device = store.device;
  ASSERT_TRUE(oc_cloud_store_load(&store2));
  compareStores(&store, &store2);

  freeStore(&store2);
  freeStore(&store);
}

#endif /* OC_DYNAMIC_ALLOCATION */

static void
writeCloudStoreData(const std::function<void()> &writePayload)
{
  std::array<char, OC_STORAGE_SVR_TAG_MAX> tag{};
  ASSERT_LT(0, oc_storage_gen_svr_tag(OC_CLOUD_STORE_NAME, kDevice, &tag[0],
                                      tag.size()));

  std::ofstream storage(std::string(kCloudStoragePath) + "/" + tag.data());
  ASSERT_TRUE(storage.good());

  oc::RepPool pool{};
  writePayload();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_size = oc_rep_get_encoded_payload_size();
  storage.write(reinterpret_cast<const char *>(payload), payload_size);

#if OC_DBG_IS_ENABLED
  auto rep = pool.ParsePayload();
  OC_DBG("storage: %s", oc::RepPool::GetJson(rep.get(), true).data());
#endif
}

TEST_F(TestCloudStore, SingleStoreData)
{
  writeCloudStoreData([]() {
    oc_rep_begin_root_object();
    oc_rep_set_int(root, cps, 1);
    oc_rep_end_root_object();
  });

  oc_cloud_store_t store{};
  store.device = kDevice;
  ASSERT_TRUE(oc_cloud_store_load(&store));

  freeStore(&store);
}

TEST_F(TestCloudStore, InvalidStoreData)
{
  std::array<char, OC_STORAGE_SVR_TAG_MAX> tag{};
  ASSERT_LT(0, oc_storage_gen_svr_tag(OC_CLOUD_STORE_NAME, kDevice, &tag[0],
                                      tag.size()));

  std::ofstream storage(std::string(kCloudStoragePath) + "/" + tag.data());
  ASSERT_TRUE(storage.good());

  writeCloudStoreData([]() {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, hello, "world");
    oc_rep_end_root_object();
  });

  oc_cloud_store_t store{};
  store.device = kDevice;
  ASSERT_FALSE(oc_cloud_store_load(&store));

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

  void TearDown() override
  {
    TestCloudStore::clean();
    oc::TestDevice::Reset();
  }
};

TEST_F(TestCloudStoreWithServer, DumpAsync)
{
  oc_cloud_store_t store = TestCloudStore::makeStore();
  oc_cloud_store_dump_async(&store);
  oc::TestDevice::PoolEventsMsV1(50ms);

  oc_cloud_store_t store1{};
  store1.device = store.device;
#ifdef OC_STORAGE
  ASSERT_TRUE(oc_cloud_store_load(&store1));
  TestCloudStore::compareStores(&store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_FALSE(oc_cloud_store_load(&store1));
  TestCloudStore::validateDefaults(&store1);
#endif /* OC_STORAGE */

  TestCloudStore::freeStore(&store1);
  TestCloudStore::freeStore(&store);
}

TEST_F(TestCloudStoreWithServer, Dump)
{
  oc_cloud_store_t store = TestCloudStore::makeStore();
#ifdef OC_STORAGE
  EXPECT_LE(0, oc_cloud_store_dump(&store));
#else  /* !OC_STORAGE */
  EXPECT_NE(0, oc_cloud_store_dump(&store));
#endif /* OC_STORAGE */
  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  store1.device = store.device;
#ifdef OC_STORAGE
  ASSERT_TRUE(oc_cloud_store_load(&store1));
  TestCloudStore::compareStores(&store, &store1);
#else  /* !OC_STORAGE */
  EXPECT_FALSE(oc_cloud_store_load(&store1));
  TestCloudStore::validateDefaults(&store1);
#endif /* OC_STORAGE */

  TestCloudStore::freeStore(&store1);
  TestCloudStore::freeStore(&store);
}
