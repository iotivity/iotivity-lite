/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/oc_helpers_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_log_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_store_internal.h"
#include "oc_helpers.h"
#include "plgd_dps_test.h"
#include "security/oc_pstat_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_endpoint_address_internal.h"

#include "gtest/gtest.h"

#include <cerrno>
#include <filesystem>
#include <memory>
#include <sys/stat.h>
#include <string>

static constexpr size_t kDeviceID = 0;
static constexpr std::string_view kStoragePath{ "dps_test_storage" };

using namespace std::chrono_literals;

class DPSStoreTest : public testing::Test {
public:
  static void SetUpTestCase() { oc_runtime_init(); }

  static void TearDownTestCase() { oc_runtime_shutdown(); }

  static bool is_directory(const char *path)
  {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
      return false;
    }
    return S_ISDIR(statbuf.st_mode) != 0;
  }

  static bool make_storage(std::string_view storage)
  {
    if (mkdir(storage.data(), S_IRWXU | S_IRWXG) == 0) {
      return true;
    }
    if ((EEXIST != errno) || !is_directory(storage.data())) {
      DPS_ERR("failed to create storage at path %s", storage.data());
      return false;
    }
    return true;
  }

  static void clean_storage()
  {
    for (const auto &entry :
         std::filesystem::directory_iterator(kStoragePath.data())) {
      std::filesystem::remove_all(entry.path());
    }
  }
};

static void
compareStores(const plgd_dps_store_t &store1, const plgd_dps_store_t &store2)
{
  ASSERT_EQ(oc_endpoint_addresses_size(&store1.endpoints),
            oc_endpoint_addresses_size(&store2.endpoints));
  const char *owner1 = oc_string(store1.owner);
  const char *owner2 = oc_string(store2.owner);
  if (owner1 == nullptr) {
    ASSERT_EQ(nullptr, owner2);
  } else {
    ASSERT_NE(nullptr, owner2);
    EXPECT_STREQ(owner1, owner2);
  }
  EXPECT_EQ(store1.has_been_provisioned_since_reset,
            store2.has_been_provisioned_since_reset);
}

TEST_F(DPSStoreTest, EncodeAndDecode)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  std::string ep1_uri = "/uri/1";
  std::string ep1_name = "name1";
  auto *ep1 =
    plgd_dps_add_endpoint_address(ctx.get(), ep1_uri.c_str(), ep1_uri.length(),
                                  ep1_name.c_str(), ep1_name.length());
  ASSERT_NE(nullptr, ep1);
  std::string ep2_uri = "/uri/2";
  std::string ep2_name = "name2";
  auto *ep2 =
    plgd_dps_add_endpoint_address(ctx.get(), ep2_uri.c_str(), ep2_uri.length(),
                                  ep2_name.c_str(), ep2_name.length());
  ASSERT_NE(nullptr, ep2);

  oc::RepPool pool{};
  ASSERT_TRUE(dps_store_encode(&ctx->store));

  plgd_dps_store_t store{};
  dps_store_init(&store, nullptr, nullptr);
  auto rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  dps_store_decode(rep.get(), &store);

  compareStores(ctx->store, store);

  dps_store_deinit(&store);
}

TEST_F(DPSStoreTest, Decode_SelectedEndpointMissingURI)
{
  oc::RepPool pool{};

  oc_rep_begin_root_object();
  oc_rep_set_text_string_v1(root, ep, "", 0);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  plgd_dps_store_t store{};
  dps_store_init(&store, nullptr, nullptr);
  dps_store_decode(rep.get(), &store);
  EXPECT_EQ(0, oc_endpoint_addresses_size(&store.endpoints));

  dps_store_deinit(&store);
}

TEST_F(DPSStoreTest, Decode_EndpointMissingURI)
{
  oc::RepPool pool{};

  oc_rep_begin_root_object();
  oc_rep_open_array(root, eps);
  oc_rep_object_array_begin_item(eps);
  oc_rep_set_text_string_v1(eps, ep, "", 0);
  oc_rep_object_array_end_item(eps);
  oc_rep_close_array(root, eps);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  plgd_dps_store_t store{};
  dps_store_init(&store, nullptr, nullptr);
  dps_store_decode(rep.get(), &store);
  EXPECT_EQ(0, oc_endpoint_addresses_size(&store.endpoints));

  dps_store_deinit(&store);
}

TEST_F(DPSStoreTest, SaveAndLoad)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  EXPECT_GT(0, dps_store_load(&ctx->store, kDeviceID));
  EXPECT_GT(0, dps_store_dump(&ctx->store, kDeviceID));

  EXPECT_FALSE(ctx->store.has_been_provisioned_since_reset);

  ASSERT_TRUE(make_storage(kStoragePath));
  ASSERT_EQ(0, oc_storage_config(kStoragePath.data()));
  std::string endpoint_addr = "coaps+tcp://127.0.0.1:12345";
  std::string endpoint_name = "dps test endpoint";
  ASSERT_NE(nullptr, plgd_dps_add_endpoint_address(
                       ctx.get(), endpoint_addr.c_str(), endpoint_addr.length(),
                       endpoint_name.c_str(), endpoint_name.length()));
  ctx->store.has_been_provisioned_since_reset = true;
  auto *selected = plgd_dps_selected_endpoint_address(ctx.get());
  ASSERT_NE(nullptr, selected);
  auto *selected_addr = oc_endpoint_address_uri(selected);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(endpoint_addr.c_str(), oc_string(*selected_addr));
  auto *selected_name = oc_endpoint_address_name(selected);
  ASSERT_NE(nullptr, selected_name);
  EXPECT_STREQ(endpoint_name.c_str(), oc_string(*selected_name));
  ASSERT_EQ(0, dps_store_dump(&ctx->store, kDeviceID));

  oc_endpoint_addresses_deinit(&ctx->store.endpoints);
  selected = plgd_dps_selected_endpoint_address(ctx.get());
  ASSERT_EQ(nullptr, selected);
  ctx->store.has_been_provisioned_since_reset = false;

  EXPECT_EQ(0, dps_store_load(&ctx->store, kDeviceID));
  selected = plgd_dps_selected_endpoint_address(ctx.get());
  ASSERT_NE(nullptr, selected);
  selected_addr = oc_endpoint_address_uri(selected);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(endpoint_addr.c_str(), oc_string(*selected_addr));
  selected_name = oc_endpoint_address_name(selected);
  ASSERT_NE(nullptr, selected_name);
  EXPECT_STREQ(endpoint_name.c_str(), oc_string(*selected_name));
  EXPECT_TRUE(ctx->store.has_been_provisioned_since_reset);

  clean_storage();
}

class DPSStoreWithDeviceTest : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());

    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;
    plgd_dps_init();
  }

  static void TearDownTestCase()
  {
    plgd_dps_shutdown();
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    ASSERT_TRUE(DPSStoreTest::make_storage(kStoragePath));
    ASSERT_EQ(0, oc_storage_config(kStoragePath.data()));
  }

  void TearDown() override { DPSStoreTest::clean_storage(); }
};

TEST_F(DPSStoreWithDeviceTest, DumpOnEndpointChange)
{
  auto *ctx = plgd_dps_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  plgd_dps_store_t store{};
  dps_store_init(&store, nullptr, nullptr);
  ASSERT_GT(0, dps_store_load(&store, kDeviceID));

  std::string ep1_uri = "coap+tcp://127.0.0.1:12345";
  ASSERT_NE(nullptr, plgd_dps_add_endpoint_address(
                       ctx, ep1_uri.c_str(), ep1_uri.length(), nullptr, 0));
  std::string ep2_uri = "coap://127.0.0.1:12345";
  ASSERT_NE(nullptr, plgd_dps_add_endpoint_address(
                       ctx, ep2_uri.c_str(), ep2_uri.length(), nullptr, 0));
#ifdef OC_DYNAMIC_ALLOCATION
  std::string ep3_uri = "coaps+tcp://127.0.0.1:12345";
  ASSERT_NE(nullptr, plgd_dps_add_endpoint_address(
                       ctx, ep3_uri.c_str(), ep3_uri.length(), nullptr, 0));
#endif /* OC_DYNAMIC_ALLOCATION */
  oc::TestDevice::PoolEventsMsV1(10ms);
  ASSERT_EQ(0, dps_store_load(&store, kDeviceID));
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(3, oc_endpoint_addresses_size(&store.endpoints));
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_EQ(2, oc_endpoint_addresses_size(&store.endpoints));
#endif /* OC_DYNAMIC_ALLOCATION */
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &store.endpoints, oc_string_view(ep1_uri.c_str(), ep1_uri.length())));

  // change selected endpoint
  oc_endpoint_addresses_select_by_uri(
    &ctx->store.endpoints, oc_string_view(ep2_uri.c_str(), ep2_uri.length()));
  oc::TestDevice::PoolEventsMsV1(10ms);
  dps_store_init(&store, nullptr, nullptr);
  ASSERT_EQ(0, dps_store_load(&store, kDeviceID));
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(3, oc_endpoint_addresses_size(&store.endpoints));
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_EQ(2, oc_endpoint_addresses_size(&store.endpoints));
#endif /* OC_DYNAMIC_ALLOCATION */
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &store.endpoints, oc_string_view(ep2_uri.c_str(), ep2_uri.length())));

  // remove selected endpoint
  ASSERT_TRUE(oc_endpoint_addresses_remove_by_uri(
    &ctx->store.endpoints, oc_string_view(ep2_uri.c_str(), ep2_uri.length())));
#ifdef OC_DYNAMIC_ALLOCATION
  oc_string_view_t selected = oc_string_view(ep3_uri.c_str(), ep3_uri.length());
#else  /* !OC_DYNAMIC_ALLOCATION */
  oc_string_view_t selected = oc_string_view(ep1_uri.c_str(), ep1_uri.length());
#endif /* OC_DYNAMIC_ALLOCATION */
  ASSERT_TRUE(
    oc_endpoint_addresses_is_selected(&ctx->store.endpoints, selected));
  oc::TestDevice::PoolEventsMsV1(10ms);
  dps_store_init(&store, nullptr, nullptr);
  ASSERT_EQ(0, dps_store_load(&store, kDeviceID));
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(2, oc_endpoint_addresses_size(&store.endpoints));
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_EQ(1, oc_endpoint_addresses_size(&store.endpoints));
#endif /* OC_DYNAMIC_ALLOCATION */
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&store.endpoints, selected));

  dps_store_deinit(&store);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
