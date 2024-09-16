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

#include "api/oc_runtime_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_endpoints_internal.h"
#include "plgd_dps_test.h"
#include "util/oc_endpoint_address.h"

#include "gtest/gtest.h"

#include <array>
#include <memory>
#include <set>
#include <string>

static constexpr size_t kDeviceID = 0;

class DPSEndpointsTest : public testing::Test {
public:
  static void SetUpTestCase() { oc_runtime_init(); }

  static void TearDownTestCase() { oc_runtime_shutdown(); }
};

TEST_F(DPSEndpointsTest, SetEndpoint)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  std::string endpoint = "coaps+tcp://plgd.cloud:25684";
  ASSERT_EQ(DPS_ENDPOINT_CHANGED, dps_set_endpoint(ctx.get(), endpoint.c_str(),
                                                   endpoint.length(), true));

  std::array<char, 256> buffer{ '\0' };
  ASSERT_LT(0, plgd_dps_get_endpoint(ctx.get(), buffer.data(), buffer.size()));
  EXPECT_STREQ(endpoint.c_str(), buffer.data());

  // not changed
  ASSERT_EQ(
    DPS_ENDPOINT_NOT_CHANGED,
    dps_set_endpoint(ctx.get(), endpoint.c_str(), endpoint.length(), true));
  ASSERT_LT(0, plgd_dps_get_endpoint(ctx.get(), buffer.data(), buffer.size()));
  EXPECT_STREQ(endpoint.c_str(), buffer.data());

  // invalid - string longer than OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH
  auto invalid = std::string(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH + 1, 'a');
  ASSERT_EQ(
    -1, dps_set_endpoint(ctx.get(), invalid.c_str(), invalid.length(), true));
}

TEST_F(DPSEndpointsTest, IsEmpty)
{
  auto ctx = dps::make_unique_context(kDeviceID);

  EXPECT_TRUE(plgd_dps_endpoint_is_empty(ctx.get()));
  EXPECT_EQ(nullptr, plgd_dps_selected_endpoint_address(ctx.get()));
}

TEST_F(DPSEndpointsTest, EndpointsAPI)
{
  auto ctx = dps::make_unique_context(kDeviceID);
  // after init, no endpoint should be selected
  EXPECT_TRUE(plgd_dps_endpoint_is_empty(ctx.get()));
  EXPECT_EQ(nullptr, plgd_dps_selected_endpoint_address(ctx.get()));

  // add
  std::string ep1_uri = "/uri/1";
  std::string ep1_name = "ep1";
  auto *ep1 =
    plgd_dps_add_endpoint_address(ctx.get(), ep1_uri.c_str(), ep1_uri.length(),
                                  ep1_name.c_str(), ep1_name.length());
  std::string ep2_uri = "/uri2";
  auto *ep2 = plgd_dps_add_endpoint_address(ctx.get(), ep2_uri.c_str(),
                                            ep2_uri.length(), nullptr, 0);
  ASSERT_NE(nullptr, ep2);
  std::string ep3_uri = "/uri3";
  std::string ep3_name = "ep3";
  auto *ep3 =
    plgd_dps_add_endpoint_address(ctx.get(), ep3_uri.c_str(), ep3_uri.length(),
                                  ep3_name.c_str(), ep3_name.length());

  auto verify_selected_endpoint = [&ctx](oc_endpoint_address_t *ep,
                                         const std::string &uri,
                                         const std::string &name) {
    auto *selected = plgd_dps_selected_endpoint_address(ctx.get());
    ASSERT_EQ(ep, selected);
    if (ep == nullptr) {
      return;
    }
    auto *selected_uri = oc_endpoint_address_uri(selected);
    ASSERT_NE(nullptr, selected_uri);
    EXPECT_STREQ(uri.c_str(), oc_string(*selected_uri));
    auto *selected_name = oc_endpoint_address_name(selected);
    ASSERT_NE(nullptr, selected_name);
    if (name.empty()) {
      EXPECT_EQ(nullptr, oc_string(*selected_name));
    } else {
      EXPECT_STREQ(name.c_str(), oc_string(*selected_name));
    }
  };

  // first item added to empty list should be selected
  verify_selected_endpoint(ep1, ep1_uri, ep1_name);

  // remove the first item
  ASSERT_TRUE(plgd_dps_remove_endpoint_address(ctx.get(), ep1));

  // next endpoint should be selected
  verify_selected_endpoint(ep2, ep2_uri, {});

  oc_endpoint_address_t notInList{};
  EXPECT_FALSE(plgd_dps_select_endpoint_address(ctx.get(), &notInList));

  std::set<std::string, std::less<>> uris{};
  // iterate
  plgd_dps_iterate_server_addresses(
    ctx.get(),
    [](oc_endpoint_address_t *eaddr, void *data) {
      auto uri = oc_endpoint_address_uri(eaddr);
      static_cast<std::set<std::string> *>(data)->insert(
        std::string(oc_string(*uri), oc_string_len(*uri)));
      return true;
    },
    &uris);

  ASSERT_EQ(2, uris.size());
  EXPECT_NE(uris.end(), uris.find(ep3_uri));
  EXPECT_NE(uris.end(), uris.find(ep2_uri));
  EXPECT_EQ(uris.end(), uris.find(ep1_uri));

  oc_endpoint_address_t *toSelect = nullptr;
  // iterate to get the last endpoint
  plgd_dps_iterate_server_addresses(
    ctx.get(),
    [](oc_endpoint_address_t *eaddr, void *data) {
      *static_cast<oc_endpoint_address_t **>(data) = eaddr;
      return true;
    },
    &toSelect);
  ASSERT_NE(nullptr, toSelect);

  ASSERT_TRUE(plgd_dps_select_endpoint_address(ctx.get(), ep3));
  verify_selected_endpoint(ep3, ep3_uri, ep3_name);

  std::string ep3_newname = "ep2";
  oc_endpoint_address_set_name(toSelect, ep3_newname.c_str(),
                               ep3_newname.length());
  verify_selected_endpoint(ep3, ep3_uri, ep3_newname);

  ASSERT_TRUE(plgd_dps_remove_endpoint_address(ctx.get(), toSelect));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
