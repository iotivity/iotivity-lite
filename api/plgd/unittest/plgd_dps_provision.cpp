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

#include "api/plgd/device-provisioning-client/plgd_dps_provision_cloud_internal.h"
#include "oc_rep.h"
#include "tests/gtest/RepPool.h"

#include "gtest/gtest.h"

#include <algorithm>
#include <string>
#include <vector>

struct cloudEndpoint
{
  std::string uri;
  std::string id;
};

static struct cloudEndpoint
makeCloudEndpoint(const std::string &uri, const std::string &id)
{
  return cloudEndpoint{ uri, id };
}

static void
makeCloudConfigurationPayload(const std::string &at, const std::string &apn,
                              const std::string &cis, const std::string &sid,
                              const std::vector<cloudEndpoint> &endpoints = {})
{
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  if (!at.empty()) {
    oc_rep_set_text_string(root, at, at.c_str());
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  if (!apn.empty()) {
    oc_rep_set_text_string(root, apn, apn.c_str());
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  if (!cis.empty()) {
    oc_rep_set_text_string(root, cis, cis.c_str());
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  if (!sid.empty()) {
    oc_rep_set_text_string(root, sid, sid.c_str());
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  if (!endpoints.empty()) {
    std::string epsKey = "x.org.iotivity.servers";
    g_err |= oc_rep_encode_text_string(oc_rep_object(root), epsKey.c_str(),
                                       epsKey.length());
    oc_rep_begin_array(oc_rep_object(root), endpoints);
    for (const auto &endpoint : endpoints) {
      oc_rep_object_array_start_item(endpoints);
      oc_rep_set_text_string(endpoints, uri, endpoint.uri.c_str());
      oc_rep_set_text_string(endpoints, id, endpoint.id.c_str());
      oc_rep_object_array_end_item(endpoints);
    }
    oc_rep_end_array(oc_rep_object(root), endpoints);
  }

  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
}

TEST(DPSFillCloudTest, MissingAccessToken)
{
  oc::RepPool pool{};

  makeCloudConfigurationPayload("", "auth_provider", "server", "server_id");
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  cloud_conf_t cloud{};
  EXPECT_FALSE(dps_register_cloud_fill_data(rep.get(), &cloud));
}

TEST(DPSFillCloudTest, MissingAuthProvider)
{
  oc::RepPool pool{};

  makeCloudConfigurationPayload("access_token", "", "server", "server_id");
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  cloud_conf_t cloud{};
  EXPECT_FALSE(dps_register_cloud_fill_data(rep.get(), &cloud));
}

TEST(DPSFillCloudTest, MissingServer)
{
  oc::RepPool pool{};

  makeCloudConfigurationPayload("access_token", "auth_provider", "",
                                "server_id");
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  cloud_conf_t cloud{};
  EXPECT_FALSE(dps_register_cloud_fill_data(rep.get(), &cloud));
}

TEST(DPSFillCloudTest, MissingServerID)
{
  oc::RepPool pool{};

  makeCloudConfigurationPayload("access_token", "auth_provider", "server", "");
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  cloud_conf_t cloud{};
  EXPECT_FALSE(dps_register_cloud_fill_data(rep.get(), &cloud));
}

TEST(DPSFillCloudTest, FillSuccess)
{
  oc::RepPool pool{};

  std::vector<cloudEndpoint> endpoints = { makeCloudEndpoint("uri/1", "id1"),
                                           makeCloudEndpoint("uri/2", "id2") };
  makeCloudConfigurationPayload("access_token", "auth_provider", "server",
                                "server id", endpoints);
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  cloud_conf_t cloud{};
  EXPECT_TRUE(dps_register_cloud_fill_data(rep.get(), &cloud));

  EXPECT_STREQ("access_token", oc_string(*cloud.access_token));
  EXPECT_STREQ("auth_provider", oc_string(*cloud.auth_provider));
  EXPECT_STREQ("server", oc_string(*cloud.ci_server));
  EXPECT_STREQ("server id", oc_string(*cloud.sid));
  EXPECT_NE(nullptr, cloud.ci_servers);
  size_t count = 0;
  for (const oc_rep_t *server = cloud.ci_servers; server != nullptr;
       server = server->next) {
    std::string_view uriKey = "uri";
    const oc_rep_t *prop = oc_rep_get_by_type_and_key(
      server->value.object, OC_REP_STRING, uriKey.data(), uriKey.length());
    ASSERT_NE(nullptr, prop);
    ASSERT_NE(nullptr, oc_string(prop->value.string));
    std::string uri = oc_string(prop->value.string);

    std::string_view idKey = "id";
    prop = oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                      idKey.data(), idKey.length());
    ASSERT_NE(nullptr, prop);
    ASSERT_NE(nullptr, oc_string(prop->value.string));
    std::string id = oc_string(prop->value.string);

    EXPECT_NE(endpoints.end(), std::find_if(endpoints.begin(), endpoints.end(),
                                            [&](const cloudEndpoint &endpoint) {
                                              return endpoint.uri == uri &&
                                                     endpoint.id == id;
                                            }));
    ++count;
  }
  EXPECT_EQ(endpoints.size(), count);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
