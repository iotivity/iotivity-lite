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

#if defined(OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING) &&                        \
  defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

#include "api/oc_rep_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_endpoints_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_log_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_resource_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_macros_internal.h"

#include "gtest/gtest.h"

#include <map>
#include <optional>
#include <string>

static constexpr size_t kDeviceID = 0;

using namespace std::chrono_literals;

class DPSResourceTest : public testing::Test {};

struct DPSEndpointData
{
  std::string uri;
  std::string name;
};

struct DPSData
{
  std::optional<int> lastErrorCode;
  std::optional<std::string> provisionStatus;
  DPSEndpointData endpoint;
  std::vector<DPSEndpointData> endpoints;
  bool forceReprovision;
};

static std::vector<DPSEndpointData>
parseDPSEndpoints(const oc_rep_t *servers)
{
  std::vector<DPSEndpointData> endpoints{};
  for (const oc_rep_t *server = servers; server != nullptr;
       server = server->next) {
    DPSEndpointData data{};
    const oc_rep_t *rep = oc_rep_get_by_type_and_key(
      server->value.object, OC_REP_STRING, "uri", OC_CHAR_ARRAY_LEN("uri"));
    if (rep == nullptr) {
      return {};
    }
    data.uri = oc_string(rep->value.string);

    rep = oc_rep_get_by_type_and_key(server->value.object, OC_REP_STRING,
                                     "name", OC_CHAR_ARRAY_LEN("name"));
    if (rep == nullptr) {
      return {};
    }
    data.name = oc_string(rep->value.string);
    endpoints.push_back(data);
  }
  return endpoints;
}

static bool
parseDPSDataProperty(const oc_rep_t *rep, DPSData &dpsData)
{
  if (rep->type == OC_REP_BOOL) {
    if (std::string(oc_string(rep->name)) == "forceReprovision") {
      dpsData.forceReprovision = rep->value.boolean;
      return true;
    }
    return false;
  }

  if (rep->type == OC_REP_INT) {
    if (std::string(oc_string(rep->name)) == "lastErrorCode") {
      dpsData.lastErrorCode = static_cast<int>(rep->value.integer);
      return true;
    }
    return false;
  }

  if (rep->type == OC_REP_STRING) {
    if (std::string(oc_string(rep->name)) == "endpoint") {
      dpsData.endpoint.uri = oc_string(rep->value.string);
      return true;
    }
    if (std::string(oc_string(rep->name)) == "endpointName") {
      dpsData.endpoint.name = oc_string(rep->value.string);
      return true;
    }
    if (std::string(oc_string(rep->name)) == "provisionStatus") {
      dpsData.provisionStatus = oc_string(rep->value.string);
      return true;
    }
    return false;
  }

  if (rep->type == OC_REP_OBJECT_ARRAY) {
    if (std::string(oc_string(rep->name)) == "endpoints") {
      dpsData.endpoints = parseDPSEndpoints(rep->value.object_array);
      return true;
    }
    return false;
  }

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
  if (rep->type == OC_REP_OBJECT) {
    if (std::string(oc_string(rep->name)) == "test") {
      return true;
    }
    return false;
  }
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

  return false;
}

static bool
parseDPSData(const oc_rep_t *rep, DPSData &dpsData)
{
  for (; rep != nullptr; rep = rep->next) {
    if (oc_rep_is_baseline_interface_property(rep)) {
      continue;
    }

    if (parseDPSDataProperty(rep, dpsData)) {
      continue;
    }
    DPS_DBG("Unexpected property: %s\n", oc_string(rep->name));
  }
  return true;
}

TEST_F(DPSResourceTest, EncodeRead)
{
  oc::RepPool pool{};

  dps_resource_data_t data{};
  data.last_error = PLGD_DPS_ERROR_RESPONSE;
  std::string status = kPlgdDpsStatusProvisioned;
  data.provision_status = status.c_str();
  data.provision_status_length = status.length();
  oc_endpoint_addresses_t ea{};
  ASSERT_TRUE(dps_endpoints_init(&ea, nullptr, nullptr));
  data.endpoints = &ea;
  std::string ep1_uri = "coap://[::1]:42";
  std::string ep1_name = "name";
  auto *ep1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_name(
           oc_string_view(ep1_uri.c_str(), ep1_uri.length()),
           oc_string_view(ep1_name.c_str(), ep1_name.length())));
  ASSERT_NE(nullptr, ep1);
  data.forceReprovision = true;
  dps_resource_encode(OC_IF_R, nullptr, &data);

  auto rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  DPSData parsed{};
  ASSERT_TRUE(parseDPSData(rep.get(), parsed));
  ASSERT_TRUE(parsed.lastErrorCode.has_value());
  EXPECT_EQ(data.last_error, *parsed.lastErrorCode);
  ASSERT_TRUE(parsed.provisionStatus.has_value());
  EXPECT_STREQ(data.provision_status, parsed.provisionStatus->c_str());
  EXPECT_STREQ(ep1_uri.c_str(), parsed.endpoint.uri.c_str());
  EXPECT_STREQ(ep1_name.c_str(), parsed.endpoint.name.c_str());
  EXPECT_EQ(0, parsed.endpoints.size());
  EXPECT_EQ(data.forceReprovision, parsed.forceReprovision);

  // no status
  rep.reset();
  pool.Clear();
  data.provision_status = nullptr;
  data.provision_status_length = 0;
  dps_resource_encode(OC_IF_R, nullptr, &data);

  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  parsed = {};
  ASSERT_TRUE(parseDPSData(rep.get(), parsed));
  ASSERT_TRUE(parsed.lastErrorCode.has_value());
  EXPECT_EQ(data.last_error, *parsed.lastErrorCode);
  ASSERT_FALSE(parsed.provisionStatus.has_value());
  EXPECT_STREQ(ep1_uri.c_str(), parsed.endpoint.uri.c_str());
  EXPECT_STREQ(ep1_name.c_str(), parsed.endpoint.name.c_str());
  EXPECT_EQ(0, parsed.endpoints.size());
  EXPECT_EQ(data.forceReprovision, parsed.forceReprovision);

  // multiple endpoints
  rep.reset();
  pool.Clear();
  std::string ep2_uri = "coap://[::1]:43";
  std::string ep2_name = "name2";
  auto *ep2 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_name(
           oc_string_view(ep2_uri.c_str(), ep2_uri.length()),
           oc_string_view(ep2_name.c_str(), ep2_name.length())));
  ASSERT_NE(nullptr, ep2);
  oc_endpoint_addresses_select(&ea, ep2);
  dps_resource_encode(OC_IF_R, nullptr, &data);

  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  parsed = {};
  ASSERT_TRUE(parseDPSData(rep.get(), parsed));
  ASSERT_TRUE(parsed.lastErrorCode.has_value());
  EXPECT_EQ(data.last_error, *parsed.lastErrorCode);
  ASSERT_FALSE(parsed.provisionStatus.has_value());
  EXPECT_STREQ(ep2_uri.c_str(), parsed.endpoint.uri.c_str());
  EXPECT_STREQ(ep2_name.c_str(), parsed.endpoint.name.c_str());
  EXPECT_EQ(2, parsed.endpoints.size());
  EXPECT_EQ(data.forceReprovision, parsed.forceReprovision);

  oc_endpoint_addresses_deinit(&ea);
}

TEST_F(DPSResourceTest, EncodeReadWrite)
{
  oc::RepPool pool{};

  dps_resource_data_t data{};
  data.last_error = PLGD_DPS_ERROR_RESPONSE;
  std::string status = kPlgdDpsStatusProvisioned;
  data.provision_status = status.c_str();
  data.provision_status_length = status.length();
  oc_endpoint_addresses_t ea{};
  ASSERT_TRUE(dps_endpoints_init(&ea, nullptr, nullptr));
  data.endpoints = &ea;
  std::string endpoint_uri = "coap://[::1]:42";
  std::string endpoint_name = "name";
  ASSERT_NE(
    nullptr,
    oc_endpoint_addresses_add(
      &ea, oc_endpoint_address_make_view_with_name(
             oc_string_view(endpoint_uri.c_str(), endpoint_uri.length()),
             oc_string_view(endpoint_name.c_str(), endpoint_name.length()))));
  data.forceReprovision = true;
  dps_resource_encode(OC_IF_RW, nullptr, &data);

  auto rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  DPSData parsed{};
  ASSERT_TRUE(parseDPSData(rep.get(), parsed));
  ASSERT_FALSE(parsed.lastErrorCode.has_value());
  ASSERT_FALSE(parsed.provisionStatus.has_value());
  EXPECT_STREQ(endpoint_uri.c_str(), parsed.endpoint.uri.c_str());
  EXPECT_STREQ(endpoint_name.c_str(), parsed.endpoint.name.c_str());
  EXPECT_EQ(data.forceReprovision, parsed.forceReprovision);

  oc_endpoint_addresses_deinit(&ea);
}

TEST_F(DPSResourceTest, StatusToString)
{
  EXPECT_STREQ(dps_status_to_str(0).data, kPlgdDpsStatusUninitialized);
  EXPECT_STREQ(dps_status_to_str(PLGD_DPS_INITIALIZED).data,
               kPlgdDpsStatusInitialized);
  EXPECT_STREQ(dps_status_to_str(PLGD_DPS_INITIALIZED | PLGD_DPS_FAILURE).data,
               kPlgdDpsStatusFailure);

  uint32_t status = PLGD_DPS_INITIALIZED;
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_TIME).data,
               kPlgdDpsStatusGetTime);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_GET_TIME | PLGD_DPS_TRANSIENT_FAILURE)
      .data,
    kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_HAS_TIME).data,
               kPlgdDpsStatusHasTime);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_HAS_TIME | PLGD_DPS_FAILURE).data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_HAS_TIME;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_OWNER).data,
               kPlgdDpsStatusGetOwner);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_GET_OWNER | PLGD_DPS_TRANSIENT_FAILURE)
      .data,
    kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_HAS_OWNER).data,
               kPlgdDpsStatusHasOwner);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_HAS_OWNER | PLGD_DPS_FAILURE).data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_HAS_OWNER;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_CLOUD).data,
               kPlgdDpsStatusGetCloud);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_GET_CLOUD | PLGD_DPS_TRANSIENT_FAILURE)
      .data,
    kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_HAS_CLOUD).data,
               kPlgdDpsStatusHasCloud);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_HAS_CLOUD | PLGD_DPS_FAILURE).data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_HAS_CLOUD;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_CREDENTIALS).data,
               kPlgdDpsStatusGetCredentials);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_CREDENTIALS |
                                 PLGD_DPS_TRANSIENT_FAILURE)
                 .data,
               kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_HAS_CREDENTIALS).data,
               kPlgdDpsStatusHasCredentials);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_FAILURE)
      .data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_HAS_CREDENTIALS;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_GET_ACLS).data,
               kPlgdDpsStatusGetAcls);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_GET_ACLS | PLGD_DPS_TRANSIENT_FAILURE)
      .data,
    kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_HAS_ACLS).data,
               kPlgdDpsStatusHasAcls);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_HAS_ACLS | PLGD_DPS_FAILURE).data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_HAS_ACLS;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_CLOUD_STARTED).data,
               kPlgdDpsStatusProvisioned);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_CLOUD_STARTED |
                                 PLGD_DPS_TRANSIENT_FAILURE)
                 .data,
               kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_CLOUD_STARTED | PLGD_DPS_FAILURE).data,
    kPlgdDpsStatusFailure);
  status |= PLGD_DPS_CLOUD_STARTED;

  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_RENEW_CREDENTIALS).data,
               kPlgdDpsStatusRenewCredentials);
  EXPECT_STREQ(dps_status_to_str(status | PLGD_DPS_RENEW_CREDENTIALS |
                                 PLGD_DPS_TRANSIENT_FAILURE)
                 .data,
               kPlgdDpsStatusTransientFailure);
  EXPECT_STREQ(
    dps_status_to_str(status | PLGD_DPS_RENEW_CREDENTIALS | PLGD_DPS_FAILURE)
      .data,
    kPlgdDpsStatusFailure);

  for (uint8_t i = 0; i < 32; ++i) {
    uint32_t flag = (1 << i);
    if ((PLGD_DPS_PROVISIONED_ALL_FLAGS & flag) == 0) {
      EXPECT_EQ(nullptr, dps_status_to_str(flag).data);
    }
  }
}

class DPSResourceTestWithServer : public testing::Test {
public:
  static void SetUpDPS()
  {
    plgd_dps_init();
    plgd_dps_context_t *dps_ctx = plgd_dps_get_context(kDeviceID);
    ASSERT_NE(nullptr, dps_ctx);
    plgd_dps_set_configuration_resource(dps_ctx, true);

    ASSERT_TRUE(oc::SetAccessInRFOTM(dps_ctx->conf, true,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE));
  }

  static void SetUpTestCase()
  {
    EXPECT_TRUE(oc::TestDevice::StartServer());
    SetUpDPS();
  }

  static void TearDownTestCase()
  {
    plgd_dps_shutdown();
    oc::TestDevice::StopServer();
  }
};

template<oc_status_t CODE = OC_STATUS_OK>
static void
getRequestWithQuery(const std::string &query = "")
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto getHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    *static_cast<bool *>(data->user_data) = true;
    EXPECT_EQ(CODE, data->code);
    DPS_DBG("GET payload: %s",
            oc::RepPool::GetJson(data->payload, true).data());
    if (data->code != OC_STATUS_OK) {
      return;
    }
    DPSData dpsData{};
    EXPECT_TRUE(parseDPSData(data->payload, dpsData));
    ASSERT_TRUE(dpsData.lastErrorCode.has_value());
    EXPECT_EQ(0, *dpsData.lastErrorCode);
    ASSERT_TRUE(dpsData.provisionStatus.has_value());
    EXPECT_STREQ(kPlgdDpsStatusUninitialized, dpsData.provisionStatus->c_str());
    EXPECT_FALSE(dpsData.forceReprovision);
  };

  auto timeout = 1s;
  bool invoked = false;
  ASSERT_TRUE(oc_do_get_with_timeout(
    PLGD_DPS_URI, &ep, query.empty() ? nullptr : query.c_str(), timeout.count(),
    getHandler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(DPSResourceTestWithServer, GetRequest_FailNoDPS)
{
  plgd_dps_shutdown();
  oc::TestDevice::PoolEventsMsV1(10ms);

  oc_resource_t *dps = dps_create_dpsconf_resource(kDeviceID);
  ASSERT_NE(nullptr, dps);
  ASSERT_TRUE(oc::SetAccessInRFOTM(dps, true, OC_PERM_RETRIEVE));

  getRequestWithQuery<OC_STATUS_INTERNAL_SERVER_ERROR>();

  dps_delete_dpsconf_resource(dps);
  SetUpDPS();
}

TEST_F(DPSResourceTestWithServer, GetRequest_FailNoDPSResource)
{
  plgd_dps_context_t *dps_ctx = plgd_dps_get_context(kDeviceID);
  ASSERT_NE(nullptr, dps_ctx);
  plgd_dps_set_configuration_resource(dps_ctx, false);

  getRequestWithQuery<OC_STATUS_NOT_FOUND>();

  plgd_dps_set_configuration_resource(dps_ctx, true);
  ASSERT_TRUE(oc::SetAccessInRFOTM(dps_ctx->conf, true,
                                   OC_PERM_RETRIEVE | OC_PERM_UPDATE));
}

TEST_F(DPSResourceTestWithServer, GetRequest)
{
  getRequestWithQuery("if=oic.if.r");
}

TEST_F(DPSResourceTestWithServer, GetRequestBaseline)
{
  getRequestWithQuery("if=oic.if.baseline");
}

template<typename Fn>
static void
postRequest(Fn encode)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto postHandler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    *static_cast<bool *>(data->user_data) = true;
    DPS_DBG("POST payload: %s",
            oc::RepPool::GetJson(data->payload, true).data());
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
  };

  bool invoked = false;
  ASSERT_TRUE(
    oc_init_post(PLGD_DPS_URI, &ep, nullptr, postHandler, HIGH_QOS, &invoked));

  encode();

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(DPSResourceTestWithServer, PostRequest)
{
  std::string ep1URI = "coap://dps.plgd.dev";
  std::string ep1Name = "plgd.dev";
  std::string ep2URI = "coaps://dps.plgd.dev";
  std::string ep2Name = "plgd.dev2";
  std::string ep3URI = "coap+tcp://dps.plgd.dev";

  postRequest([&ep1URI, &ep1Name, &ep2URI, &ep2Name, &ep3URI] {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, endpoint, ep1URI.c_str());
    oc_rep_set_text_string(root, endpointName, ep1Name.c_str());
    std::string_view key{ "endpoints" };
    g_err |=
      oc_rep_encode_text_string(oc_rep_object(root), key.data(), key.length());
    oc_rep_begin_array(oc_rep_object(root), servers);
    oc_rep_object_array_begin_item(servers);
    oc_rep_set_text_string(servers, uri, ep2URI.c_str());
    oc_rep_set_text_string(servers, name, ep2Name.c_str());
    oc_rep_object_array_end_item(servers);
    oc_rep_object_array_begin_item(servers);
    oc_rep_set_text_string(servers, uri, ep3URI.c_str());
    oc_rep_object_array_end_item(servers);
    oc_rep_end_array(oc_rep_object(root), servers);
    oc_rep_end_root_object();
  });

  plgd_dps_context_t *dps_ctx = plgd_dps_get_context(kDeviceID);
  ASSERT_NE(nullptr, dps_ctx);
  const auto *selected = plgd_dps_selected_endpoint_address(dps_ctx);
  ASSERT_NE(nullptr, selected);
  EXPECT_STREQ(ep1URI.c_str(), oc_string(*oc_endpoint_address_uri(selected)));
  EXPECT_STREQ(ep1Name.c_str(), oc_string(*oc_endpoint_address_name(selected)));

  std::map<std::string, const oc_endpoint_address_t *, std::less<>> endpoints{};
  plgd_dps_iterate_server_addresses(
    dps_ctx,
    [](oc_endpoint_address_t *ea, void *data) {
      auto &eps =
        *static_cast<std::map<std::string, const oc_endpoint_address_t *> *>(
          data);
      const oc_string_t *uri = oc_endpoint_address_uri(ea);
      eps[oc_string(*uri)] = ea;
      return true;
    },
    &endpoints);

  ASSERT_EQ(3, endpoints.size());
  auto it = endpoints.find(ep1URI);
  ASSERT_NE(endpoints.end(), it);
  EXPECT_STREQ(ep1Name.c_str(),
               oc_string(*oc_endpoint_address_name(it->second)));
  it = endpoints.find(ep2URI);
  ASSERT_NE(endpoints.end(), it);
  EXPECT_STREQ(ep2Name.c_str(),
               oc_string(*oc_endpoint_address_name(it->second)));
  it = endpoints.find(ep3URI);
  ASSERT_NE(endpoints.end(), it);
  EXPECT_EQ(nullptr, oc_string(*oc_endpoint_address_name(it->second)));

  oc_endpoint_addresses_deinit(&dps_ctx->store.endpoints);
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING &&                           \
          OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
