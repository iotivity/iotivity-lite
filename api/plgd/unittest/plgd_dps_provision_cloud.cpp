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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_context_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_log_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_manager_internal.h"
#include "api/plgd/device-provisioning-client/plgd_dps_provision_cloud_internal.h"
#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "security/oc_pstat_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"

#include "gtest/gtest.h"

#include <array>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

static constexpr size_t kDeviceID = 0;

class DPSProvisionCloudWithServerTest : public testing::Test {
public:
  static void SetUpTestCase()
  {
    EXPECT_TRUE(oc::TestDevice::StartServer());
    plgd_dps_init();
  }

  static void TearDownTestCase()
  {
    plgd_dps_shutdown();
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFOTM;
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;
  }

  void TearDown() override
  {
    oc::TestDevice::Reset();
    auto cloud_ctx = oc_cloud_get_context(kDeviceID);
    ASSERT_NE(nullptr, cloud_ctx);
    oc_cloud_context_clear(cloud_ctx, false);
  }

  static void clearCloudServers(size_t device)
  {
    auto cloud_ctx = oc_cloud_get_context(device);
    ASSERT_NE(nullptr, cloud_ctx);
    do {
      const oc_endpoint_address_t *ea =
        oc_cloud_selected_server_address(cloud_ctx);
      if (ea == nullptr) {
        break;
      }
      oc_cloud_remove_server_address(cloud_ctx, ea);
    } while (true);
  }

  static int encodeConfResourcePayload(const std::string &cis,
                                       const std::string &sid,
                                       const std::string &at,
                                       const std::string &apn)
  {
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, cis, cis.c_str());
    oc_rep_set_text_string(root, sid, sid.c_str());
    oc_rep_set_text_string(root, at, at.c_str());
    oc_rep_set_text_string(root, apn, apn.c_str());
    oc_rep_end_root_object();
    return oc_rep_get_cbor_errno();
  }
};

TEST_F(DPSProvisionCloudWithServerTest, HandleSetCloudResponseFail)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  oc_client_response_t data{};
  data.user_data = ctx.get();
  data.code = OC_STATUS_OK;
  // invalid payload
  EXPECT_EQ(PLGD_DPS_ERROR_RESPONSE, dps_handle_set_cloud_response(&data));

  oc::RepPool pool{};

  // invalid sid
  ctx->device = kDeviceID;
  ASSERT_EQ(CborNoError,
            encodeConfResourcePayload("cis", "not-an-UUID", "at", "apn"));
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_ERROR_SET_CLOUD, dps_handle_set_cloud_response(&data));
  rep.reset();
  pool.Clear();

  ASSERT_EQ(CborNoError,
            encodeConfResourcePayload(
              "cis", "00000000-0000-0000-0000-000000000001", "at", "apn"));
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  // invalid device
  ctx->device = 42;
  EXPECT_EQ(PLGD_DPS_ERROR_SET_CLOUD, dps_handle_set_cloud_response(&data));

  ctx->device = kDeviceID;
  // logged in and no cloud server set
  auto cloud_ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, cloud_ctx);
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  clearCloudServers(kDeviceID);
  EXPECT_EQ(PLGD_DPS_ERROR_SET_CLOUD, dps_handle_set_cloud_response(&data));
}

TEST_F(DPSProvisionCloudWithServerTest, HandleSetCloudResponse)
{
  oc::RepPool pool{};

  std::string cis = "cis";
  std::string sid = "00000000-0000-0000-0000-000000000001";
  std::string at = "at";
  std::string apn = "apn";
  ASSERT_EQ(CborNoError, encodeConfResourcePayload(cis, sid, at, apn));
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  auto ctx = std::make_unique<plgd_dps_context_t>();
  oc_client_response_t data{};
  data.user_data = ctx.get();
  data.code = OC_STATUS_OK;
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));

  // update signed in cloud with same data
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  ASSERT_NE(nullptr, cloud_ctx);
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));
  rep.reset();
  pool.Clear();

  // update signed in cloud with different cis
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  cis = "nextcis";
  ASSERT_EQ(CborNoError, encodeConfResourcePayload(cis, sid, at, apn));
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));
  rep.reset();
  pool.Clear();

  // update signed in cloud with different apn
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  apn = "nextapn";
  ASSERT_EQ(CborNoError, encodeConfResourcePayload(cis, sid, at, apn));
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));
  rep.reset();
  pool.Clear();

  // update signed in cloud with different sid, but not connected to a cloud
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  sid = "00000000-0000-0000-0000-000000000002";
  ASSERT_EQ(CborNoError, encodeConfResourcePayload(cis, sid, at, apn));
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));
  rep.reset();
  pool.Clear();

  // update signed in cloud with different sid and connected to a cloud
  cloud_ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  std::string uid = "501";
  oc_set_string(&cloud_ctx->store.uid, uid.c_str(), uid.length());
  sid = "00000000-0000-0000-0000-000000000003";
  oc_endpoint_t ep = oc::endpoint::FromString("coap://[ff02::158]");
  memcpy(cloud_ctx->cloud_ep, &ep, sizeof(oc_endpoint_t));
  cloud_ctx->cloud_ep_state = OC_SESSION_CONNECTED;
  ASSERT_EQ(CborNoError, encodeConfResourcePayload(cis, sid, at, apn));
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  EXPECT_EQ(PLGD_DPS_OK, dps_handle_set_cloud_response(&data));
  EXPECT_EQ(OC_SESSION_DISCONNECTED, cloud_ctx->cloud_ep_state);
}

TEST_F(DPSProvisionCloudWithServerTest, HasCloudConfiguration)
{
  // invalid device
  EXPECT_FALSE(dps_has_cloud_configuration(42));

  auto cloud_ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, cloud_ctx);

  // missing access token
  oc_cloud_context_clear(cloud_ctx, false);
  ASSERT_EQ(nullptr, oc_string(*oc_cloud_get_access_token(cloud_ctx)));
  EXPECT_FALSE(dps_has_cloud_configuration(kDeviceID));

  // no selected gateway
  clearCloudServers(kDeviceID);
  EXPECT_FALSE(dps_has_cloud_configuration(kDeviceID));

  // ok
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(cloud_ctx, "coap://[ff02::158]",
                                                "access_token", "", ""));
  EXPECT_TRUE(dps_has_cloud_configuration(kDeviceID));
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudHandler)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  oc_client_response_t data{};
  data.user_data = ctx.get();
  data.code = OC_STATUS_OK;

  // if PLGD_DPS_HAS_CLOUD is not set then PLGD_DPS_GET_CLOUD must be set
  ctx->status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_HAS_OWNER;
  dps_set_cloud_handler(&data);
  EXPECT_EQ(PLGD_DPS_ERROR_SET_CLOUD, ctx->last_error);
  EXPECT_NE(0, ctx->status & PLGD_DPS_FAILURE);

  // returned error code
  ctx->status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_HAS_OWNER |
                PLGD_DPS_GET_CLOUD;
  data.code = OC_STATUS_BAD_REQUEST;
  dps_set_cloud_handler(&data);
  EXPECT_EQ(PLGD_DPS_ERROR_RESPONSE, ctx->last_error);
  EXPECT_NE(0, ctx->status & PLGD_DPS_FAILURE);

  // invalid payload
  data.code = OC_STATUS_OK;
  data.payload = nullptr;
  dps_set_cloud_handler(&data);
  EXPECT_EQ(PLGD_DPS_ERROR_RESPONSE, ctx->last_error);
  EXPECT_NE(0, ctx->status & PLGD_DPS_FAILURE);

  // ok
  oc::RepPool pool{};
  ASSERT_EQ(CborNoError,
            encodeConfResourcePayload(
              "cis", "00000000-0000-0000-0000-000000000001", "at", "apn"));
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  data.payload = rep.get();
  dps_set_cloud_handler(&data);
  EXPECT_EQ(PLGD_DPS_OK, ctx->last_error);
  EXPECT_EQ(PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_HAS_OWNER |
              PLGD_DPS_HAS_CLOUD,
            ctx->status);

  // if PLGD_DPS_HAS_CLOUD flag is already set then nothing should be done
  ctx->status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_HAS_OWNER |
                PLGD_DPS_HAS_CLOUD;
  data.payload = nullptr;
  dps_set_cloud_handler(&data);
  EXPECT_EQ(PLGD_DPS_OK, ctx->last_error);

  dps_manager_stop(ctx.get());
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudEncodeSelectedGatewayFail)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = 42;
  EXPECT_FALSE(dps_provisioning_set_cloud_encode_selected_gateway(ctx.get()));

  oc::RepPool pool{ 1 };
  ctx->device = kDeviceID;
  oc_rep_begin_root_object();
  EXPECT_FALSE(dps_provisioning_set_cloud_encode_selected_gateway(ctx.get()));
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudEncodeSelectedGateway)
{
  oc::RepPool pool{};
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = kDeviceID;

  // with selected gateway
  oc_rep_begin_root_object();
  EXPECT_TRUE(dps_provisioning_set_cloud_encode_selected_gateway(ctx.get()));
  oc_rep_end_root_object();
  auto rep = pool.ParsePayload();
  DPS_DBG("%s", oc::RepPool::GetJson(rep.get(), true).data());

  rep.reset();
  pool.Clear();

  // without selected gateway and selected gateway id
  clearCloudServers(kDeviceID);

  oc_rep_begin_root_object();
  EXPECT_TRUE(dps_provisioning_set_cloud_encode_selected_gateway(ctx.get()));
  oc_rep_end_root_object();
  rep = pool.ParsePayload();
  DPS_DBG("%s", oc::RepPool::GetJson(rep.get(), true).data());
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudEncodePayloadFail)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = 42;
  EXPECT_FALSE(dps_provisioning_set_cloud_encode_payload(ctx.get()));

  oc::RepPool pool{ 1 };
  ctx->device = kDeviceID;
  EXPECT_FALSE(dps_provisioning_set_cloud_encode_payload(ctx.get()));
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudEncodePayload)
{
  oc::RepPool pool{};
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = kDeviceID;
  EXPECT_TRUE(dps_provisioning_set_cloud_encode_payload(ctx.get()));
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloudFail)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = kDeviceID;
  oc_endpoint_t ep = oc::endpoint::FromString("coap://[ff02::158]");
  ctx->endpoint = &ep;

  // must be in RFNOP state
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  pstat->s = OC_DOS_RFOTM;
  EXPECT_FALSE(dps_provisioning_set_cloud(ctx.get()));
}

TEST_F(DPSProvisionCloudWithServerTest, SetCloud)
{
  auto ctx = std::make_unique<plgd_dps_context_t>();
  ctx->device = kDeviceID;
  oc_endpoint_t ep = oc::endpoint::FromString("coap://[ff02::158]");
  ctx->endpoint = &ep;

  EXPECT_TRUE(dps_provisioning_set_cloud(ctx.get()));
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
