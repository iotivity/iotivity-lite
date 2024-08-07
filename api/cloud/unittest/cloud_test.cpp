/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "api/cloud/oc_cloud_apis_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_deregister_internal.h"
#include "api/cloud/oc_cloud_endpoints_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/cloud/oc_cloud_schedule_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "messaging/coap/conf.h"
#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_uuid.h"
#include "port/oc_network_event_handler_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_secure_string_internal.h"
#include "util/oc_features.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#include "security/oc_svr_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include "gtest/gtest.h"

#include <array>
#include <set>
#include <string>
#include <vector>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

class TestCloud : public testing::Test {
public:
  void SetUp() override { oc_runtime_init(); }

  void TearDown() override { oc_runtime_shutdown(); }
};

TEST_F(TestCloud, cloud_is_connection_error_code)
{
  std::set<oc_status_t> connectionErrors{
    OC_STATUS_SERVICE_UNAVAILABLE,
    OC_STATUS_GATEWAY_TIMEOUT,
    OC_CONNECTION_CLOSED,
    OC_TRANSACTION_TIMEOUT,
  };
  for (int i = OC_STATUS_OK; i <= OC_CANCELLED; ++i) {
    bool contains = connectionErrors.count(static_cast<oc_status_t>(i)) == 1;
    EXPECT_EQ(contains,
              cloud_is_connection_error_code(static_cast<oc_status_t>(i)));
  }
}

TEST_F(TestCloud, oc_cloud_set_retry_timeouts)
{
  std::vector<uint16_t> tooManyTimeouts(OC_CLOUD_RETRY_TIMEOUTS_SIZE + 1, 0);
  EXPECT_FALSE(oc_cloud_set_retry_timeouts(tooManyTimeouts.data(),
                                           tooManyTimeouts.size()));

  std::vector<uint16_t> invalidTimeouts{ 1, 42, /*invalid*/ 0, 13 };
  EXPECT_FALSE(oc_cloud_set_retry_timeouts(invalidTimeouts.data(),
                                           invalidTimeouts.size()));

  // restore default values by using NULL
  EXPECT_TRUE(oc_cloud_set_retry_timeouts(nullptr, 0));
}

TEST_F(TestCloud, oc_cloud_get_retry_timeouts)
{
  std::array<uint16_t, 3> timeouts{ 1, 42, 13 };
  ASSERT_TRUE(oc_cloud_set_retry_timeouts(timeouts.data(), timeouts.size()));

  std::array<uint16_t, 1> tooSmall{};
  EXPECT_EQ(-1, oc_cloud_get_retry_timeouts(tooSmall.data(), tooSmall.size()));

  std::vector<uint16_t> result{};
  result.resize(timeouts.size());
  EXPECT_EQ(timeouts.size(),
            oc_cloud_get_retry_timeouts(result.data(), result.size()));
  for (size_t i = 0; i < timeouts.size(); ++i) {
    EXPECT_EQ(timeouts[i], result[i]);
  }

  EXPECT_TRUE(oc_cloud_set_retry_timeouts(nullptr, 0));
  result.resize(OC_CLOUD_RETRY_TIMEOUTS_SIZE);
  EXPECT_EQ(OC_CLOUD_RETRY_TIMEOUTS_SIZE,
            oc_cloud_get_retry_timeouts(result.data(), result.size()));
}

TEST_F(TestCloud, oc_cloud_init_fail)
{
  ASSERT_TRUE(oc_cloud_init());
  // multiple initialization is not allowed
  EXPECT_FALSE(oc_cloud_init());

  oc_cloud_shutdown();
}

TEST_F(TestCloud, oc_cloud_shutdown_fail)
{
  oc_network_event_handler_mutex_init();
  oc_ri_init();
  oc_core_init();
  ASSERT_EQ(0, oc_init_platform("OCFTest", nullptr, nullptr));
  ASSERT_EQ(
    0, oc_add_device(
         oc::DefaultDevice.uri.c_str(), oc::DefaultDevice.rt.c_str(),
         oc::DefaultDevice.name.c_str(), oc::DefaultDevice.spec_version.c_str(),
         oc::DefaultDevice.data_model_version.c_str(), nullptr, nullptr));
#ifdef OC_SECURITY
  oc_sec_svr_create();
#endif /* OC_SECURITY */
  ASSERT_TRUE(oc_cloud_init());

  oc_cloud_shutdown();
  // multiple shutdown is not allowed, but the app should not crash
  oc_cloud_shutdown();

#ifdef OC_SECURITY
  oc_sec_svr_free();
#endif /* OC_SECURITY */
#ifdef OC_HAS_FEATURE_PUSH
  oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
  oc_connectivity_shutdown(/*device*/ 0);
  oc_core_shutdown();
  oc_ri_shutdown();
  oc_network_event_handler_mutex_destroy();
}

#if !defined(OC_SECURITY)
// we need static allocation to ensure that allocation fails
// we need insecure build, because for secure build we need to have a valid
// pstat, which is not the case here
TEST_F(TestCloud, cloud_init_devices)
{
  EXPECT_FALSE(cloud_init_devices(1));

  oc_ri_init();
  oc_core_init();
  // add device 0, but platform resource is missing
  ASSERT_EQ(
    0, oc_add_device(
         oc::DefaultDevice.uri.c_str(), oc::DefaultDevice.rt.c_str(),
         oc::DefaultDevice.name.c_str(), oc::DefaultDevice.spec_version.c_str(),
         oc::DefaultDevice.data_model_version.c_str(), nullptr, nullptr));
  EXPECT_FALSE(cloud_init_devices(1));

  ASSERT_EQ(0, oc_init_platform("OCFTest", nullptr, nullptr));
  EXPECT_TRUE(cloud_init_devices(1));
  cloud_deinit_devices(1);

  EXPECT_FALSE(cloud_init_devices(2));

  oc_cloud_shutdown();
#ifdef OC_HAS_FEATURE_PUSH
  oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
  oc_connectivity_shutdown(/*device*/ 0);
  oc_core_shutdown();
  oc_ri_shutdown();
}

#endif /* !OC_SECURITY */

class TestCloudWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override
  {
    oc::TestDevice::Reset();

    auto *ctx = oc_cloud_get_context(kDeviceID);
    oc_cloud_context_clear(ctx, false);
  }
};

TEST_F(TestCloudWithServer, oc_cloud_get_context)
{
  EXPECT_NE(nullptr, oc_cloud_get_context(kDeviceID));
  EXPECT_EQ(nullptr, oc_cloud_get_context(42));
}

TEST_F(TestCloudWithServer, set_published_resources_ttl)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  uint32_t default_ttl = ctx->time_to_live;
  oc_cloud_set_published_resources_ttl(ctx, 42);
  EXPECT_EQ(42, ctx->time_to_live);

  oc_cloud_set_published_resources_ttl(ctx, default_ttl);
}

TEST_F(TestCloudWithServer, cloud_status)
{
  oc_cloud_status_t status;
  memset(&status, 0, sizeof(status));
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_INITIALIZED;
  cloud_manager_cb(ctx);
  EXPECT_EQ(ctx->store.status, status);
}

TEST_F(TestCloudWithServer, cloud_set_last_error)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
  ASSERT_EQ(CLOUD_ERROR_RESPONSE, ctx->last_error);
}

TEST_F(TestCloudWithServer, oc_cloud_update_by_resource)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_FAILURE;

  oc_cloud_conf_update_t data{};
  auto access_token = OC_STRING_LOCAL("access_token");
  data.access_token = &access_token;
  auto auth_provider = OC_STRING_LOCAL("auth_provider");
  data.auth_provider = &auth_provider;
  auto ci_server = OC_STRING_LOCAL("ci_server");
  data.ci_server = &ci_server;
  auto sid = OC_STRING_LOCAL("12345678-1234-5678-1234-567812345678");
  oc_str_to_uuid(oc_string(sid), &data.sid);

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
  auto ci_servers_rep = pool.ParsePayload();
  auto *ci_servers = oc_rep_get_by_type_and_key(
    ci_servers_rep.get(), OC_REP_OBJECT_ARRAY, key.c_str(), key.length());
  ASSERT_NE(nullptr, ci_servers);
  data.ci_servers = ci_servers->value.object_array;
  oc_cloud_update_by_resource(ctx, &data);

  EXPECT_STREQ(oc_string(*data.access_token),
               oc_string(*oc_cloud_get_access_token(ctx)));
  EXPECT_STREQ(oc_string(*data.auth_provider),
               oc_string(*oc_cloud_get_authorization_provider_name(ctx)));
  const auto *ctx_cis = oc_cloud_get_server_uri(ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(oc_string(*data.ci_server), oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(data.sid, *oc_cloud_get_server_id(ctx)));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
}

TEST_F(TestCloudWithServer, oc_cloud_provision_conf_resource)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);

  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(ctx, nullptr, nullptr, nullptr,
                                                 nullptr));

  std::string invalid(OC_MAX_STRING_LENGTH, 'a');
  const char *ci_server = "ci_server";
  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(ctx, ci_server, nullptr,
                                                 nullptr, nullptr));

  const char *access_token = "access_token";
  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                 nullptr, nullptr));

  const char *sid = "12345678-1234-5678-1234-567812345678";
  oc_uuid_t sid_uuid;
  oc_str_to_uuid(sid, &sid_uuid);
  EXPECT_EQ(0, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                sid, nullptr));

  const char *auth_provider = "auth_provider";
  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(
                  ctx, invalid.c_str(), access_token, sid, auth_provider));
  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(
                  ctx, ci_server, invalid.c_str(), sid, auth_provider));
  EXPECT_EQ(-1,
            oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                             invalid.c_str(), auth_provider));
  EXPECT_EQ(-1, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                 sid, invalid.c_str()));

  ASSERT_EQ(0, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                sid, auth_provider));
  EXPECT_STREQ(access_token, oc_string(*oc_cloud_get_access_token(ctx)));
  EXPECT_STREQ(auth_provider,
               oc_string(*oc_cloud_get_authorization_provider_name(ctx)));
  const auto *ctx_cis = oc_cloud_get_server_uri(ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(ci_server, oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(sid_uuid, *oc_cloud_get_server_id(ctx)));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);

  ASSERT_EQ(0, oc_cloud_provision_conf_resource(ctx, "", "", "", ""));
  EXPECT_EQ(nullptr, oc_string(*oc_cloud_get_access_token(ctx)));
  EXPECT_EQ(nullptr, oc_string(*oc_cloud_get_authorization_provider_name(ctx)));
  ctx_cis = oc_cloud_get_server_uri(ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID,
                               *oc_cloud_get_server_id(ctx)));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
}

TEST_F(TestCloudWithServer, oc_cloud_provision_conf_resource_with_started_cloud)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_FALSE(
    oc_cloud_registration_context_is_initialized(&ctx->registration_ctx));
  ctx->store.status = OC_CLOUD_INITIALIZED;
  ASSERT_EQ(0, oc_cloud_manager_start(ctx, nullptr, nullptr));
  ASSERT_TRUE(
    oc_cloud_registration_context_is_initialized(&ctx->registration_ctx));
  auto defaulServer = OC_STRING_LOCAL(OCF_COAPCLOUDCONF_DEFAULT_CIS);
  EXPECT_TRUE(
    oc_string_is_equal(&ctx->registration_ctx.initial_server, &defaulServer));

  std::string_view ci_server = "ci_server";
  std::string_view access_token = "access_token";
  std::string_view sid = "12345678-1234-5678-1234-567812345678";
  oc_uuid_t sid_uuid;
  oc_str_to_uuid(sid.data(), &sid_uuid);
  std::string_view auth_provider = "auth_provider";
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(ctx, ci_server.data(),
                                                access_token.data(), sid.data(),
                                                auth_provider.data()));
  EXPECT_STREQ(access_token.data(), oc_string(*oc_cloud_get_access_token(ctx)));
  EXPECT_STREQ(auth_provider.data(),
               oc_string(*oc_cloud_get_authorization_provider_name(ctx)));
  const auto *ctx_cis = oc_cloud_get_server_uri(ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(ci_server.data(), oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(sid_uuid, *oc_cloud_get_server_id(ctx)));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
  EXPECT_TRUE(oc_cloud_manager_is_started(ctx));
  EXPECT_TRUE(oc_string_view_is_equal(
    oc_string_view2(&ctx->registration_ctx.initial_server),
    oc_string_view(ci_server.data(), ci_server.length())));
}

TEST_F(TestCloudWithServer, oc_cloud_action_to_str)
{
  std::string v;
  v.assign(oc_cloud_action_to_str(OC_CLOUD_ACTION_REGISTER));
  EXPECT_EQ(OC_CLOUD_ACTION_REGISTER_STR, v);
  v.assign(oc_cloud_action_to_str(OC_CLOUD_ACTION_REFRESH_TOKEN));
  EXPECT_EQ(OC_CLOUD_ACTION_REFRESH_TOKEN_STR, v);
  v.assign(oc_cloud_action_to_str(OC_CLOUD_ACTION_LOGIN));
  EXPECT_EQ(OC_CLOUD_ACTION_LOGIN_STR, v);
  v.assign(oc_cloud_action_to_str(OC_CLOUD_ACTION_UNKNOWN));
  EXPECT_EQ(OC_CLOUD_ACTION_UNKNOWN_STR, v);
}

static void
setRFNOP(void)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFNOP;
#endif /* OC_SECURITY */
}

static void
provisionCloud(oc_cloud_context_t *ctx, const std::string &uid = {})
{
  const char *access_token = "access_token";
  const char *auth_provider = "auth_provider";
  const char *ci_server = "coap://224.0.1.187:5683";
  const char *sid = "12345678-1234-5678-1234-567812345678";
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(ctx, ci_server, access_token,
                                                sid, auth_provider));
  if (!uid.empty()) {
    oc_set_string(&ctx->store.uid, uid.c_str(), uid.length());
  }
}

TEST_F(TestCloudWithServer, oc_cloud_register_already_registered)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // if the cloud is already registered, then the callback is called immediately
  ctx->store.status = OC_CLOUD_REGISTERED;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_REGISTERED, status);
  };

  ASSERT_EQ(0, oc_cloud_register(ctx, cbk, &cbk_called));
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_register_fail_invalid_input)
{
  EXPECT_EQ(-1, oc_cloud_register(nullptr, nullptr, nullptr));

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_EQ(-1, oc_cloud_register(ctx, nullptr, nullptr));
}

TEST_F(TestCloudWithServer, oc_cloud_register_fail_invalid_status)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // all other states than OC_CLOUD_INITIALIZED or OC_CLOUD_REGISTERED are
  // invalid
  ctx->store.status = OC_CLOUD_DEREGISTERED;
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_register(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_register_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  ASSERT_EQ(-1, oc_cloud_register(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_register)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx);
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };
  EXPECT_TRUE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_register(ctx, cbk, &cbk_called, timeout.count()));
  EXPECT_FALSE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_login_already_logged_in)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // if the cloud is already logged in, then the callback is called immediately
  ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN, status);
  };

  ASSERT_EQ(0, oc_cloud_login(ctx, cbk, &cbk_called));
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_login_fail_invalid_input)
{
  EXPECT_EQ(-1, oc_cloud_login(nullptr, nullptr, nullptr));

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_EQ(-1, oc_cloud_login(ctx, nullptr, nullptr));
}

TEST_F(TestCloudWithServer, oc_cloud_login_fail_invalid_status)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // must contain the OC_CLOUD_REGISTERED flag to be valid
  ctx->store.status = OC_CLOUD_INITIALIZED;
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_login(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_login_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ctx->store.status = OC_CLOUD_REGISTERED;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  ASSERT_EQ(-1, oc_cloud_login(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_login)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "uid");
  ctx->store.status = OC_CLOUD_REGISTERED;
  EXPECT_TRUE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_login(ctx, cbk, &cbk_called, timeout.count()));
  EXPECT_FALSE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_refresh_token_fail_invalid_input)
{
  EXPECT_EQ(-1, oc_cloud_refresh_token(nullptr, nullptr, nullptr));

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_EQ(-1, oc_cloud_refresh_token(ctx, nullptr, nullptr));
}

TEST_F(TestCloudWithServer, oc_cloud_refresh_token_fail_invalid_status)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // must contain the OC_CLOUD_REGISTERED flag to be valid
  ctx->store.status = OC_CLOUD_INITIALIZED;
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_refresh_token(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_refresh_token_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ctx->store.status = OC_CLOUD_REGISTERED;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  ASSERT_EQ(-1, oc_cloud_refresh_token(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_refresh_token)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string refresh_token = "refresh_token";
  oc_set_string(&ctx->store.refresh_token, refresh_token.c_str(),
                refresh_token.length());
  ctx->store.status = OC_CLOUD_REGISTERED;
  EXPECT_TRUE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };

  auto timeout = 1s;
  ASSERT_EQ(0,
            oc_cloud_do_refresh_token(ctx, cbk, &cbk_called, timeout.count()));
  EXPECT_FALSE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_logout_fail_invalid_input)
{
  EXPECT_EQ(-1, oc_cloud_logout(nullptr, nullptr, nullptr));

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_EQ(-1, oc_cloud_logout(ctx, nullptr, nullptr));
}

TEST_F(TestCloudWithServer, oc_cloud_logout_fail_invalid_status)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // must contain the OC_CLOUD_LOGGED_IN flag to be valid
  ctx->store.status = OC_CLOUD_INITIALIZED;
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_logout(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_logout_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  ASSERT_EQ(-1, oc_cloud_logout(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_logout)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  EXPECT_TRUE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_logout(ctx, cbk, &cbk_called, timeout.count()));
  EXPECT_FALSE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_deregister_fail_invalid_input)
{
  EXPECT_EQ(-1, oc_cloud_deregister(nullptr, nullptr, nullptr));

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_EQ(-1, oc_cloud_deregister(ctx, nullptr, nullptr));
}

TEST_F(TestCloudWithServer, oc_cloud_deregister_fail_invalid_status)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // must contain the OC_CLOUD_REGISTERED flag to be valid
  ctx->store.status = OC_CLOUD_INITIALIZED;
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_deregister(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_deregister_fail_already_deregistering)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  // if the cloud is already logged in, then the callback is called immediately
  ctx->store.status = OC_CLOUD_REGISTERED;
  ctx->store.cps = OC_CPS_DEREGISTERING;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };

  ASSERT_EQ(CLOUD_DEREGISTER_ERROR_ALREADY_DEREGISTERING,
            oc_cloud_deregister(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_deregister_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ctx->store.status = OC_CLOUD_REGISTERED;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  ASSERT_EQ(-1, oc_cloud_deregister(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_deregister_with_short_access_token)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  ctx->store.status = OC_CLOUD_REGISTERED;
  EXPECT_TRUE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_deregister(ctx, /*sync*/ true, timeout.count(), cbk,
                                      &cbk_called));
  EXPECT_FALSE(oc_endpoint_is_empty(oc_cloud_get_server(ctx)));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestCloudWithServer,
       oc_cloud_deregister_fail_not_logged_in_long_access_token)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  ASSERT_EQ(-1, oc_cloud_deregister(ctx, cbk, &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_deregister_logged_in)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t status,
                void *user_data) {
    *static_cast<bool *>(user_data) = true;
    EXPECT_EQ(OC_CLOUD_FAILURE, (status & OC_CLOUD_FAILURE));
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_deregister(ctx, /*sync*/ true, timeout.count(), cbk,
                                      &cbk_called));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_deregister_with_refresh_token)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  std::string refresh_token = "refresh_token";
  oc_set_string(&ctx->store.refresh_token, refresh_token.c_str(),
                refresh_token.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_deregister(ctx, /*sync*/ false, timeout.count(), cbk,
                                      &cbk_called));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer,
       oc_cloud_deregister_with_refresh_token_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  std::string refresh_token = "refresh_token";
  oc_set_string(&ctx->store.refresh_token, refresh_token.c_str(),
                refresh_token.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };

  ASSERT_EQ(-1, oc_cloud_do_deregister(ctx, /*sync*/ false, /*timeout*/ 0, cbk,
                                       &cbk_called));
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_do_deregister_with_login)
{
  setRFNOP();

  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED;

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };

  auto timeout = 1s;
  ASSERT_EQ(0, oc_cloud_do_deregister(ctx, /*sync*/ false, timeout.count(), cbk,
                                      &cbk_called));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_FALSE(cbk_called);
}

TEST_F(TestCloudWithServer, oc_cloud_deregister_with_login_fail_invalid_server)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  provisionCloud(ctx, "501");
  std::string longAccessToken(COAP_MAX_HEADER_SIZE, 'a');
  oc_set_string(&ctx->store.access_token, longAccessToken.c_str(),
                longAccessToken.length());
  ASSERT_FALSE(oc_cloud_check_accesstoken_for_deregister(ctx));
  ctx->store.status = OC_CLOUD_REGISTERED;
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);

  bool cbk_called = false;
  auto cbk = [](oc_cloud_context_t *, oc_cloud_status_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };

  ASSERT_EQ(-1, oc_cloud_do_deregister(ctx, /*sync*/ false, /*timeout*/ 0, cbk,
                                       &cbk_called));
  EXPECT_FALSE(cbk_called);

  ctx->store.cps = OC_CPS_UNINITIALIZED;
  std::string refresh_token = "refresh_token";
  oc_set_string(&ctx->store.refresh_token, refresh_token.c_str(),
                refresh_token.length());
  ctx->store.expires_in = -1;
  // permanent access token should force login attempt even if refresh token is
  // set
  ASSERT_TRUE(cloud_context_has_permanent_access_token(ctx));
  ASSERT_EQ(-1, oc_cloud_do_deregister(ctx, /*sync*/ false, /*timeout*/ 0, cbk,
                                       &cbk_called));
  EXPECT_FALSE(cbk_called);
}

// TODO: async deregister steps with mocked cloud

TEST_F(TestCloudWithServer, EndpointAPI)
{
  oc_cloud_context_t *ctx = cloud_context_init(/*device*/ 0);
  ASSERT_NE(nullptr, ctx);
  // after initialization, the default endpoint should be selected
  const auto *ctx_cis = oc_cloud_get_server_uri(ctx);
  ASSERT_NE(nullptr, ctx_cis);
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, oc_string(*ctx_cis));
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID,
                               *oc_cloud_get_server_id(ctx)));
  // remove default
  oc_endpoint_addresses_clear(&ctx->store.ci_servers);
  // no endpoint selected -> both cis and sid should be nullptr
  EXPECT_EQ(nullptr, oc_cloud_selected_server_address(ctx));
  EXPECT_EQ(nullptr, oc_cloud_get_server_uri(ctx));
  EXPECT_EQ(nullptr, oc_cloud_get_server_id(ctx));

  // add
  std::string uri1 = "/uri/1";
  oc_uuid_t uid1;
  oc_gen_uuid(&uid1);
  auto *ep1 =
    oc_cloud_add_server_address(ctx, uri1.c_str(), uri1.length(), uid1);
  ASSERT_NE(nullptr, ep1);
  std::string uri2 = "/uri/2";
  oc_uuid_t uid2;
  oc_gen_uuid(&uid2);
  auto *ep2 =
    oc_cloud_add_server_address(ctx, uri2.c_str(), uri2.length(), uid2);
  ASSERT_NE(nullptr, ep2);
  std::string uri3 = "/uri/3";
  oc_uuid_t uid3;
  oc_gen_uuid(&uid3);
  auto *ep3 =
    oc_cloud_add_server_address(ctx, uri3.c_str(), uri3.length(), uid3);
  ASSERT_NE(nullptr, ep3);

  // first item added to empty list should be selected
  EXPECT_EQ(ep1, oc_cloud_selected_server_address(ctx));
  EXPECT_STREQ(uri1.c_str(), oc_string(*oc_cloud_get_server_uri(ctx)));
  EXPECT_TRUE(oc_uuid_is_equal(uid1, *oc_cloud_get_server_id(ctx)));

  // remove the first item
  ASSERT_TRUE(oc_cloud_remove_server_address(ctx, ep1));

  // next endpoint should be selected
  EXPECT_EQ(ep2, oc_cloud_selected_server_address(ctx));
  EXPECT_STREQ(uri2.c_str(), oc_string(*oc_cloud_get_server_uri(ctx)));
  EXPECT_TRUE(oc_uuid_is_equal(uid2, *oc_cloud_get_server_id(ctx)));

  std::set<std::string, std::less<>> uris{};
  // iterate
  oc_cloud_iterate_server_addresses(
    ctx,
    [](oc_endpoint_address_t *ea, void *data) {
      auto uri = oc_endpoint_address_uri(ea);
      static_cast<std::set<std::string> *>(data)->insert(
        std::string(oc_string(*uri), oc_string_len(*uri)));
      return true;
    },
    &uris);

  ASSERT_EQ(2, uris.size());
  EXPECT_NE(uris.end(), uris.find(uri3));
  EXPECT_NE(uris.end(), uris.find(uri2));
  EXPECT_EQ(uris.end(), uris.find(uri1));

  oc_endpoint_address_t *toSelect = nullptr;
  // iterate to get the last endpoint
  oc_cloud_iterate_server_addresses(
    ctx,
    [](oc_endpoint_address_t *ea, void *data) {
      *static_cast<oc_endpoint_address_t **>(data) = ea;
      return true;
    },
    &toSelect);

  oc_endpoint_address_t notInList{};
  EXPECT_FALSE(oc_cloud_select_server_address(ctx, &notInList));

  ASSERT_NE(nullptr, toSelect);
  EXPECT_TRUE(oc_cloud_select_server_address(ctx, toSelect));
  EXPECT_EQ(ep3, oc_cloud_selected_server_address(ctx));
  EXPECT_STREQ(uri3.c_str(), oc_string(*oc_cloud_get_server_uri(ctx)));
  EXPECT_TRUE(oc_uuid_is_equal(uid3, *oc_cloud_get_server_id(ctx)));

  oc_uuid_t uid;
  oc_gen_uuid(&uid);
  oc_endpoint_address_set_uuid(toSelect, uid);
  EXPECT_TRUE(oc_uuid_is_equal(uid, *oc_endpoint_address_uuid(toSelect)));
  EXPECT_TRUE(oc_uuid_is_equal(uid, *oc_cloud_get_server_id(ctx)));

  EXPECT_TRUE(oc_cloud_remove_server_address(ctx, toSelect));

  cloud_context_deinit(ctx);
}

#endif /* OC_DYNAMIC_ALLOCATION */
