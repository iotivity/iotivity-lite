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
#include "api/cloud/oc_cloud_manager_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/cloud/oc_cloud_schedule_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_runtime_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_rep.h"
#include "oc_cloud.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

using namespace std::chrono_literals;

#ifndef OC_SECURITY

// cannot use lower value than 1s because oc_cloud_schedule_action_t::timeout is
// in seconds
static constexpr auto kTimeout = 1s;
static constexpr auto kTestServer = OC_STRING_VIEW("coap://224.0.1.187:5683");

class TestCloudManager : public testing::Test {
public:
  oc_cloud_context_t m_context;

  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override
  {
    std::array<uint16_t, 2> timeouts = {
      std::chrono::duration_cast<std::chrono::milliseconds>(kTimeout).count(),
      // make the second timeout longer, so we can interrupt the retry
      std::chrono::duration_cast<std::chrono::milliseconds>(5s).count(),
    };
    ASSERT_TRUE(oc_cloud_set_retry_timeouts(timeouts.data(), timeouts.size()));

    memset(&m_context, 0, sizeof(m_context));
    m_context.cloud_ep = oc_new_endpoint();
    memset(m_context.cloud_ep, 0, sizeof(oc_endpoint_t));
    oc_cloud_store_initialize(&m_context.store, cloud_context_on_server_change,
                              &m_context);
    oc_uuid_t sid;
    oc_gen_uuid(&sid);
    ASSERT_NE(nullptr,
              oc_endpoint_addresses_add(
                &m_context.store.ci_servers,
                oc_endpoint_address_make_view_with_uuid(kTestServer, sid)));
    ASSERT_TRUE(oc_endpoint_addresses_select_by_uri(&m_context.store.ci_servers,
                                                    kTestServer));
    std::string uid = "501";
    oc_set_string(&m_context.store.uid, uid.c_str(), uid.length());
    std::string token = "access_token";
    oc_set_string(&m_context.store.access_token, token.c_str(), token.length());
    std::string rtoken = "refresh_token";
    oc_set_string(&m_context.store.refresh_token, rtoken.c_str(),
                  rtoken.length());
  }

  void TearDown() override
  {
    oc_cloud_set_schedule_action(&m_context, nullptr, nullptr);
    ASSERT_TRUE(oc_cloud_set_retry_timeouts(nullptr, 0));

    oc_free_endpoint(m_context.cloud_ep);
    oc_cloud_store_deinitialize(&m_context.store);
    oc::TestDevice::Reset();
  }

  static void schedule_stop_cloud_manager(oc_cloud_context_t *ctx)
  {
    oc_set_delayed_callback(
      ctx,
      [](void *data) -> oc_event_callback_retval_t {
        auto *ctx = static_cast<oc_cloud_context_t *>(data);
        cloud_manager_stop(ctx);
        return OC_EVENT_DONE;
      },
      0);
  }
};

TEST_F(TestCloudManager, oc_cloud_manager_start_fail)
{
  EXPECT_EQ(-1, oc_cloud_manager_start(nullptr, nullptr, nullptr));
}

TEST_F(TestCloudManager, oc_cloud_manager_stop_fail)
{
  EXPECT_EQ(-1, oc_cloud_manager_stop(nullptr));
}

TEST_F(TestCloudManager, oc_cloud_manager_stop_v1)
{
  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));
  ASSERT_TRUE(oc_cloud_manager_is_started(&m_context));

  // if cloud is registered and logged in, then the login flag should be
  // removed, so on restart will attempt to login again
  m_context.store.status =
    OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  m_context.store.cps = OC_CPS_REGISTERED;
  oc_cloud_manager_stop_v1(&m_context, false);
  EXPECT_FALSE(oc_cloud_manager_is_started(&m_context));
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED, m_context.store.status);
  EXPECT_EQ(OC_CPS_REGISTERED, m_context.store.cps);

  // if cloud is stopped during registration, then it should be in the ready to
  // register state
  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));
  ASSERT_TRUE(oc_cloud_manager_is_started(&m_context));
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_REGISTERING;
  oc_cloud_manager_stop_v1(&m_context, false);
  EXPECT_FALSE(oc_cloud_manager_is_started(&m_context));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
  EXPECT_EQ(OC_CPS_READYTOREGISTER, m_context.store.cps);

  // if the cloud is not configured, then the configuration should be reset
  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));
  ASSERT_TRUE(oc_cloud_manager_is_started(&m_context));
  m_context.store.status =
    OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  m_context.store.cps = OC_CPS_REGISTERED;
  // this sets the default cloud server, but access token will not be set
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(&m_context, "", "", "", ""));
  ASSERT_EQ(nullptr, oc_string(*oc_cloud_get_access_token(&m_context)));
  oc_cloud_manager_stop_v1(&m_context, false);
  EXPECT_FALSE(oc_cloud_manager_is_started(&m_context));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
  EXPECT_EQ(OC_CPS_UNINITIALIZED, m_context.store.cps);

  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));
  ASSERT_TRUE(oc_cloud_manager_is_started(&m_context));
  m_context.store.status =
    OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_LOGGED_IN;
  m_context.store.cps = OC_CPS_REGISTERED;
  // access token set
  ASSERT_EQ(0, oc_cloud_provision_conf_resource(&m_context, "", "access_token",
                                                "", ""));
  ASSERT_NE(nullptr, oc_string(*oc_cloud_get_access_token(&m_context)));
  // but no cloud server set
  oc_endpoint_addresses_clear(&m_context.store.ci_servers);
  oc_cloud_manager_stop_v1(&m_context, false);
  EXPECT_FALSE(oc_cloud_manager_is_started(&m_context));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
  EXPECT_EQ(OC_CPS_UNINITIALIZED, m_context.store.cps);
}

TEST_F(TestCloudManager, oc_cloud_manager_is_started)
{
  EXPECT_FALSE(oc_cloud_manager_is_started(&m_context));
}

TEST_F(TestCloudManager, cloud_manager_start_initialized_schedule_turnoff)
{
  // When
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t, uint8_t, uint64_t *, uint16_t *, void *) -> bool {
      return false;
    },
    nullptr);

  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  cloud_manager_start(&m_context);
  oc::TestDevice::PoolEventsMsV1(100ms);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_EQ(0, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_CONNECT, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
}

TEST_F(TestCloudManager,
       cloud_manager_start_initialized_schedule_without_retry_and_access_token)
{
  // When
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t action, uint8_t retry, uint64_t *delay,
       uint16_t *timeout, void *data) -> bool {
      auto *ctx = static_cast<oc_cloud_context_t *>(data);
      if (action == OC_CLOUD_ACTION_REGISTER && retry == 0) {
        *delay = 0;
        *timeout = kTimeout.count();
        return true;
      }
      // to avoid override m_context.last_error and m_context.store.status
      schedule_stop_cloud_manager(ctx);
      return false;
    },
    &m_context);

  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  oc_free_string(&m_context.store.access_token);

  cloud_manager_start(&m_context);
  oc::TestDevice::PoolEventsMsV1(kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_EQ(1, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_CONNECT, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_initialized_without_retry_f)
{
  // When
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t, uint8_t retry_count, uint64_t *delay,
       uint16_t *timeout, void *data) -> bool {
      auto *ctx = static_cast<oc_cloud_context_t *>(data);
      if (retry_count == 0) {
        *delay = 0;
        *timeout = kTimeout.count();
        return true;
      }
      // to avoid override m_context.last_error and m_context.store.status
      schedule_stop_cloud_manager(ctx);
      return false;
    },
    &m_context);

  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  cloud_manager_start(&m_context);
  oc::TestDevice::PoolEventsMsV1(kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_CONNECT, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_initialized_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  cloud_manager_start(&m_context);
  // by default: first retry should happen timeout + jitter
  // ([timeout/2..timeout])  (see default_schedule_action)
  oc::TestDevice::PoolEventsMsV1(
    /*timeout*/ kTimeout + /*max possible jitter*/ kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_registered_without_retry_and_uid_f)
{
  // When
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t action, uint8_t retry, uint64_t *delay,
       uint16_t *timeout, void *data) -> bool {
      auto *ctx = static_cast<oc_cloud_context_t *>(data);
      if (action == OC_CLOUD_ACTION_LOGIN && retry == 0) {
        *delay = 0;
        *timeout = kTimeout.count();
        return true;
      }
      // to avoid override m_context.last_error and m_context.store.status
      schedule_stop_cloud_manager(ctx);
      return false;
    },
    &m_context);
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  m_context.store.expires_in = -1;
  oc_free_string(&m_context.store.uid);
  cloud_manager_start(&m_context);
  oc::TestDevice::PoolEventsMsV1(kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_CONNECT, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_FAILURE,
            m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_registered_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  m_context.store.expires_in = -1;
  cloud_manager_start(&m_context);
  // by default: first retry should happen timeout + jitter
  // ([timeout/2..timeout])  (see default_schedule_action)
  oc::TestDevice::PoolEventsMsV1(
    /*timeout*/ kTimeout + /*max possible jitter*/ kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry.count);
  EXPECT_EQ(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED, m_context.store.status);
}

TEST_F(TestCloudManager,
       cloud_manager_start_with_refresh_token_without_uid_and_retry_f)
{
  // When
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t action, uint8_t retry, uint64_t *delay,
       uint16_t *timeout, void *data) -> bool {
      auto *ctx = static_cast<oc_cloud_context_t *>(data);
      if (action == OC_CLOUD_ACTION_REFRESH_TOKEN && retry == 0) {
        *delay = 0;
        *timeout = kTimeout.count();
        return true;
      }
      // to avoid override m_context.last_error and m_context.store.status
      schedule_stop_cloud_manager(ctx);
      return false;
    },
    &m_context);
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  oc_free_string(&m_context.store.uid);
  cloud_manager_start(&m_context);
  oc::TestDevice::PoolEventsMsV1(kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_EQ(0, m_context.retry.count);
  EXPECT_LT(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_REFRESH_ACCESS_TOKEN, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED | OC_CLOUD_FAILURE,
            m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_with_refresh_token_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  cloud_manager_start(&m_context);
  // by default: first retry should happen timeout + jitter
  // ([timeout/2..timeout])  (see default_schedule_action)
  oc::TestDevice::PoolEventsMsV1(
    /*timeout*/ kTimeout + /*max possible jitter*/ kTimeout, true);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_EQ(0, m_context.retry.count);
  EXPECT_LT(0, m_context.retry.refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_select_next_server_on_retry)
{
  // single try -> the cloud server endpoint should be changed after each try
  uint16_t timeout =
    std::chrono::duration_cast<std::chrono::milliseconds>(kTimeout).count();
  ASSERT_TRUE(oc_cloud_set_retry_timeouts(&timeout, 1));

  oc_string_view_t uri = OC_STRING_VIEW("coap://13.3.7.187:5683");
  oc_uuid_t sid;
  oc_gen_uuid(&sid);
  auto *ep = oc_endpoint_addresses_add(
    &m_context.store.ci_servers,
    oc_endpoint_address_make_view_with_uuid(uri, sid));
  ASSERT_NE(nullptr, ep);
  ASSERT_FALSE(
    oc_endpoint_addresses_is_selected(&m_context.store.ci_servers, uri));
  // default cloud server (127.0.0.1), kTestServer and uri
  ASSERT_EQ(3, oc_endpoint_addresses_size(&m_context.store.ci_servers));

  ASSERT_TRUE(oc_endpoint_addresses_is_selected(&m_context.store.ci_servers,
                                                kTestServer));
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));
  // by default: first retry should happen timeout + jitter
  // ([timeout/2..timeout])  (see default_schedule_action)
  auto interval = (/* 3 servers to try */ 3) *
                  (/*timeout*/ kTimeout + /*max possible jitter*/ kTimeout);
  oc::TestDevice::PoolEventsMsV1(interval, true);

  // the retries should loop all servers and loop back to the original
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&m_context.store.ci_servers,
                                                kTestServer));
  ASSERT_EQ(0, oc_cloud_manager_stop(&m_context));
}

TEST_F(TestCloudManager, cloud_manager_select_next_server_on_custom_retry)
{
  struct schedule_action_t
  {
    oc_cloud_context_t *ctx;
    bool epChanged;
  };
  schedule_action_t scheduleAction = { &m_context, false };
  oc_cloud_set_schedule_action(
    &m_context,
    [](oc_cloud_action_t action, uint8_t retry, uint64_t *delay,
       uint16_t *timeout, void *data) -> bool {
      if (action == OC_CLOUD_ACTION_REGISTER && retry == 0) {
        *delay = 0;
        *timeout = kTimeout.count();
        return true;
      }
      auto *sact = static_cast<schedule_action_t *>(data);
      if (!sact->epChanged) {
        oc_endpoint_addresses_select_next(&sact->ctx->store.ci_servers);
        sact->epChanged = true;
      }
      return false;
    },
    &scheduleAction);

  oc_string_view_t uri = OC_STRING_VIEW("coap://13.3.7.187:5683");
  oc_uuid_t sid;
  oc_gen_uuid(&sid);
  auto *ep = oc_endpoint_addresses_add(
    &m_context.store.ci_servers,
    oc_endpoint_address_make_view_with_uuid(uri, sid));
  ASSERT_NE(nullptr, ep);
  ASSERT_FALSE(
    oc_endpoint_addresses_is_selected(&m_context.store.ci_servers, uri));
  ASSERT_EQ(3, oc_endpoint_addresses_size(&m_context.store.ci_servers));

  ASSERT_TRUE(oc_endpoint_addresses_is_selected(&m_context.store.ci_servers,
                                                kTestServer));
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  ASSERT_EQ(0, oc_cloud_manager_start(&m_context, nullptr, nullptr));

  // 2 servers should be tried -> after the first server is tried, the schedule
  //  action invokes oc_endpoint_addresses_select_next but only once; after that
  // the retry should stop because the server selection was not changed
  auto interval = (/* 2 servers to try */ 2) * (/*timeout*/ kTimeout);
  oc::TestDevice::PoolEventsMsV1(interval, true);

  EXPECT_TRUE(
    oc_endpoint_addresses_is_selected(&m_context.store.ci_servers, uri));
  ASSERT_EQ(0, oc_cloud_manager_stop(&m_context));
}

#endif /* !OC_SECURITY */

class TestCloudManagerData : public testing::Test {
public:
  static void SetUpTestCase() { oc_runtime_init(); }
  static void TearDownTestCase() { oc_runtime_shutdown(); }

  void SetUp() override
  {
    memset(&m_context, 0, sizeof(m_context));
    oc_cloud_endpoint_addresses_init(&m_context.store.ci_servers, nullptr,
                                     nullptr, OC_STRING_VIEW_NULL, {});
  }

  void TearDown() override
  {
    Clear();
    oc_cloud_store_deinitialize(&m_context.store);
  }

  void Clear() { pool_.Clear(); }

  oc::oc_rep_unique_ptr ParsePayload() { return pool_.ParsePayload(); }

  static void PrintJson(const oc_rep_t *rep)
  {
    (void)rep;
#if OC_DBG_IS_ENABLED
    size_t json_size = oc_rep_to_json(rep, nullptr, 0, true);
    std::vector<char> json{};
    json.resize(json_size + 1);
    oc_rep_to_json(rep, &json[0], json.capacity(), true);
    OC_PRINTF("%s", json.data());
#endif /* OC_DBG_IS_ENABLED */
  }

  oc::oc_rep_unique_ptr GetPayload(
    std::optional<std::string> access_token,
    std::optional<std::string> refresh_token = {},
    std::optional<std::string> uid = {}, int64_t expires_in = -1);

  oc_cloud_context_t *GetContext() { return &m_context; }

  bool IsEmptyContext() const
  {
    return oc_endpoint_addresses_is_empty(&m_context.store.ci_servers) &&
           oc_string(m_context.store.access_token) == nullptr &&
           oc_string(m_context.store.refresh_token) == nullptr &&
           oc_string(m_context.store.uid) == nullptr &&
           m_context.store.expires_in == 0 && m_context.store.status == 0;
  }

private:
  oc_cloud_context_t m_context{};
  oc::RepPool pool_{};
};

oc::oc_rep_unique_ptr
TestCloudManagerData::GetPayload(std::optional<std::string> access_token,
                                 std::optional<std::string> refresh_token,
                                 std::optional<std::string> uid,
                                 int64_t expires_in)
{
  oc_rep_begin_root_object();
  if (access_token.has_value()) {
    oc_rep_set_text_string(root, accesstoken, access_token->c_str());
  }
  if (refresh_token.has_value()) {
    oc_rep_set_text_string(root, refreshtoken, refresh_token->c_str());
  }
  if (uid.has_value()) {
    oc_rep_set_text_string(root, uid, uid->c_str());
  }
  if (expires_in >= 0) {
    oc_rep_set_int(root, expiresin, expires_in);
  }
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = ParsePayload();
  PrintJson(rep.get());
  return rep;
}

TEST_F(TestCloudManagerData, cloud_manager_calculate_refresh_token_expiration)
{
  // long internal (>1hour) -> refresh schedule 10mins before expiration
  std::chrono::milliseconds expires_in = 2h;
  auto expires_in_ms =
    cloud_manager_calculate_refresh_token_expiration(expires_in.count());
  EXPECT_LT(0, expires_in_ms);
  EXPECT_GT(expires_in.count(), expires_in_ms);

  // middle internal (>4mins) -> refresh schedule 2mins before expiration
  expires_in = 5min;
  expires_in_ms =
    cloud_manager_calculate_refresh_token_expiration(expires_in.count());
  EXPECT_LT(0, expires_in_ms);
  EXPECT_GT(expires_in.count(), expires_in_ms);

  // short internal (>20s) -> refresh schedule 10secs before expiration
  expires_in = 1min;
  expires_in_ms =
    cloud_manager_calculate_refresh_token_expiration(expires_in.count());
  EXPECT_LT(0, expires_in_ms);
  EXPECT_GT(expires_in.count(), expires_in_ms);

  // immediate expiration (<=20s)
  expires_in = 10s;
  expires_in_ms =
    cloud_manager_calculate_refresh_token_expiration(expires_in.count());
  EXPECT_EQ(expires_in.count(), expires_in_ms);
}

TEST_F(TestCloudManagerData, cloud_manager_parse_register_data_invalid)
{
  // {
  //   plgd: "dev",
  // }
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, plgd, "dev");
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = ParsePayload();
  EXPECT_FALSE(cloud_manager_handle_register_response(GetContext(), rep.get()));
  EXPECT_TRUE(IsEmptyContext());
  rep.reset();
  Clear();

  // {
  //   accesstoken: "",
  // }
  EXPECT_FALSE(
    cloud_manager_handle_register_response(GetContext(), GetPayload("").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  // }
  EXPECT_FALSE(cloud_manager_handle_register_response(
    GetContext(), GetPayload("accesstoken").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "",
  // }
  EXPECT_FALSE(cloud_manager_handle_register_response(
    GetContext(), GetPayload("accesstoken", "").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  // }
  EXPECT_FALSE(cloud_manager_handle_register_response(
    GetContext(), GetPayload("accesstoken", "refreshtoken").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  //   uid: "",
  // }
  EXPECT_FALSE(cloud_manager_handle_register_response(
    GetContext(), GetPayload("accesstoken", "refreshtoken", "").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  //   uid: "uid",
  // }
  EXPECT_FALSE(cloud_manager_handle_register_response(
    GetContext(), GetPayload("accesstoken", "refreshtoken", "uid").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();
}

TEST_F(TestCloudManagerData, cloud_manager_parse_register_data)
{
  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  //   uid: "uid",
  //   expiresin: 42,
  // }
  std::string at{ "accesstoken" };
  std::string rt{ "refreshtoken" };
  std::string uid{ "uid" };
  int64_t expiresin = 0;
  oc::oc_rep_unique_ptr rep = GetPayload(at, rt, uid, expiresin);
  EXPECT_TRUE(cloud_manager_handle_register_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());

  EXPECT_STREQ(at.c_str(), oc_string(GetContext()->store.access_token));
  EXPECT_STREQ(rt.c_str(), oc_string(GetContext()->store.refresh_token));
  EXPECT_STREQ(uid.c_str(), oc_string(GetContext()->store.uid));
  EXPECT_EQ(expiresin, GetContext()->store.expires_in);
  EXPECT_FALSE((GetContext()->store.status & OC_CLOUD_TOKEN_EXPIRY) != 0);
  rep.reset();
  Clear();

  at = "accesstoken42";
  rt = "refreshtoken42";
  uid = "uid42";
  expiresin = 42;
  rep = GetPayload(at, rt, uid, expiresin);
  EXPECT_TRUE(cloud_manager_handle_register_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());
  EXPECT_EQ(expiresin, GetContext()->store.expires_in);
  EXPECT_STREQ(at.c_str(), oc_string(GetContext()->store.access_token));
  EXPECT_STREQ(rt.c_str(), oc_string(GetContext()->store.refresh_token));
  EXPECT_STREQ(uid.c_str(), oc_string(GetContext()->store.uid));
  EXPECT_TRUE((GetContext()->store.status & OC_CLOUD_TOKEN_EXPIRY) != 0);
  rep.reset();
  Clear();
}

TEST_F(TestCloudManagerData, cloud_manager_parse_redirect)
{
  std::string redirect{ "coap://mock.plgd.dev" };
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, redirecturi, redirect.c_str());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  PrintJson(rep.get());

  oc_endpoint_addresses_reinit(&GetContext()->store.ci_servers,
                               oc_endpoint_address_make_view_with_uuid(
                                 OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS),
                                 OCF_COAPCLOUDCONF_DEFAULT_SID));
  EXPECT_TRUE(cloud_manager_handle_redirect_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &GetContext()->store.ci_servers,
    oc_string_view(redirect.c_str(), redirect.length())));

  GetContext()->cloud_ep = oc_new_endpoint();
  oc_endpoint_addresses_reinit(
    &GetContext()->store.ci_servers,
    oc_endpoint_address_make_view_with_uuid(OC_STRING_VIEW_NULL, {}));
  EXPECT_TRUE(cloud_manager_handle_redirect_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &GetContext()->store.ci_servers,
    oc_string_view(redirect.c_str(), redirect.length())));
  oc_cloud_set_endpoint(GetContext());
  oc_free_endpoint(GetContext()->cloud_ep);
  GetContext()->cloud_ep = nullptr;

  EXPECT_TRUE(cloud_manager_handle_redirect_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(
    &GetContext()->store.ci_servers,
    oc_string_view(redirect.c_str(), redirect.length())));
}

TEST_F(TestCloudManagerData, cloud_manager_parse_redirect_fail_invalid_payload)
{
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, plgd, "dev");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep1 = ParsePayload();
  PrintJson(rep1.get());
  EXPECT_FALSE(
    cloud_manager_handle_redirect_response(GetContext(), rep1.get()));
  rep1.reset();
  Clear();

  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, redirecturi, "");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep2 = ParsePayload();
  PrintJson(rep2.get());
  EXPECT_FALSE(
    cloud_manager_handle_redirect_response(GetContext(), rep2.get()));
  rep2.reset();
  Clear();
}

TEST_F(TestCloudManagerData, cloud_manager_parse_refresh_token_data_invalid)
{
  // {
  //   accesstoken: "accesstoken",
  // }
  EXPECT_FALSE(cloud_manager_handle_refresh_token_response(
    GetContext(), GetPayload("accesstoken").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   refreshtoken: "refreshtoken",
  // }
  EXPECT_FALSE(cloud_manager_handle_refresh_token_response(
    GetContext(), GetPayload("", "refreshtoken").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();

  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  // }
  EXPECT_FALSE(cloud_manager_handle_refresh_token_response(
    GetContext(), GetPayload("accesstoken", "refreshtoken").get()));
  EXPECT_TRUE(IsEmptyContext());
  Clear();
}

TEST_F(TestCloudManagerData, cloud_manager_parse_refresh_token_data)
{
  // {
  //   accesstoken: "accesstoken",
  //   refreshtoken: "refreshtoken",
  //   expiresin: 42,
  // }
  std::string at{ "accesstoken" };
  std::string rt{ "refreshtoken" };
  int64_t expiresin = 42;
  oc::oc_rep_unique_ptr rep = GetPayload(at, rt, "", expiresin);
  EXPECT_TRUE(
    cloud_manager_handle_refresh_token_response(GetContext(), rep.get()));
  EXPECT_FALSE(IsEmptyContext());

  EXPECT_STREQ(at.c_str(), oc_string(GetContext()->store.access_token));
  EXPECT_STREQ(rt.c_str(), oc_string(GetContext()->store.refresh_token));
  EXPECT_EQ(expiresin, GetContext()->store.expires_in);
}
