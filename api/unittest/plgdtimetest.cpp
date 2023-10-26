/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_HAS_FEATURE_PLGD_TIME

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/plgd/plgd_time_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SECURITY
#include "security/oc_security_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>

#ifdef OC_SECURITY
#include <mbedtls/platform_time.h>
#ifdef OC_PKI
#include <mbedtls/ssl.h>
#endif /* OC_PKI */
#endif /* OC_SECURITY */

static const std::string testStorage{ "storage_test" };

using namespace std::chrono_literals;

class TestPlgdTime : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));

    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_core_init();
    plgd_time_create_resource();
    plgd_time_configure(
      /*use_in_mbedtls*/ true,
      /*set_system_time*/ nullptr,
      /*set_system_time_data*/ nullptr);
  }

  static void TearDownTestCase()
  {
    oc_core_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();

    for (const auto &entry : std::filesystem::directory_iterator(testStorage)) {
      std::filesystem::remove_all(entry.path());
    }
    ASSERT_EQ(0, oc_storage_reset());
  }
};

TEST_F(TestPlgdTime, EncodeFail)
{
  oc::RepPool pool{};
  int flags = PLGD_TIME_ENCODE_FLAG_TO_STORAGE;
#ifdef OC_SECURITY
  flags |= PLGD_TIME_ENCODE_FLAG_SECURE;
#endif /* OC_SECURITY */

  plgd_time_t pt{};
  EXPECT_NE(0, plgd_time_encode(pt, OC_IF_CREATE, flags));

  pt.store.last_synced_time = std::numeric_limits<oc_clock_time_t>::max();
  EXPECT_NE(0, plgd_time_encode(pt, OC_IF_BASELINE, flags));
}

TEST_F(TestPlgdTime, Encode)
{
  oc::RepPool pool{};

  plgd_time_t pt{};
  pt.store.last_synced_time = oc_clock_time();
  EXPECT_EQ(0,
            plgd_time_encode(pt, OC_IF_RW, PLGD_TIME_ENCODE_FLAG_TO_STORAGE));
}

TEST_F(TestPlgdTime, GetFail)
{
  EXPECT_EQ(static_cast<oc_clock_time_t>(-1), plgd_time());
}

TEST_F(TestPlgdTime, SetAndGetTime)
{
  constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
  oc_clock_time_t start = oc_clock_time() - kOneDay;
  oc_clock_time_t ut = oc_clock_time_monotonic();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), ut);
  plgd_time_set(start, ut, false, false);

  EXPECT_EQ(start, plgd_time_last_synced_time());

  oc_clock_time_t now = plgd_time();
  EXPECT_LE(start, now);
  EXPECT_GT(oc_clock_time(), now);
}

TEST_F(TestPlgdTime, Seconds)
{
  constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
  oc_clock_time_t start = oc_clock_time() - kOneDay;
  oc_clock_time_t ut = oc_clock_time_monotonic();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), ut);
  plgd_time_set(start, ut, false, false);

  auto now_ts = plgd_time_seconds();
  EXPECT_NE(-1, now_ts);
  oc_clock_time_t start_ts = start / OC_CLOCK_SECOND;
  EXPECT_LE(start_ts, now_ts);
  EXPECT_GT(oc_clock_seconds(), now_ts);
  EXPECT_GT(oc_clock_seconds_v1(), now_ts);
}

TEST_F(TestPlgdTime, IsActive)
{
  plgd_time_set(0, 0, false, false);
  EXPECT_FALSE(plgd_time_is_active());

  oc_clock_time_t lst = oc_clock_time();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), lst);
  oc_clock_time_t ut = oc_clock_time_monotonic();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), ut);
  plgd_time_set(lst, ut, false, false);
  EXPECT_TRUE(plgd_time_is_active());
}

TEST_F(TestPlgdTime, DumpAndLoad)
{
  oc_clock_time_t lst = oc_clock_time();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), lst);
  oc_clock_time_t ut = oc_clock_time_monotonic();
  EXPECT_NE(static_cast<oc_clock_time_t>(-1), ut);
  plgd_time_set(lst, ut, /*dump*/ true, /*notify*/ false);
  const auto *pt = plgd_time_get();
  EXPECT_EQ(lst, pt->store.last_synced_time);
  EXPECT_EQ(ut, pt->update_time);

  plgd_time_set(0, 0, false, false);
  pt = plgd_time_get();
  EXPECT_EQ(0, pt->store.last_synced_time);
  EXPECT_EQ(0, pt->update_time);

  plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC);
  EXPECT_TRUE(plgd_time_load());
  EXPECT_EQ(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE, plgd_time_status());

  pt = plgd_time_get();
  EXPECT_EQ(lst, pt->store.last_synced_time);
  // update time is not stored, instead monotonic time at the time of loading is
  // used
  EXPECT_LE(ut, pt->update_time);
}

TEST_F(TestPlgdTime, Status)
{
  plgd_time_set_status(PLGD_TIME_STATUS_SYNCING);
  EXPECT_EQ(PLGD_TIME_STATUS_SYNCING, plgd_time_status());

  plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC);
  EXPECT_EQ(PLGD_TIME_STATUS_IN_SYNC, plgd_time_status());

  plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE);
  EXPECT_EQ(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE, plgd_time_status());
}

TEST_F(TestPlgdTime, StatusToStr)
{
  EXPECT_EQ(nullptr,
            plgd_time_status_to_str(static_cast<plgd_time_status_t>(-1)));

  EXPECT_STREQ(PLGD_TIME_STATUS_SYNCING_STR,
               plgd_time_status_to_str(PLGD_TIME_STATUS_SYNCING));
  EXPECT_STREQ(PLGD_TIME_STATUS_IN_SYNC_STR,
               plgd_time_status_to_str(PLGD_TIME_STATUS_IN_SYNC));
  EXPECT_STREQ(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR,
               plgd_time_status_to_str(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE));
}

TEST_F(TestPlgdTime, StatusFromStr)
{
  EXPECT_EQ(-1, plgd_time_status_from_str("fail", OC_CHAR_ARRAY_LEN("fail")));

  EXPECT_EQ(
    PLGD_TIME_STATUS_SYNCING,
    plgd_time_status_from_str(PLGD_TIME_STATUS_SYNCING_STR,
                              OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_SYNCING_STR)));
  EXPECT_EQ(
    PLGD_TIME_STATUS_IN_SYNC,
    plgd_time_status_from_str(PLGD_TIME_STATUS_IN_SYNC_STR,
                              OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_SYNCING_STR)));
  EXPECT_EQ(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE,
            plgd_time_status_from_str(
              PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR,
              OC_CHAR_ARRAY_LEN(PLGD_TIME_STATUS_IN_SYNC_FROM_STORAGE_STR)));
}

struct PlgdTime
{
  oc_clock_time_t time;
  oc_clock_time_t lst;
  int status;
};

static constexpr size_t kDeviceID{ 0 };

class TestPlgdTimeWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
    oc::TestDevice::ConfigurePlgdTime(true);

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(PLGD_TIME, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    plgd_time_set_time(0);
    plgd_time_set_status(PLGD_TIME_STATUS_IN_SYNC);
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    plgd_time_set_time(oc_clock_time());
  }

  void TearDown() override
  {
    oc::TestDevice::DropOutgoingMessages();
    coap_free_all_transactions();
    oc_client_cbs_shutdown();
    oc::TestDevice::CloseSessions(kDeviceID);
    // wait for asynchronous closing of sessions to finish
    oc::TestDevice::PoolEventsMsV1(10ms);
    oc::TestDevice::ClearSystemTime();
  }

  static PlgdTime decodePayload(const oc_rep_t *rep)
  {
    PlgdTime pt{};
    pt.status = -1;
    for (; rep != nullptr; rep = rep->next) {
      if (rep->type != OC_REP_STRING) {
        continue;
      }
      if (oc_rep_is_property(rep, PLGD_TIME_PROP_TIME,
                             OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_TIME))) {
        oc_clock_time_t time;
        if (!oc_clock_parse_time_rfc3339_v1(oc_string(rep->value.string),
                                            oc_string_len(rep->value.string),
                                            &time)) {
          OC_ERR("cannot parse %s(%s)", oc_string(rep->name),
                 oc_string(rep->value.string));
          continue;
        }
        pt.time = time;
        continue;
      }
      if (oc_rep_is_property(
            rep, PLGD_TIME_PROP_LAST_SYNCED_TIME,
            OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_LAST_SYNCED_TIME))) {
        oc_clock_time_t lst;
        if (!oc_clock_parse_time_rfc3339_v1(oc_string(rep->value.string),
                                            oc_string_len(rep->value.string),
                                            &lst)) {
          OC_ERR("cannot parse %s(%s)", oc_string(rep->name),
                 oc_string(rep->value.string));
          continue;
        }
        pt.lst = lst;
        continue;
      }
      if (oc_rep_is_property(rep, PLGD_TIME_PROP_STATUS,
                             OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_STATUS))) {
        int status = plgd_time_status_from_str(
          oc_string(rep->value.string), oc_string_len(rep->value.string));
        if (status == -1) {
          OC_ERR("cannot parse %s(%s)", oc_string(rep->name),
                 oc_string(rep->value.string));
          continue;
        }
        pt.status = status;
        continue;
      }
    }
    return pt;
  }

#ifdef OC_SECURITY
  static bool prepareSecureDevice(size_t device, bool addCertificates = true)
  {
#if defined(OC_PKI) && !defined(OC_DYNAMIC_ALLOCATION)
    if (addCertificates) {
      OC_ERR(
        "cannot allocate multiple certificates without dynamic allocation, "
        "default bytes pool too small");
      return false;
    }
#endif /* OC_PKI && OC_DYNAMIC_ALLOCATION */

    oc_sec_self_own(device);

#ifdef OC_PKI
    if (addCertificates) {
      // valid from Nov 29, 2018 to Nov 29, 2068
      oc::pki::TrustAnchor trustCA{
        "pki_certs/certification_tests_rootca1.pem",
        true,
      };
      EXPECT_TRUE(trustCA.Add(device));

      // valid from Nov 29, 2018 to Nov 29, 2068
      oc::pki::IdentityCertificate mfgCertificate{
        "pki_certs/certification_tests_ee.pem",
        "pki_certs/certification_tests_key.pem",
        true,
      };
      EXPECT_TRUE(mfgCertificate.Add(device));

      // expired: was valid from Apr 14, 2020 to May 14, 2020
      // TODO: get a valid certificate and remove
      // oc_pki_set_verify_certificate_cb
      oc::pki::IntermediateCertificate subCertificate{
        "pki_certs/certification_tests_subca1.pem"
      };
      EXPECT_TRUE(subCertificate.Add(device, mfgCertificate.CredentialID()));

      oc_pki_set_verify_certificate_cb([](oc_tls_peer_t *peer,
                                          const mbedtls_x509_crt *, int,
                                          uint32_t *flags) {
        if (peer->role == MBEDTLS_SSL_IS_SERVER) {
          OC_DBG("disable time verification for server (peer=%p)",
                 (void *)peer);
          *flags &= ~((uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
                                 MBEDTLS_X509_BADCERT_FUTURE));
        }
        return 0;
      });
    }
#else  /* !OC_PKI */
    (void)addCertificates;
#endif /* OC_PKI */
    return true;
  }

  static void resetSecureDevice(size_t device)
  {
#ifdef OC_PKI
    oc_pki_set_verify_certificate_cb(nullptr);
#endif /* OC_PKI */
    oc_tls_close_peers(nullptr, nullptr);
    oc_reset_device_v1(device, true);
    // need to wait for closing of TLS sessions
    oc::TestDevice::PoolEventsMs(200);
  }

#endif /* OC_SECURITY */
};

TEST_F(TestPlgdTimeWithServer, GetResource)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(PLGD_TIME, 0));
}

TEST_F(TestPlgdTimeWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_status(PLGD_TIME_STATUS_SYNCING);
  PlgdTime pt{};
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_get_with_timeout(PLGD_TIME_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &pt));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_NE(0, pt.time);
#ifndef OC_SECURITY
  // properties lastSyncedTime and status aren't available for insecure
  // connections on a secure device
  EXPECT_NE(0, pt.lst);
  EXPECT_EQ(plgd_time_status(), pt.status);
#endif /* !OC_SECURITY */
  std::array<char, 64> ts{};
  EXPECT_LT(0, oc_clock_encode_time_rfc3339(pt.lst, ts.data(), ts.size()));
  OC_DBG("GET plgd time: %s", ts.data());
}

TEST_F(TestPlgdTimeWithServer, GetRequestEmpty)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_time(0);
  PlgdTime pt{};
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_get_with_timeout(PLGD_TIME_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &pt));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_EQ(0, pt.time);
  EXPECT_EQ(0, pt.lst);
  EXPECT_EQ(-1, pt.status);
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

static void
encodeSystemClock(oc_clock_time_t lst)
{
  std::array<char, 64> lst_rfc3339{};
  if (lst > 0) {
    EXPECT_LT(0, oc_clock_encode_time_rfc3339(lst, lst_rfc3339.data(),
                                              lst_rfc3339.size()));
  }
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, lastSyncedTime, lst_rfc3339.data());
  oc_rep_end_root_object();
  ASSERT_EQ(0, g_err);
}

TEST_F(TestPlgdTimeWithServer, PostRequestFail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_LT(OC_STATUS_NOT_MODIFIED, data->code);
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(PLGD_TIME_URI, &ep, nullptr, post_handler, HIGH_QOS,
                           &invoked));
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, lastSyncedTime, "bad format");
  oc_rep_end_root_object();
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  invoked = false;
  ASSERT_TRUE(oc_init_post(PLGD_TIME_URI, &ep, nullptr, post_handler, HIGH_QOS,
                           &invoked));
  oc_rep_start_root_object();
  oc_rep_set_int(root, lastSyncedTime, 1337);
  oc_rep_end_root_object();
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(TestPlgdTimeWithServer, PostRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_CHANGED, data->code);
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_status(PLGD_TIME_STATUS_SYNCING);
  PlgdTime pt{};
  ASSERT_TRUE(
    oc_init_post(PLGD_TIME_URI, &ep, nullptr, post_handler, HIGH_QOS, &pt));
  constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
  oc_clock_time_t yesterday = oc_clock_time() - kOneDay;
  encodeSystemClock(yesterday);
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_EQ(PLGD_TIME_STATUS_IN_SYNC, plgd_time_status());

  EXPECT_EQ(yesterday, pt.lst);
  EXPECT_EQ(plgd_time_status(), pt.status);

  oc_clock_time_t pt_time = plgd_time();
  EXPECT_GE(pt_time, yesterday);
  EXPECT_LT(pt_time, oc_clock_time());

  std::array<char, 64> ts{};
  EXPECT_LT(0, oc_clock_encode_time_rfc3339(pt_time, ts.data(), ts.size()));
  OC_DBG("POST plgd time: %s", ts.data());

  EXPECT_NE(0, oc::TestDevice::GetSystemTime());
}

TEST_F(TestPlgdTimeWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  auto encode_payload = []() { encodeSystemClock(oc_clock_time()); };
  oc::testNotSupportedMethod(OC_PUT, &ep, PLGD_TIME_URI, encode_payload);
}

TEST_F(TestPlgdTimeWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, PLGD_TIME_URI);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_CLIENT

TEST_F(TestPlgdTimeWithServer, FetchTimeFail)
{
#ifdef OC_SECURITY
  if (!prepareSecureDevice(kDeviceID, false)) {
    OC_WRN("Test skipped");
    return;
  }
#endif /* OC_SECURITY */

  unsigned ep_flags = 0;
#ifdef OC_SECURITY
  ep_flags |= SECURED;
#endif /* OC_SECURITY */
#ifdef OC_TCP
  ep_flags |= TCP;
#endif /* OC_TCP */

  std::array<char, 16> scheme{};
  ASSERT_NE(-1,
            oc_endpoint_flags_to_scheme(ep_flags, &scheme[0], scheme.size()));

  std::string ep_str = std::string(scheme.data()) + "[ff02::158]:12345";
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);

  auto fetch_handler = [](oc_status_t code, oc_clock_time_t, void *data) {
    oc::TestDevice::Terminate();
    OC_DBG("fetch time handler timeout");
    ASSERT_TRUE(code == OC_CONNECTION_CLOSED || code == OC_REQUEST_TIMEOUT);
    *(static_cast<bool *>(data)) = true;
  };

  bool invoked = false;
  unsigned fetch_flags = 0;
  auto timeout = 1s;
  ASSERT_TRUE(plgd_time_fetch(
    plgd_time_fetch_config(&ep, PLGD_TIME_URI, fetch_handler, &invoked,
                           timeout.count(), /*selected_identity_credid*/ -1,
                           /*disable_time_verification*/ true),
    &fetch_flags));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

#ifdef OC_SECURITY
  resetSecureDevice(kDeviceID);
#endif /* OC_SECURITY */
}

#ifndef OC_INOUT_BUFFER_POOL

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)

struct TCPSessionData
{
  bool disconnected;
  const oc_endpoint_t *ep;
};

static session_event_handler_v1_t
addTCPEventCallback(TCPSessionData *tcp_data)
{
  auto tcp_events = [](const oc_endpoint_t *endpoint, oc_session_state_t state,
                       void *data) {
#ifdef OC_DEBUG
    oc_string_t ep_str{};
    oc_endpoint_to_string(endpoint, &ep_str);
    OC_DBG("session event endpoint=%s state=%d", oc_string(ep_str), (int)state);
    oc_free_string(&ep_str);
#endif /* OC_DEBUG */
    auto *tsd = static_cast<TCPSessionData *>(data);
    if ((oc_endpoint_compare(endpoint, tsd->ep) == 0) &&
        (state == OC_SESSION_DISCONNECTED)) {
      OC_DBG("tcp session disconnected");
      tsd->disconnected = true;
      oc::TestDevice::Terminate();
    }
  };

  EXPECT_EQ(0, oc_add_session_event_callback_v1(tcp_events, tcp_data));
  return tcp_events;
}

static void
waitForTCPEventCallback(const TCPSessionData *tcp_data)
{
  if (!tcp_data->disconnected) {
    OC_DBG("waiting to close insecure TCP session");
    oc::TestDevice::PoolEvents(5);
  }
  EXPECT_TRUE(tcp_data->disconnected);
}

#endif /* OC_TCP || OC_SESSION_EVENTS */

TEST_F(TestPlgdTimeWithServer, FetchTimeConnectInsecureConnection)
{
  unsigned include_flags = 0;
  unsigned exclude_flags = 0;
#ifdef OC_TCP
#if defined(OC_SECURITY) && defined(OC_PKI)
  if (!prepareSecureDevice(kDeviceID)) {
    OC_WRN("Test skipped");
    return;
  }
  include_flags |= SECURED;
#endif /* OC_SECURITY && OC_PKI */
  include_flags |= TCP;
#else  /* !OC_TCP */
  // TODO: fix DTLS openning of connection by client_api
  exclude_flags = SECURED;
#endif /* OC_TCP */
  auto epOpt =
    oc::TestDevice::GetEndpoint(kDeviceID, include_flags, exclude_flags);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  TCPSessionData tcp_data{};
  session_event_handler_v1_t tcp_events{};
  if ((ep.flags & TCP) != 0) {
    tcp_data.ep = &ep;
    tcp_events = addTCPEventCallback(&tcp_data);
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

  auto fetch_handler = [](oc_status_t code, oc_clock_time_t time, void *data) {
    oc::TestDevice::Terminate();
    OC_DBG("fetch time handler");
    EXPECT_EQ(OC_STATUS_OK, code);
    *static_cast<oc_clock_time_t *>(data) = time;
  };

  oc_clock_time_t time = 0;
  unsigned fetch_flags = 0;
  auto timeout = 5s;
  ASSERT_TRUE(plgd_time_fetch(
    plgd_time_fetch_config(&ep, PLGD_TIME_URI, fetch_handler, &time,
                           timeout.count(), /*selected_identity_credid*/ -1,
                           /*disable_time_verification*/ true),
    &fetch_flags));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_NE(0, time);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  if (tcp_events != nullptr &&
      (fetch_flags & PLGD_TIME_FETCH_FLAG_TCP_SESSION_OPENED) != 0) {
    waitForTCPEventCallback(&tcp_data);
    EXPECT_EQ(0,
              oc_remove_session_event_callback_v1(tcp_events, nullptr, true));
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

#ifdef OC_SECURITY
  resetSecureDevice(kDeviceID);
#endif /* OC_SECURITY */
}

TEST_F(TestPlgdTimeWithServer, FetchTimeAlreadyConnectedInsecure)
{
  // TODO: use already connected endpoint
}

#if defined(OC_SECURITY) && defined(OC_PKI)

TEST_F(TestPlgdTimeWithServer, FetchTimeConnectSkipVerification)
{
#ifdef OC_SECURITY
  if (!prepareSecureDevice(kDeviceID)) {
    OC_WRN("Test skipped");
    return;
  }
#endif /* OC_SECURITY */

  unsigned include_flags = 0;
  unsigned exclude_flags = 0;
#ifdef OC_TCP
  include_flags |= SECURED | TCP;
#else  /* !OC_TCP */
  // TODO: fix DTLS openning of connection by client_api
  exclude_flags = SECURED;
#endif /* OC_TCP */
  auto epOpt =
    oc::TestDevice::GetEndpoint(kDeviceID, include_flags, exclude_flags);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  session_event_handler_v1_t tcp_events{};
  TCPSessionData tcp_data{};
  if ((ep.flags & TCP) != 0) {
    tcp_data.ep = &ep;
    tcp_events = addTCPEventCallback(&tcp_data);
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

  auto verify_connection = [](oc_tls_peer_t *, const mbedtls_x509_crt *, int,
                              uint32_t *flags) {
    OC_DBG("skip verification for fetch time connection");
    *flags = 0;
    return 0;
  };

  auto fetch_handler = [](oc_status_t code, oc_clock_time_t time, void *data) {
    oc::TestDevice::Terminate();
    OC_DBG("fetch time handler");
    EXPECT_EQ(OC_STATUS_OK, code);
    *static_cast<oc_clock_time_t *>(data) = time;
  };

  oc_clock_time_t time = 0;
  unsigned fetch_flags = 0;
  auto timeout = 5s;
  ASSERT_TRUE(
    plgd_time_fetch(plgd_time_fetch_config_with_custom_verification(
                      &ep, PLGD_TIME_URI, fetch_handler, &time, timeout.count(),
                      /*selected_identity_credid*/ -1, verify_connection, {}),
                    &fetch_flags));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_NE(0, time);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  if (tcp_events != nullptr &&
      (fetch_flags & PLGD_TIME_FETCH_FLAG_TCP_SESSION_OPENED) != 0) {
    waitForTCPEventCallback(&tcp_data);
    EXPECT_EQ(0,
              oc_remove_session_event_callback_v1(tcp_events, nullptr, true));
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

  resetSecureDevice(kDeviceID);
}

TEST_F(TestPlgdTimeWithServer, FetchTimeAlreadyConnectedSecure)
{
  // TODO: use already connected endpoint
}

#endif /* OC_SECURITY && OC_PKI */

#endif /* !OC_INOUT_BUFFER_POOL */

#endif /* OC_CLIENT */

#ifdef OC_SECURITY

class TestMbedTLSPlgdTime : public testing::Test {
public:
  static void SetUpTestCase()
  {
    EXPECT_TRUE(oc::TestDevice::StartServer());

    oc_mbedtls_platform_time_init();
  }

  static void TearDownTestCase()
  {
    oc_mbedtls_platform_time_deinit();
    plgd_time_set_time(0);

    oc::TestDevice::StopServer();
  }
};

TEST_F(TestMbedTLSPlgdTime, GetTimeUnsynchronized)
{
  // reset plgd time, so standard time(NULL) will be used
  plgd_time_set_time(0);

  time_t now_ts = time(nullptr);
  oc_clock_wait(2 * OC_CLOCK_SECOND); // wait 2 secs
  mbedtls_time_t ts = mbedtls_time(nullptr);

  EXPECT_LT(now_ts, ts);
}

TEST_F(TestMbedTLSPlgdTime, GetTime)
{
  constexpr auto kOneDay = 60 * 60 * 24;
  oc_clock_time_t yesterday = oc_clock_time() - kOneDay * OC_CLOCK_SECOND;
  plgd_time_set_time(yesterday);

  mbedtls_time_t ts = mbedtls_time(nullptr);
  time_t now_ts = time(nullptr);

  EXPECT_GT(now_ts, ts);

  constexpr auto kOneMinute = 60;
  EXPECT_LT(now_ts, ts + kOneDay + kOneMinute);
}

#endif /* OC_SECURITY */

#endif /* OC_HAS_FEATURE_PLGD_TIME */
