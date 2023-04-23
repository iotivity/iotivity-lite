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

#include "api/oc_core_res_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "api/plgd/plgd_time_internal.h"
#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_network_monitor.h"
#include "oc_ri.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_macros.h"

#ifdef OC_SECURITY
#include "security/oc_security_internal.h"
#include "security/oc_pstat.h"
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <filesystem>
#include <gtest/gtest.h>

#ifdef OC_SECURITY
#include <mbedtls/platform_time.h>
#ifdef OC_PKI
#include <mbedtls/ssl.h>
#endif /* OC_PKI */
#endif /* OC_SECURITY */

static const std::string testStorage{ "storage_test" };

class TestPlgdTime : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));

    oc_clock_init();
    oc_core_init();
    plgd_time_configure(
      /*use_in_mbedtls*/ true,
      /*set_system_time*/ nullptr,
      /*set_system_time_data*/ nullptr);
    oc_network_event_handler_mutex_init();
  }

  static void TearDownTestCase()
  {
    oc_network_event_handler_mutex_destroy();
    oc_core_shutdown();

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

class TestPlgdTimeWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
    oc::TestDevice::ConfigurePlgdTime(true);

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_t *sc = oc_core_get_resource_by_index(PLGD_TIME, /*device*/ 0);
    ASSERT_NE(nullptr, sc);
    oc_resource_make_public(sc);
    oc_resource_set_access_in_RFOTM(
      sc, true,
      static_cast<oc_ace_permissions_t>(OC_PERM_RETRIEVE | OC_PERM_UPDATE));
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
        pt.time = oc_clock_parse_time_rfc3339(oc_string(rep->value.string),
                                              oc_string_len(rep->value.string));
        continue;
      }
      if (oc_rep_is_property(
            rep, PLGD_TIME_PROP_LAST_SYNCED_TIME,
            OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_LAST_SYNCED_TIME))) {
        pt.lst = oc_clock_parse_time_rfc3339(oc_string(rep->value.string),
                                             oc_string_len(rep->value.string));
        continue;
      }
      if (oc_rep_is_property(rep, PLGD_TIME_PROP_STATUS,
                             OC_CHAR_ARRAY_LEN(PLGD_TIME_PROP_STATUS))) {
        int status = plgd_time_status_from_str(
          oc_string(rep->value.string), oc_string_len(rep->value.string));
        if (status == -1) {
          OC_ERR("cannot parse status(%s)", oc_string(rep->value.string));
          continue;
        }
        pt.status = status;
        continue;
      }
    }
    return pt;
  }

#ifdef OC_SECURITY
  static void prepareSecureDevice(size_t device)
  {
    oc_sec_self_own(device);

    // valid from Nov 29, 2018 to Nov 29, 2068
    oc::pki::TrustAnchor trustCA{
      "pki_certs/certification_tests_rootca1.pem",
      true,
    };
    ASSERT_TRUE(trustCA.Add(device));

    // valid from Nov 29, 2018 to Nov 29, 2068
    oc::pki::IdentityCertificate mfgCertificate{
      "pki_certs/certification_tests_ee.pem",
      "pki_certs/certification_tests_key.pem",
      true,
    };
    ASSERT_TRUE(mfgCertificate.Add(device));

    // expired: was valid from Apr 14, 2020 to May 14, 2020
    // TODO: get a valid certificate and remove oc_pki_set_verify_certificate_cb
    oc::pki::IntermediateCertificate subCertificate{
      "pki_certs/certification_tests_subca1.pem"
    };
    ASSERT_TRUE(subCertificate.Add(device, mfgCertificate.CredentialID()));

    oc_pki_set_verify_certificate_cb(
      [](oc_tls_peer_t *peer, const mbedtls_x509_crt *, int, uint32_t *flags) {
        if (peer->role == MBEDTLS_SSL_IS_SERVER) {
          OC_DBG("disable time verification for server (peer=%p)",
                 (void *)peer);
          *flags &= ~((uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
                                 MBEDTLS_X509_BADCERT_FUTURE));
        }
        return 0;
      });
  }

  static void resetSecureDevice(size_t device)
  {
    oc_pki_set_verify_certificate_cb(nullptr);
    oc_pstat_reset_device(device, true);
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
  // get insecure connection to the testing device
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_status(PLGD_TIME_STATUS_SYNCING);
  PlgdTime pt{};
  EXPECT_TRUE(oc_do_get(PLGD_TIME_URI, ep, "if=" OC_IF_BASELINE_STR,
                        get_handler, HIGH_QOS, &pt));
  oc::TestDevice::PoolEvents(5);

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
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_time(0);
  PlgdTime pt{};
  EXPECT_TRUE(oc_do_get(PLGD_TIME_URI, ep, "if=" OC_IF_BASELINE_STR,
                        get_handler, HIGH_QOS, &pt));
  oc::TestDevice::PoolEvents(5);

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
}

TEST_F(TestPlgdTimeWithServer, PostRequestFail)
{
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  bool invoked = false;
  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_LT(OC_STATUS_NOT_MODIFIED, data->code);
    oc::TestDevice::Terminate();
    auto *invoked = static_cast<bool *>(data->user_data);
    *invoked = true;
  };

  ASSERT_TRUE(
    oc_init_post(PLGD_TIME_URI, ep, nullptr, post_handler, HIGH_QOS, &invoked));
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, lastSyncedTime, "bad format");
  oc_rep_end_root_object();
  EXPECT_TRUE(oc_do_post());
  oc::TestDevice::PoolEvents(5);
  EXPECT_TRUE(invoked);

  invoked = false;
  ASSERT_TRUE(
    oc_init_post(PLGD_TIME_URI, ep, nullptr, post_handler, HIGH_QOS, &invoked));
  oc_rep_start_root_object();
  oc_rep_set_int(root, lastSyncedTime, 1337);
  oc_rep_end_root_object();
  EXPECT_TRUE(oc_do_post());
  oc::TestDevice::PoolEvents(5);
  EXPECT_TRUE(invoked);
}

TEST_F(TestPlgdTimeWithServer, PostRequest)
{
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *pt = static_cast<PlgdTime *>(data->user_data);
    *pt = decodePayload(data->payload);
  };

  plgd_time_set_status(PLGD_TIME_STATUS_SYNCING);
  PlgdTime pt{};
  ASSERT_TRUE(
    oc_init_post(PLGD_TIME_URI, ep, nullptr, post_handler, HIGH_QOS, &pt));
  constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
  oc_clock_time_t yesterday = oc_clock_time() - kOneDay;
  encodeSystemClock(yesterday);
  EXPECT_TRUE(oc_do_post());
  oc::TestDevice::PoolEvents(5);

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

TEST_F(TestPlgdTimeWithServer, DeleteRequestFail)
{
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto delete_handler = [](oc_client_response_t *data) {
    EXPECT_LT(OC_STATUS_NOT_MODIFIED, data->code);
    oc::TestDevice::Terminate();
    bool *invoked = static_cast<bool *>(data->user_data);
    *invoked = true;
  };

  bool invoked = false;
  EXPECT_TRUE(oc_do_delete(PLGD_TIME_URI, ep, nullptr, delete_handler, HIGH_QOS,
                           &invoked));
  oc::TestDevice::PoolEvents(5);

  EXPECT_TRUE(invoked);
}

TEST_F(TestPlgdTimeWithServer, PutRequestFail)
{
  const oc_endpoint_t *ep =
    oc::TestDevice::GetEndpoint(/*device*/ 0, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto put_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_METHOD_NOT_ALLOWED, data->code);
    oc::TestDevice::Terminate();
    bool *invoked = static_cast<bool *>(data->user_data);
    *invoked = true;
  };

  bool invoked = false;
  ASSERT_TRUE(
    oc_init_put(PLGD_TIME_URI, ep, nullptr, put_handler, HIGH_QOS, &invoked));
  encodeSystemClock(oc_clock_time());
  EXPECT_TRUE(oc_do_put());
  oc::TestDevice::PoolEvents(5);

  EXPECT_TRUE(invoked);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_CLIENT

TEST_F(TestPlgdTimeWithServer, FetchTimeFail)
{
  unsigned flags = 0;
#ifdef OC_SECURITY
  flags |= SECURED;
#endif /* OC_SECURITY */
#ifdef OC_TCP
  flags |= TCP;
#endif /* OC_TCP */

  std::string ep_str =
    std::string(oc_endpoint_flags_to_scheme(flags)) + "[ff02::158]:12345";
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);

  auto fetch_handler = [](oc_status_t code, oc_clock_time_t, void *data) {
    OC_DBG("fetch time handler timeout");
    EXPECT_TRUE(oc_ri_client_cb_terminated(code));
    *(static_cast<bool *>(data)) = true;
    oc::TestDevice::Terminate();
  };

#ifdef OC_SECURITY
  if ((ep.flags & SECURED) != 0) {
    oc_sec_self_own(/*device*/ 0);
  }
#endif /* OC_SECURITY */

  bool invoked = false;
  unsigned fetch_flags = 0;
  EXPECT_TRUE(plgd_time_fetch(
    plgd_time_fetch_config(&ep, PLGD_TIME_URI, fetch_handler, &invoked,
                           /*timeout*/ 5, /*selected_identity_credid*/ -1,
                           /*disable_time_verification*/ true),
    &fetch_flags));

  oc::TestDevice::PoolEvents(5);
  EXPECT_TRUE(invoked);

#ifdef OC_SECURITY
  oc_pstat_reset_device(/*device*/ 0, true);
#endif /* OC_SECURITY */
}

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
waitForTCPEventCallback(TCPSessionData *tcp_data)
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
  unsigned flags = 0;
#ifdef OC_TCP
  flags |= TCP;
#endif /* OC_TCP */
#ifdef OC_SECURITY
  flags |= SECURED;
#endif /* OC_SECURITY */
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(/*device*/ 0, flags);
  ASSERT_NE(nullptr, ep);

#ifdef OC_SECURITY
  prepareSecureDevice(/*device*/ 0);
#endif /* OC_SECURITY */

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  TCPSessionData tcp_data{};
  session_event_handler_v1_t tcp_events{};
  if ((ep->flags & TCP) != 0) {
    tcp_data.ep = ep;
    tcp_events = addTCPEventCallback(&tcp_data);
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

  auto fetch_handler = [](oc_status_t code, oc_clock_time_t time, void *data) {
    OC_DBG("fetch time handler");
    EXPECT_EQ(OC_STATUS_OK, code);
    auto *t = static_cast<oc_clock_time_t *>(data);
    *t = time;
    oc::TestDevice::Terminate();
  };

  oc_clock_time_t time = 0;
  unsigned fetch_flags = 0;
  EXPECT_TRUE(plgd_time_fetch(
    plgd_time_fetch_config(ep, PLGD_TIME_URI, fetch_handler, &time,
                           /*timeout*/ 5, /*selected_identity_credid*/ -1,
                           /*disable_time_verification*/ true),
    &fetch_flags));

  oc::TestDevice::PoolEvents(5);
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
  resetSecureDevice(/*device*/ 0);
#endif /* OC_SECURITY */
}

TEST_F(TestPlgdTimeWithServer, FetchTimeAlreadyConnectedInsecure)
{
  // TODO: use already connected endpoint
}

#ifdef OC_SECURITY

TEST_F(TestPlgdTimeWithServer, FetchTimeConnectSkipVerification)
{
  unsigned flags = SECURED;
#ifdef OC_TCP
  flags |= TCP;
#endif /* OC_TCP */
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(/*device*/ 0, flags);
  ASSERT_NE(nullptr, ep);

  prepareSecureDevice(/*device*/ 0);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  session_event_handler_v1_t tcp_events{};
  TCPSessionData tcp_data{};
  if ((ep->flags & TCP) != 0) {
    tcp_data.ep = ep;
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
    OC_DBG("fetch time handler");
    EXPECT_EQ(OC_STATUS_OK, code);
    auto *t = static_cast<oc_clock_time_t *>(data);
    *t = time;
    oc::TestDevice::Terminate();
  };

  oc_clock_time_t time = 0;
  unsigned fetch_flags = 0;
  EXPECT_TRUE(
    plgd_time_fetch(plgd_time_fetch_config_with_custom_verification(
                      ep, PLGD_TIME_URI, fetch_handler, &time,
                      /*timeout*/ 5,
                      /*selected_identity_credid*/ -1, verify_connection, {}),
                    &fetch_flags));

  oc::TestDevice::PoolEvents(5);
  EXPECT_NE(0, time);

#if defined(OC_TCP) && defined(OC_SESSION_EVENTS)
  if (tcp_events != nullptr &&
      (fetch_flags & PLGD_TIME_FETCH_FLAG_TCP_SESSION_OPENED) != 0) {
    waitForTCPEventCallback(&tcp_data);
    EXPECT_EQ(0,
              oc_remove_session_event_callback_v1(tcp_events, nullptr, true));
  }
#endif /* OC_TCP && OC_SESSION_EVENTS */

  resetSecureDevice(/*device*/ 0);
}

TEST_F(TestPlgdTimeWithServer, FetchTimeAlreadyConnectedSecure)
{
  // TODO: use already connected endpoint
}

#endif /* OC_SECURITY */

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
