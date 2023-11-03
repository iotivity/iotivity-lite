/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_sp.h"
#include "oc_store.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "security/oc_sp_internal.h"
#include "security/oc_svr_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"
#include "util/oc_macros_internal.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

class TestSecurityProfile : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(oc::DefaultDevice.uri.c_str(),
                               oc::DefaultDevice.rt.c_str(),
                               oc::DefaultDevice.name.c_str(),
                               oc::DefaultDevice.spec_version.c_str(),
                               oc::DefaultDevice.data_model_version.c_str(),
                               nullptr, nullptr));
    oc_sec_svr_create();
    ASSERT_EQ(0, oc::TestStorage.Config());
  }

  static void TearDownTestCase()
  {
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(kDeviceID);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();

    ASSERT_EQ(0, oc::TestStorage.Clear());
  }

  static bool isEqual(const oc_sec_sp_t &lhs, const oc_sec_sp_t &rhs)
  {
    return lhs.supported_profiles == rhs.supported_profiles &&
           lhs.current_profile == rhs.current_profile &&
           lhs.credid == rhs.credid;
  }

  static void expectEqual(const oc_sec_sp_t &lhs, const oc_sec_sp_t &rhs,
                          bool ignoreCredid = false)
  {
    EXPECT_EQ(lhs.supported_profiles, rhs.supported_profiles);
    EXPECT_EQ(lhs.current_profile, rhs.current_profile);
    if (!ignoreCredid) {
      EXPECT_EQ(lhs.credid, rhs.credid);
    }
  }
};

TEST_F(TestSecurityProfile, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_index(OCF_SEC_SP, SIZE_MAX));
}

TEST_F(TestSecurityProfile, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_SEC_SP, kDeviceID));
}

TEST_F(TestSecurityProfile, GetResourceByURI_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_uri_v1(
              OCF_SEC_SP_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_SP_URI), SIZE_MAX));
}

TEST_F(TestSecurityProfile, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_SEC_SP_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_SP_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_SEC_SP_URI, oc_string(res->uri));
}

TEST_F(TestSecurityProfile, Copy)
{
  oc_sec_sp_t sp1;
  sp1.supported_profiles = OC_SP_BASELINE | OC_SP_BLACK | OC_SP_BLUE;
  sp1.current_profile = OC_SP_BLACK;
  sp1.credid = 42;

  oc_sec_sp_t sp2{};
  oc_sec_sp_copy(&sp2, &sp1);
  expectEqual(sp1, sp2);

  oc_sec_sp_copy(&sp1, &sp1);
  expectEqual(sp2, sp1);

  oc_sec_sp_clear(&sp1);
  EXPECT_FALSE(isEqual(sp1, sp2));
}

TEST_F(TestSecurityProfile, FromString)
{
  EXPECT_EQ(0, oc_sec_sp_type_from_string("", 0));

  EXPECT_EQ(OC_SP_BASELINE, oc_sec_sp_type_from_string(
                              OC_SP_BASELINE_OID, strlen(OC_SP_BASELINE_OID)));
  EXPECT_EQ(OC_SP_BLACK, oc_sec_sp_type_from_string(OC_SP_BLACK_OID,
                                                    strlen(OC_SP_BLACK_OID)));
  EXPECT_EQ(OC_SP_BLUE,
            oc_sec_sp_type_from_string(OC_SP_BLUE_OID, strlen(OC_SP_BLUE_OID)));
  EXPECT_EQ(OC_SP_PURPLE, oc_sec_sp_type_from_string(OC_SP_PURPLE_OID,
                                                     strlen(OC_SP_PURPLE_OID)));
}

TEST_F(TestSecurityProfile, ToString)
{
  EXPECT_EQ(nullptr, oc_sec_sp_type_to_string(static_cast<oc_sp_types_t>(0)));

  EXPECT_STREQ(OC_SP_BASELINE_OID, oc_sec_sp_type_to_string(OC_SP_BASELINE));
  EXPECT_STREQ(OC_SP_BLACK_OID, oc_sec_sp_type_to_string(OC_SP_BLACK));
  EXPECT_STREQ(OC_SP_BLUE_OID, oc_sec_sp_type_to_string(OC_SP_BLUE));
  EXPECT_STREQ(OC_SP_PURPLE_OID, oc_sec_sp_type_to_string(OC_SP_PURPLE));
}

TEST_F(TestSecurityProfile, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_sec_sp_default(kDeviceID);

  oc_sec_sp_t def{};
  oc_sec_sp_copy(&def, oc_sec_sp_get(kDeviceID));
  oc_sec_sp_get(kDeviceID)->supported_profiles =
    OC_SP_BASELINE | OC_SP_BLACK | OC_SP_BLUE | OC_SP_PURPLE;
  oc_sec_sp_get(kDeviceID)->current_profile = OC_SP_BLUE;
  EXPECT_FALSE(isEqual(def, *oc_sec_sp_get(kDeviceID)));

  // load values from storage
  oc_sec_load_sp(kDeviceID);
  EXPECT_TRUE(isEqual(def, *oc_sec_sp_get(kDeviceID)));
}

TEST_F(TestSecurityProfile, Decode_FailInvalidProperty)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_int(root, myAttribute, 1337);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_sec_sp_t sp_parsed{};
  EXPECT_FALSE(oc_sec_sp_decode(rep.get(), /*flags*/ 0, &sp_parsed));
}

TEST_F(TestSecurityProfile, Decode_FailInvalidPropertyType)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_int(root, currentprofile, 42);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_sec_sp_t sp_parsed{};
  EXPECT_FALSE(oc_sec_sp_decode(rep.get(), /*flags*/ 0, &sp_parsed));
}

TEST_F(TestSecurityProfile, Decode_FailInvalidSupportedProfiles)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_array(root, supportedprofiles);
  oc_rep_add_text_string(supportedprofiles, "invalid");
  oc_rep_close_array(root, supportedprofiles);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_sec_sp_t sp_parsed{};
  EXPECT_FALSE(oc_sec_sp_decode(rep.get(), /*flags*/ 0, &sp_parsed));
}

TEST_F(TestSecurityProfile, Decode_FailInvalidCurrentProfile)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_array(root, supportedprofiles);
  oc_rep_add_text_string(supportedprofiles,
                         oc_sec_sp_type_to_string(OC_SP_BASELINE));
  oc_rep_close_array(root, supportedprofiles);
  oc_rep_set_text_string(root, currentprofile,
                         oc_sec_sp_type_to_string(OC_SP_PURPLE));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_sec_sp_t sp_parsed{};
  EXPECT_FALSE(oc_sec_sp_decode(rep.get(), /*flags*/ 0, &sp_parsed));
}

TEST_F(TestSecurityProfile, Decode_FailUnsupportedCurrentProfile)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, currentprofile, "invalid");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_sec_sp_t sp_parsed{};
  EXPECT_FALSE(oc_sec_sp_decode(rep.get(), /*flags*/ 0, &sp_parsed));
}

TEST_F(TestSecurityProfile, EncodeAndDecodeForDevice)
{
  oc_sec_sp_t *profile = oc_sec_sp_get(kDeviceID);
  ASSERT_NE(nullptr, profile);
  profile->supported_profiles = OC_SP_BASELINE | OC_SP_BLACK | OC_SP_PURPLE;
  profile->current_profile = OC_SP_BLACK;

  oc_sec_sp_t profile_copy{};
  oc_sec_sp_copy(&profile_copy, profile);

  oc::RepPool pool{};
  ASSERT_TRUE(oc_sec_sp_encode_for_device(kDeviceID, /*flags*/ 0));

  oc_sec_sp_clear(profile);
  profile->credid = profile_copy.credid;
  EXPECT_FALSE(isEqual(*oc_sec_sp_get(kDeviceID), profile_copy));

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  EXPECT_TRUE(oc_sec_sp_decode_for_device(rep.get(), kDeviceID));
  expectEqual(*oc_sec_sp_get(kDeviceID), profile_copy);
}

class TestSecurityProfileWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SEC_SP, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    oc_sec_sp_default(kDeviceID);
  }
};

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestSecurityProfileWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_sec_sp_t *profile = oc_sec_sp_get(kDeviceID);
  ASSERT_NE(nullptr, profile);
  profile->supported_profiles = OC_SP_BLACK | OC_SP_BLUE | OC_SP_PURPLE;
  profile->current_profile = OC_SP_PURPLE;

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *sp = static_cast<oc_sec_sp_t *>(data->user_data);
    EXPECT_TRUE(oc_sec_sp_decode(
      data->payload, OC_SEC_SP_DECODE_FLAG_IGNORE_UNKNOWN_PROPERTIES, sp));
  };

  auto timeout = 1s;
  oc_sec_sp_t sp{};
  sp.credid = oc_sec_sp_get(kDeviceID)->credid;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_SP_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &sp));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  TestSecurityProfile::expectEqual(*oc_sec_sp_get(kDeviceID), sp);
}

static oc_sec_sp_t
encodePayload(unsigned supported_profiles, oc_sp_types_t current_profile)
{
  oc_sec_sp_t sp_new{};
  sp_new.supported_profiles = supported_profiles;
  sp_new.current_profile = current_profile;
  EXPECT_EQ(0, oc_sec_sp_encode_with_resource(&sp_new, /*sp_res*/ nullptr,
                                              /*flags*/ 0));
  return sp_new;
}

TEST_F(TestSecurityProfileWithServer, PostRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_sec_sp_t *profile = oc_sec_sp_get(kDeviceID);
  ASSERT_NE(nullptr, profile);
  profile->supported_profiles = OC_SP_BLACK | OC_SP_BLUE | OC_SP_PURPLE;
  profile->current_profile = OC_SP_PURPLE;

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_SP_URI, &ep, nullptr, post_handler, HIGH_QOS,
                           &invoked));

  oc_sec_sp_t sp_new = encodePayload(OC_SP_BASELINE | OC_SP_BLACK, OC_SP_BLACK);

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  ASSERT_TRUE(invoked);
  TestSecurityProfile::expectEqual(*oc_sec_sp_get(kDeviceID), sp_new, true);
}

TEST_F(TestSecurityProfileWithServer, PostRequest_FailInvalidData)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_BAD_REQUEST, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_SP_URI, &ep, nullptr, post_handler, HIGH_QOS,
                           &invoked));
  oc_rep_start_root_object();
  oc_rep_set_int(root, myAttribute, 1337);
  oc_rep_end_root_object();
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  ASSERT_TRUE(invoked);
}

#else /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestSecurityProfileWithServer, GetRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_GET, &ep, OCF_SEC_SP_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

TEST_F(TestSecurityProfileWithServer, PostRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_POST, &ep, OCF_SEC_SP_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM  */

TEST_F(TestSecurityProfileWithServer, PutRequest_Fail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SEC_SP_URI, nullptr, error_code);
}

TEST_F(TestSecurityProfileWithServer, DeleteRequest_Fail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_SEC_SP_URI, nullptr,
                             error_code);
}

#endif /* OC_SECURITY */
