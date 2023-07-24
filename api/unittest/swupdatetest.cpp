/******************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_config.h"

#ifdef OC_SOFTWARE_UPDATE

#include "api/oc_core_res_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/oc_swupdate_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_swupdate.h"
#include "port/oc_log_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "tests/gtest/Clock.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"
#include "util/oc_macros_internal.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#include <algorithm>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <vector>

static constexpr size_t kDeviceID{ 0 };

using namespace std::chrono_literals;

class TestSWUpdate : public testing::Test {
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
    oc_swupdate_create();
    ASSERT_EQ(0, oc::TestStorage.Config());
  }

  static void TearDownTestCase()
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_swupdate_free();
    oc_connectivity_shutdown(kDeviceID);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();

    ASSERT_EQ(0, oc::TestStorage.Clear());
  }

  static oc_swupdate_t createSWUpdate(
    const std::string &purl, const std::string &nv = "",
    const std::string &signage = "",
    oc_swupdate_action_t swupdateaction = OC_SWUPDATE_IDLE,
    oc_swupdate_state_t swupdatestate = OC_SWUPDATE_STATE_IDLE,
    int swupdateresult = OC_SWUPDATE_RESULT_IDLE,
    oc_clock_time_t lastupdate = 0, oc_clock_time_t updatetime = 0)
  {
    oc_swupdate_t swu{};
    if (!purl.empty()) {
      oc_new_string(&swu.purl, purl.c_str(), purl.length());
    }
    if (!nv.empty()) {
      oc_new_string(&swu.nv, nv.c_str(), nv.length());
    }
    if (!signage.empty()) {
      oc_new_string(&swu.signage, signage.c_str(), signage.length());
    }
    swu.swupdateaction = swupdateaction;
    swu.swupdatestate = swupdatestate;
    swu.swupdateresult = swupdateresult;
    swu.lastupdate = lastupdate;
    swu.updatetime = updatetime;
    return swu;
  }

  static bool isEqual(const oc_swupdate_t &lhs, const oc_swupdate_t &rhs)
  {
    return oc_string_is_equal(&lhs.purl, &rhs.purl) &&
           oc_string_is_equal(&lhs.nv, &rhs.nv) &&
           oc_string_is_equal(&lhs.signage, &rhs.signage) &&
           lhs.swupdateaction == rhs.swupdateaction &&
           lhs.swupdatestate == rhs.swupdatestate &&
           lhs.swupdateresult == rhs.swupdateresult &&
           lhs.lastupdate == rhs.lastupdate && lhs.updatetime == rhs.updatetime;
  }

  static void expectEqual(const oc_swupdate_t &lhs, const oc_swupdate_t &rhs)
  {
    EXPECT_TRUE(oc_string_is_equal(&lhs.purl, &rhs.purl));
    EXPECT_TRUE(oc_string_is_equal(&lhs.nv, &rhs.nv));
    EXPECT_TRUE(oc_string_is_equal(&lhs.signage, &rhs.signage));
    EXPECT_EQ(lhs.swupdateaction, rhs.swupdateaction);
    EXPECT_EQ(lhs.swupdatestate, rhs.swupdatestate);
    EXPECT_EQ(lhs.swupdateresult, rhs.swupdateresult);
    EXPECT_EQ(lhs.lastupdate, rhs.lastupdate);
    EXPECT_EQ(lhs.updatetime, rhs.updatetime);
  }
};

TEST_F(TestSWUpdate, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_index(OCF_SW_UPDATE, /*device*/ SIZE_MAX));
}

TEST_F(TestSWUpdate, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_SW_UPDATE, kDeviceID));
}

TEST_F(TestSWUpdate, GetResourceByURI_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_uri_v1(
                       OCF_SW_UPDATE_URI, OC_CHAR_ARRAY_LEN(OCF_SW_UPDATE_URI),
                       /*device*/ SIZE_MAX));
}

TEST_F(TestSWUpdate, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_SW_UPDATE_URI, OC_CHAR_ARRAY_LEN(OCF_SW_UPDATE_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_SW_UPDATE_URI, oc_string(res->uri));
}

TEST_F(TestSWUpdate, Copy)
{
  oc_swupdate_t swu1 =
    createSWUpdate("testURL", "testVersion", "testSignage", OC_SWUPDATE_UPGRADE,
                   OC_SWUPDATE_STATE_UPGRADING, OC_SWUPDATE_RESULT_UPGRADE_FAIL,
                   oc_clock_time(), oc_clock_time());
  oc_swupdate_t swu2{};
  oc_swupdate_copy(&swu2, &swu1);
  expectEqual(swu1, swu2);

  oc_swupdate_copy(&swu1, &swu1);
  expectEqual(swu1, swu2);

  oc_swupdate_clear(&swu1);
  EXPECT_FALSE(isEqual(swu1, swu2));

  oc_swupdate_clear(&swu2);
}

TEST_F(TestSWUpdate, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_swupdate_default(kDeviceID);

  oc_swupdate_t def{};
  oc_swupdate_copy(&def, oc_swupdate_get(kDeviceID));

  oc_swupdate_t swu_new = createSWUpdate(
    "testURL", "testVersion", "testSignage", OC_SWUPDATE_UPGRADE,
    OC_SWUPDATE_STATE_UPGRADING, OC_SWUPDATE_RESULT_UPGRADE_FAIL);
  oc_swupdate_copy(oc_swupdate_get(kDeviceID), &swu_new);
  oc_swupdate_clear(&swu_new);
  EXPECT_FALSE(isEqual(def, *oc_swupdate_get(kDeviceID)));

  // load values from storage
  EXPECT_LT(0, oc_swupdate_load(kDeviceID));
  EXPECT_TRUE(isEqual(def, *oc_swupdate_get(kDeviceID)));

  oc_swupdate_clear(&def);
}

TEST_F(TestSWUpdate, ScheduleUpdateOnLoad)
{
  ASSERT_FALSE(oc_swupdate_action_is_scheduled(kDeviceID));
  oc_swupdate_t *swupdate = oc_swupdate_get(kDeviceID);
  ASSERT_NE(nullptr, swupdate);

  constexpr oc_clock_time_t kOneMinute = 60 * OC_CLOCK_SECOND;
  std::string packageURL = "https://update.plgd.dev";
  oc_set_string(&swupdate->purl, packageURL.c_str(), packageURL.length());
  swupdate->swupdateaction = OC_SWUPDATE_ISAC;
  swupdate->updatetime = oc_clock_time() + kOneMinute;

  ASSERT_LT(0, oc_swupdate_dump(kDeviceID));
  oc_swupdate_load(kDeviceID);

  EXPECT_TRUE(oc_swupdate_action_is_scheduled(kDeviceID));
  oc_swupdate_default(kDeviceID);
  EXPECT_FALSE(oc_swupdate_action_is_scheduled(kDeviceID));
}

TEST_F(TestSWUpdate, EncodeAndDecodeForDevice)
{
  oc_swupdate_t *swu = oc_swupdate_get(kDeviceID);
  ASSERT_NE(nullptr, swu);
  oc_swupdate_t swu_new = createSWUpdate(
    "testURL", "testVersion", "testSignage", OC_SWUPDATE_UPGRADE,
    OC_SWUPDATE_STATE_UPGRADING, OC_SWUPDATE_RESULT_UPGRADE_FAIL);
  oc_swupdate_copy(oc_swupdate_get(kDeviceID), &swu_new);
  oc_swupdate_clear(&swu_new);

  oc_swupdate_t swu_copy{};
  oc_swupdate_copy(&swu_copy, swu);

  oc::RepPool pool{};
  ASSERT_TRUE(oc_swupdate_encode_for_device(kDeviceID, /*flags*/ 0));

  oc_swupdate_clear(swu);
  EXPECT_FALSE(isEqual(*oc_swupdate_get(kDeviceID), swu_copy));

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  EXPECT_TRUE(
    oc_swupdate_decode_for_device(rep.get(),
                                  OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE |
                                    OC_SWUPDATE_DECODE_FLAG_IGNORE_ERRORS,
                                  kDeviceID));
  expectEqual(*oc_swupdate_get(kDeviceID), swu_copy);

  oc_swupdate_clear(&swu_copy);
}

TEST_F(TestSWUpdate, Decode_FailInvalidIntProperty)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_int(root, myAttribute, 1337);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailInvalidStringProperty)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, myAttribute, "leet");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailReadonlyUpdateResult)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_int(root, swupdateresult, OC_SWUPDATE_RESULT_SUCCESS);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailReadonlyNewVersion)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, nv, "4.2");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailReadonlySigned)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, signed, "plgd.dev");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailReadonlyUpdateState)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, swupdatestate,
                         oc_swupdate_state_to_str(OC_SWUPDATE_STATE_UPGRADING));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailReadonlyLastUpdate)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
    oc_clock_time(), [](const char *timestamp) {
      oc_rep_set_text_string(root, lastupdate, timestamp);
      return g_err == 0;
    }));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(rep.get(), /*flags*/ 0, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailInvalidLastUpdate)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, lastupdate, "not a valid timestamp");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(
    rep.get(), OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailInvalidAction)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, swupdateaction, "not valid action");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(
    rep.get(), OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailInvalidState)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, swupdatestate, "not valid state");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(
    rep.get(), OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE, &swu_parsed));
}

TEST_F(TestSWUpdate, Decode_FailInvalidUpdateTime)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(
    root, updatetime,
    "not a valid update time timestamp, one that is additionally extra "
    "extra very long as well");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  oc_swupdate_t swu_parsed{};
  EXPECT_FALSE(oc_swupdate_decode(
    rep.get(), OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE, &swu_parsed));
}

TEST_F(TestSWUpdate, ConvertAction)
{
  EXPECT_EQ(nullptr,
            oc_swupdate_action_to_str(static_cast<oc_swupdate_action_t>(-1)));
  std::string str{ "invalid value" };
  EXPECT_EQ(-1, oc_swupdate_action_from_str(str.c_str(), str.length()));

  str = oc_swupdate_action_to_str(OC_SWUPDATE_IDLE);
  EXPECT_EQ(OC_SWUPDATE_IDLE,
            oc_swupdate_action_from_str(str.c_str(), str.length()));
  str = oc_swupdate_action_to_str(OC_SWUPDATE_ISAC);
  EXPECT_EQ(OC_SWUPDATE_ISAC,
            oc_swupdate_action_from_str(str.c_str(), str.length()));
  str = oc_swupdate_action_to_str(OC_SWUPDATE_ISVV);
  EXPECT_EQ(OC_SWUPDATE_ISVV,
            oc_swupdate_action_from_str(str.c_str(), str.length()));
  str = oc_swupdate_action_to_str(OC_SWUPDATE_UPGRADE);
  EXPECT_EQ(OC_SWUPDATE_UPGRADE,
            oc_swupdate_action_from_str(str.c_str(), str.length()));
}

TEST_F(TestSWUpdate, ConvertState)
{
  EXPECT_EQ(nullptr,
            oc_swupdate_state_to_str(static_cast<oc_swupdate_state_t>(-1)));
  std::string str{ "invalid value" };
  EXPECT_EQ(-1, oc_swupdate_state_from_str(str.c_str(), str.length()));

  str = oc_swupdate_state_to_str(OC_SWUPDATE_STATE_IDLE);
  EXPECT_EQ(OC_SWUPDATE_STATE_IDLE,
            oc_swupdate_state_from_str(str.c_str(), str.length()));
  str = oc_swupdate_state_to_str(OC_SWUPDATE_STATE_NSA);
  EXPECT_EQ(OC_SWUPDATE_STATE_NSA,
            oc_swupdate_state_from_str(str.c_str(), str.length()));
  str = oc_swupdate_state_to_str(OC_SWUPDATE_STATE_SVV);
  EXPECT_EQ(OC_SWUPDATE_STATE_SVV,
            oc_swupdate_state_from_str(str.c_str(), str.length()));
  str = oc_swupdate_state_to_str(OC_SWUPDATE_STATE_SVA);
  EXPECT_EQ(OC_SWUPDATE_STATE_SVA,
            oc_swupdate_state_from_str(str.c_str(), str.length()));
  str = oc_swupdate_state_to_str(OC_SWUPDATE_STATE_UPGRADING);
  EXPECT_EQ(OC_SWUPDATE_STATE_UPGRADING,
            oc_swupdate_state_from_str(str.c_str(), str.length()));
}

class TestSWUpdateImplementation {
public:
  static int ValidateURL(const char *purl)
  {
    ++validateURLCounter_;
    if (purl != nullptr && (std::string(purl) == failingPackageURL)) {
      return -1;
    }
    return 0;
  };

  static int CheckNewVersion(size_t, const char *, const char *)
  {
    ++checkNewVersionCounter_;
    return 0;
  }

  static int DownloadUpgrade(size_t, const char *)
  {
    ++downloadUpgradeCounter_;
    return 0;
  }

  static int PerformUpgrade(size_t, const char *)
  {
    ++performUpgradeCounter_;
    return 0;
  }

  static void Clear()
  {
    validateURLCounter_ = 0;
    checkNewVersionCounter_ = 0;
    downloadUpgradeCounter_ = 0;
    performUpgradeCounter_ = 0;
#ifdef OC_SECURITY
    oc_sec_pstat_set_current_mode(kDeviceID, static_cast<oc_dpmtype_t>(0));
#endif /* OC_SECURITY */
  }

  static std::string failingPackageURL;

  static int validateURLCounter_;
  static int checkNewVersionCounter_;
  static int downloadUpgradeCounter_;
  static int performUpgradeCounter_;
  static oc_swupdate_cb_t instance;
};

std::string TestSWUpdateImplementation::failingPackageURL("duckduckgo.com");
int TestSWUpdateImplementation::validateURLCounter_ = 0;
int TestSWUpdateImplementation::checkNewVersionCounter_ = 0;
int TestSWUpdateImplementation::downloadUpgradeCounter_ = 0;
int TestSWUpdateImplementation::performUpgradeCounter_ = 0;
oc_swupdate_cb_t TestSWUpdateImplementation::instance{
  /*validate_purl=*/TestSWUpdateImplementation::ValidateURL,
  /*check_new_version=*/TestSWUpdateImplementation::CheckNewVersion,
  /*download_update=*/TestSWUpdateImplementation::DownloadUpgrade,
  /*perform_upgrade=*/TestSWUpdateImplementation::PerformUpgrade,
};

class TestSWUpdateWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SW_UPDATE, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

    oc_swupdate_clear(oc_swupdate_get(kDeviceID));
    TestSWUpdateImplementation::Clear();
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    oc_swupdate_set_impl(&TestSWUpdateImplementation::instance);
  }

  void TearDown() override
  {
    oc_swupdate_clear(oc_swupdate_get(kDeviceID));
    TestSWUpdateImplementation::Clear();
  }
};

struct ValidateUpdateError
{
  std::string property;
  oc_swupdate_validate_update_error_t error;
};

template<bool Continue = true>
static bool
storeError(const oc_rep_t *rep, oc_swupdate_validate_update_error_t error,
           void *data)
{
  OC_DBG("SWU validation error(%d)", static_cast<int>(error));
  auto *errors = static_cast<std::vector<ValidateUpdateError> *>(data);
  errors->push_back({ rep != nullptr ? oc_string(rep->name) : "", error });
  return Continue;
}

static bool
hasStoredError(const std::vector<ValidateUpdateError> &errors,
               std::string_view property,
               oc_swupdate_validate_update_error_t error)
{
  return std::any_of(
    std::begin(errors), std::end(errors), [property, error](const auto &e) {
      return (property.empty() || e.property == property) && e.error == error;
    });
}

TEST_F(TestSWUpdateWithServer, ValidateUpdate_FailInvalidImplementation)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  std::string packageURL{ "https://test.package.com" };
  oc_rep_set_text_string(root, purl, packageURL.c_str());
  oc_rep_set_text_string(root, updatetime, "now");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_swupdate_set_impl(nullptr);
  std::vector<ValidateUpdateError> errors{};
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError, &errors));
  ASSERT_EQ(1, errors.size());
  EXPECT_EQ(OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_IMPLEMENTATION,
            errors[0].error);
  errors.clear();

  oc_swupdate_cb_t instance{
    /*validate_purl=*/nullptr,
    /*check_new_version=*/TestSWUpdateImplementation::CheckNewVersion,
    /*download_update=*/TestSWUpdateImplementation::DownloadUpgrade,
    /*perform_upgrade=*/TestSWUpdateImplementation::PerformUpgrade,
  };
  oc_swupdate_set_impl(&instance);
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError, &errors));
  ASSERT_EQ(1, errors.size());
  EXPECT_EQ(OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_IMPLEMENTATION,
            errors[0].error);
}

TEST_F(TestSWUpdateWithServer, ValidateUpdate_FailMissingRequired)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<ValidateUpdateError> errors{};
  // continue after error
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError<true>, &errors));
  ASSERT_EQ(2, errors.size());
  EXPECT_TRUE(hasStoredError(
    errors, "", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_UPDATETIME_NOT_SET));
  EXPECT_TRUE(
    hasStoredError(errors, "", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_PURL_NOT_SET));

  errors.clear();
  // stop on first error
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError<false>, &errors));
  EXPECT_EQ(1, errors.size());
}

TEST_F(TestSWUpdateWithServer, ValidateUpdate_FailReadonly)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  std::string packageURL{ "https://test.package.com" };
  oc_rep_set_text_string(root, purl, packageURL.c_str());
  oc_rep_set_text_string(root, updatetime, "none");
  oc_rep_set_int(root, swupdateresult, OC_SWUPDATE_RESULT_SUCCESS);
  oc_rep_set_text_string(root, nv, "4.2");
  oc_rep_set_text_string(root, signed, "plgd.dev");
  oc_rep_set_text_string(root, swupdatestate,
                         oc_swupdate_state_to_str(OC_SWUPDATE_STATE_UPGRADING));
  ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
    oc_clock_time(), [](const char *timestamp) {
      oc_rep_set_text_string(root, lastupdate, timestamp);
      return g_err == 0;
    }));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<ValidateUpdateError> errors{};
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError, &errors));
  ASSERT_EQ(5, errors.size());
  EXPECT_TRUE(
    hasStoredError(errors, "swupdateresult",
                   OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY));
  EXPECT_TRUE(hasStoredError(
    errors, "nv", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY));
  EXPECT_TRUE(hasStoredError(
    errors, "signed", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY));
  EXPECT_TRUE(
    hasStoredError(errors, "swupdatestate",
                   OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY));
  EXPECT_TRUE(hasStoredError(
    errors, "lastupdate", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY));
}

TEST_F(TestSWUpdateWithServer, ValidateUpdate_InvalidProperty)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  std::string packageURL{ "https://test.package.com" };
  oc_rep_set_text_string(root, purl, packageURL.c_str());
  oc_rep_set_text_string(root, updatetime, "now");

  oc_rep_set_text_string(root, invalid, "does not exist");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<ValidateUpdateError> errors{};
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError, &errors));
  ASSERT_EQ(1, errors.size());
  EXPECT_TRUE(hasStoredError(
    errors, "invalid", OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY));
}

TEST_F(TestSWUpdateWithServer, ValidateUpdate_InvalidPropertyValue)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  std::string packageURL{ "https://test.package.com" };
  oc_rep_set_text_string(root, purl, packageURL.c_str());

  oc_rep_set_text_string(root, updatetime, "not a valid timestamp");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<ValidateUpdateError> errors{};
  EXPECT_FALSE(oc_swupdate_validate_update(kDeviceID, pool.ParsePayload().get(),
                                           storeError, &errors));
  ASSERT_EQ(1, errors.size());
  EXPECT_TRUE(
    hasStoredError(errors, "updatetime",
                   OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY_VALUE));
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestSWUpdateWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_swupdate_t *swupdate = oc_swupdate_get(kDeviceID);
  ASSERT_NE(nullptr, swupdate);
  constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
  oc_swupdate_t swu_new = TestSWUpdate::createSWUpdate(
    "testURL", "testVersion", "testSignage", OC_SWUPDATE_UPGRADE,
    OC_SWUPDATE_STATE_UPGRADING, OC_SWUPDATE_RESULT_UPGRADE_FAIL,
    oc_clock_time() + kOneDay, oc_clock_time() + kOneDay);
  oc_swupdate_copy(oc_swupdate_get(kDeviceID), &swu_new);
  oc_swupdate_clear(&swu_new);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *swu = static_cast<oc_swupdate_t *>(data->user_data);
    EXPECT_TRUE(oc_swupdate_decode(data->payload,
                                   OC_SWUPDATE_DECODE_FLAG_IGNORE_ERRORS |
                                     OC_SWUPDATE_DECODE_FLAG_FROM_STORAGE,
                                   swu));
  };

  auto timeout = 1s;
  oc_swupdate_t swu_get{};
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SW_UPDATE_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &swu_get));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  TestSWUpdate::expectEqual(*oc_swupdate_get(kDeviceID), swu_get);
  oc_swupdate_clear(&swu_get);
}

static void
postRequest(const std::function<void()> &payloadFn)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SW_UPDATE_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  payloadFn();

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

// test special value "none" for updatetime which disables scheduled update
TEST_F(TestSWUpdateWithServer, PostRequestNoUpdate)
{
  oc_swupdate_action_schedule(kDeviceID,
                              oc_clock_time() + oc::DurationToTicks(1h));
  ASSERT_TRUE(oc_swupdate_action_is_scheduled(kDeviceID));

  std::string packageURL{ "https://test.package.com" };
  oc_swupdate_action_t swupdateaction{ OC_SWUPDATE_ISAC };

  auto post_payload = [packageURL, swupdateaction] {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, packageURL.c_str());
    oc_rep_set_text_string(root, swupdateaction,
                           oc_swupdate_action_to_str(swupdateaction));
    oc_rep_set_text_string(root, updatetime, "none");
    oc_rep_end_root_object();
  };

  postRequest(post_payload);

  EXPECT_STREQ(packageURL.c_str(), oc_string(oc_swupdate_get(kDeviceID)->purl));
  EXPECT_EQ(swupdateaction, oc_swupdate_get(kDeviceID)->swupdateaction);
  EXPECT_FALSE(oc_swupdate_action_is_scheduled(kDeviceID));
}

// test special value "now" for updatetime which triggers immediate update
TEST_F(TestSWUpdateWithServer, PostRequestUpdateNow)
{
  std::string packageURL{ "https://test.package.com" };
  oc_swupdate_action_t swupdateaction{ OC_SWUPDATE_UPGRADE };

  oc_clock_time_t start = oc_clock_time();

  auto post_payload = [packageURL, swupdateaction] {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, packageURL.c_str());
    oc_rep_set_text_string(root, swupdateaction,
                           oc_swupdate_action_to_str(swupdateaction));
    oc_rep_set_text_string(root, updatetime, "now");
    oc_rep_end_root_object();
  };

  postRequest(post_payload);

  EXPECT_STREQ(packageURL.c_str(), oc_string(oc_swupdate_get(kDeviceID)->purl));
  EXPECT_EQ(swupdateaction, oc_swupdate_get(kDeviceID)->swupdateaction);

  oc_clock_time_t end = oc_clock_time();
  EXPECT_LT(start, oc_swupdate_get(kDeviceID)->updatetime);
  EXPECT_GT(end, oc_swupdate_get(kDeviceID)->updatetime);
}

TEST_F(TestSWUpdateWithServer, PostRequestScheduleUpdate)
{
  auto update_after = 500ms;
  auto post_payload = [update_after]() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, "https://test.package.com");
    oc_rep_set_text_string(root, swupdateaction,
                           oc_swupdate_action_to_str(OC_SWUPDATE_ISAC));
    ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
      oc_clock_time() + oc::DurationToTicks(update_after),
      [](const char *timestamp) {
        oc_rep_set_text_string(root, updatetime, timestamp);
        return g_err == 0;
      }));
    oc_rep_end_root_object();
  };

  postRequest(post_payload);
  EXPECT_TRUE(oc_swupdate_action_is_scheduled(kDeviceID));

  oc::TestDevice::PoolEventsMs(update_after.count() + 200);
  EXPECT_EQ(1, TestSWUpdateImplementation::checkNewVersionCounter_);
}

// special case if package URL was set previously and then empty string can be
// used to skip URL validation
TEST_F(TestSWUpdateWithServer, PostRequestEmptyPackageURL)
{
  std::string purl{ "https://test.package.com" };
  std::string post_purl{ purl };
  oc_swupdate_action_t post_action{ OC_SWUPDATE_IDLE };
  auto post_payload = [&post_purl, &post_action]() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, post_purl.c_str());
    oc_rep_set_text_string(root, swupdateaction,
                           oc_swupdate_action_to_str(post_action));
    oc_rep_set_text_string(root, updatetime, "none");
    oc_rep_end_root_object();
  };

  // idle action to set and validate package URL
  postRequest(post_payload);
  EXPECT_EQ(1, TestSWUpdateImplementation::validateURLCounter_);

  // other actions can now use empty string to skip URL validation
  post_action = OC_SWUPDATE_ISAC;
  post_purl = {};
  postRequest(post_payload);
  EXPECT_EQ(1, TestSWUpdateImplementation::validateURLCounter_);

  post_action = OC_SWUPDATE_ISVV;
  postRequest(post_payload);
  EXPECT_EQ(1, TestSWUpdateImplementation::validateURLCounter_);

  post_action = OC_SWUPDATE_UPGRADE;
  postRequest(post_payload);
  EXPECT_EQ(1, TestSWUpdateImplementation::validateURLCounter_);
}

template<oc_status_t ErrorCode>
static void
postRequestWithFailure(const std::function<void()> &payloadFn)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(ErrorCode, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SW_UPDATE_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  // get payload
  payloadFn();

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}
// POST request should fail if updatetime is not set
TEST_F(TestSWUpdateWithServer, PostRequest_FailUpdateTimeMissing)
{
  auto get_payload = []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, "https://test.package.com");
    oc_rep_end_root_object();
  };
  postRequestWithFailure<OC_STATUS_NOT_ACCEPTABLE>(get_payload);

  EXPECT_EQ(0, TestSWUpdateImplementation::validateURLCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::checkNewVersionCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
}

// POST request should fail if updatetime is in the past
TEST_F(TestSWUpdateWithServer, PostRequest_FailUpdateTimeInPast)
{
  auto get_payload = []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, purl, "https://test.package.com");
    constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
    ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
      oc_clock_time() - kOneDay, [](const char *timestamp) {
        oc_rep_set_text_string(root, updatetime, timestamp);
        return g_err == 0;
      }));
    oc_rep_end_root_object();
  };
  postRequestWithFailure<OC_STATUS_NOT_ACCEPTABLE>(get_payload);

  EXPECT_EQ(0, TestSWUpdateImplementation::validateURLCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::checkNewVersionCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
}

// POST request should fail if purl is not set
TEST_F(TestSWUpdateWithServer, PostRequest_FailPackageURLNotSet)
{
  auto get_payload = []() {
    oc_rep_start_root_object();
    constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
    ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
      oc_clock_time() + kOneDay, [](const char *timestamp) {
        oc_rep_set_text_string(root, updatetime, timestamp);
        return g_err == 0;
      }));
    oc_rep_end_root_object();
  };
  postRequestWithFailure<OC_STATUS_NOT_ACCEPTABLE>(get_payload);

  EXPECT_EQ(0, TestSWUpdateImplementation::validateURLCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::checkNewVersionCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
}

// POST request should fail if purl does not pass validation
TEST_F(TestSWUpdateWithServer, PostRequest_FailInvalidPackageURL)
{
  auto get_payload = []() {
    oc_rep_start_root_object();
    constexpr oc_clock_time_t kOneDay = 60 * 60 * 24 * OC_CLOCK_SECOND;
    ASSERT_TRUE(oc_swupdate_encode_clocktime_to_string(
      oc_clock_time() + kOneDay, [](const char *timestamp) {
        oc_rep_set_text_string(root, updatetime, timestamp);
        return g_err == 0;
      }));
    oc_rep_set_text_string(
      root, purl, TestSWUpdateImplementation::failingPackageURL.c_str());
    oc_rep_end_root_object();
  };
  postRequestWithFailure<OC_STATUS_NOT_ACCEPTABLE>(get_payload);

  EXPECT_EQ(1, TestSWUpdateImplementation::validateURLCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::checkNewVersionCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
}

TEST_F(TestSWUpdateWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  auto encode_payload = []() {
    oc_swupdate_t swu_new{};
    EXPECT_EQ(0, oc_swupdate_encode_with_resource(&swu_new, /*swu_res*/ nullptr,
                                                  /*flags*/ 0));
  };
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SW_UPDATE_URI, encode_payload);
}

TEST_F(TestSWUpdateWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_SW_UPDATE_URI);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

/** Test all SWU steps
 *   - SWU notification with success (OC_SWUPDATE_RESULT_SUCCESS) should trigger
 * the corresponding action
 */
TEST_F(TestSWUpdateWithServer, Upgrade)
{
  std::string version{ "4.2" };

  EXPECT_EQ(0, TestSWUpdateImplementation::checkNewVersionCounter_);
  oc_swupdate_perform_action(OC_SWUPDATE_ISAC, kDeviceID);
  EXPECT_EQ(1, TestSWUpdateImplementation::checkNewVersionCounter_);
#ifdef OC_SECURITY
  EXPECT_EQ(0, oc_sec_pstat_current_mode(kDeviceID));
#endif /* OC_SECURITY */

  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  oc_swupdate_notify_new_version_available(kDeviceID, version.c_str(),
                                           OC_SWUPDATE_RESULT_SUCCESS);
  EXPECT_EQ(1, TestSWUpdateImplementation::downloadUpgradeCounter_);
#ifdef OC_SECURITY
  EXPECT_EQ(OC_DPM_NSA, oc_sec_pstat_current_mode(kDeviceID));
#endif /* OC_SECURITY */

  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
  oc_swupdate_notify_downloaded(kDeviceID, version.c_str(),
                                OC_SWUPDATE_RESULT_SUCCESS);
  EXPECT_EQ(1, TestSWUpdateImplementation::performUpgradeCounter_);
#ifdef OC_SECURITY
  EXPECT_EQ(OC_DPM_NSA | OC_DPM_SVV, oc_sec_pstat_current_mode(kDeviceID));
#endif /* OC_SECURITY */

  oc_clock_time_t updatetime = oc_clock_time();
  oc_swupdate_notify_upgrading(kDeviceID, version.c_str(), updatetime,
                               OC_SWUPDATE_RESULT_SUCCESS);
#ifdef OC_SECURITY
  EXPECT_EQ(OC_DPM_NSA | OC_DPM_SVV | OC_DPM_SSV,
            oc_sec_pstat_current_mode(kDeviceID));
#endif /* OC_SECURITY */

  oc_swupdate_notify_done(kDeviceID, OC_SWUPDATE_RESULT_SUCCESS);
#ifdef OC_SECURITY
  EXPECT_EQ(0, oc_sec_pstat_current_mode(kDeviceID));
#endif /* OC_SECURITY */
}

/** Notification with unsuccesful result should not trigger the next step */
TEST_F(TestSWUpdateWithServer, UpgradeNoNextStep)
{
  std::string version{ "4.2" };

  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);
  oc_swupdate_notify_new_version_available(kDeviceID, version.c_str(),
                                           OC_SWUPDATE_RESULT_SVV_FAIL);
  EXPECT_EQ(0, TestSWUpdateImplementation::downloadUpgradeCounter_);

  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
  oc_swupdate_notify_downloaded(kDeviceID, version.c_str(),
                                OC_SWUPDATE_RESULT_CONN_FAIL);
  EXPECT_EQ(0, TestSWUpdateImplementation::performUpgradeCounter_);
}

#endif /* OC_SOFTWARE_UPDATE */
