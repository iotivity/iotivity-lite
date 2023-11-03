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
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_store.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_svr_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Resource.h"
#include "util/oc_features.h"

#ifdef OC_SOFTWARE_UPDATE
#include "api/oc_swupdate_internal.h"
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <filesystem>
#include <gtest/gtest.h>
#include <string>

static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };
static const std::string testStorage{ "storage_test" };

class TestPstat : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(),
                               kDeviceName.c_str(), kOCFSpecVersion.c_str(),
                               kOCFDataModelVersion.c_str(), nullptr, nullptr));
    oc_sec_svr_create();
#ifdef OC_SOFTWARE_UPDATE
    oc_swupdate_create();
#endif /* OC_SOFTWARE_UPDATE */

    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));
  }

  static void TearDownTestCase()
  {
#ifdef OC_SOFTWARE_UPDATE
    oc_swupdate_free();
#endif /* OC_SOFTWARE_UPDATE */
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(0);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();

    for (const auto &entry : std::filesystem::directory_iterator(testStorage)) {
      std::filesystem::remove_all(entry.path());
    }
    ASSERT_EQ(0, oc_storage_reset());
  }

  static bool IsEqual(const oc_sec_pstat_t &lhs, const oc_sec_pstat_t &rhs)
  {
    return lhs.s == rhs.s && lhs.p == rhs.p && lhs.isop == rhs.isop &&
           lhs.cm == rhs.cm && lhs.tm == rhs.tm && lhs.om == rhs.om &&
           lhs.sm == rhs.sm && oc_uuid_is_equal(lhs.rowneruuid, rhs.rowneruuid);
  }

  static void ExpectEqual(const oc_sec_pstat_t &lhs, const oc_sec_pstat_t &rhs)
  {
    EXPECT_EQ(lhs.s, rhs.s);
    EXPECT_EQ(lhs.p, rhs.p);
    EXPECT_EQ(lhs.isop, rhs.isop);
    EXPECT_EQ(lhs.cm, rhs.cm);
    EXPECT_EQ(lhs.tm, rhs.tm);
    EXPECT_EQ(lhs.om, rhs.om);
    EXPECT_EQ(lhs.sm, rhs.sm);
  }
};

TEST_F(TestPstat, Copy)
{
  oc_sec_pstat_t ps1{};
  ps1.s = OC_DOS_SRESET;
  ps1.p = true;
  ps1.isop = true;
  ps1.cm = OC_DPM_SSV;
  ps1.tm = OC_DPM_NSA;
  ps1.om = 4;
  ps1.sm = 4;

  oc_sec_pstat_t ps2{};
  oc_sec_pstat_copy(&ps2, &ps1);
  ExpectEqual(ps1, ps2);

  oc_sec_pstat_copy(&ps1, &ps1);
  ExpectEqual(ps2, ps1);

  oc_sec_pstat_clear(&ps1, false);
  EXPECT_FALSE(IsEqual(ps1, ps2));
}

TEST_F(TestPstat, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_sec_pstat_default(0);

  oc_sec_pstat_t def{};
  oc_sec_pstat_copy(&def, oc_sec_get_pstat(0));
  oc_sec_pstat_clear(oc_sec_get_pstat(0), false);
  EXPECT_FALSE(IsEqual(def, *oc_sec_get_pstat(0)));

  // load values from storage
  oc_sec_load_pstat(0);
  EXPECT_TRUE(IsEqual(def, *oc_sec_get_pstat(0)));
}

static constexpr size_t kDeviceID{ 0 };

class TestPstatWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SEC_PSTAT, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }
};

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#else /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestPstatWithServer, PostRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_POST, &ep, "/oic/sec/pstat", nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestPstatWithServer, PutRequest_Fail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_PUT, &ep, "/oic/sec/pstat", nullptr,
                             error_code);
}

TEST_F(TestPstatWithServer, DeleteRequest_Fail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_DELETE, &ep, "/oic/sec/pstat", nullptr,
                             error_code);
}

#endif /* OC_SECURITY */
