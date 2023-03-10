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
#include "api/oc_storage_internal.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_sp.h"
#include "oc_store.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "security/oc_sp_internal.h"
#include "security/oc_svr_internal.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <algorithm>
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

class TestSecurityProfile : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_network_event_handler_mutex_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(),
                               kDeviceName.c_str(), kOCFSpecVersion.c_str(),
                               kOCFDataModelVersion.c_str(), nullptr, nullptr));
    oc_sec_svr_create();
    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));
  }

  static void TearDownTestCase()
  {
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(0);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_network_event_handler_mutex_destroy();

    for (const auto &entry : std::filesystem::directory_iterator(testStorage)) {
      std::filesystem::remove_all(entry.path());
    }
    ASSERT_EQ(0, oc_storage_reset());
  }

  static bool IsEqual(const oc_sec_sp_t &lhs, const oc_sec_sp_t &rhs)
  {
    return lhs.supported_profiles == rhs.supported_profiles &&
           lhs.current_profile == rhs.current_profile &&
           lhs.credid == rhs.credid;
  }

  static void ExpectEqual(const oc_sec_sp_t &lhs, const oc_sec_sp_t &rhs)
  {
    EXPECT_EQ(lhs.supported_profiles, rhs.supported_profiles);
    EXPECT_EQ(lhs.current_profile, rhs.current_profile);
    EXPECT_EQ(lhs.credid, rhs.credid);
  }
};

TEST_F(TestSecurityProfile, Copy)
{
  oc_sec_sp_t sp1;
  sp1.supported_profiles = OC_SP_BASELINE | OC_SP_BLACK | OC_SP_BLUE;
  sp1.current_profile = OC_SP_BLACK;
  sp1.credid = 42;

  oc_sec_sp_t sp2{};
  oc_sec_sp_copy(&sp2, &sp1);
  ExpectEqual(sp1, sp2);

  oc_sec_sp_copy(&sp1, &sp1);
  ExpectEqual(sp2, sp1);

  oc_sec_sp_clear(&sp1);
  EXPECT_FALSE(IsEqual(sp1, sp2));
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
  oc_sec_sp_default(0);

  oc_sec_sp_t def{};
  oc_sec_sp_copy(&def, oc_sec_get_sp(0));
  oc_sec_sp_clear(oc_sec_get_sp(0));
  EXPECT_FALSE(IsEqual(def, *oc_sec_get_sp(0)));

  // load values from storage
  oc_sec_load_sp(0);
  EXPECT_TRUE(IsEqual(def, *oc_sec_get_sp(0)));
}

#endif /* OC_SECURITY */
