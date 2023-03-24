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
#include "oc_store.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_svr_internal.h"
#include "util/oc_macros.h"

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

class TestDoxm : public testing::Test {
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

  static bool IsEqual(const oc_sec_doxm_t &lhs, const oc_sec_doxm_t &rhs)
  {
    if (lhs.oxmsel != rhs.oxmsel || lhs.sct != rhs.sct ||
        lhs.owned != rhs.owned || lhs.num_oxms != rhs.num_oxms ||
        !oc_uuid_is_equal(lhs.deviceuuid, rhs.deviceuuid) ||
        !oc_uuid_is_equal(lhs.devowneruuid, rhs.devowneruuid) ||
        !oc_uuid_is_equal(lhs.rowneruuid, rhs.rowneruuid)) {
      return false;
    }
    for (int i = 0; i < std::min<int>(lhs.num_oxms, OC_ARRAY_SIZE(lhs.oxms));
         ++i) {
      if (lhs.oxms[i] != rhs.oxms[i]) {
        return false;
      }
    }
    return true;
  }
};

TEST_F(TestDoxm, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_sec_doxm_default(0);

  oc_sec_doxm_t def{};
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(0);
  ASSERT_NE(nullptr, doxm);
  memcpy(&def, doxm, sizeof(oc_sec_doxm_t));
  // overwrite doxm data with 0
  memset(doxm, 0, sizeof(oc_sec_doxm_t));

  EXPECT_FALSE(IsEqual(def, *oc_sec_get_doxm(0)));

  // load values from storage
  oc_sec_load_doxm(0);
  EXPECT_TRUE(IsEqual(def, *oc_sec_get_doxm(0)));
}

#endif /* OC_SECURITY */
