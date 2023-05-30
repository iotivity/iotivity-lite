/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "oc_config.h"

#ifdef OC_INTROSPECTION

#include "api/oc_introspection_internal.h"
#include "oc_core_res.h"
#include "oc_ri.h"

#include "tests/gtest/Device.h"
#include "tests/gtest/Resource.h"

#include <gtest/gtest.h>

class TestIntrospectionWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_INTROSPECTION_WK, /*device*/ 0,
                                     OC_PERM_RETRIEVE));
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_INTROSPECTION_DATA, /*device*/ 0,
                                     OC_PERM_RETRIEVE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }
};

TEST_F(TestIntrospectionWithServer, GetResource)
{
  EXPECT_NE(nullptr,
            oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, /*device*/ 0));
}

TEST_F(TestIntrospectionWithServer, GetDataResource)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_INTROSPECTION_DATA,
                                                   /*device*/ 0));
}

TEST_F(TestIntrospectionWithServer, GetRequest)
{
  // TODO: OC_GET on OCF_INTROSPECTION_WK
}

TEST_F(TestIntrospectionWithServer, GetDataRequest)
{
  // TODO: OC_GET on OCF_INTROSPECTION_DATA
}

#endif /* OC_INTROSPECTION */
