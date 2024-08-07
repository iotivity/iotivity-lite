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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_internal.h"
#include "api/oc_link_internal.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_ri.h"
#include "tests/gtest/Device.h"

#include "gtest/gtest.h"

static constexpr size_t kDeviceID{ 0 };

class TestCloudRD : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override { oc::TestDevice::Reset(); }

  static oc_resource_t *findResource(oc_link_t *head, const oc_resource_t *res)
  {
    for (oc_link_t *l = head; l; l = l->next) {
      if (l->resource == res) {
        return l->resource;
      }
    }
    return nullptr;
  }
};

TEST_F(TestCloudRD, cloud_publish_f)
{
  // When
  int ret = oc_cloud_add_resource(nullptr);

  // Then
  ASSERT_EQ(-1, ret);
}

TEST_F(TestCloudRD, cloud_publish_p)
{
  // When
  oc_resource_t *res1 = oc_new_resource(nullptr, "/light/1", 1, kDeviceID);
  oc_resource_bind_resource_type(res1, "test");
  int ret = oc_cloud_add_resource(res1);

  // Then
  ASSERT_EQ(0, ret);
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  ASSERT_NE(nullptr, ctx->rd_publish_resources);
  EXPECT_EQ(res1, findResource(ctx->rd_publish_resources, res1));

  // Clean-up
  oc_cloud_delete_resource(res1);
  EXPECT_TRUE(oc_delete_resource(res1));
}

TEST_F(TestCloudRD, cloud_delete)
{
  // When
  oc_resource_t *res1 = oc_new_resource(nullptr, "/light/1", 1, kDeviceID);
  oc_resource_bind_resource_type(res1, "test");
  int ret = oc_cloud_add_resource(res1);
  ASSERT_EQ(0, ret);
  oc_cloud_delete_resource(res1);

  // Then
  oc_cloud_context_t *ctx = oc_cloud_get_context(kDeviceID);
  ASSERT_NE(nullptr, ctx);
  EXPECT_EQ(nullptr, findResource(ctx->rd_publish_resources, res1));

  // Clean-up
  EXPECT_TRUE(oc_delete_resource(res1));
}
