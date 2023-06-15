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

#include "oc_core_res.h"
#include "oc_ri.h"
#include "tests/gtest/Device.h"

#include <gtest/gtest.h>
#include <cstddef>

static constexpr size_t kDeviceID{ 0 };

class TestCloudResourceWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestCloudResourceWithServer, GetResource)
{
  EXPECT_NE(nullptr,
            oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, kDeviceID));
}

TEST_F(TestCloudResourceWithServer, GetRequest)
{
  // TODO
}

TEST_F(TestCloudResourceWithServer, PostRequest)
{
  // TODO
}

TEST_F(TestCloudResourceWithServer, PutRequest_FailMethodNotSupported)
{
  // TODO
}

TEST_F(TestCloudResourceWithServer, DeleteRequest_FailMethodNotSupported)
{
  // TODO
}
