/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include <gtest/gtest.h>

extern "C" {
  #include "cloud_access.h"
}

class TestCloudAccess: public testing::Test
{
  protected:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F(TestCloudAccess, oc_sign_up_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_sign_up(ep, NULL, NULL, NULL , 0,NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_sign_up_with_auth_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_sign_up_with_auth(ep, NULL, NULL, 0, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_sign_in_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_sign_in(ep, NULL, NULL, 0, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_sign_out_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_sign_out(ep, NULL, 0, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_refresh_access_token_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_refresh_access_token(ep, NULL, NULL, 0, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_set_device_profile_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_set_device_profile(ep, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_delete_device_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_delete_device(ep, NULL, 0, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_find_ping_resource_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_find_ping_resource(ep, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_send_ping_request_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_send_ping_request(ep, 1, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_send_ping_update_f)
{
  // Given
  oc_endpoint_t *ep = NULL;
  int interval[4] = { 1, 2, 4, 8 };

  // When
  bool ret = oc_send_ping_update(ep, interval, 4, NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}
