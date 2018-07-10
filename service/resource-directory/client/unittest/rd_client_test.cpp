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
  #include "rd_client.h"
}

class TestRDClient: public testing::Test
{
  protected:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F(TestRDClient, rd_publish_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_publish(ep, NULL, 0, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_publish_with_device_id_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_publish_with_device_id(ep, NULL, NULL, NULL, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_publish_all_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_publish_all(ep, 0, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_delete_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_delete(ep, NULL, 0, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_delete_with_device_id_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_delete_with_device_id(ep, NULL, NULL, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}
