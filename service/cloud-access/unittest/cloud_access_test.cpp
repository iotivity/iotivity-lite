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

#include "cloud_access.h"
#include "oc_api.h"
#include "oc_endpoint.h"

class TestCloudAccess: public testing::Test
{
  public:
    static oc_handler_t s_handler;
    static oc_endpoint_t s_endpoint;

    static void onPostResponse(oc_client_response_t *data)
    {
      (void) data;
    }

    static int appInit(void)
    {
      int result = oc_init_platform("Samsung", NULL, NULL);
      result |= oc_add_device("/oic/d", "oic.d.light", "Jaehong's Light",
                              "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
      return result;
    }

    static void signalEventLoop(void)
    {
    }

  protected:
    static void SetUpTestCase()
    {
      s_handler.init = &appInit;
      s_handler.signal_event_loop = &signalEventLoop;
      int ret = oc_main_init(&s_handler);
      ASSERT_EQ(0, ret);

      oc_string_t ep_str;
      oc_new_string(&ep_str, "coap://224.0.1.187:5683", 23);
      oc_string_to_endpoint(&ep_str, &s_endpoint, NULL);
      oc_free_string(&ep_str);
    }

    static void TearDownTestCase()
    {
      oc_main_shutdown();
    }
};
oc_handler_t TestCloudAccess::s_handler;
oc_endpoint_t TestCloudAccess::s_endpoint;

TEST_F(TestCloudAccess, oc_sign_up_p)
{
  // When
  bool ret = oc_sign_up(&s_endpoint, "auth_provider", "uid", "access_token", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestCloudAccess, oc_sign_up_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = oc_sign_up(ep, NULL, NULL, NULL , 0,NULL, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestCloudAccess, oc_sign_up_with_auth_p)
{
  // When
  bool ret = oc_sign_up_with_auth(&s_endpoint, "auth_provider", "auth_code", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_sign_in_p)
{
  // When
  bool ret = oc_sign_in(&s_endpoint, "uid", "access_token", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_sign_out_p)
{
  // When
  bool ret = oc_sign_out(&s_endpoint, "access_token", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_refresh_access_token_p)
{
  // When
  bool ret = oc_refresh_access_token(&s_endpoint, "uid", "refresh_token", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_set_device_profile_p)
{
  // When
  bool ret = oc_set_device_profile(&s_endpoint, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_delete_device_p)
{
  // When
  bool ret = oc_delete_device(&s_endpoint, "uid", 0, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_find_ping_resource_p)
{
  // When
  bool ret = oc_find_ping_resource(&s_endpoint, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_send_ping_request_p)
{
  // When
  bool ret = oc_send_ping_request(&s_endpoint, 1, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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

TEST_F(TestCloudAccess, oc_send_ping_update_p)
{
  // Given
  int interval[4] = { 1, 2, 4, 8 };

  // When
  bool ret = oc_send_ping_update(&s_endpoint, interval, 4, onPostResponse, NULL);

  // Then
  EXPECT_TRUE(ret);
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
