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
#include "oc_api.h"
#include "oc_endpoint.h"
#include "rd_client.h"
}

class TestRDClient: public testing::Test
{
  public:
    static oc_handler_t s_handler;

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

    static void onPostResponse(oc_client_response_t *data)
    {
      (void) data;
    }

  protected:
    static void SetUpTestCase()
    {
      s_handler.init = &appInit;
      s_handler.signal_event_loop = &signalEventLoop;
      int ret = oc_main_init(&s_handler);
      ASSERT_EQ(0, ret);
    }

    static void TearDownTestCase()
    {
      oc_main_shutdown();
    }
};
oc_handler_t TestRDClient::s_handler;

TEST_F(TestRDClient, rd_publish_p)
{
  // Given
  oc_endpoint_t ep;
  oc_string_t ep_str;
  oc_new_string(&ep_str, "coap://224.0.1.187:5683", strlen("coap://224.0.1.187:5683"));
  oc_string_to_endpoint(&ep_str, &ep, NULL);

  // When
  bool ret = rd_publish(&ep, NULL, 0, onPostResponse, LOW_QOS, NULL);

  // Then
  EXPECT_TRUE(ret);
}

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
