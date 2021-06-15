/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "oc_api.h"
#include "oc_endpoint.h"
#include "rd_client.h"

class TestRDClient : public testing::Test
{
public:
  static oc_handler_t s_handler;
  static oc_endpoint_t s_endpoint;

  static void onPostResponse(oc_client_response_t *data) { (void)data; }

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", NULL, NULL);
    result |= oc_add_device("/oic/d", "oic.d.light", "Jaehong's Light",
                            "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
    return result;
  }

  static void signalEventLoop(void) {}

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

  static void TearDownTestCase() { oc_main_shutdown(); }
};
oc_handler_t TestRDClient::s_handler;
oc_endpoint_t TestRDClient::s_endpoint;

TEST_F(TestRDClient, rd_publish_p)
{
  // When
  bool ret = rd_publish(&s_endpoint, NULL, 0, 0, onPostResponse, LOW_QOS, NULL);

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestRDClient, rd_publish_f)
{
  // Given
  oc_endpoint_t *ep = NULL;

  // When
  bool ret = rd_publish(ep, NULL, 0, 0, NULL, LOW_QOS, NULL);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_delete_p)
{
  // When
  bool ret = rd_delete(&s_endpoint, NULL, 0, onPostResponse, LOW_QOS, NULL);

  // Then
  EXPECT_TRUE(ret);
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
