/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "oc_api.h"
#include "oc_endpoint.h"
#include "rd_client.h"
#include "tests/gtest/Endpoint.h"

#include <gtest/gtest.h>

class TestRDClient : public testing::Test {
public:
  static oc_handler_t s_handler;
  static oc_endpoint_t s_endpoint;

  static void onPostResponse(oc_client_response_t *)
  {
    // no-op for tests
  }

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", nullptr, nullptr);
    result |= oc_add_device("/oic/d", "oic.d.light", "Jaehong's Light",
                            "ocf.1.0.0", "ocf.res.1.0.0", nullptr, nullptr);
    return result;
  }

  static void signalEventLoop(void)
  {
    // no-op for tests
  }

protected:
  static void SetUpTestCase()
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);

    s_endpoint = oc::endpoint::FromString("coap://224.0.1.187:5683");
  }

  static void TearDownTestCase() { oc_main_shutdown(); }
};
oc_handler_t TestRDClient::s_handler;
oc_endpoint_t TestRDClient::s_endpoint;

TEST_F(TestRDClient, rd_publish_p)
{
  // When
  bool ret =
    rd_publish(&s_endpoint, nullptr, 0, 0, onPostResponse, LOW_QOS, nullptr);

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestRDClient, rd_publish_f)
{
  // Given
  const oc_endpoint_t *ep = nullptr;

  // When
  bool ret = rd_publish(ep, nullptr, 0, 0, nullptr, LOW_QOS, nullptr);

  // Then
  EXPECT_FALSE(ret);
}

TEST_F(TestRDClient, rd_delete_p)
{
  // When
  bool ret =
    rd_delete(&s_endpoint, nullptr, 0, onPostResponse, LOW_QOS, nullptr);

  // Then
  EXPECT_TRUE(ret);
}

TEST_F(TestRDClient, rd_delete_f)
{
  // Given
  const oc_endpoint_t *ep = nullptr;

  // When
  bool ret = rd_delete(ep, nullptr, 0, nullptr, LOW_QOS, nullptr);

  // Then
  EXPECT_FALSE(ret);
}
