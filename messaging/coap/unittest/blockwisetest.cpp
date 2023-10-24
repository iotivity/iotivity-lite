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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "oc_config.h"

#ifdef OC_BLOCK_WISE

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_blockwise_internal.h"
#include "api/oc_client_api_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "api/oc_message_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/engine_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_config.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "security/oc_pstat_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_process_internal.h"

#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kBlockSize = 16;

static void
dropOutgoingMessages()
{
  OC_PROCESS_NAME(oc_message_buffer_handler);
  oc_process_drop(
    &oc_message_buffer_handler,
    [](oc_process_event_t, oc_process_data_t data, const void *) {
      auto *message = static_cast<oc_message_t *>(data);
      oc_message_unref(message);
      return true;
    },
    nullptr);
}

class TestMessagingBlockwise : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_random_init();
    oc_clock_init();
#ifdef OC_SECURITY
    oc_sec_pstat_init_for_devices(1);
#endif /* OC_SECURITY */
#ifdef OC_CLIENT
    oc_client_cbs_init();
#endif /* OC_CLIENT */

    coap_init_connection();
  }

  static void TearDownTestCase()
  {
#ifdef OC_SECURITY
    oc_sec_pstat_free();
#endif /* OC_SECURITY */
    oc_random_destroy();
  }

  void TearDown() override
  {
    coap_free_all_transactions();
#ifdef OC_CLIENT
    oc_client_cbs_shutdown();
#endif /* OC_CLIENT */
    oc_blockwise_free_all_buffers(true);
  }

  oc_blockwise_state_t *allocBuffer(
    bool response = false, std::string_view href = "/test",
    std::string_view endpoint = "coap://[ff02::152]",
    oc_method_t method = OC_GET, oc_blockwise_role_t role = OC_BLOCKWISE_CLIENT,
    uint32_t buffer_size = 8)
  {
    oc_endpoint_t ep = oc::endpoint::FromString(std::string(endpoint));
    if (!response) {
      return oc_blockwise_alloc_request_buffer(href.data(), href.length(), &ep,
                                               method, role, buffer_size);
    }
    return oc_blockwise_alloc_response_buffer(href.data(), href.length(), &ep,
                                              method, role, buffer_size,
                                              CONTENT_2_05, false);
  }
};

TEST_F(TestMessagingBlockwise, AllocBlockwiseRequest)
{
  oc_blockwise_state_t *bw = allocBuffer();
  ASSERT_NE(nullptr, bw);
}

TEST_F(TestMessagingBlockwise, AllocBlockwiseRequest_F)
{
  std::string_view ep_str = "coap://[ff02::152]";
  oc_endpoint_t ep = oc::endpoint::FromString(std::string(ep_str));
  ASSERT_EQ(nullptr, oc_blockwise_alloc_request_buffer(nullptr, 0, &ep, OC_GET,
                                                       OC_BLOCKWISE_CLIENT, 8));

#ifndef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    ASSERT_NE(nullptr, allocBuffer());
  }
  EXPECT_EQ(nullptr, allocBuffer());
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestMessagingBlockwise, AllocBlockwiseResponse)
{
  oc_blockwise_state_t *bw = allocBuffer(true);
  ASSERT_NE(nullptr, bw);
}

TEST_F(TestMessagingBlockwise, AllocBlockwiseResponse_F)
{
  std::string_view ep_str = "coap://[ff02::152]";
  oc_endpoint_t ep = oc::endpoint::FromString(std::string(ep_str));
  ASSERT_EQ(nullptr, oc_blockwise_alloc_response_buffer(nullptr, 0, &ep, OC_GET,
                                                        OC_BLOCKWISE_CLIENT, 8,
                                                        CONTENT_2_05, false));

#ifndef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    ASSERT_NE(nullptr, allocBuffer(true));
  }
  EXPECT_EQ(nullptr, allocBuffer(true));
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestMessagingBlockwise, FreeBlockwiseRequest)
{
  oc_blockwise_free_request_buffer(nullptr);

  oc_blockwise_state_t *bw = allocBuffer();
  ASSERT_NE(nullptr, bw);
  oc_blockwise_free_request_buffer(bw);
}

TEST_F(TestMessagingBlockwise, FreeBlockwiseResponse)
{
  oc_blockwise_free_response_buffer(nullptr);

  oc_blockwise_state_t *bw = allocBuffer(true);
  ASSERT_NE(nullptr, bw);
  oc_blockwise_free_response_buffer(bw);
}

TEST_F(TestMessagingBlockwise, FindRequest)
{
  std::string_view h1 = "/req";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_endpoint_t ep1 = oc::endpoint::FromString(std::string(ep1_str));
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  std::string_view q1 = "?type=request";

  std::string_view h2 = "/resp";
  std::string_view ep2_str = "coap://[ff02::152]";
  oc_endpoint_t ep2 = oc::endpoint::FromString(std::string(ep2_str));
  oc_method_t m2 = OC_POST;
  oc_blockwise_role_t r2 = OC_BLOCKWISE_SERVER;
  std::string_view q2 = "?type=response";

  oc_blockwise_state_t *bw = allocBuffer(false, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw);
  oc_set_string(&bw->uri_query, q1.data(), q1.length());
  // non-matching role
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep1, m1,
                                             q1.data(), q1.length(), r2));
  // non-matching method
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep1, m2,
                                             q1.data(), q1.length(), r1));
  // non-matching query
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep1, m1,
                                             q2.data(), q2.length(), r1));
  // non-matching endpoint
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep2, m1,
                                             q1.data(), q1.length(), r1));
  // non-matching href
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h2.data(), h2.length(), &ep1, m1,
                                             q1.data(), q1.length(), r1));
  // matching
  EXPECT_EQ(bw,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep1, m1,
                                             q1.data(), q1.length(), r1));

  // response vs request list
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep1, m1,
                                              q1.data(), q1.length(), r1));
}

TEST_F(TestMessagingBlockwise, FindReponse)
{
  std::string_view h1 = "/resp";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_endpoint_t ep1 = oc::endpoint::FromString(std::string(ep1_str));
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  std::string_view q1 = "?type=response";

  std::string_view h2 = "/req";
  std::string_view ep2_str = "coap://[ff02::152]";
  oc_endpoint_t ep2 = oc::endpoint::FromString(std::string(ep2_str));
  oc_method_t m2 = OC_POST;
  oc_blockwise_role_t r2 = OC_BLOCKWISE_SERVER;
  std::string_view q2 = "?type=request";

  oc_blockwise_state_t *bw = allocBuffer(true, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw);
  oc_set_string(&bw->uri_query, q1.data(), q1.length());

  // non-matching role
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep1, m1,
                                              q1.data(), q1.length(), r2));
  // non-matching method
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep1, m2,
                                              q1.data(), q1.length(), r1));
  // non-matching query
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep1, m1,
                                              q2.data(), q2.length(), r1));
  // non-matching endpoint
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep2, m1,
                                              q1.data(), q1.length(), r1));
  // non-matching href
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer(h2.data(), h2.length(), &ep1, m1,
                                              q1.data(), q1.length(), r1));
  // matching
  EXPECT_EQ(bw,
            oc_blockwise_find_response_buffer(h1.data(), h1.length(), &ep1, m1,
                                              q1.data(), q1.length(), r1));

  // request vs response list
  EXPECT_EQ(nullptr,
            oc_blockwise_find_request_buffer(h1.data(), h1.length(), &ep1, m1,
                                             q1.data(), q1.length(), r1));
}

#ifdef OC_CLIENT

TEST_F(TestMessagingBlockwise, FindRequestByMid)
{
  // not added yet
  uint16_t mid = 1;
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_mid(mid));

  std::string_view h1 = "/resp";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(false, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  bw1->mid = mid;

  // non-matching mid
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_mid(2));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_request_buffer_by_mid(mid));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_mid(mid));
}

TEST_F(TestMessagingBlockwise, FindResponseByMid)
{
  // not added yet
  uint16_t mid = 1;
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_mid(mid));

  std::string_view h1 = "/resp";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(true, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  bw1->mid = mid;

  // non-matching mid
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_mid(2));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_response_buffer_by_mid(mid));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_mid(mid));
}

TEST_F(TestMessagingBlockwise, FindRequestByToken)
{
  // not added yet
  std::array<uint8_t, COAP_TOKEN_LEN> token1{};
  memset(&token1[0], 1, token1.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_token(token1.data(),
                                                               token1.size()));

  std::string_view h1 = "/req";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(false, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  memcpy(&bw1->token[0], token1.data(), token1.size());
  bw1->token_len = token1.size();

  // shorter token
  std::array<uint8_t, 1> token2{};
  memset(&token2[0], 2, token2.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_token(token2.data(),
                                                               token2.size()));
  // non-matching token
  std::array<uint8_t, COAP_TOKEN_LEN> token3{};
  memset(&token3[0], 3, token2.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_token(token3.data(),
                                                               token3.size()));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_request_buffer_by_token(token1.data(),
                                                           token1.size()));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_token(token1.data(),
                                                               token1.size()));
}

TEST_F(TestMessagingBlockwise, FindResponseByToken)
{
  // not added yet
  std::array<uint8_t, COAP_TOKEN_LEN> token1{};
  memset(&token1[0], 1, token1.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_token(token1.data(),
                                                                token1.size()));

  std::string_view h1 = "/resp";
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(true, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  memcpy(&bw1->token[0], token1.data(), token1.size());
  bw1->token_len = token1.size();

  // shorter token
  std::array<uint8_t, 1> token2{};
  memset(&token2[0], 2, token2.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_token(token2.data(),
                                                                token2.size()));
  // non-matching token
  std::array<uint8_t, COAP_TOKEN_LEN> token3{};
  memset(&token3[0], 3, token3.size());
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_token(token3.data(),
                                                                token3.size()));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_response_buffer_by_token(token1.data(),
                                                            token1.size()));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_token(token1.data(),
                                                                token1.size()));
}

TEST_F(TestMessagingBlockwise, FindRequestByClientCallback)
{
  // not added yet
  oc_client_cb_t cb1{};
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_endpoint_t ep1 = oc::endpoint::FromString(std::string(ep1_str));
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep1, &cb1));

  std::string_view h1 = "/req";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(false, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  bw1->client_cb = &cb1;

  // non-matching client callback
  oc_client_cb_t cb2{};
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep1, &cb2));
  // non-matching endpoint
  oc_endpoint_t ep2 = oc::endpoint::FromString("coap://[ff02::152]");
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep2, &cb1));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_request_buffer_by_client_cb(&ep1, &cb1));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep1, &cb1));
}

TEST_F(TestMessagingBlockwise, FindResponseByClientCallback)
{
  // not added yet
  oc_client_cb_t cb1{};
  std::string_view ep1_str = "coap://[ff02::151]";
  oc_endpoint_t ep1 = oc::endpoint::FromString(std::string(ep1_str));
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer_by_client_cb(&ep1, &cb1));

  std::string_view h1 = "/resp";
  oc_method_t m1 = OC_GET;
  oc_blockwise_role_t r1 = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(true, h1, ep1_str, m1, r1);
  ASSERT_NE(nullptr, bw1);
  bw1->client_cb = &cb1;

  // non-matching client callback
  oc_client_cb_t cb2{};
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer_by_client_cb(&ep1, &cb2));
  // non-matching endpoint
  oc_endpoint_t ep2 = oc::endpoint::FromString("coap://[ff02::152]");
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer_by_client_cb(&ep2, &cb1));
  // matching
  EXPECT_EQ(bw1, oc_blockwise_find_response_buffer_by_client_cb(&ep1, &cb1));

  // server role
  bw1->role = OC_BLOCKWISE_SERVER;
  EXPECT_EQ(nullptr,
            oc_blockwise_find_response_buffer_by_client_cb(&ep1, &cb1));
}

TEST_F(TestMessagingBlockwise, ScrubRequestBuffersByClientCallback)
{
  std::string_view ep_str = "coap://[ff02::151]";
  oc_endpoint_t ep = oc::endpoint::FromString(std::string(ep_str));
  oc_method_t m = OC_GET;

  std::string_view h1 = "/req";
  oc_blockwise_role_t r = OC_BLOCKWISE_CLIENT;
  oc_blockwise_state_t *bw1 = allocBuffer(false, h1, ep_str, m, r);
  ASSERT_NE(nullptr, bw1);
  oc_client_cb_t cb1{};
  bw1->client_cb = &cb1;
  ASSERT_NE(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep, &cb1));

  std::string_view h2 = "/resp";
  oc_blockwise_state_t *bw2 = allocBuffer(true, h2, ep_str, m, r);
  ASSERT_NE(nullptr, bw2);
  oc_client_cb_t cb2{};
  bw2->client_cb = &cb2;
  ASSERT_NE(nullptr, oc_blockwise_find_response_buffer_by_client_cb(&ep, &cb2));

  // non-matching client callback
  oc_client_cb_t cb3{};
  oc_blockwise_scrub_buffers_for_client_cb(&cb3);

  EXPECT_NE(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep, &cb1));
  EXPECT_NE(nullptr, oc_blockwise_find_response_buffer_by_client_cb(&ep, &cb2));

  // remove cb1
  oc_blockwise_scrub_buffers_for_client_cb(&cb1);
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep, &cb1));
  EXPECT_NE(nullptr, oc_blockwise_find_response_buffer_by_client_cb(&ep, &cb2));

  // remove cb2
  oc_blockwise_scrub_buffers_for_client_cb(&cb2);
  EXPECT_EQ(nullptr, oc_blockwise_find_request_buffer_by_client_cb(&ep, &cb1));
  EXPECT_EQ(nullptr, oc_blockwise_find_response_buffer_by_client_cb(&ep, &cb2));
}

#endif /* OC_CLIENT */

TEST_F(TestMessagingBlockwise, BlockwiseRequest)
{
  std::string ep_str{ "coap://[ff02::152]" };
  oc_endpoint_t endpoint = oc::endpoint::FromString(ep_str);
  coap_packet_t request_pkt;
  coap_udp_init_message(&request_pkt, COAP_TYPE_NON, COAP_POST, coap_get_mid());
  std::string uri = "/oic/res";
  coap_options_set_uri_path(&request_pkt, uri.c_str(), uri.length());

  std::array<uint8_t, 3 * kBlockSize> payload{};
  for (size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<uint8_t>(i / kBlockSize);
  }
  coap_set_payload(&request_pkt, payload.data(), kBlockSize);
  coap_options_set_block1(&request_pkt, 0, 1, kBlockSize, 0);

  auto skip_response = [](coap_make_response_ctx_t *, oc_endpoint_t *,
                          void *data) {
    *static_cast<bool *>(data) = true;
    return true;
  };

  coap_packet_t response_pkt;
  coap_receive_ctx_t ctx = {
    /*.request =*/&request_pkt,
    /*.response =*/&response_pkt,
    /*.transaction =*/nullptr,
    /*.block1 =*/coap_packet_get_block_options(&request_pkt, false),
    /*.block2 =*/coap_packet_get_block_options(&request_pkt, true),
    /*.request_buffer =*/nullptr,
    /*.response_buffer =*/nullptr,
  };
  bool invoked = false;
  ASSERT_EQ(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, &invoked));
  // the first block should be written to the partial request buffer
  ASSERT_NE(nullptr, ctx.request_buffer);
  ASSERT_EQ(kBlockSize, ctx.request_buffer->next_block_offset);
  for (size_t i = 0; i < ctx.request_buffer->next_block_offset; ++i) {
    EXPECT_EQ(i / kBlockSize, ctx.request_buffer->buffer[i]);
  }
  EXPECT_FALSE(invoked);
  // clean-up
  coap_free_all_transactions();

  // duplicate block
  EXPECT_EQ(COAP_RECEIVE_SKIP_DUPLICATE_MESSAGE,
            coap_receive(&ctx, &endpoint, skip_response, &invoked));
  // no change in the request buffer
  ASSERT_EQ(kBlockSize, ctx.request_buffer->next_block_offset);
  for (size_t i = 0; i < ctx.request_buffer->next_block_offset; ++i) {
    EXPECT_EQ(i / kBlockSize, ctx.request_buffer->buffer[i]);
  }
  EXPECT_EQ(0, ctx.request_buffer->payload_size);
  EXPECT_FALSE(invoked);
  // clean-up
  coap_free_all_transactions();

  // same block num, different mid - data will be ignored because the block is
  // already written
  for (size_t i = 0; i < kBlockSize; ++i) {
    payload[i] = 'a';
  }
  request_pkt.mid = coap_get_mid();
  EXPECT_EQ(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, &invoked));
  ASSERT_EQ(kBlockSize, ctx.request_buffer->next_block_offset);
  for (size_t i = 0; i < ctx.request_buffer->next_block_offset; ++i) {
    EXPECT_EQ(i / kBlockSize, ctx.request_buffer->buffer[i]);
  }
  EXPECT_EQ(0, ctx.request_buffer->payload_size);
  EXPECT_FALSE(invoked);
  // clean-up
  for (size_t i = 0; i < kBlockSize; ++i) {
    payload[i] = static_cast<uint8_t>(i / kBlockSize);
  }
  coap_free_all_transactions();

  // next block
  request_pkt.mid = coap_get_mid();
  coap_set_payload(&request_pkt, payload.data() + kBlockSize, kBlockSize);
  coap_options_set_block1(&request_pkt, 1, 1, kBlockSize, kBlockSize);
  ctx.block1 = coap_packet_get_block_options(&request_pkt, false);
  EXPECT_EQ(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, &invoked));
  // two blocks should be written to the partial request buffer
  ASSERT_EQ(2 * kBlockSize, ctx.request_buffer->next_block_offset);
  for (size_t i = 0; i < ctx.request_buffer->next_block_offset; ++i) {
    EXPECT_EQ(i / kBlockSize, ctx.request_buffer->buffer[i]);
  }
  EXPECT_EQ(0, ctx.request_buffer->payload_size);
  EXPECT_FALSE(invoked);
  // clean-up
  coap_free_all_transactions();

  // final block
  request_pkt.mid = coap_get_mid();
  coap_set_payload(&request_pkt, payload.data() + 2 * kBlockSize, kBlockSize);
  coap_options_set_block1(&request_pkt, 2, 0, kBlockSize, 2 * kBlockSize);
  ctx.block1 = coap_packet_get_block_options(&request_pkt, false);
  EXPECT_EQ(COAP_RECEIVE_SUCCESS,
            coap_receive(
              &ctx, &endpoint,
              [](coap_make_response_ctx_t *ctx, oc_endpoint_t *, void *data) {
                *static_cast<bool *>(data) = true;
                coap_set_status_code(ctx->response, VALID_2_03);
                return true;
              },
              &invoked));
  EXPECT_TRUE(invoked);
  EXPECT_EQ(payload.size(), ctx.request_buffer->payload_size);
  EXPECT_TRUE(memcmp(payload.data(), ctx.request_buffer->buffer,
                     ctx.request_buffer->payload_size) == 0);
}

TEST_F(TestMessagingBlockwise, BlockwiseRequest_FailInvalidSize)
{
  std::string ep_str{ "coap://[ff02::152]" };
  oc_endpoint_t endpoint = oc::endpoint::FromString(ep_str);
  coap_packet_t request_pkt;
  coap_udp_init_message(&request_pkt, COAP_TYPE_NON, COAP_POST, coap_get_mid());
  std::string uri = "/oic/res";
  coap_options_set_uri_path(&request_pkt, uri.c_str(), uri.length());
  coap_options_set_block1(&request_pkt, 0, 1, kBlockSize, 0);
  coap_options_set_size1(&request_pkt, kBlockSize);

  auto skip_response = [](coap_make_response_ctx_t *, oc_endpoint_t *, void *) {
    return true;
  };

  coap_packet_t response_pkt;
  std::array<uint8_t, kBlockSize> payload{};
  memset(&payload[0], 'a', payload.size());
  coap_set_payload(&request_pkt, payload.data(), payload.size());

  coap_block_options_t block1 = {
    /*.num=*/0,
    /*.offset=*/kBlockSize, // offset >= than allocated size
    /*.size=*/kBlockSize,
    /*.more=*/0,
    /*.enabled=*/true,
  };
  coap_receive_ctx_t ctx = {
    /*.request =*/&request_pkt,
    /*.response =*/&response_pkt,
    /*.transaction =*/nullptr,
    /*.block1 =*/block1,
    /*.block2 =*/coap_packet_get_block_options(&request_pkt, true),
    /*.request_buffer =*/nullptr,
    /*.response_buffer =*/nullptr,
  };
  EXPECT_NE(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, nullptr));
  // clean-up
  coap_free_all_transactions();

  request_pkt.mid = coap_get_mid();
  block1.offset = 1;        // offset < than allocated size
  block1.size = kBlockSize; // offset + size >=than allocated size
  ctx.block1 = block1;
  EXPECT_NE(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, nullptr));
  // clean-up
  coap_free_all_transactions();

  request_pkt.mid = coap_get_mid();
  block1.offset = 1; // offset < than allocated size, but invalid because num =
                     // 1 should have offset=0
  block1.size = 1;   // offset + size <= than allocated size
  ctx.block1 = block1;
  EXPECT_NE(COAP_RECEIVE_SUCCESS,
            coap_receive(&ctx, &endpoint, skip_response, nullptr));
}

static constexpr size_t kDeviceID = 0;
static constexpr size_t kAppDataMaxSize = 16384;
static constexpr std::string_view kResourceURI = "/dyn";

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
static const long g_max_app_data_size{ oc_get_max_app_data_size() };
#endif /* !OC_APP_DATA_BUFFER_SIZE */

struct ResourseData
{
  std::string data;
};

class TestMessagingBlockwiseWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(kAppDataMaxSize);
#endif /* !OC_APP_DATA_BUFFER_SIZE */

    ASSERT_TRUE(oc::TestDevice::StartServer());

    resourceData.data = std::string(OC_BLOCK_SIZE * 2, 'a');

    oc::DynamicResourceHandler handlers{};
    handlers.onGet = onGet;
    handlers.onGetData = &resourceData;
    handlers.onPost = onPost;
    handlers.onPostData = &resourceData;
    oc_resource_t *res = oc::TestDevice::AddDynamicResource(
      oc::makeDynamicResourceToAdd("Dynamic Device 1", kResourceURI.data(),
                                   { "oic.d.dynamic", "oic.d.test" },
                                   { OC_IF_BASELINE, OC_IF_RW }, handlers,
                                   OC_SECURE),
      kDeviceID);
    ASSERT_NE(res, nullptr);

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(res, true, OC_PERM_RETRIEVE | OC_PERM_UPDATE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)
    oc_set_max_app_data_size(g_max_app_data_size);
#endif /* !OC_APP_DATA_BUFFER_SIZE */
  }

  static void onGet(oc_request_t *, oc_interface_mask_t, void *);
  static void onPost(oc_request_t *, oc_interface_mask_t, void *);

  static ResourseData resourceData;
};

ResourseData TestMessagingBlockwiseWithServer::resourceData{};

void
TestMessagingBlockwiseWithServer::onGet(oc_request_t *request,
                                        oc_interface_mask_t, void *data)
{
  const auto *rd = static_cast<ResourseData *>(data);
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, data, rd->data.c_str(), rd->data.length());
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

void
TestMessagingBlockwiseWithServer::onPost(oc_request_t *request,
                                         oc_interface_mask_t, void *data)
{
  auto *rd = static_cast<ResourseData *>(data);
  for (const oc_rep_t *rep = request->request_payload; rep != nullptr;
       rep = rep->next) {
    std::string name = oc_string(rep->name);
    if (rep->type == OC_REP_STRING && name == "data") {
      rd->data.assign(oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
    }
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

TEST_F(TestMessagingBlockwiseWithServer, BlockwiseRequest_FailInvalidMessage)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc_message_t *msg = oc_allocate_message();
  memset(&msg->data[0], 'a', 42);
  msg->length = 42;
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));

  EXPECT_NE(COAP_NO_ERROR, coap_process_inbound_message(msg));

  // clean-up
  // invalid message generates an error response that we want to drop
  dropOutgoingMessages();

  oc_message_unref(msg);
}

// we need smaller block size or bigger byte pool for these tests with static
// memory allocation
#ifdef OC_DYNAMIC_ALLOCATION

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestMessagingBlockwiseWithServer, GetLargeResource)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED | TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  auto configure_packet = [](coap_packet_t *packet, const void *) {
    coap_options_set_block2(packet, 0, 0, static_cast<uint16_t>(OC_BLOCK_SIZE),
                            0);
  };

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_request(OC_GET, kResourceURI.data(), &ep, nullptr,
                            timeout.count(), get_handler, LOW_QOS, &invoked,
                            configure_packet, nullptr));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

TEST_F(TestMessagingBlockwiseWithServer, PostLargeResource)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED | TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  bool invoked = false;
  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    *static_cast<bool *>(data->user_data) = true;
  };

  auto configure_packet = [](coap_packet_t *packet, const void *) {
    coap_options_set_block1(packet, 0, 1, static_cast<uint16_t>(OC_BLOCK_SIZE),
                            0);
  };
  ASSERT_TRUE(oc_init_async_request(OC_POST, kResourceURI.data(), &ep, nullptr,
                                    post_handler, HIGH_QOS, &invoked,
                                    configure_packet, nullptr));
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, data, resourceData.data.c_str(),
                            resourceData.data.length());
  oc_rep_end_root_object();
  ASSERT_EQ(0, g_err);
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_DYNAMIC_ALLOCATION */

#endif // OC_BLOCK_WISE
