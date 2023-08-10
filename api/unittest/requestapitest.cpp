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

#include "api/oc_helpers_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/constants.h"
#include "oc_api.h"
#include "oc_etag.h"
#include "oc_ri.h"
#include "port/oc_random.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <vector>

namespace {

class OCRequest {
public:
  OCRequest()
  {
    resp_.response_buffer = &respBuf_;
    req_.response = &resp_;
  }

  oc_request_t &request() { return req_; }
  oc_response_t &response() { return resp_; }
  oc_response_buffer_t &responseBuffer() { return respBuf_; }

private:
  oc_response_buffer_t respBuf_{};
  oc_response_t resp_{};
  oc_request_t req_{};
};

}

class TestRequestApi : public ::testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }
  static void TearDownTestCase() { oc_random_destroy(); }
};

TEST_F(TestRequestApi, GetPayloadRaw_F)
{
  const uint8_t *payload{};
  size_t payloadSize{};
  oc_content_format_t cf{};
  OCRequest req{};

  // invalid input
  EXPECT_FALSE(
    oc_get_request_payload_raw(nullptr, &payload, &payloadSize, &cf));
  EXPECT_FALSE(
    oc_get_request_payload_raw(&req.request(), nullptr, &payloadSize, &cf));
  EXPECT_FALSE(
    oc_get_request_payload_raw(&req.request(), &payload, nullptr, &cf));
  EXPECT_FALSE(oc_get_request_payload_raw(&req.request(), &payload,
                                          &payloadSize, nullptr));

  // empty payload
  EXPECT_FALSE(
    oc_get_request_payload_raw(&req.request(), &payload, &payloadSize, &cf));
}

TEST_F(TestRequestApi, GetPayloadRaw)
{
  OCRequest req{};
  req.request().content_format = APPLICATION_CBOR;
  std::vector<uint8_t> req_payload{ 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
  req.request()._payload = req_payload.data();
  req.request()._payload_len = req_payload.size();

  const uint8_t *payload{};
  size_t payloadSize{};
  oc_content_format_t cf{};
  EXPECT_TRUE(
    oc_get_request_payload_raw(&req.request(), &payload, &payloadSize, &cf));
  EXPECT_EQ(APPLICATION_CBOR, cf);
  EXPECT_EQ(req.request()._payload_len, payloadSize);
  EXPECT_EQ(0, memcmp(payload, req.request()._payload, payloadSize));
}

#ifdef OC_HAS_FEATURE_ETAG

TEST_F(TestRequestApi, SetSendResponseETag_F)
{
  OCRequest req{};
  req.request().method = OC_POST;
  std::vector<uint8_t> etag(COAP_ETAG_LEN, '\0');
  oc_random_buffer(etag.data(), etag.size());
  EXPECT_GT(
    0, oc_set_send_response_etag(&req.request(), etag.data(), etag.size()));
  EXPECT_EQ(req.responseBuffer().etag.length, 0);
  EXPECT_TRUE(std::all_of(std::begin(req.responseBuffer().etag.value),
                          std::end(req.responseBuffer().etag.value),
                          [](uint8_t value) { return value == 0; }));

  req.request().method = OC_GET;
  etag.resize(COAP_ETAG_LEN + 1);
  oc_random_buffer(etag.data(), etag.size());
  EXPECT_GT(
    0, oc_set_send_response_etag(&req.request(), etag.data(), etag.size()));
  EXPECT_EQ(req.responseBuffer().etag.length, 0);
  EXPECT_TRUE(std::all_of(std::begin(req.responseBuffer().etag.value),
                          std::end(req.responseBuffer().etag.value),
                          [](uint8_t value) { return value == 0; }));
}

TEST_F(TestRequestApi, SetSendResponseETag)
{
  OCRequest req;
  req.request().method = OC_GET;
  std::vector<uint8_t> etag(COAP_ETAG_LEN, '\0');
  oc_random_buffer(etag.data(), etag.size());

  EXPECT_EQ(
    0, oc_set_send_response_etag(&req.request(), etag.data(), etag.size()));
  EXPECT_EQ(req.responseBuffer().etag.length, etag.size());
  EXPECT_EQ(0,
            memcmp(req.responseBuffer().etag.value, etag.data(), etag.size()));
}

#endif // OC_HAS_FEATURE_ETAG
