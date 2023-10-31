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

#include "api/client/oc_client_cb_internal.h"
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/rd_client_internal.h"
#include "api/oc_link_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

static constexpr size_t kDeviceID{ 0 };

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

  static void SetUpTestCase()
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);

    s_endpoint = oc::endpoint::FromString("coap://224.0.1.187:5683");
  }

  static void TearDownTestCase() { oc_main_shutdown(); }

  void TearDown() override
  {
    oc::TestDevice::DropOutgoingMessages();
    coap_free_all_transactions();
    oc_client_cbs_shutdown();
  }
};

oc_handler_t TestRDClient::s_handler;
oc_endpoint_t TestRDClient::s_endpoint;

namespace {
struct RDLink
{
  std::string href;
  std::string rel;
};

std::optional<RDLink>
parseLink(const oc_rep_t *rep)
{
  char *val = nullptr;
  size_t valSize = 0;
  if (!oc_rep_get_string(rep, "href", &val, &valSize)) {
    return {};
  }
  RDLink link{};
  link.href = std::string(val, valSize);

  val = nullptr;
  valSize = 0;
  if (oc_rep_get_string(rep, "rel", &val, &valSize)) {
    link.rel = std::string(val, valSize);
  }
  return link;
}

struct RDPayload
{
  std::string di;
  std::string n;
  uint32_t ttl;
  std::vector<RDLink> links;
};

std::optional<RDPayload>
parseRepresentation(const oc_rep_t *rep)
{
  char *val = nullptr;
  size_t valSize = 0;
  if (!oc_rep_get_string(rep, "di", &val, &valSize)) {
    return {};
  }
  RDPayload payload{};
  payload.di = std::string(val, valSize);

  val = nullptr;
  valSize = 0;
  if (!oc_rep_get_string(rep, "n", &val, &valSize)) {
    return {};
  }
  payload.n = std::string(val, valSize);

  int64_t ttl;
  if (!oc_rep_get_int(rep, "ttl", &ttl)) {
    return {};
  }
  payload.ttl = static_cast<uint32_t>(ttl);

  if (oc_rep_t *links = nullptr;
      oc_rep_get_object_array(rep, "links", &links)) {
    for (oc_rep_t *link = links; link != nullptr; link = link->next) {
      auto rdLink = parseLink(link->value.object);
      if (!rdLink.has_value()) {
        return {};
      }
      payload.links.push_back(std::move(rdLink.value()));
    }
  }

  return payload;
}

} // namespace

TEST_F(TestRDClient, PublishEncode_FailPayloadTooLargeForBuffer)
{
  oc::RepPool pool{ 1 };

  oc_string_view_t id{ OC_STRING_VIEW("id") };
  oc_string_view_t name{ OC_STRING_VIEW("name") };
  EXPECT_FALSE(rd_publish_encode(nullptr, id, name,
                                 /*ttl*/ 0));
}

TEST_F(TestRDClient, PublishEncode)
{
  oc::RepPool pool{};

  oc_string_view_t id{ OC_STRING_VIEW("id") };
  oc_string_view_t name{ OC_STRING_VIEW("name") };

  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  // only first rel is used, so this will be ignored and only "hosts" will be in
  // the payload
  oc_link_add_rel(link_p, "custom");

  oc_resource_t *d = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  oc_link_t *link_d = oc_new_link(d);
  oc_link_clear_rels(link_d);
  link_p->next = link_d;

  ASSERT_TRUE(rd_publish_encode(link_p, id, name, /*ttl*/ 42));

  auto rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());

  auto rd = parseRepresentation(rep.get());
  ASSERT_TRUE(rd.has_value());
  EXPECT_STREQ(id.data, rd->di.c_str());
  EXPECT_STREQ(name.data, rd->n.c_str());
  EXPECT_EQ(42, rd->ttl);
  ASSERT_EQ(2, rd->links.size());
  EXPECT_STREQ("/oic/p", rd->links[0].href.c_str());
  EXPECT_STREQ("hosts", rd->links[0].rel.c_str());
  EXPECT_STREQ("/oic/d", rd->links[1].href.c_str());
  EXPECT_TRUE(rd->links[1].rel.empty());

  oc_delete_link(link_d);
  oc_delete_link(link_p);
}

TEST_F(TestRDClient, Publish_FailBadInput)
{
  // invalid device
  EXPECT_FALSE(rd_publish(/*links*/ nullptr, &s_endpoint, /*device*/ 42,
                          /*ttl*/ 0, onPostResponse, LOW_QOS,
                          /*user_data*/ nullptr));
}

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)

TEST_F(TestRDClient, Publish_FailPayloadTooLarge)
{
  auto kDefaultSize = static_cast<size_t>(oc_get_max_app_data_size());
  oc_set_max_app_data_size(1);
  EXPECT_FALSE(rd_publish(/*links*/ nullptr, &s_endpoint, /*device*/ kDeviceID,
                          /*ttl*/ 0, onPostResponse, LOW_QOS,
                          /*user_data*/ nullptr));

  oc_set_max_app_data_size(kDefaultSize);
}

#endif // OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestRDClient, Publish_TooManyRequests)
{
  for (int i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    EXPECT_TRUE(rd_publish(/*links*/ nullptr, &s_endpoint, /*device*/ kDeviceID,
                           /*ttl*/ 0, onPostResponse, LOW_QOS,
                           /*user_data*/ nullptr));
  }
  EXPECT_FALSE(rd_publish(/*links*/ nullptr, &s_endpoint, /*device*/ kDeviceID,
                          /*ttl*/ 0, onPostResponse, LOW_QOS,
                          /*user_data*/ nullptr));
}

#endif // !OC_DYNAMIC_ALLOCATION

TEST_F(TestRDClient, Publish)
{
  // if not links list is provied then oic/p and oic/d resources will be
  // published
  EXPECT_TRUE(rd_publish(/*links*/ nullptr, &s_endpoint, /*device*/ kDeviceID,
                         /*ttl*/ 0, onPostResponse, LOW_QOS,
                         /*user_data*/ nullptr));

  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  EXPECT_TRUE(rd_publish(link_p, &s_endpoint, /*device*/ kDeviceID,
                         /*ttl*/ 0, onPostResponse, LOW_QOS,
                         /*user_data*/ nullptr));
  oc_delete_link(link_p);
}

TEST_F(TestRDClient, Delete_FailBadInput)
{
  // invalid device
  oc_link_t links{};
  rd_links_partition_t partition{};
  EXPECT_EQ(RD_DELETE_ERROR, rd_delete(&links, &s_endpoint,
                                       /*device*/ 42, onPostResponse, LOW_QOS,
                                       /*user_data*/ nullptr, &partition));
}

TEST_F(TestRDClient, Delete)
{
  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  rd_links_partition_t partition{};
  ASSERT_EQ(RD_DELETE_ALL,
            rd_delete(link_p, &s_endpoint, kDeviceID, onPostResponse, LOW_QOS,
                      /*user_data*/ nullptr, &partition));
  EXPECT_EQ(nullptr, partition.not_deleted);
  EXPECT_EQ(link_p, partition.deleted);

  oc_delete_link(link_p);
}

static size_t
countLinks(const oc_link_t *links)
{
  size_t count = 0;
  for (; links != nullptr; links = links->next) {
    ++count;
  }
  return count;
}

#ifndef OC_DYNAMIC_ALLOCATION

static size_t
countTotalLinks()
{
  size_t count = 0;
  cloud_context_iterate(
    [](oc_cloud_context_t *ctx, void *user_data) {
      auto *count = static_cast<size_t *>(user_data);
      *count += countLinks(ctx->rd_publish_resources);
      *count += countLinks(ctx->rd_published_resources);
      *count += countLinks(ctx->rd_delete_resources);
    },
    &count);
  return count;
}

#endif // !OC_DYNAMIC_ALLOCATION

TEST_F(TestRDClient, Delete_ManyLinks)
{
#ifdef OC_DYNAMIC_ALLOCATION
  size_t kMaxLinks = 100;
#else  // !OC_DYNAMIC_ALLOCATION
  size_t kMaxLinks = OC_MAX_APP_RESOURCES;
  size_t total = countTotalLinks();
  if (total >= kMaxLinks) {
    OC_DBG("Skipping test, already %zu links", total);
    return;
  }
  kMaxLinks -= total;
#endif // OC_DYNAMIC_ALLOCATION
  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  OC_LIST_LOCAL(links);
  for (size_t i = 0; i < kMaxLinks; ++i) {
    oc_link_t *link_p = oc_new_link(p);
    oc_list_add(links, link_p);
  }
  ASSERT_EQ(kMaxLinks, oc_list_length(links));

  auto *to_delete = static_cast<oc_link_t *>(oc_list_head(links));
  rd_delete_result_t result;
  do {
    rd_links_partition_t partition{};
    result =
      rd_delete(to_delete, &s_endpoint, kDeviceID, onPostResponse, LOW_QOS,
                /*user_data*/ nullptr, &partition);
    for (oc_link_t *link = partition.deleted; link != nullptr;) {
      auto next = link->next;
      oc_delete_link(link);
      link = next;
    }
    to_delete = partition.not_deleted;

    // we drop the messages because otherwise they would get deallocated on
    // timeout
    oc::TestDevice::DropOutgoingMessages();
  } while (result == RD_DELETE_PARTIAL);

  EXPECT_EQ(RD_DELETE_ALL, result);
  EXPECT_EQ(nullptr, to_delete);
}

TEST_F(TestRDClient, DeleteIterateLinks_FailBufferTooSmall)
{
  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  rd_links_partition_t partition{};
  std::vector<char> buffer;
  buffer.resize(1); // not enough to even write the "di=${id}" part
  EXPECT_EQ(
    RD_DELETE_ERROR,
    rd_delete_fill_and_send_single_packet(
      link_p, &s_endpoint, OC_STRING_VIEW("id"), &buffer[0], buffer.size(),
      [](const oc_endpoint_t *, oc_string_view_t, void *) { return false; },
      /*on_packet_ready_data*/ nullptr, &partition));

  // di=id&ins=
  buffer.resize(6); // not enough to write a single link
  EXPECT_EQ(
    RD_DELETE_ERROR,
    rd_delete_fill_and_send_single_packet(
      link_p, &s_endpoint, OC_STRING_VIEW("id"), &buffer[0], buffer.size(),
      [](const oc_endpoint_t *, oc_string_view_t, void *) { return true; },
      /*on_packet_ready_data*/ nullptr, &partition));

  oc_delete_link(link_p);
}

TEST_F(TestRDClient, DeleteIterateLinks_FailToSendSingle)
{
  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  rd_links_partition_t partition{};
  std::array<char, COAP_MAX_HEADER_SIZE> buffer{};
  EXPECT_EQ(
    RD_DELETE_ERROR,
    rd_delete_fill_and_send_single_packet(
      link_p, &s_endpoint, OC_STRING_VIEW("id"), &buffer[0], buffer.size(),
      [](const oc_endpoint_t *, oc_string_view_t, void *) { return false; },
      /*on_packet_ready_data*/ nullptr, &partition));

  oc_delete_link(link_p);
}

TEST_F(TestRDClient, DeleteIterateLinks_PartialBuffer)
{
  // query: di=${deviceUUID}&ins=${instanceID}
  // get buffer size for 1 link
  oc_resource_t *p = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  oc_link_t *link_p = oc_new_link(p);
  oc_resource_t *d = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  oc_link_t *link_d = oc_new_link(d);
  link_p->next = link_d;
  oc_resource_t *r = oc_core_get_resource_by_index(OCF_RES, kDeviceID);
  oc_link_t *link_r = oc_new_link(r);
  link_d->next = link_r;
  ASSERT_EQ(3, countLinks(link_p));

  std::string instanceID = std::to_string(std::max(link_p->ins, link_d->ins));
  std::string deviceUUID = "id";
  std::string query = "di=" + deviceUUID + "&ins=" + instanceID;
  std::vector<char> buffer;
  buffer.resize(query.length() + 1);

  std::vector<oc_link_t *> deleted{};
  int invoke_count = 0;
  oc_link_t *to_delete = link_p;
  oc_link_t *not_deleted = nullptr;
  while (invoke_count < 2) {
    rd_links_partition_t partition{};
    rd_delete_result_t result = rd_delete_fill_and_send_single_packet(
      to_delete, &s_endpoint, OC_STRING_VIEW("id"), &buffer[0], buffer.size(),
      [](const oc_endpoint_t *, oc_string_view_t, void *data) {
        auto count = static_cast<int *>(data);
        ++(*count);
        // allow first packet to be sent
        return (*count == 1);
      },
      &invoke_count, &partition);
    if (invoke_count == 2) {
      ASSERT_EQ(RD_DELETE_ERROR, result);
      break;
    }
    ASSERT_EQ(RD_DELETE_PARTIAL, result);
    not_deleted = partition.not_deleted;
    to_delete = not_deleted;
    for (auto link = partition.deleted; link != nullptr; link = link->next) {
      deleted.push_back(link);
    }
  }
  ASSERT_EQ(1, deleted.size());
  EXPECT_EQ(link_p, deleted[0]);
  for (auto link : deleted) {
    oc_delete_link(link);
  }

  EXPECT_EQ(2, countLinks(not_deleted));
  EXPECT_EQ(link_d, not_deleted);
  for (oc_link_t *link = not_deleted; link != nullptr;) {
    auto next = link->next;
    oc_delete_link(link);
    link = next;
  }
}
