/****************************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#include "api/cloud/oc_cloud_endpoint_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "tests/gtest/RepPool.h"

#include <array>
#include <gtest/gtest.h>
#include <string>

class TestCloudEndpoint : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override
  {
    ASSERT_TRUE(
      oc_cloud_endpoints_init(&ce, nullptr, nullptr, OC_STRING_VIEW_NULL, {}));
  }

  void TearDown() override { oc_cloud_endpoints_deinit(&ce); }

  oc_cloud_endpoints_t &getCloudEndpoints() { return ce; }

private:
  oc_cloud_endpoints_t ce;
};

static std::string
encodeCloudEndpointItem(const std::string &uri, oc_uuid_t id)
{
  std::array<char, OC_UUID_LEN> id_str{};
  oc_uuid_to_str(&id, &id_str[0], id_str.size());
  return std::string(R"({"uri":")") + uri.c_str() + R"(","id":")" +
         id_str.data() + R"("})";
}

TEST_F(TestCloudEndpoint, InitWithDefault)
{
  oc_cloud_endpoints_t ce{};
  ASSERT_TRUE(oc_cloud_endpoints_init(
    &ce, nullptr, nullptr, OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS),
    OCF_COAPCLOUDCONF_DEFAULT_SID));
  EXPECT_TRUE(oc_cloud_endpoint_contains(
    &ce, OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS)));
  auto *selected = ce.selected;
  ASSERT_NE(nullptr, selected);
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, oc_string(selected->uri));
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID, selected->id));
  oc_cloud_endpoints_deinit(&ce);
}

TEST_F(TestCloudEndpoint, Init_FailInvalidDefault)
{
  oc_cloud_endpoints_t ce{};
  std::string tooLong(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH + 1, 'a');
  EXPECT_FALSE(oc_cloud_endpoints_init(
    &ce, nullptr, nullptr, oc_string_view(tooLong.c_str(), tooLong.length()),
    {}));
  oc_cloud_endpoints_deinit(&ce);
}

TEST_F(TestCloudEndpoint, IsEmpty)
{
  oc_cloud_endpoints_t ceEmpty{};
  EXPECT_TRUE(oc_cloud_endpoints_is_empty(&ceEmpty));
  EXPECT_EQ(0, oc_cloud_endpoints_size(&ceEmpty));

  const oc_cloud_endpoints_t &ce{ getCloudEndpoints() };
  EXPECT_TRUE(oc_cloud_endpoints_is_empty(&ce));
  EXPECT_EQ(0, oc_cloud_endpoints_size(&ce));
}

TEST_F(TestCloudEndpoint, Contains)
{
  oc_cloud_endpoints_t ceEmpty{};
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ceEmpty, OC_STRING_VIEW_NULL));

  const oc_cloud_endpoints_t &ce{ getCloudEndpoints() };
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ce, OC_STRING_VIEW_NULL));
}

TEST_F(TestCloudEndpoint, AddAndRemove)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ce, uri1));
  auto *ep1 = oc_cloud_endpoint_add(&ce, uri1, {});
  EXPECT_NE(nullptr, ep1);
  EXPECT_TRUE(oc_cloud_endpoint_contains(&ce, uri1));
  EXPECT_EQ(1, oc_cloud_endpoints_size(&ce));

  auto uri2 = OC_STRING_VIEW("/uri/2");
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ce, uri2));
  EXPECT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri2, {}));
  EXPECT_TRUE(oc_cloud_endpoint_contains(&ce, uri2));
  EXPECT_EQ(2, oc_cloud_endpoints_size(&ce));

  EXPECT_TRUE(oc_cloud_endpoint_remove_by_uri(&ce, uri2));
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ce, uri2));
  EXPECT_EQ(1, oc_cloud_endpoints_size(&ce));

  EXPECT_TRUE(oc_cloud_endpoint_remove(&ce, ep1));
  EXPECT_FALSE(oc_cloud_endpoint_contains(&ce, uri1));
  EXPECT_EQ(0, oc_cloud_endpoints_size(&ce));
}

TEST_F(TestCloudEndpoint, Add_Fail)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  ASSERT_FALSE(oc_cloud_endpoint_add(&ce, OC_STRING_VIEW_NULL, {}));
  std::string tooLong(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH + 1, 'a');
  ASSERT_FALSE(oc_cloud_endpoint_add(
    &ce, oc_string_view(tooLong.c_str(), tooLong.length()), {}));

#ifndef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < OC_CLOUD_MAX_ENDPOINT_ADDRESSES; i++) {
    auto uri = std::string("/uri/") + std::to_string(i);
    ASSERT_NE(nullptr, oc_cloud_endpoint_add(
                         &ce, oc_string_view(uri.c_str(), uri.length()), {}));
  }

  auto uri = OC_STRING_VIEW("/fail");
  EXPECT_EQ(nullptr, oc_cloud_endpoint_add(&ce, uri, {}));
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestCloudEndpoint, Add_DuplicateFail)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri1, {}));
  EXPECT_EQ(nullptr, oc_cloud_endpoint_add(&ce, uri1, {}));
}

TEST_F(TestCloudEndpoint, Remove_Fail)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri1, {}));

  // element not in the list
  oc_cloud_endpoint_t ep{};
  EXPECT_FALSE(oc_cloud_endpoint_remove(&ce, &ep));

  // no element with the given URI
  EXPECT_FALSE(oc_cloud_endpoint_remove_by_uri(&ce, OC_STRING_VIEW_NULL));
  EXPECT_FALSE(oc_cloud_endpoint_remove_by_uri(&ce, OC_STRING_VIEW("/fail")));
}

TEST_F(TestCloudEndpoint, Select)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri1, id1));

  // when adding to an empty list, the first added item is automatically
  // selected
  EXPECT_TRUE(oc_cloud_endpoint_is_selected(&ce, uri1));
  auto *selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri1.data, oc_string(*selected_addr));
  auto *selected_id = oc_cloud_endpoint_selected_id(&ce);
  ASSERT_NE(nullptr, selected_id);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *selected_id));

  // non-existing URI shouldn't change the selection
  EXPECT_FALSE(oc_cloud_endpoint_select_by_uri(&ce, OC_STRING_VIEW("/fail")));
  EXPECT_FALSE(oc_cloud_endpoint_is_selected(&ce, OC_STRING_VIEW("/fail")));
  EXPECT_TRUE(oc_cloud_endpoint_is_selected(&ce, uri1));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri1.data, oc_string(*selected_addr));

#ifdef OC_DYNAMIC_ALLOCATION
  auto uri2 = OC_STRING_VIEW("/uri/2");
  oc_uuid_t id2;
  oc_gen_uuid(&id2);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri2, id2));
  EXPECT_FALSE(oc_cloud_endpoint_is_selected(&ce, uri2));
  auto uri3 = OC_STRING_VIEW("/uri/3");
  oc_uuid_t id3;
  oc_gen_uuid(&id3);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri3, id3));
  EXPECT_FALSE(oc_cloud_endpoint_is_selected(&ce, uri3));

  EXPECT_TRUE(oc_cloud_endpoint_select_by_uri(&ce, uri2));
  EXPECT_TRUE(oc_cloud_endpoint_is_selected(&ce, uri2));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri2.data, oc_string(*selected_addr));
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  ASSERT_NE(nullptr, selected_id);
  EXPECT_TRUE(oc_uuid_is_equal(id2, *selected_id));

  EXPECT_TRUE(oc_cloud_endpoint_select_by_uri(&ce, uri3));
  EXPECT_TRUE(oc_cloud_endpoint_is_selected(&ce, uri3));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri3.data, oc_string(*selected_addr));
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  ASSERT_NE(nullptr, selected_id);
  EXPECT_TRUE(oc_uuid_is_equal(id3, *selected_id));
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestCloudEndpoint, RemoveSelected)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };
  auto selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_EQ(nullptr, selected_addr);
  auto selected_id = oc_cloud_endpoint_selected_id(&ce);
  ASSERT_EQ(nullptr, selected_id);

  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  auto *ep1 = oc_cloud_endpoint_add(&ce, uri1, id1);
  ASSERT_NE(nullptr, ep1);

#ifdef OC_DYNAMIC_ALLOCATION
  auto uri2 = OC_STRING_VIEW("/uri/2");
  oc_uuid_t id2;
  oc_gen_uuid(&id2);
  auto *ep2 = oc_cloud_endpoint_add(&ce, uri2, id2);
  ASSERT_NE(nullptr, ep2);
  auto uri3 = OC_STRING_VIEW("/uri/3");
  oc_uuid_t id3;
  oc_gen_uuid(&id3);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri3, id3));
  EXPECT_TRUE(oc_cloud_endpoint_select_by_uri(&ce, uri2));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri2.data, oc_string(*selected_addr));
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  EXPECT_TRUE(oc_uuid_is_equal(id2, *selected_id));

  EXPECT_TRUE(oc_cloud_endpoint_remove(&ce, ep2));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  // uri3 is next, so it should be selected
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri3.data, oc_string(*selected_addr));
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  EXPECT_TRUE(oc_uuid_is_equal(id3, *selected_id));

  EXPECT_TRUE(oc_cloud_endpoint_remove_by_uri(&ce, uri3));
  // the list should rotate back to uri1 after uri3 is removed
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri1.data, oc_string(*selected_addr));
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *selected_id));
#endif /* OC_DYNAMIC_ALLOCATION */

  EXPECT_TRUE(oc_cloud_endpoint_remove(&ce, ep1));
  EXPECT_EQ(0, oc_cloud_endpoints_size(&ce));
  EXPECT_FALSE(oc_cloud_endpoint_is_selected(&ce, uri1));
  selected_addr = oc_cloud_endpoint_selected_address(&ce);
  ASSERT_EQ(nullptr, selected_addr);
  selected_id = oc_cloud_endpoint_selected_id(&ce);
  ASSERT_EQ(nullptr, selected_id);
}

TEST_F(TestCloudEndpoint, Find)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  auto ce1 = oc_cloud_endpoint_add(&ce, uri1, {});
  ASSERT_NE(nullptr, ce1);
  auto uri2 = OC_STRING_VIEW("/uri/2");
  auto ce2 = oc_cloud_endpoint_add(&ce, uri2, {});
  ASSERT_NE(nullptr, ce2);
  auto uri3 = OC_STRING_VIEW("/uri/3");

  auto found = oc_cloud_endpoint_find(&ce, uri1);
  EXPECT_EQ(ce1, found);
  found = oc_cloud_endpoint_find(&ce, uri2);
  EXPECT_EQ(ce2, found);
  found = oc_cloud_endpoint_find(&ce, uri3);
  EXPECT_EQ(nullptr, found);

  oc_cloud_endpoints_t ceEmpty{};
  EXPECT_EQ(nullptr, oc_cloud_endpoint_find(&ceEmpty, uri1));
}

TEST_F(TestCloudEndpoint, EncodeEmpty)
{
  oc::RepPool pool{};

  // if the list is empty, nothing should be encoded
  oc_rep_begin_root_object();
  oc_cloud_endpoints_encode(oc_rep_object(root), &getCloudEndpoints(),
                            OC_STRING_VIEW("servers"), true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_EQ(nullptr, rep.get());
}

TEST_F(TestCloudEndpoint, EncodeSingle)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };
  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  auto *ep1 = oc_cloud_endpoint_add(&ce, uri1, id1);
  ASSERT_NE(nullptr, ep1);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_cloud_endpoints_encode(oc_rep_object(root), &getCloudEndpoints(),
                            OC_STRING_VIEW("servers"),
                            /*skipIfSingleAndSelected*/ false);
  oc_rep_end_root_object();
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(rep.get(), R"({"servers":[)" +
                                      encodeCloudEndpointItem(uri1.data, id1) +
                                      R"(]})");
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  oc_cloud_endpoints_encode(oc_rep_object(root), &getCloudEndpoints(),
                            OC_STRING_VIEW("servers"),
                            /*skipIfSingleAndSelected*/ true);
  oc_rep_end_root_object();
  rep = pool.ParsePayload();
  EXPECT_EQ(nullptr, rep.get());
}

TEST_F(TestCloudEndpoint, EncodeMultiple)
{
  oc_cloud_endpoints_t &ce{ getCloudEndpoints() };
  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri1, id1));
  auto uri2 = OC_STRING_VIEW("/uri/2");
  oc_uuid_t id2;
  oc_gen_uuid(&id2);
  ASSERT_NE(nullptr, oc_cloud_endpoint_add(&ce, uri2, id2));

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_cloud_endpoints_encode(oc_rep_object(root), &getCloudEndpoints(),
                            OC_STRING_VIEW("servers"),
                            /*skipIfSingleAndSelected*/ false);
  oc_rep_end_root_object();
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(
    rep.get(), R"({"servers":[)" + encodeCloudEndpointItem(uri1.data, id1) +
                 "," + encodeCloudEndpointItem(uri2.data, id2) + R"(]})");
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  oc_cloud_endpoints_encode(oc_rep_object(root), &getCloudEndpoints(),
                            OC_STRING_VIEW("servers"),
                            /*skipIfSingleAndSelected*/ true);
  oc_rep_end_root_object();
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(
    rep.get(), R"({"servers":[)" + encodeCloudEndpointItem(uri1.data, id1) +
                 "," + encodeCloudEndpointItem(uri2.data, id2) + R"(]})");
}
