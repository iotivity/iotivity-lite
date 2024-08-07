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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST

#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_memb.h"
#include "util/oc_mmem_internal.h"

#include <array>
#include "gtest/gtest.h"
#include <string>

static constexpr size_t OC_MAX_ENDPOINT_ADDRESSES = 3;

OC_MEMB(g_endpoint_addresses_s, oc_endpoint_address_t,
        OC_MAX_ENDPOINT_ADDRESSES);

static std::string
encodeEndpointAddressWithUUID(const std::string &uri, oc_uuid_t id)
{
  std::array<char, OC_UUID_LEN> id_str{};
  if (oc_uuid_to_str_v1(&id, &id_str[0], id_str.size()) < 0) {
    return std::string{};
  }
  return std::string(R"({"uri":")") + uri.c_str() + R"(","id":")" +
         id_str.data() + R"("})";
}

static std::string
encodeEndpointAddressWithName(const std::string &uri, const std::string &name)
{
  return std::string(R"({"uri":")") + uri.c_str() + R"(","name":")" +
         name.c_str() + R"("})";
}

class TestEndpointAddress : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }
};

TEST_F(TestEndpointAddress, EncodeWithUUID)
{
  oc::RepPool pool{};

  auto uri_key = OC_STRING_VIEW("uri");
  auto uuid_key = OC_STRING_VIEW("id");
  auto uri = OC_STRING_VIEW("/uri");
  oc_uuid_t id{};
  oc_gen_uuid(&id);
  oc_rep_begin_root_object();
  oc_endpoint_address_encode(oc_rep_object(root), uri_key, uuid_key,
                             OC_STRING_VIEW_NULL,
                             oc_endpoint_address_make_view_with_uuid(uri, id));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(rep.get(),
                         encodeEndpointAddressWithUUID(uri.data, id));
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  // when the key for the UUID is not provided, the UUID is not encoded
  oc_endpoint_address_encode(oc_rep_object(root), uri_key, OC_STRING_VIEW_NULL,
                             OC_STRING_VIEW_NULL,
                             oc_endpoint_address_make_view_with_uuid(uri, id));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(rep.get(),
                         std::string(R"({"uri":")") + uri.data + R"("})");
}

TEST_F(TestEndpointAddress, EncodeWithName)
{
  oc::RepPool pool{};

  auto uri_key = OC_STRING_VIEW("uri");
  auto name_key = OC_STRING_VIEW("name");
  auto uri = OC_STRING_VIEW("/uri");
  auto name = OC_STRING_VIEW("plgd.dev");

  oc_rep_begin_root_object();
  oc_endpoint_address_encode(
    oc_rep_object(root), uri_key, OC_STRING_VIEW_NULL, name_key,
    oc_endpoint_address_make_view_with_name(uri, name));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(rep.get(),
                         encodeEndpointAddressWithName(uri.data, name.data));
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  // when the key for the name is not provided, the name is not encoded
  oc_endpoint_address_encode(
    oc_rep_object(root), uri_key, OC_STRING_VIEW_NULL, OC_STRING_VIEW_NULL,
    oc_endpoint_address_make_view_with_name(uri, name));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(rep.get(),
                         std::string(R"({"uri":")") + uri.data + R"("})");
}

class TestEndpointAddresses : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override
  {
    ASSERT_TRUE(oc_endpoint_addresses_init(
      &ea, &g_endpoint_addresses_s, nullptr, nullptr,
      oc_endpoint_address_make_view_with_uuid(OC_STRING_VIEW_NULL, {})));
  }

  void TearDown() override { oc_endpoint_addresses_deinit(&ea); }

  oc_endpoint_addresses_t &getAddresses() { return ea; }

private:
  oc_endpoint_addresses_t ea;
};

TEST_F(TestEndpointAddresses, InitWithDefault)
{
  oc_endpoint_addresses_t ea{};
  ASSERT_TRUE(
    oc_endpoint_addresses_init(&ea, &g_endpoint_addresses_s, nullptr, nullptr,
                               oc_endpoint_address_make_view_with_uuid(
                                 OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS),
                                 OCF_COAPCLOUDCONF_DEFAULT_SID)));
  EXPECT_TRUE(oc_endpoint_addresses_contains(
    &ea, OC_STRING_VIEW(OCF_COAPCLOUDCONF_DEFAULT_CIS)));
  auto *selected = ea.selected;
  ASSERT_NE(nullptr, selected);
  EXPECT_STREQ(OCF_COAPCLOUDCONF_DEFAULT_CIS, oc_string(selected->uri));
  EXPECT_TRUE(oc_uuid_is_equal(OCF_COAPCLOUDCONF_DEFAULT_SID,
                               selected->metadata.id.uuid));
  oc_endpoint_addresses_deinit(&ea);
}

TEST_F(TestEndpointAddresses, Init_FailInvalidDefault)
{
  oc_endpoint_addresses_t ea{};
  std::string tooLong(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH + 1, 'a');
  EXPECT_FALSE(oc_endpoint_addresses_init(
    &ea, &g_endpoint_addresses_s, nullptr, nullptr,
    oc_endpoint_address_make_view_with_uuid(
      oc_string_view(tooLong.c_str(), tooLong.length()), {})));
  oc_endpoint_addresses_deinit(&ea);
}

TEST_F(TestEndpointAddresses, IsEmpty)
{
  oc_endpoint_addresses_t eaEmpty{};
  EXPECT_EQ(0, oc_endpoint_addresses_size(&eaEmpty));
  EXPECT_TRUE(oc_endpoint_addresses_is_empty(&eaEmpty));

  const oc_endpoint_addresses_t &ea{ getAddresses() };
  EXPECT_EQ(0, oc_endpoint_addresses_size(&ea));
  EXPECT_TRUE(oc_endpoint_addresses_is_empty(&ea));
}

TEST_F(TestEndpointAddresses, Contains)
{
  oc_endpoint_addresses_t eaEmpty{};
  EXPECT_FALSE(oc_endpoint_addresses_contains(&eaEmpty, OC_STRING_VIEW_NULL));

  const oc_endpoint_addresses_t &ea{ getAddresses() };
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, OC_STRING_VIEW_NULL));
}

TEST_F(TestEndpointAddresses, AddAndSet)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri1));
  oc_uuid_t id1{};
  oc_gen_uuid(&id1);
  auto *ep1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri1, id1));
  EXPECT_NE(nullptr, ep1);
  EXPECT_TRUE(oc_endpoint_addresses_contains(&ea, uri1));
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ea));

  auto uri2 = OC_STRING_VIEW("/uri/2");
  auto name2 = OC_STRING_VIEW("name2");
  oc_uuid_t id2{};
  oc_gen_uuid(&id2);
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri2));
  auto *ep2 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_name(uri2, name2));
  EXPECT_NE(nullptr, ep2);
  EXPECT_TRUE(oc_endpoint_addresses_contains(&ea, uri2));
  EXPECT_EQ(2, oc_endpoint_addresses_size(&ea));

  EXPECT_STREQ(uri1.data, oc_string(*oc_endpoint_address_uri(ep1)));
  auto *ep_uuid1 = oc_endpoint_address_uuid(ep1);
  ASSERT_NE(nullptr, ep_uuid1);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *ep_uuid1));
  auto *ep_name1 = oc_endpoint_address_name(ep1);
  EXPECT_EQ(nullptr, ep_name1);

  EXPECT_STREQ(uri2.data, oc_string(*oc_endpoint_address_uri(ep2)));
  auto *ep_uuid2 = oc_endpoint_address_uuid(ep2);
  EXPECT_EQ(nullptr, ep_uuid2);
  auto *ep_name2 = oc_endpoint_address_name(ep2);
  ASSERT_NE(nullptr, ep_name2);
  EXPECT_STREQ(name2.data, oc_string(*ep_name2));

  // keep the metadata type, just change the value
  oc_uuid_t id3{};
  oc_gen_uuid(&id3);
  oc_endpoint_address_set_uuid(ep1, id3);
  ep_uuid1 = oc_endpoint_address_uuid(ep1);
  ASSERT_NE(nullptr, ep_uuid1);
  EXPECT_TRUE(oc_uuid_is_equal(id3, *ep_uuid1));

  auto name3 = OC_STRING_VIEW("name3");
  oc_endpoint_address_set_name(ep2, name3.data, name3.length);
  ep_name2 = oc_endpoint_address_name(ep2);
  ASSERT_NE(nullptr, ep_name2);
  EXPECT_STREQ(name3.data, oc_string(*ep_name2));

  // change the metadata type
  oc_endpoint_address_set_name(ep1, nullptr, 0);
  ep_name1 = oc_endpoint_address_name(ep1);
  ASSERT_NE(nullptr, ep_name1);
  EXPECT_EQ(nullptr, oc_string(*ep_name1));
}

TEST_F(TestEndpointAddresses, AddAndRemove)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri1));
  auto *ep1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri1, {}));
  EXPECT_NE(nullptr, ep1);
  EXPECT_TRUE(oc_endpoint_addresses_contains(&ea, uri1));
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ea));

  auto uri2 = OC_STRING_VIEW("/uri/2");
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri2));
  EXPECT_NE(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_name(uri2, {})));
  EXPECT_TRUE(oc_endpoint_addresses_contains(&ea, uri2));
  EXPECT_EQ(2, oc_endpoint_addresses_size(&ea));

  EXPECT_TRUE(oc_endpoint_addresses_remove_by_uri(&ea, uri2));
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri2));
  EXPECT_EQ(1, oc_endpoint_addresses_size(&ea));

  EXPECT_TRUE(oc_endpoint_addresses_remove(&ea, ep1));
  EXPECT_FALSE(oc_endpoint_addresses_contains(&ea, uri1));
  EXPECT_EQ(0, oc_endpoint_addresses_size(&ea));
}

TEST_F(TestEndpointAddresses, Add_Fail)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  ASSERT_EQ(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(
                              OC_STRING_VIEW_NULL, {})));
  std::string tooLong(OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH + 1, 'a');
  ASSERT_EQ(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_uuid(
                     oc_string_view(tooLong.c_str(), tooLong.length()), {})));

#ifndef OC_DYNAMIC_ALLOCATION
#ifdef OC_TEST
  size_t available_size = oc_mmem_available_size(BYTE_POOL);
  ASSERT_LT(4, available_size);
  oc_string_t reserved_pool{};
  std::string reserved(available_size - 4, 'a');
  oc_new_string(&reserved_pool, reserved.c_str(), reserved.length());

  // only 3 characters are available in the pool
  // - fail to allocate uri
  std::string tooLongReserved(4, 'a');
  ASSERT_EQ(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(
                              oc_string_view(tooLongReserved.c_str(),
                                             tooLongReserved.length()),
                              {})));
  // - fail to allocate name
  ASSERT_EQ(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_name(
                              OC_STRING_VIEW("/a"),
                              oc_string_view(tooLongReserved.c_str(),
                                             tooLongReserved.length()))));

  oc_free_string(&reserved_pool);
#endif /* OC_TEST */

  for (size_t i = 0; i < OC_MAX_ENDPOINT_ADDRESSES; i++) {
    auto uri = std::string("/uri/") + std::to_string(i);
    ASSERT_NE(nullptr,
              oc_endpoint_addresses_add(
                &ea, oc_endpoint_address_make_view_with_uuid(
                       oc_string_view(uri.c_str(), uri.length()), {})));
  }

  auto uri = OC_STRING_VIEW("/fail");
  EXPECT_EQ(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(uri, {})));
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestEndpointAddresses, Add_DuplicateFail)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  ASSERT_NE(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(uri1, {})));
  EXPECT_EQ(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(uri1, {})));
}

TEST_F(TestEndpointAddresses, Remove_Fail)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  ASSERT_NE(nullptr, oc_endpoint_addresses_add(
                       &ea, oc_endpoint_address_make_view_with_uuid(uri1, {})));

  // element not in the list
  oc_endpoint_address_t ep{};
  EXPECT_FALSE(oc_endpoint_addresses_remove(&ea, &ep));

  // no element with the given URI
  EXPECT_FALSE(oc_endpoint_addresses_remove_by_uri(&ea, OC_STRING_VIEW_NULL));
  EXPECT_FALSE(
    oc_endpoint_addresses_remove_by_uri(&ea, OC_STRING_VIEW("/fail")));
}

TEST_F(TestEndpointAddresses, Select)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto on_selected_change = oc_endpoint_addresses_get_on_selected_change(&ea);
  ASSERT_EQ(nullptr, on_selected_change.cb);
  ASSERT_EQ(nullptr, on_selected_change.cb_data);
  bool on_change_invoked = false;
  oc_endpoint_addresses_set_on_selected_change(
    &ea, [](void *data) { *static_cast<bool *>(data) = true; },
    &on_change_invoked);

  bool selected_changed = oc_endpoint_addresses_select_next(&ea);
  EXPECT_FALSE(selected_changed);
  EXPECT_FALSE(on_change_invoked);
  auto *selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  EXPECT_EQ(nullptr, selected_addr);
  auto *selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  EXPECT_EQ(nullptr, selected_uuid);
  auto *selected_name = oc_endpoint_addresses_selected_name(&ea);
  EXPECT_EQ(nullptr, selected_name);

  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_uuid(uri1, id1)));
  // when adding to an empty list, the first added item is automatically
  // selected
  EXPECT_TRUE(on_change_invoked);
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&ea, uri1));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri1.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  ASSERT_NE(nullptr, selected_uuid);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *selected_uuid));
  // the selected item doesn't have name, just uuid
  selected_name = oc_endpoint_addresses_selected_name(&ea);
  ASSERT_EQ(nullptr, selected_name);

  // non-existing URI shouldn't change the selection
  on_change_invoked = false;
  EXPECT_FALSE(
    oc_endpoint_addresses_select_by_uri(&ea, OC_STRING_VIEW("/fail")));
  EXPECT_FALSE(on_change_invoked);
  EXPECT_FALSE(oc_endpoint_addresses_is_selected(&ea, OC_STRING_VIEW("/fail")));
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&ea, uri1));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri1.data, oc_string(*selected_addr));

#ifdef OC_DYNAMIC_ALLOCATION
  auto uri2 = OC_STRING_VIEW("/uri/2");
  oc_uuid_t id2;
  oc_gen_uuid(&id2);
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_uuid(uri2, id2)));
  EXPECT_FALSE(oc_endpoint_addresses_is_selected(&ea, uri2));
  auto uri3 = OC_STRING_VIEW("/uri/3");
  auto name3 = OC_STRING_VIEW("name3");
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_name(uri3, name3)));
  EXPECT_FALSE(oc_endpoint_addresses_is_selected(&ea, uri3));

  EXPECT_TRUE(oc_endpoint_addresses_select_by_uri(&ea, uri2));
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&ea, uri2));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri2.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  ASSERT_NE(nullptr, selected_uuid);
  EXPECT_TRUE(oc_uuid_is_equal(id2, *selected_uuid));
  selected_name = oc_endpoint_addresses_selected_name(&ea);
  EXPECT_EQ(nullptr, selected_name);

  EXPECT_TRUE(oc_endpoint_addresses_select_by_uri(&ea, uri3));
  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&ea, uri3));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri3.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  EXPECT_EQ(nullptr, selected_uuid);
  selected_name = oc_endpoint_addresses_selected_name(&ea);
  ASSERT_NE(nullptr, selected_name);
  EXPECT_STREQ(name3.data, oc_string(*selected_name));

  // rotate back to uri1
  on_change_invoked = false;
  selected_changed = oc_endpoint_addresses_select_next(&ea);
  EXPECT_TRUE(selected_changed);
  EXPECT_TRUE(on_change_invoked);
#else  /* !OC_DYNAMIC_ALLOCATION  */
  // the list has a single element, so the selection should stay at uri1
  on_change_invoked = false;
  selected_changed = oc_endpoint_addresses_select_next(&ea);
  EXPECT_FALSE(selected_changed);
  EXPECT_FALSE(on_change_invoked);
#endif /* OC_DYNAMIC_ALLOCATION */

  EXPECT_TRUE(oc_endpoint_addresses_is_selected(&ea, uri1));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  EXPECT_STREQ(uri1.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  ASSERT_NE(nullptr, selected_uuid);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *selected_uuid));
  selected_name = oc_endpoint_addresses_selected_name(&ea);
  ASSERT_EQ(nullptr, selected_name);
}

TEST_F(TestEndpointAddresses, RemoveSelected)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };
  auto selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_EQ(nullptr, selected_addr);
  auto selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  ASSERT_EQ(nullptr, selected_uuid);

  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  auto *ep1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri1, id1));
  ASSERT_NE(nullptr, ep1);

#ifdef OC_DYNAMIC_ALLOCATION
  auto uri2 = OC_STRING_VIEW("/uri/2");
  oc_uuid_t id2;
  oc_gen_uuid(&id2);
  auto *ep2 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri2, id2));
  ASSERT_NE(nullptr, ep2);
  auto uri3 = OC_STRING_VIEW("/uri/3");
  oc_uuid_t id3;
  oc_gen_uuid(&id3);
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_uuid(uri3, id3)));
  EXPECT_TRUE(oc_endpoint_addresses_select_by_uri(&ea, uri2));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri2.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  EXPECT_TRUE(oc_uuid_is_equal(id2, *selected_uuid));

  EXPECT_TRUE(oc_endpoint_addresses_remove(&ea, ep2));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  // uri3 is next, so it should be selected
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri3.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  EXPECT_TRUE(oc_uuid_is_equal(id3, *selected_uuid));

  EXPECT_TRUE(oc_endpoint_addresses_remove_by_uri(&ea, uri3));
  // the list should rotate back to uri1 after uri3 is removed
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_NE(nullptr, selected_addr);
  ASSERT_STREQ(uri1.data, oc_string(*selected_addr));
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  EXPECT_TRUE(oc_uuid_is_equal(id1, *selected_uuid));
#endif /* OC_DYNAMIC_ALLOCATION */

  EXPECT_TRUE(oc_endpoint_addresses_remove(&ea, ep1));
  EXPECT_EQ(0, oc_endpoint_addresses_size(&ea));
  EXPECT_FALSE(oc_endpoint_addresses_is_selected(&ea, uri1));
  selected_addr = oc_endpoint_addresses_selected_uri(&ea);
  ASSERT_EQ(nullptr, selected_addr);
  selected_uuid = oc_endpoint_addresses_selected_uuid(&ea);
  ASSERT_EQ(nullptr, selected_uuid);
}

TEST_F(TestEndpointAddresses, Find)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };

  auto uri1 = OC_STRING_VIEW("/uri/1");
  auto ce1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri1, {}));
  ASSERT_NE(nullptr, ce1);
  auto uri2 = OC_STRING_VIEW("/uri/2");
  auto ce2 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_name(uri2, {}));
  ASSERT_NE(nullptr, ce2);
  auto uri3 = OC_STRING_VIEW("/uri/3");

  auto found = oc_endpoint_addresses_find(&ea, uri1);
  EXPECT_EQ(ce1, found);
  found = oc_endpoint_addresses_find(&ea, uri2);
  EXPECT_EQ(ce2, found);
  found = oc_endpoint_addresses_find(&ea, uri3);
  EXPECT_EQ(nullptr, found);

  oc_endpoint_addresses_t ceEmpty{};
  EXPECT_EQ(nullptr, oc_endpoint_addresses_find(&ceEmpty, uri1));
}

TEST_F(TestEndpointAddresses, EncodeEmpty)
{
  oc::RepPool pool{};

  // if the list is empty, nothing should be encoded
  oc_rep_begin_root_object();
  oc_endpoint_addresses_encode(oc_rep_object(root), &getAddresses(),
                               OC_STRING_VIEW("servers"), true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_EQ(nullptr, rep.get());
}

TEST_F(TestEndpointAddresses, EncodeSingle)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };
  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  auto *ep1 = oc_endpoint_addresses_add(
    &ea, oc_endpoint_address_make_view_with_uuid(uri1, id1));
  ASSERT_NE(nullptr, ep1);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_endpoint_addresses_encode(oc_rep_object(root), &getAddresses(),
                               OC_STRING_VIEW("servers"),
                               /*skipIfSingleAndSelected*/ false);
  oc_rep_end_root_object();
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(
    rep.get(), R"({"servers":[)" +
                 encodeEndpointAddressWithUUID(uri1.data, id1) + R"(]})");
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  oc_endpoint_addresses_encode(oc_rep_object(root), &getAddresses(),
                               OC_STRING_VIEW("servers"),
                               /*skipIfSingleAndSelected*/ true);
  oc_rep_end_root_object();
  rep = pool.ParsePayload();
  EXPECT_EQ(nullptr, rep.get());
}

TEST_F(TestEndpointAddresses, EncodeMultiple)
{
  oc_endpoint_addresses_t &ea{ getAddresses() };
  auto uri1 = OC_STRING_VIEW("/uri/1");
  oc_uuid_t id1;
  oc_gen_uuid(&id1);
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_uuid(uri1, id1)));
  auto uri2 = OC_STRING_VIEW("/uri/2");
  auto name2 = OC_STRING_VIEW("name2");
  ASSERT_NE(nullptr,
            oc_endpoint_addresses_add(
              &ea, oc_endpoint_address_make_view_with_name(uri2, name2)));

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_endpoint_addresses_encode(oc_rep_object(root), &getAddresses(),
                               OC_STRING_VIEW("servers"),
                               /*skipIfSingleAndSelected*/ false);
  oc_rep_end_root_object();
  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(
    rep.get(),
    R"({"servers":[)" + encodeEndpointAddressWithUUID(uri1.data, id1) + "," +
      encodeEndpointAddressWithName(uri2.data, name2.data) + R"(]})");
  rep.reset();
  pool.Clear();

  oc_rep_begin_root_object();
  oc_endpoint_addresses_encode(oc_rep_object(root), &getAddresses(),
                               OC_STRING_VIEW("servers"),
                               /*skipIfSingleAndSelected*/ true);
  oc_rep_end_root_object();
  rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  oc::RepPool::CheckJson(
    rep.get(),
    R"({"servers":[)" + encodeEndpointAddressWithUUID(uri1.data, id1) + "," +
      encodeEndpointAddressWithName(uri2.data, name2.data) + R"(]})");
}

#endif /* OC_HAS_FEATURE_ENDPOINT_ADDRESS_LIST */
