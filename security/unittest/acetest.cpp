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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifdef OC_SECURITY

#include "api/oc_helpers_internal.h"
#include "oc_enums.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "security/oc_ace_internal.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_list.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

class TestACE : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  static void checkEncodedACE(
    const oc_sec_ace_t *ace, const oc_rep_t *rep,
    std::vector<const oc_ace_res_t *> expResources = {})
  {
    ASSERT_NE(nullptr, rep);
    OC_DBG("payload: %s", oc::RepPool::GetJson(rep, true).data());
    oc_sec_ace_decode_t decoded{};
    ASSERT_TRUE(oc_sec_decode_ace(rep, &decoded));
    EXPECT_EQ(ace->aceid, decoded.aceid);
    EXPECT_TRUE(
      oc_ace_has_matching_subject(ace, decoded.subject_type, decoded.subject));
    EXPECT_EQ(ace->permission, decoded.permission);
    EXPECT_TRUE(oc_ace_has_matching_tag(ace, oc_string_view2(decoded.tag)));
    if (expResources.empty()) {
      EXPECT_EQ(nullptr, decoded.resources);
    } else {
      ASSERT_NE(nullptr, decoded.resources);
      std::vector<oc_sec_ace_res_decode_t> resources{};
      ASSERT_TRUE(oc_sec_decode_ace_resources(
        decoded.resources,
        [](const oc_sec_ace_res_decode_t *aceresdecode, void *user_data) {
          auto *resources =
            static_cast<std::vector<oc_sec_ace_res_decode_t> *>(user_data);
          resources->push_back(*aceresdecode);
        },
        &resources));
      ASSERT_EQ(expResources.size(), resources.size());
      for (const auto &resource : resources) {
        auto it = std::find_if(expResources.begin(), expResources.end(),
                               [&resource](const oc_ace_res_t *aceres) {
                                 oc_string_view_t href1 =
                                   oc_string_view2(&aceres->href);
                                 oc_string_view_t href2 =
                                   oc_string_view2(resource.href);
                                 return aceres->wildcard == resource.wildcard &&
                                        oc_string_view_is_equal(href1, href2);
                               });
        ASSERT_NE(it, expResources.end());
        expResources.erase(it);
      }
      EXPECT_TRUE(expResources.empty());
    }
  }

  static void checkInvalidPayload(const oc_rep_t *rep)
  {
    ASSERT_NE(nullptr, rep);
    OC_DBG("payload: %s", oc::RepPool::GetJson(rep, true).data());
    oc_sec_ace_decode_t decoded{};
    EXPECT_FALSE(oc_sec_decode_ace(rep, &decoded));
  }
};

TEST_F(TestACE, NewUUID)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_view_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  EXPECT_EQ(OC_SUBJECT_UUID, ace->subject_type);
  EXPECT_TRUE(oc_uuid_is_equal(uuid, ace->subject.uuid));
  EXPECT_EQ(42, ace->aceid);
  EXPECT_EQ(OC_PERM_RETRIEVE, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  ASSERT_NE(nullptr, oc_string(ace->tag));
  EXPECT_STREQ(tag.data, oc_string(ace->tag));
  oc_sec_free_ace(ace);
}

TEST_F(TestACE, NewRole)
{
  oc_ace_subject_view_t subject_role{};
  auto testRole = OC_STRING_VIEW("test.role");
  subject_role.role = { testRole, {} };
  auto tag = OC_STRING_VIEW("role");
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_ROLE, subject_role, 13,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE, tag);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_ROLE, ace->subject_type);
  ASSERT_NE(nullptr, oc_string(ace->subject.role.role));
  EXPECT_STREQ(testRole.data, oc_string(ace->subject.role.role));
  ASSERT_EQ(nullptr, oc_string(ace->subject.role.authority));
  EXPECT_EQ(13, ace->aceid);
  EXPECT_EQ(OC_PERM_RETRIEVE | OC_PERM_UPDATE, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  ASSERT_NE(nullptr, oc_string(ace->tag));
  EXPECT_STREQ(tag.data, oc_string(ace->tag));
  oc_sec_free_ace(ace);

  // empty role.authority is equal to NULL
  auto testAuthority = OC_STRING_VIEW("");
  ace = oc_sec_new_ace(OC_SUBJECT_ROLE, subject_role, 13,
                       OC_PERM_RETRIEVE | OC_PERM_UPDATE, tag);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(nullptr, oc_string(ace->subject.role.authority));
  oc_sec_free_ace(ace);

  oc_ace_subject_view_t subject_role_with_authority{};
  testRole = OC_STRING_VIEW("test.newrole");
  testAuthority = OC_STRING_VIEW("test.authority");
  subject_role_with_authority.role = { testRole, testAuthority };
  ace = oc_sec_new_ace(OC_SUBJECT_ROLE, subject_role_with_authority, 37,
                       OC_PERM_DELETE | OC_PERM_NOTIFY, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_ROLE, ace->subject_type);
  ASSERT_NE(nullptr, oc_string(ace->subject.role.role));
  EXPECT_STREQ(testRole.data, oc_string(ace->subject.role.role));
  ASSERT_NE(nullptr, oc_string(ace->subject.role.authority));
  EXPECT_STREQ(testAuthority.data, oc_string(ace->subject.role.authority));
  EXPECT_EQ(37, ace->aceid);
  EXPECT_EQ(OC_PERM_DELETE | OC_PERM_NOTIFY, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  EXPECT_EQ(nullptr, oc_string(ace->tag));
  oc_sec_free_ace(ace);
}

TEST_F(TestACE, NewAnonConn)
{
  oc_ace_subject_view_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, anon_conn, 1,
                                     OC_PERM_NONE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_CONN, ace->subject_type);
  EXPECT_EQ(OC_CONN_ANON_CLEAR, ace->subject.conn);
  EXPECT_EQ(1, ace->aceid);
  EXPECT_EQ(OC_PERM_NONE, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  EXPECT_EQ(nullptr, oc_string(ace->tag));
  oc_sec_free_ace(ace);
}

TEST_F(TestACE, NewCryptConn)
{
  oc_ace_subject_view_t crypt_conn{};
  crypt_conn.conn = OC_CONN_AUTH_CRYPT;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, crypt_conn, 2,
                                     OC_PERM_CREATE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_CONN, ace->subject_type);
  EXPECT_EQ(OC_CONN_AUTH_CRYPT, ace->subject.conn);
  EXPECT_EQ(2, ace->aceid);
  EXPECT_EQ(OC_PERM_CREATE, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  EXPECT_EQ(nullptr, oc_string(ace->tag));
  oc_sec_free_ace(ace);
}

TEST_F(TestACE, GetOrAddResource)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_view_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  auto href = OC_STRING_VIEW("/uri/1");
  auto res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  EXPECT_TRUE(res_data.created);
  EXPECT_NE(nullptr, res_data.res);

  // get the same resource
  res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, false);
  EXPECT_FALSE(res_data.created);
  EXPECT_NE(nullptr, res_data.res);

  // cannot create the same resource again, get will be invoked instead
  res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  EXPECT_FALSE(res_data.created);
  EXPECT_NE(nullptr, res_data.res);

  // trying to create a resource without href or wildcard should fail
  res_data =
    oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL, OC_ACE_NO_WC, true);
  EXPECT_FALSE(res_data.created);
  EXPECT_EQ(nullptr, res_data.res);

  // try to get a resource that does not exist
  auto href2 = OC_STRING_VIEW("/uri/2");
  res_data = oc_sec_ace_get_or_add_res(ace, href2, OC_ACE_NO_WC, false);
  EXPECT_FALSE(res_data.created);
  EXPECT_EQ(nullptr, res_data.res);

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, FindResource)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_view_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  // href-only
  auto href = OC_STRING_VIEW("/uri/1");
  auto res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // href + wildcard
  auto href2 = OC_STRING_VIEW("/uri/2");
  res_data = oc_sec_ace_get_or_add_res(ace, href2, OC_ACE_WC_ALL_SECURED, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // wildcard-only
  res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                       OC_ACE_WC_ALL_PUBLIC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // wc-all
  res_data =
    oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL, OC_ACE_WC_ALL, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // once wc-all is added, adding other wildcard resources should fail
  res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                       OC_ACE_WC_ALL_SECURED, true);
  ASSERT_FALSE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);
  res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                       OC_ACE_WC_ALL_PUBLIC, true);
  ASSERT_FALSE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // find the resource by href
  oc_ace_res_t *res =
    oc_sec_ace_find_resource(nullptr, ace, href, OC_ACE_NO_WC);
  ASSERT_NE(nullptr, res);
  EXPECT_STREQ(href.data, oc_string(res->href));
  // no other should match
  res = oc_sec_ace_find_resource(res, nullptr, href, OC_ACE_NO_WC);
  EXPECT_EQ(nullptr, res);

  // find the resource by wildcard (2 resource match = secured + all)
  int count = 0;
  res = oc_sec_ace_find_resource(nullptr, ace, OC_STRING_VIEW_NULL,
                                 OC_ACE_WC_ALL_SECURED);
  ASSERT_NE(nullptr, res);
  while (res != nullptr) {
    ++count;
    res = oc_sec_ace_find_resource(res, nullptr, OC_STRING_VIEW_NULL,
                                   OC_ACE_WC_ALL_SECURED);
  }
  EXPECT_EQ(2, count);

  // find public + secured wildcard (3 resources match = public, secured + all)
  count = 0;
  res = oc_sec_ace_find_resource(nullptr, ace, OC_STRING_VIEW_NULL,
                                 OC_ACE_WC_ALL_SECURED | OC_ACE_WC_ALL_PUBLIC);
  ASSERT_NE(nullptr, res);
  while (res != nullptr) {
    ++count;
    res =
      oc_sec_ace_find_resource(res, nullptr, OC_STRING_VIEW_NULL,
                               OC_ACE_WC_ALL_SECURED | OC_ACE_WC_ALL_PUBLIC);
  }
  EXPECT_EQ(3, count);

  // find wc-all
  res =
    oc_sec_ace_find_resource(nullptr, ace, OC_STRING_VIEW_NULL, OC_ACE_WC_ALL);
  ASSERT_NE(nullptr, res);
  ASSERT_EQ(nullptr, oc_string(res->href));
  EXPECT_EQ(OC_ACE_WC_ALL, res->wildcard);
  // no other should match
  res =
    oc_sec_ace_find_resource(res, nullptr, OC_STRING_VIEW_NULL, OC_ACE_WC_ALL);
  EXPECT_EQ(nullptr, res);

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, WildcardToString)
{
  EXPECT_EQ(nullptr, oc_ace_wildcard_to_string(OC_ACE_NO_WC).data);
  EXPECT_EQ(nullptr,
            oc_ace_wildcard_to_string(static_cast<oc_ace_wildcard_t>(-1)).data);

  EXPECT_STREQ(OC_ACE_WC_ALL_STR,
               oc_ace_wildcard_to_string(OC_ACE_WC_ALL).data);
  EXPECT_STREQ(OC_ACE_WC_ALL_PUBLIC_STR,
               oc_ace_wildcard_to_string(OC_ACE_WC_ALL_PUBLIC).data);
  EXPECT_STREQ(OC_ACE_WC_ALL_SECURED_STR,
               oc_ace_wildcard_to_string(OC_ACE_WC_ALL_SECURED).data);
}

TEST_F(TestACE, WildcardFromString)
{
  EXPECT_EQ(-1, oc_ace_wildcard_from_string(OC_STRING_VIEW("")));

  EXPECT_EQ(OC_ACE_WC_ALL,
            oc_ace_wildcard_from_string(OC_STRING_VIEW(OC_ACE_WC_ALL_STR)));
  EXPECT_EQ(OC_ACE_WC_ALL_PUBLIC, oc_ace_wildcard_from_string(
                                    OC_STRING_VIEW(OC_ACE_WC_ALL_PUBLIC_STR)));
  EXPECT_EQ(OC_ACE_WC_ALL_SECURED, oc_ace_wildcard_from_string(OC_STRING_VIEW(
                                     OC_ACE_WC_ALL_SECURED_STR)));
}

TEST_F(TestACE, ConnectionTypeToString)
{
  EXPECT_EQ(nullptr, oc_ace_connection_type_to_string(
                       static_cast<oc_ace_connection_type_t>(-1))
                       .data);

  EXPECT_STREQ(OC_CONN_AUTH_CRYPT_STR,
               oc_ace_connection_type_to_string(OC_CONN_AUTH_CRYPT).data);
  EXPECT_STREQ(OC_CONN_ANON_CLEAR_STR,
               oc_ace_connection_type_to_string(OC_CONN_ANON_CLEAR).data);
}

TEST_F(TestACE, ConnectionTypeFromString)
{
  EXPECT_EQ(-1, oc_ace_connection_type_from_string(OC_STRING_VIEW("")));

  EXPECT_EQ(OC_CONN_AUTH_CRYPT, oc_ace_connection_type_from_string(
                                  OC_STRING_VIEW(OC_CONN_AUTH_CRYPT_STR)));
  EXPECT_EQ(OC_CONN_ANON_CLEAR, oc_ace_connection_type_from_string(
                                  OC_STRING_VIEW(OC_CONN_ANON_CLEAR_STR)));
}

TEST_F(TestACE, EncodeUUID)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_view_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(ace, pool.ParsePayload().get());

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeRole)
{
  oc_ace_subject_view_t subject_role{};
  auto testRole = OC_STRING_VIEW("test.role");
  auto testAuthority = OC_STRING_VIEW("test.authority");
  subject_role.role = { testRole, testAuthority };
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_ROLE, subject_role, 13,
                   OC_PERM_RETRIEVE | OC_PERM_UPDATE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(ace, pool.ParsePayload().get());

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeAnonConn)
{
  oc_ace_subject_view_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, anon_conn, 1,
                                     OC_PERM_NONE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(ace, pool.ParsePayload().get());

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeCryptConn)
{
  oc_ace_subject_view_t crypt_conn{};
  crypt_conn.conn = OC_CONN_AUTH_CRYPT;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, crypt_conn, 2,
                                     OC_PERM_CREATE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(ace, pool.ParsePayload().get());

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeWithResources)
{
  oc_ace_subject_view_t subject_role{};
  auto testRole = OC_STRING_VIEW("test.role");
  subject_role.role = { testRole, {} };
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_ROLE, subject_role, 17,
                                     OC_PERM_NOTIFY, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);

  // href resource
  auto href = OC_STRING_VIEW("/uri/1");
  auto res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // wc-all secured resource
  auto wc_all_res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                                   OC_ACE_WC_ALL_SECURED, true);
  ASSERT_TRUE(wc_all_res_data.created);
  ASSERT_NE(nullptr, wc_all_res_data.res);

  // wc-all public resource
  auto wc_all_public_res_data = oc_sec_ace_get_or_add_res(
    ace, OC_STRING_VIEW_NULL, OC_ACE_WC_ALL_PUBLIC, true);
  ASSERT_TRUE(wc_all_public_res_data.created);
  ASSERT_NE(nullptr, wc_all_public_res_data.res);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<const oc_ace_res_t *> expResources = {
    res_data.res, wc_all_res_data.res, wc_all_public_res_data.res
  };
  checkEncodedACE(ace, pool.ParsePayload().get(), expResources);

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeWithWCAllResource)
{
  oc_ace_subject_view_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, anon_conn, 1,
                                     OC_PERM_CREATE, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);

  // wc-all resource
  auto res_data =
    oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL, OC_ACE_WC_ALL, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  std::vector<const oc_ace_res_t *> expResources = { res_data.res };
  checkEncodedACE(ace, pool.ParsePayload().get(), expResources);

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, Decode_FailInvalidStringProperty)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_set_text_string(root, plgd, "dev");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

TEST_F(TestACE, Decode_FailInvalidIntProperty)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_set_int(root, plgd.dev, 42);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

TEST_F(TestACE, Decode_FailInvalidObjectProperty)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_set_key(oc_rep_object(root), "objects");
  oc_rep_begin_array(oc_rep_object(root), objects);
  oc_rep_object_array_begin_item(objects);
  oc_rep_object_array_end_item(objects);
  oc_rep_end_array(oc_rep_object(root), objects);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

// permission is uint16_t type
TEST_F(TestACE, Decode_FailInvalidPermission)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_set_int(root, permission, std::numeric_limits<int64_t>::max());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

#if INT_MAX < INT64_MAX

// aceid is int type
TEST_F(TestACE, Decode_FailInvalidAceid)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_set_int(root, aceid, std::numeric_limits<int64_t>::max());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

#endif /* INT_MAX < INT64_MAX */

TEST_F(TestACE, Decode_FailInvalidObject)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_open_object(root, empty);
  oc_rep_close_object(root, empty);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubject_FailInvalidProperty)
{
  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_rep_open_object(root, subject);
  oc_rep_set_text_string(subject, plgd, "dev");
  oc_rep_close_object(root, subject);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  checkInvalidPayload(pool.ParsePayload().get());

  pool.Clear();
  oc_rep_begin_root_object();
  oc_rep_open_object(root, subject);
  oc_rep_set_int(subject, plgd, 42);
  oc_rep_close_object(root, subject);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  checkInvalidPayload(pool.ParsePayload().get());
}

static void
encodeSubject(const std::map<std::string, std::string, std::less<>> &properties)
{
  oc_rep_begin_root_object();
  oc_rep_open_object(root, subject);
  for (const auto &[key, value] : properties) {
    g_err |= oc_rep_object_set_text_string(oc_rep_object(subject), key.c_str(),
                                           key.length(), value.c_str(),
                                           value.length());
  }
  oc_rep_close_object(root, subject);
  oc_rep_end_root_object();
}

TEST_F(TestACE, DecodeSubjectUUID)
{
  std::string uuid_str = "550e8400-e29b-41d4-a716-446655440000";
  oc_uuid_t uuid{};
  ASSERT_NE(-1, oc_str_to_uuid_v1(uuid_str.c_str(), uuid_str.length(), &uuid));
  oc_sec_ace_t ace{};
  ace.subject_type = OC_SUBJECT_UUID;
  ace.subject.uuid = uuid;

  oc::RepPool pool{};
  encodeSubject({ { OC_ACE_PROP_SUBJECT_UUID, uuid_str } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(&ace, pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubjectUUID_FailInvalidUUID)
{
  oc::RepPool pool{};
  encodeSubject({ { OC_ACE_PROP_SUBJECT_UUID, "invalid-uuid" } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubjectRole)
{
  oc_sec_ace_t ace{};
  ace.subject_type = OC_SUBJECT_ROLE;
  ace.subject.role = {
    /*.role =*/OC_STRING_LOCAL("role"),
    /*.authority =*/OC_STRING_LOCAL("authority"),
  };

  oc::RepPool pool{};
  encodeSubject(
    { { OC_ACE_PROP_SUBJECT_ROLE, oc_string(ace.subject.role.role) },
      { OC_ACE_PROP_SUBJECT_AUTHORITY,
        oc_string(ace.subject.role.authority) } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(&ace, pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubjectRole_FailMissingRole)
{
  oc::RepPool pool{};
  encodeSubject({ { OC_ACE_PROP_SUBJECT_AUTHORITY, "authority" } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubjectConn)
{
  oc_sec_ace_t ace{};
  ace.subject_type = OC_SUBJECT_CONN;
  ace.subject.conn = OC_CONN_ANON_CLEAR;

  oc::RepPool pool{};
  encodeSubject(
    { { OC_ACE_PROP_SUBJECT_CONNTYPE,
        oc_ace_connection_type_to_string(ace.subject.conn).data } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkEncodedACE(&ace, pool.ParsePayload().get());
}

TEST_F(TestACE, DecodeSubjectConn_FailInvalidConnType)
{
  oc::RepPool pool{};
  encodeSubject({ { OC_ACE_PROP_SUBJECT_CONNTYPE, "invalid-conn-type" } });
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  checkInvalidPayload(pool.ParsePayload().get());
}

#endif /* OC_SECURITY */
