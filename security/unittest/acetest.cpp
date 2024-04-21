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

#include <gtest/gtest.h>

class TestACE : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override
  {
    // TODO: rm
    oc_log_set_level(OC_LOG_LEVEL_DEBUG);
  }

  void TearDown() override { oc_log_set_level(OC_LOG_LEVEL_INFO); }
};

TEST_F(TestACE, NewUUID)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, &subject_uuid, 42, OC_PERM_RETRIEVE, tag);
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
  oc_ace_subject_t subject_role{};
  auto testRole = OC_STRING_LOCAL("test.role");
  subject_role.role = { testRole, {} };
  auto tag = OC_STRING_VIEW("role");
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_ROLE, &subject_role, 13,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE, tag);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_ROLE, ace->subject_type);
  ASSERT_NE(nullptr, oc_string(ace->subject.role.role));
  EXPECT_STREQ(oc_string(testRole), oc_string(ace->subject.role.role));
  ASSERT_EQ(nullptr, oc_string(ace->subject.role.authority));
  EXPECT_EQ(13, ace->aceid);
  EXPECT_EQ(OC_PERM_RETRIEVE | OC_PERM_UPDATE, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  ASSERT_NE(nullptr, oc_string(ace->tag));
  EXPECT_STREQ(tag.data, oc_string(ace->tag));
  oc_sec_free_ace(ace);

  // empty role.authority is equal to NULL
  auto testAuthority = OC_STRING_LOCAL("");
  ace = oc_sec_new_ace(OC_SUBJECT_ROLE, &subject_role, 13,
                       OC_PERM_RETRIEVE | OC_PERM_UPDATE, tag);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(nullptr, oc_string(ace->subject.role.authority));
  oc_sec_free_ace(ace);

  oc_ace_subject_t subject_role_with_authority{};
  testRole = OC_STRING_LOCAL("test.newrole");
  testAuthority = OC_STRING_LOCAL("test.authority");
  subject_role_with_authority.role = { testRole, testAuthority };
  ace = oc_sec_new_ace(OC_SUBJECT_ROLE, &subject_role_with_authority, 37,
                       OC_PERM_DELETE | OC_PERM_NOTIFY, OC_STRING_VIEW_NULL);
  ASSERT_NE(ace, nullptr);
  ASSERT_EQ(OC_SUBJECT_ROLE, ace->subject_type);
  ASSERT_NE(nullptr, oc_string(ace->subject.role.role));
  EXPECT_STREQ(oc_string(testRole), oc_string(ace->subject.role.role));
  ASSERT_NE(nullptr, oc_string(ace->subject.role.authority));
  EXPECT_STREQ(oc_string(testAuthority),
               oc_string(ace->subject.role.authority));
  EXPECT_EQ(37, ace->aceid);
  EXPECT_EQ(OC_PERM_DELETE | OC_PERM_NOTIFY, ace->permission);
  EXPECT_EQ(0, oc_list_length(ace->resources));
  EXPECT_EQ(nullptr, oc_string(ace->tag));
  oc_sec_free_ace(ace);
}

TEST_F(TestACE, NewAnonConn)
{
  oc_ace_subject_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, &anon_conn, 1,
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
  oc_ace_subject_t crypt_conn{};
  crypt_conn.conn = OC_CONN_AUTH_CRYPT;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, &crypt_conn, 2,
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
  oc_ace_subject_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, &subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  oc_string_view_t href = OC_STRING_VIEW("/uri/1");
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
  oc_string_view_t href2 = OC_STRING_VIEW("/uri/2");
  res_data = oc_sec_ace_get_or_add_res(ace, href2, OC_ACE_NO_WC, false);
  EXPECT_FALSE(res_data.created);
  EXPECT_EQ(nullptr, res_data.res);

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, FindResource)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, &subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  // href-only
  oc_string_view_t href = OC_STRING_VIEW("/uri/1");
  auto res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // href + wildcard
  oc_string_view_t href2 = OC_STRING_VIEW("/uri/2");
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
  while (res != NULL) {
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
  while (res != NULL) {
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

TEST_F(TestACE, EncodeUUID)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_t subject_uuid{};
  subject_uuid.uuid = uuid;
  auto tag = OC_STRING_VIEW("l33t");
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_UUID, &subject_uuid, 42, OC_PERM_RETRIEVE, tag);
  ASSERT_NE(ace, nullptr);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeRole)
{
  oc_ace_subject_t subject_role{};
  auto testRole = OC_STRING_LOCAL("test.role");
  auto testAuthority = OC_STRING_LOCAL("test.authority");
  subject_role.role = { testRole, testAuthority };
  oc_sec_ace_t *ace =
    oc_sec_new_ace(OC_SUBJECT_ROLE, &subject_role, 13,
                   OC_PERM_RETRIEVE | OC_PERM_UPDATE, OC_STRING_VIEW_NULL);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeAnonConn)
{
  oc_ace_subject_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, &anon_conn, 1,
                                     OC_PERM_NONE, OC_STRING_VIEW_NULL);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeCryptConn)
{
  oc_ace_subject_t crypt_conn{};
  crypt_conn.conn = OC_CONN_AUTH_CRYPT;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, &crypt_conn, 2,
                                     OC_PERM_CREATE, OC_STRING_VIEW_NULL);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeWithResources)
{
  oc_ace_subject_t subject_role{};
  auto testRole = OC_STRING_LOCAL("test.role");
  subject_role.role = { testRole, {} };
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_ROLE, &subject_role, 17,
                                     OC_PERM_NOTIFY, OC_STRING_VIEW_NULL);

  // href resource
  oc_string_view_t href = OC_STRING_VIEW("/uri/1");
  auto res_data = oc_sec_ace_get_or_add_res(ace, href, OC_ACE_NO_WC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // wc-all secured resource
  res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                       OC_ACE_WC_ALL_SECURED, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  // wc-all public resource
  res_data = oc_sec_ace_get_or_add_res(ace, OC_STRING_VIEW_NULL,
                                       OC_ACE_WC_ALL_PUBLIC, true);
  ASSERT_TRUE(res_data.created);
  ASSERT_NE(nullptr, res_data.res);

  oc::RepPool pool{};
  oc_rep_begin_root_object();
  oc_sec_encode_ace(oc_rep_object(root), ace, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

TEST_F(TestACE, EncodeWithWCAllResource)
{
  oc_ace_subject_t anon_conn{};
  anon_conn.conn = OC_CONN_ANON_CLEAR;
  oc_sec_ace_t *ace = oc_sec_new_ace(OC_SUBJECT_CONN, &anon_conn, 1,
                                     OC_PERM_CREATE, OC_STRING_VIEW_NULL);

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

  oc::oc_rep_unique_ptr rep = pool.ParsePayload();
  ASSERT_NE(nullptr, rep.get());
  OC_DBG("payload: %s", oc::RepPool::GetJson(rep.get(), true).data());
  // TODO: decode and check

  oc_sec_free_ace(ace);
}

#endif /* OC_SECURITY */
