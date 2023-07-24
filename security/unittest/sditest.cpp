/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "api/oc_ri_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_store.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "security/oc_sdi_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_macros_internal.h"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

static const std::string testStorage{ "storage_test" };

class TestSdi : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }

  static void TearDownTestCase() { oc_random_destroy(); }

  static oc_sec_sdi_t createSdi(bool priv, const std::string &name,
                                oc_sec_sdi_t &sdi)
  {
    sdi.priv = priv;
    oc_gen_uuid(&sdi.uuid);
    oc_new_string(&sdi.name, name.c_str(), name.length());
    return sdi;
  }

  static bool isEqual(oc_sec_sdi_t &lhs, oc_sec_sdi_t &rhs)
  {
    return lhs.priv == rhs.priv && oc_uuid_is_equal(lhs.uuid, rhs.uuid) &&
           oc_string_len(lhs.name) == oc_string_len(rhs.name) &&
           (oc_string(lhs.name) == oc_string(rhs.name) ||
            memcmp(oc_string(lhs.name), oc_string(rhs.name),
                   oc_string_len(lhs.name)));
  }

  static void expectEqual(oc_sec_sdi_t &lhs, oc_sec_sdi_t &rhs)
  {
    EXPECT_EQ(lhs.priv, rhs.priv);
    EXPECT_TRUE(oc_uuid_is_equal(lhs.uuid, rhs.uuid));
    if (oc_string(lhs.name) == nullptr) {
      EXPECT_EQ(nullptr, oc_string(rhs.name));
    } else {
      EXPECT_STREQ(oc_string(lhs.name), oc_string(rhs.name));
    }
  }
};

#ifndef DYNAMIC_ALLOCATION

TEST_F(TestSdi, EncodeFail)
{
  // not enough memory to encode to encode sdi
  oc::RepPool pool{ 10 };

  oc_sec_sdi_t sdi{};
  createSdi(true, "test", sdi);
  EXPECT_NE(
    0, oc_sec_sdi_encode_with_resource(&sdi, nullptr, OCF_SEC_SDI_DEFAULT_IF));

  oc_free_string(&sdi.name);
}

#endif /* !DYNAMIC_ALLOCATION */

TEST_F(TestSdi, Encode)
{
  oc::RepPool pool{};

  oc_sec_sdi_t sdi{};
  createSdi(true, "test", sdi);
  EXPECT_EQ(
    0, oc_sec_sdi_encode_with_resource(&sdi, nullptr, OCF_SEC_SDI_DEFAULT_IF));

  oc_free_string(&sdi.name);
}

TEST_F(TestSdi, DecodeFromStorageFail_MissingProperties)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, test, "test");
  oc_rep_end_root_object();

  auto rep = pool.ParsePayload();
  oc_sec_sdi_t sdi_parsed{};
  EXPECT_FALSE(
    oc_sec_sdi_decode_with_state(rep.get(), OC_DOS_RFOTM, true, &sdi_parsed));
}

TEST_F(TestSdi, DecodeFail_InvalidStateForUUID)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, OC_UUID_LEN> uuid_str{};
  oc_uuid_to_str(&uuid, &uuid_str[0], uuid_str.size());
  oc_rep_set_text_string(root, uuid, uuid_str.data());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  // can only set uuid in RFOTM when no from storage
  auto rep = pool.ParsePayload();
  oc_sec_sdi_t sdi_parsed{};
  EXPECT_FALSE(
    oc_sec_sdi_decode_with_state(rep.get(), OC_DOS_RFPRO, false, &sdi_parsed));
}

TEST_F(TestSdi, DecodeFail_InvalidStateForName)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, name, "test");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  // can set name only in OC_DOS_RFOTM, OC_DOS_RFPRO or OC_DOS_SRESET
  auto rep = pool.ParsePayload();
  oc_sec_sdi_t sdi_parsed{};
  EXPECT_FALSE(
    oc_sec_sdi_decode_with_state(rep.get(), OC_DOS_RESET, false, &sdi_parsed));
}

TEST_F(TestSdi, DecodeFail_InvalidStateForPriv)
{
  oc::RepPool pool{};

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, priv, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  // can set priv only in OC_DOS_RFOTM, OC_DOS_RFPRO or OC_DOS_SRESET
  auto rep = pool.ParsePayload();
  oc_sec_sdi_t sdi_parsed{};
  EXPECT_FALSE(
    oc_sec_sdi_decode_with_state(rep.get(), OC_DOS_RFNOP, false, &sdi_parsed));
}

TEST_F(TestSdi, Decode)
{
  oc::RepPool pool{};

  oc_sec_sdi_t sdi{};
  createSdi(true, "test123", sdi);
  EXPECT_EQ(
    0, oc_sec_sdi_encode_with_resource(&sdi, nullptr, OCF_SEC_SDI_DEFAULT_IF));

  auto rep = pool.ParsePayload();
  oc_sec_sdi_t sdi_parsed{};
  EXPECT_TRUE(
    oc_sec_sdi_decode_with_state(rep.get(), OC_DOS_RFOTM, false, &sdi_parsed));

  TestSdi::expectEqual(sdi, sdi_parsed);

  oc_free_string(&sdi_parsed.name);
  oc_free_string(&sdi.name);
}

static constexpr size_t kDeviceID{ 0 };

class TestSdiWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_EQ(0, oc_storage_config(testStorage.c_str()));

    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SEC_SDI, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

    ASSERT_EQ(0, oc_storage_reset());
    for (const auto &entry : std::filesystem::directory_iterator(testStorage)) {
      std::filesystem::remove_all(entry.path());
    }
  }
};

TEST_F(TestSdiWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_SEC_SDI, kDeviceID));
}

TEST_F(TestSdiWithServer, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_SEC_SDI_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_SDI_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_SEC_SDI_URI, oc_string(res->uri));
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestSdiWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    auto *sdi = static_cast<oc_sec_sdi_t *>(data->user_data);
    EXPECT_TRUE(oc_sec_sdi_decode_with_state(data->payload, OC_DOS_RFOTM,
                                             /*from_storage*/ false, sdi));
  };

  auto timeout = 1s;
  oc_sec_sdi_t sdi{};
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_SDI_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &sdi));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  oc_sec_sdi_t *s = oc_sec_sdi_get(kDeviceID);
  ASSERT_NE(nullptr, s);
  TestSdi::expectEqual(*s, sdi);
}

TEST_F(TestSdiWithServer, PostRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    // TODO: fill response in SDI
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_SDI_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  oc_sec_sdi_t sdi_new{};
  TestSdi::createSdi(true, "new sdi name", sdi_new);
  oc_sec_sdi_encode_with_resource(&sdi_new, /*sdi_res*/ nullptr,
                                  static_cast<oc_interface_mask_t>(0));

  auto timeout = 1s;
  EXPECT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);
  TestSdi::expectEqual(*oc_sec_sdi_get(kDeviceID), sdi_new);

  oc_free_string(&sdi_new.name);
}

TEST_F(TestSdiWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto encode_payload = []() {
    oc_sec_sdi_t sdi_new{};
    oc_sec_sdi_encode_with_resource(&sdi_new, /*sdi_res*/ nullptr,
                                    static_cast<oc_interface_mask_t>(0));
  };
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SEC_SDI_URI, encode_payload);
}

TEST_F(TestSdiWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_SEC_SDI_URI);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestSdiWithServer, Copy)
{
  oc_sec_sdi_t sdi1{};
  TestSdi::createSdi(true, "test", sdi1);
  oc_uuid_t uuid = sdi1.uuid;

  oc_sec_sdi_copy(&sdi1, &sdi1);
  EXPECT_TRUE(sdi1.priv);
  EXPECT_TRUE(oc_uuid_is_equal(uuid, sdi1.uuid));
  EXPECT_STREQ("test", oc_string(sdi1.name));

  oc_sec_sdi_t sdi2{};
  oc_sec_sdi_copy(&sdi2, &sdi1);

  EXPECT_EQ(sdi1.priv, sdi2.priv);
  EXPECT_TRUE(oc_uuid_is_equal(sdi1.uuid, sdi2.uuid));
  EXPECT_STREQ(oc_string(sdi1.name), oc_string(sdi2.name));

  oc_sec_sdi_clear(&sdi1);
  EXPECT_NE(sdi1.priv, sdi2.priv);
  EXPECT_FALSE(oc_uuid_is_equal(sdi1.uuid, sdi2.uuid));
  EXPECT_STRNE(oc_string(sdi1.name), oc_string(sdi2.name));

  oc_free_string(&sdi2.name);
  oc_free_string(&sdi1.name);
}

TEST_F(TestSdiWithServer, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_sec_sdi_default(kDeviceID);

  oc_sec_sdi_t def{};
  const oc_sec_sdi_t *sdi = oc_sec_sdi_get(kDeviceID);
  oc_sec_sdi_copy(&def, sdi);

  // overwrite sdi data
  oc_sec_sdi_t sdi_new{};
  TestSdi::createSdi(true, "test", sdi_new);
  oc_sec_sdi_copy(oc_sec_sdi_get(kDeviceID), &sdi_new);

  EXPECT_TRUE(!TestSdi::isEqual(def, *oc_sec_sdi_get(kDeviceID)));

  // load values from storage
  oc_sec_load_sdi(kDeviceID);
  EXPECT_TRUE(TestSdi::isEqual(def, *oc_sec_sdi_get(kDeviceID)));

  oc_free_string(&sdi_new.name);
  oc_free_string(&def.name);
}

#endif /* OC_SECURITY */
