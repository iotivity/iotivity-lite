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

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_core_res_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_store.h"
#include "port/oc_log_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_tls_internal.h"
#include "util/oc_macros_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

namespace {

bool
IsEqual(const oc_sec_doxm_t &lhs, const oc_sec_doxm_t &rhs,
        bool ignoreOxms = true)
{
  if (lhs.oxmsel != rhs.oxmsel || lhs.sct != rhs.sct ||
      lhs.owned != rhs.owned ||
      !oc_uuid_is_equal(lhs.deviceuuid, rhs.deviceuuid) ||
      !oc_uuid_is_equal(lhs.devowneruuid, rhs.devowneruuid) ||
      !oc_uuid_is_equal(lhs.rowneruuid, rhs.rowneruuid)) {
    return false;
  }
  if (!ignoreOxms) {
    if (lhs.num_oxms != rhs.num_oxms) {
      return false;
    }
    for (int i = 0; i < std::min<int>(lhs.num_oxms, OC_ARRAY_SIZE(lhs.oxms));
         ++i) {
      if (lhs.oxms[i] != rhs.oxms[i]) {
        return false;
      }
    }
  }
  return true;
}

class Doxm {
public:
  explicit Doxm(size_t device)
    : device_(device)
  {
    const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
    if (doxm == nullptr) {
      throw std::string("Doxm not found");
    }
    memcpy(&doxm_, doxm, sizeof(oc_sec_doxm_t));
  }

  oc_sec_doxm_t *get() const
  {
    oc_sec_doxm_t *doxm = oc_sec_get_doxm(device_);
    if (doxm == nullptr) {
      throw std::string("Doxm not found");
    }
    return doxm;
  }

  bool wasModified() const { return !IsEqual(doxm_, *get()); }

  void updateDeviceUUID() { doxm_.deviceuuid = get()->deviceuuid; }

private:
  oc_sec_doxm_t doxm_{};
  size_t device_{};
};

}

class TestDoxm : public testing::Test {
public:
  void TearDown() override { oc_ownership_status_free_all_cbs(); }
};

TEST_F(TestDoxm, IsDoxmURI_F)
{
  EXPECT_FALSE(oc_sec_is_doxm_resource_uri(OC_STRING_VIEW_NULL));
  EXPECT_FALSE(oc_sec_is_doxm_resource_uri(OC_STRING_VIEW("")));
}

TEST_F(TestDoxm, IsDoxmURI_P)
{
  std::string uri = OCF_SEC_DOXM_URI;
  EXPECT_TRUE(
    oc_sec_is_doxm_resource_uri(oc_string_view(uri.c_str(), uri.length())));
  uri = uri.substr(1, uri.length() - 1);
  EXPECT_TRUE(
    oc_sec_is_doxm_resource_uri(oc_string_view(uri.c_str(), uri.length())));
}

TEST_F(TestDoxm, OwnershipStatus)
{
  auto cb1 = [](const oc_uuid_t *, size_t, bool, void *) {
    // no-op
  };
  bool cb1_data{};

  auto cb2 = [](const oc_uuid_t *, size_t, bool, void *) {
    // no-op
  };
  bool cb2_data{};

  oc_add_ownership_status_cb(cb1, &cb1_data);
  EXPECT_NE(nullptr, oc_ownership_status_get_cb(cb1, &cb1_data));

  EXPECT_EQ(nullptr, oc_ownership_status_get_cb(cb1, &cb2_data));
  EXPECT_EQ(nullptr, oc_ownership_status_get_cb(cb2, &cb1_data));
  EXPECT_EQ(nullptr, oc_ownership_status_get_cb(cb2, &cb2_data));

  oc_remove_ownership_status_cb(cb1, &cb1_data);
  EXPECT_EQ(nullptr, oc_ownership_status_get_cb(cb1, &cb1_data));

  oc_remove_ownership_status_cb(cb1, &cb1_data);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestDoxm, AddOwnershipStatus_Fail)
{
  auto dummyCb = [](const oc_uuid_t *, size_t, bool, void *) {
    // no-op
  };
  for (int i = 0; i < OC_MAX_DOXM_OWNED_CBS; ++i) {
    EXPECT_EQ(0, oc_add_ownership_status_cb_v1(dummyCb, nullptr));
  }
  EXPECT_EQ(-1, oc_add_ownership_status_cb_v1(dummyCb, nullptr));
}

#endif /* !OC_DYNAMIC_ALLOCATION */

static constexpr size_t kDeviceID{ 0 };

class TestDoxmWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Config());
#endif // OC_STORAGE

    ASSERT_TRUE(oc::TestDevice::StartServer());
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Clear());
#endif // OC_STORAGE
  }

  void SetUp() override
  {
#ifdef OC_TEST
    oc_test_set_doxm_separate_response_delay_ms(0);
#endif /* OC_TEST */
    oc_sec_doxm_default(kDeviceID);
  }

  void TearDown() override
  {
    oc_set_select_oxms_cb(nullptr, nullptr);
    oc_set_random_pin_callback(nullptr, nullptr);
    oc_ownership_status_free_all_cbs();
    oc::TestDevice::DropOutgoingMessages();
    coap_free_all_transactions();
    oc_client_cbs_shutdown_multicasts();
    oc_client_cbs_shutdown();
  }
};

TEST_F(TestDoxmWithServer, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_index(OCF_SEC_DOXM, /*device*/
                                                   SIZE_MAX));
}

TEST_F(TestDoxmWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID));
}

TEST_F(TestDoxmWithServer, GetResourceByURI_F)
{
  EXPECT_EQ(nullptr, oc_core_get_resource_by_uri_v1(
                       OCF_SEC_DOXM_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_DOXM_URI),
                       /*device*/ SIZE_MAX));
}

TEST_F(TestDoxmWithServer, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OCF_SEC_DOXM_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_DOXM_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OCF_SEC_DOXM_URI, oc_string(res->uri));
}

TEST_F(TestDoxmWithServer, DumpAndLoad)
{
  // load default values and dump them to storage
  oc_sec_doxm_default(kDeviceID);

  oc_sec_doxm_t def{};
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(kDeviceID);
  ASSERT_NE(nullptr, doxm);
  memcpy(&def, doxm, sizeof(oc_sec_doxm_t));
  // overwrite doxm data with 0
  memset(doxm, 0, sizeof(oc_sec_doxm_t));

  EXPECT_FALSE(IsEqual(def, *oc_sec_get_doxm(kDeviceID)));

  // load values from storage
  oc_sec_load_doxm(kDeviceID);
  EXPECT_TRUE(IsEqual(def, *oc_sec_get_doxm(kDeviceID)));
}

TEST_F(TestDoxmWithServer, Decode_FailBaselinePropertyNotFromStorage)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, n, "plgd.dev test");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  EXPECT_FALSE(doxm.wasModified());
}

// bool property:
//   - owned
// preconditions (not from storage):
//   - owned: device must be in RFOTM state, connection is DOC

TEST_F(TestDoxmWithServer, Decode_FailInvalidBoolProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, plgd, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  EXPECT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailInvalidOwnedValueType)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, owned, "plgd.dev");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailInvalidOwnedState)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, owned, false);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  // device is not in RFOTM state
  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));
  oc_sec_self_disown(kDeviceID);
  // oc_sec_doxm_default in oc_sec_self_disown regenerates device UUID
  doxm.updateDeviceUUID();

  // Device Onboarding Connection (doc) must be true
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, SetOwned)
{
  struct ownerShipStatus
  {
    bool owned;
    bool invoked;
  };
  ownerShipStatus status{};
  oc_add_ownership_status_cb_v1(
    [](const oc_uuid_t *, size_t device_index, bool owned, void *user_data) {
      EXPECT_EQ(kDeviceID, device_index);
      static_cast<ownerShipStatus *>(user_data)->owned = owned;
      static_cast<ownerShipStatus *>(user_data)->invoked = true;
    },
    &status);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, owned, true);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ true, kDeviceID));
  EXPECT_TRUE(doxm.wasModified());
  EXPECT_TRUE(status.invoked);
  EXPECT_TRUE(status.owned);

  // oc_sec_doxm_default resets owned to false and it should invoked the
  // ownership status callback
  doxm = Doxm{ kDeviceID };
  status = {};
  oc_sec_doxm_default(kDeviceID);
  EXPECT_TRUE(doxm.wasModified());
  EXPECT_TRUE(status.invoked);
  EXPECT_FALSE(status.owned);
}

// int properties:
//   - oxmsel
//   - sct
// preconditions (not from storage):
//   - oxmsel: device must be in RFOTM state, connection is not DOC
//   - sct: not modifiable

TEST_F(TestDoxmWithServer, Decode_FailInvalidIntProperty)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, plgd, 42);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailInvalidOxmselValueType)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, oxmsel, "plgd");
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  Doxm doxm{ kDeviceID };
  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailInvalidOxmselState)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, OC_OXMTYPE_JW);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  // device is not in RFOTM state
  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));
  oc_sec_self_disown(kDeviceID);
  // oc_sec_doxm_default in oc_sec_self_disown regenerates device UUID
  doxm.updateDeviceUUID();

  // Device Onboarding Connection (DOC) must be false
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailInvalidOxmselValue)
{
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, INT_MAX);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailSctNotFromStorage)
{
  Doxm doxm{ kDeviceID };
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, sct, 42);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, SelectJustWorks)
{
  auto justWorksSelectedCb = [](size_t device_index, int *oxms, int *num_oxms,
                                void *user_data) {
    EXPECT_EQ(kDeviceID, device_index);
    EXPECT_EQ(1, *num_oxms);
    EXPECT_EQ(OC_OXMTYPE_JW, oxms[0]);
    EXPECT_EQ(-1, oxms[1]);
    EXPECT_EQ(-1, oxms[2]);
    *static_cast<bool *>(user_data) = true;
  };

  bool cbInvoked = false;
  oc_set_select_oxms_cb(justWorksSelectedCb, &cbInvoked);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, OC_OXMTYPE_JW);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ false, kDeviceID));
  EXPECT_TRUE(cbInvoked);
  EXPECT_TRUE(doxm.wasModified());
  EXPECT_EQ(OC_OXMTYPE_JW, oc_sec_get_doxm(kDeviceID)->oxmsel);
}

TEST_F(TestDoxmWithServer, SelectRandomPin)
{
  auto randomPinSelectedCb = [](size_t device_index, int *oxms, int *num_oxms,
                                void *user_data) {
    EXPECT_EQ(kDeviceID, device_index);
    EXPECT_EQ(2, *num_oxms);
    EXPECT_EQ(OC_OXMTYPE_JW, oxms[0]);
    EXPECT_EQ(OC_OXMTYPE_RDP, oxms[1]);
    EXPECT_EQ(-1, oxms[2]);
    *static_cast<bool *>(user_data) = true;
  };
  bool pinSelectedInvoked = false;
  oc_set_select_oxms_cb(randomPinSelectedCb, &pinSelectedInvoked);

  auto randomPinCallback = [](const unsigned char *, size_t, void *user_data) {
    *static_cast<bool *>(user_data) = true;
  };
  bool pinGenerated = false;
  oc_set_random_pin_callback(randomPinCallback, &pinGenerated);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, OC_OXMTYPE_RDP);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ false, kDeviceID));
  EXPECT_TRUE(pinSelectedInvoked);
  EXPECT_TRUE(pinGenerated);
  EXPECT_TRUE(doxm.wasModified());
  EXPECT_EQ(OC_OXMTYPE_RDP, oc_sec_get_doxm(kDeviceID)->oxmsel);
}

#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)

// parsing of the mfg certificates aborts without dynamic allocation fails
TEST_F(TestDoxmWithServer, SelectCertOTM)
{
  auto certOTMSelectedCb = [](size_t device_index, int *oxms, int *num_oxms,
                              void *user_data) {
    EXPECT_EQ(kDeviceID, device_index);
    EXPECT_EQ(2, *num_oxms);
    EXPECT_EQ(OC_OXMTYPE_JW, oxms[0]);
    EXPECT_EQ(OC_OXMTYPE_MFG_CERT, oxms[1]);
    EXPECT_EQ(-1, oxms[2]);
    *static_cast<bool *>(user_data) = true;
  };
  bool cbInvoked = false;
  oc_set_select_oxms_cb(certOTMSelectedCb, &cbInvoked);

  oc::pki::IdentityCertificate mfgcert{ "pki_certs/ee.pem", "pki_certs/key.pem",
                                        true };
  ASSERT_TRUE(mfgcert.Add(kDeviceID));

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, OC_OXMTYPE_MFG_CERT);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ false, kDeviceID));
  EXPECT_TRUE(cbInvoked);
  EXPECT_TRUE(doxm.wasModified());
  EXPECT_EQ(OC_OXMTYPE_MFG_CERT, oc_sec_get_doxm(kDeviceID)->oxmsel);

  oc_sec_cred_clear(kDeviceID, nullptr, nullptr);
}

#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */

// string properties:
//   - deviceuuid
//   - devowneruuid
//   - rowneruuid
// preconditions (not from storage):
//   - deviceuuid: device must be in RFOTM state, connection is DOC
//   - devowneruuid: device must be in RFOTM state, connection is DOC
//   - rowneruuid: device must be in RFOTM or SRESET state, connection is DOC

static std::array<char, OC_UUID_LEN>
genUUID(const oc_uuid_t *uuid = nullptr)
{
  oc_uuid_t uuid_new{};
  do {
    oc_gen_uuid(&uuid_new);
  } while (uuid != nullptr && oc_uuid_is_equal(*uuid, uuid_new));
  std::array<char, OC_UUID_LEN> uuid_buf{};
  oc_uuid_to_str(&uuid_new, uuid_buf.data(), uuid_buf.size());
  return uuid_buf;
}

TEST_F(TestDoxmWithServer, Decode_FailDeviceUUIDNotDOC)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, deviceuuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailDeviceUUIDNotRFOTM)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, deviceuuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  // device is not in RFOTM state
  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));
  oc_sec_self_disown(kDeviceID);
  // oc_sec_doxm_default in oc_sec_self_disown regenerates device UUID
  doxm.updateDeviceUUID();

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_DeviceUUID)
{
  Doxm doxm{ kDeviceID };
  auto uuid_buf = genUUID(&doxm.get()->deviceuuid);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, deviceuuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ true, kDeviceID));

  ASSERT_TRUE(doxm.wasModified());
  std::array<char, OC_UUID_LEN> uuid2_buf{};
  oc_uuid_to_str(&doxm.get()->deviceuuid, uuid2_buf.data(), uuid2_buf.size());
  EXPECT_STREQ(uuid_buf.data(), uuid2_buf.data());
}

TEST_F(TestDoxmWithServer, Decode_FailDeviceOwnerUUIDNotDOC)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, devowneruuid, uuid_buf.data(),
                            uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailDeviceOwnerUUIDNotRFOTM)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, devowneruuid, uuid_buf.data(),
                            uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  // device is not in RFOTM state
  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));
  oc_sec_self_disown(kDeviceID);
  // oc_sec_doxm_default in oc_sec_self_disown regenerates device UUID
  doxm.updateDeviceUUID();

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_DeviceOwnerUUID)
{
  Doxm doxm{ kDeviceID };
  auto uuid_buf = genUUID(&doxm.get()->devowneruuid);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, devowneruuid, uuid_buf.data(),
                            uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ true, kDeviceID));

  ASSERT_TRUE(doxm.wasModified());
  std::array<char, OC_UUID_LEN> uuid2_buf{};
  oc_uuid_to_str(&doxm.get()->devowneruuid, uuid2_buf.data(), uuid2_buf.size());
  EXPECT_STREQ(uuid_buf.data(), uuid2_buf.data());
}

TEST_F(TestDoxmWithServer, Decode_FailResourceOwnerUUIDNotDOC)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, rowneruuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ false, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailResourceOwnerUUIDNotRFOTM)
{
  auto uuid_buf = genUUID();

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, rowneruuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  Doxm doxm{ kDeviceID };
  // device is not in RFOTM or SRESET state
  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));
  oc_sec_self_disown(kDeviceID);
  // oc_sec_doxm_default in oc_sec_self_disown regenerates device UUID
  doxm.updateDeviceUUID();

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_ResourceOwnerUUID)
{
  Doxm doxm{ kDeviceID };
  auto uuid_buf = genUUID(&doxm.get()->devowneruuid);

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, rowneruuid, uuid_buf.data(), uuid_buf.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_TRUE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                 /*doc*/ true, kDeviceID));

  ASSERT_TRUE(doxm.wasModified());
  std::array<char, OC_UUID_LEN> uuid2_buf{};
  oc_uuid_to_str(&doxm.get()->rowneruuid, uuid2_buf.data(), uuid2_buf.size());
  EXPECT_STREQ(uuid_buf.data(), uuid2_buf.data());
}

// int array properties:
//   - oxms
// preconditions (not from storage):
//   - oxms: not modifiable

TEST_F(TestDoxmWithServer, Decode_FailUnknownIntArrayProperty)
{
  Doxm doxm{ kDeviceID };
  oc::RepPool pool{};
  oc_rep_start_root_object();
  std::array<int, 2> arr{ 42, 1337 };
  oc_rep_set_int_array(root, plgd, arr.data(), arr.size());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ true,
                                  /*doc*/ true, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, Decode_FailOxmsNotFromStorage)
{
  Doxm doxm{ kDeviceID };
  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_int_array(root, oxms, doxm.get()->oxms, doxm.get()->num_oxms);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

// there is no double array property in doxm
TEST_F(TestDoxmWithServer, Decode_FailInvalidPropertyType)
{
  Doxm doxm{ kDeviceID };
  oc::RepPool pool{};
  oc_rep_start_root_object();
  std::vector<double> math_constants = { 3.14159, 2.71828 };
  oc_rep_open_array(root, math_constants);
  for (const auto &v : math_constants) {
    oc_rep_add_double(math_constants, v);
  }
  oc_rep_close_array(root, math_constants);
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto rep = pool.ParsePayload();
  EXPECT_FALSE(oc_sec_decode_doxm(rep.get(), /*from_storage*/ false,
                                  /*doc*/ true, kDeviceID));

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_DOXM_URI, &ep, nullptr,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

template<oc_status_t CODE>
static void
getRequestFail(const char *query)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(CODE, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_DOXM_URI, &ep, query,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestDoxmWithServer, GetRequest_InvalidOwned)
{
  // same length as "true"
  getRequestFail<OC_STATUS_BAD_REQUEST>("owned=tttt");

  // same length as "false"
  getRequestFail<OC_STATUS_BAD_REQUEST>("owned=fffff");

  getRequestFail<OC_STATUS_BAD_REQUEST>("owned");

  getRequestFail<OC_STATUS_BAD_REQUEST>("owned=longlongerlongest");
}

TEST_F(TestDoxmWithServer, GetRequest_FailNonMatchingOwned)
{
  getRequestFail<OC_STATUS_BAD_REQUEST>("owned=true");

  oc_sec_get_doxm(kDeviceID)->owned = true;
  getRequestFail<OC_STATUS_BAD_REQUEST>("owned=false");
}

#ifdef OC_CLIENT

TEST_F(TestDoxmWithServer, GetRequestByMulticast)
{
  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  ASSERT_FALSE(oc_is_owned_device(kDeviceID));
  bool invoked = false;
  ASSERT_TRUE(
    oc_do_ip_multicast(OCF_SEC_DOXM_URI, "owned=false", get_handler, &invoked));
  oc::TestDevice::PoolEventsMsV1(1s, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestDoxmWithServer, GetRequestByMulticast_IgnoreNonMatching)
{
  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  ASSERT_FALSE(oc_is_owned_device(kDeviceID));
  bool invoked = false;
  ASSERT_TRUE(
    oc_do_ip_multicast(OCF_SEC_DOXM_URI, "owned=true", get_handler, &invoked));
  oc::TestDevice::PoolEventsMsV1(200ms);
  EXPECT_FALSE(invoked);
}

#if defined(OC_TEST) && defined(OC_DYNAMIC_ALLOCATION) &&                      \
  !defined(OC_INOUT_BUFFER_POOL)

// Sending multiple GET requests to the same device in a short time period
// should result in requests being ignored if there is a separate response
// already pending.
//
// We need dynamic allocation, to be able to allocate sufficient number of
// oc_client_cb_t instances needed for multiple multicast requests.
TEST_F(TestDoxmWithServer, GetRequestByMulticastRepeated)
{
  auto delay = 300ms;
  // make the pending period long enough so multiple get requests can be sent
  oc_test_set_doxm_separate_response_delay_ms(delay.count());

  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    (*static_cast<int *>(data->user_data))++;
  };
  int invoked = 0;
  for (int i = 0; i < 3; ++i) {
    ASSERT_TRUE(
      oc_do_ip_multicast(OCF_SEC_DOXM_URI, nullptr, get_handler, &invoked))
      << "failed send multicast request(" << i << ")";
  }
  oc::TestDevice::PoolEventsMsV1(delay + 200ms);
  EXPECT_EQ(1, invoked);
}

#endif /* OC_TEST && OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_POOL */

TEST_F(TestDoxmWithServer, PostRequest_FailNotDOC)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_BAD_REQUEST, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };
  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_DOXM_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, owned, false);
  oc_rep_end_root_object();

  Doxm doxm{ kDeviceID };
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);

  ASSERT_FALSE(doxm.wasModified());
}

TEST_F(TestDoxmWithServer, PostRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };
  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_DOXM_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  oc_rep_start_root_object();
  oc_rep_set_int(root, oxmsel, OC_OXMTYPE_JW);
  oc_rep_end_root_object();

  auto timeout = 1s;
  EXPECT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);
}

#endif /* OC_CLIENT */

TEST_F(TestDoxmWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SEC_DOXM_URI, nullptr,
                             OC_STATUS_METHOD_NOT_ALLOWED);
}

TEST_F(TestDoxmWithServer, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_SEC_DOXM_URI, nullptr,
                             OC_STATUS_METHOD_NOT_ALLOWED);
}

TEST_F(TestDoxmWithServer, Owned)
{
  ASSERT_FALSE(oc_is_owned_device(kDeviceID));

  ASSERT_EQ(0, oc_sec_self_own(kDeviceID));
  EXPECT_TRUE(oc_is_owned_device(kDeviceID));

  oc_sec_self_disown(kDeviceID);
  ASSERT_FALSE(oc_is_owned_device(kDeviceID));
}

TEST_F(TestDoxmWithServer, Owned_F)
{
  // invalid device index
  EXPECT_FALSE(oc_is_owned_device(42));

#ifdef OC_DYNAMIC_ALLOCATION
  // doxm data not allocated
  oc_sec_doxm_free();

  EXPECT_FALSE(oc_is_owned_device(kDeviceID));

  // restore
  oc_sec_doxm_init();
#endif /* OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_SECURITY */
