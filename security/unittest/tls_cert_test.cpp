/******************************************************************
 *
 * Copyright (c) 2022 Daniel Adam
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2018 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#if defined(OC_SECURITY) && defined(OC_PKI)

#ifdef OC_DYNAMIC_ALLOCATION // need bigger OC_BYTES_POOL_SIZE for this test to
                             // pass

#include "gtest/gtest.h"

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_cred_internal.h"
#include "oc_pki.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_tls.h"

#include <array>
#include <cstdio>
#include <ctime>
#include <string>
#include <stdexcept>
#include <vector>

class Certificate {
public:
  Certificate() = default;

  bool Load(const std::string &path);

  static long ReadPemFile(std::string &file_path, char *buffer,
                          size_t buffer_size);

  std::string path_{};
  char data_[8192]{};
  size_t dataLen_{ 0 };
};

bool
Certificate::Load(const std::string &path)
{
  path_ = path;
  dataLen_ = 0;
  long ret = Certificate::ReadPemFile(path_, data_, sizeof(data_));
  if (ret < 0) {
    return false;
  }
  dataLen_ = static_cast<size_t>(ret);
  return true;
}

long
Certificate::ReadPemFile(std::string &file_path, char *buffer,
                         size_t buffer_size)
{
  FILE *fp = fopen(file_path.c_str(), "r");
  if (fp == nullptr) {
    printf("%s:%d\n", __func__, __LINE__);
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    printf("%s:%d\n", __func__, __LINE__);
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    printf("%s:%d\n", __func__, __LINE__);
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)buffer_size) {
    printf("%s:%d\n", __func__, __LINE__);
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    printf("%s:%d\n", __func__, __LINE__);
    fclose(fp);
    return -1;
  }
  auto to_read = static_cast<size_t>(pem_len);
  if (fread(buffer, 1, to_read, fp) < to_read) {
    printf("%s:%d\n", __func__, __LINE__);
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  return pem_len;
}

class CertificateKey {
public:
  CertificateKey() = default;

  bool Load(const std::string &path);

  std::string path_{};
  char data_[4096]{};
  size_t dataLen_{ 0 };
};

bool
CertificateKey::Load(const std::string &path)
{
  path_ = path;
  dataLen_ = 0;
  long ret = Certificate::ReadPemFile(path_, data_, sizeof(data_));
  if (ret < 0) {
    return false;
  }
  dataLen_ = static_cast<size_t>(ret);
  return true;
}

class IdentityCertificate {
public:
  IdentityCertificate() = default;

  bool Add(size_t device);
  bool Load(const std::string &certificatePath, const std::string &keyPath);
  bool LoadAndAdd(const std::string &certificatePath,
                  const std::string &keyPath, size_t device);

  int credid_{ -1 };
  Certificate cert_;
  CertificateKey key_;
};

bool
IdentityCertificate::Load(const std::string &certificatePath,
                          const std::string &keyPath)
{
  return cert_.Load(certificatePath) && key_.Load(keyPath);
}

bool
IdentityCertificate::Add(size_t device)
{
  if (cert_.dataLen_ == 0 || key_.dataLen_ == 0) {
    return false;
  }
  if (credid_ != -1) {
    return false;
  }

  int credid = oc_pki_add_mfg_cert(
    device, reinterpret_cast<const unsigned char *>(cert_.data_),
    cert_.dataLen_, reinterpret_cast<const unsigned char *>(key_.data_),
    key_.dataLen_);
  if (credid < 0) {
    return false;
  }
  credid_ = credid;
  return true;
}

bool
IdentityCertificate::LoadAndAdd(const std::string &certificatePath,
                                const std::string &keyPath, size_t device)
{
  if (!cert_.Load(certificatePath) || !key_.Load(keyPath)) {
    return false;
  }
  return Add(device);
}

class IntermediateCertificate {
public:
  IntermediateCertificate() = default;

  bool Add(size_t device, int entity_credid);
  bool Load(const std::string &path);
  bool LoadAndAdd(const std::string &path, size_t device, int entity_credid);

  int credid_{ -1 };
  Certificate cert_;
};

bool
IntermediateCertificate::Add(size_t device, int entity_credid)
{
  if (cert_.dataLen_ == 0) {
    return false;
  }
  if (credid_ != -1) {
    return false;
  }
  if (entity_credid == -1) {
    return false;
  }

  int credid = oc_pki_add_mfg_intermediate_cert(
    device, entity_credid, reinterpret_cast<const unsigned char *>(cert_.data_),
    cert_.dataLen_);
  if (credid < 0) {
    return false;
  }
  credid_ = credid;
  return true;
}

bool
IntermediateCertificate::Load(const std::string &path)
{
  return cert_.Load(path);
}

bool
IntermediateCertificate::LoadAndAdd(const std::string &path, size_t device,
                                    int entity_credid)
{
  if (!cert_.Load(path)) {
    return false;
  }
  return Add(device, entity_credid);
}

class TrustAnchor {
public:
  TrustAnchor() = default;

  bool Add(size_t device);
  bool Load(const std::string &path);
  bool LoadAndAdd(const std::string &path, size_t device);

  int credid_{ -1 };
  Certificate cert_;
};

bool
TrustAnchor::Add(size_t device)
{
  if (cert_.dataLen_ == 0) {
    return false;
  }
  if (credid_ != -1) {
    return false;
  }

  int credid = oc_pki_add_mfg_trust_anchor(
    device, reinterpret_cast<const unsigned char *>(cert_.data_),
    cert_.dataLen_);
  if (credid < 0) {
    return false;
  }
  credid_ = credid;
  return true;
}

bool
TrustAnchor::Load(const std::string &path)
{
  return cert_.Load(path);
}

bool
TrustAnchor::LoadAndAdd(const std::string &path, size_t device)
{
  if (!cert_.Load(path)) {
    return false;
  }
  return Add(device);
}

class TestTlsCertificates : public testing::Test {
protected:
  void SetUp() override
  {
    oc_core_init();
    oc_random_init();
    oc_network_event_handler_mutex_init();
    oc_tls_init_context();
    oc_device_info_t *info =
      oc_core_add_new_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                             "ocf.res.1.0.0", nullptr, nullptr);
    EXPECT_NE(nullptr, info);
    oc_sec_cred_init();

    EXPECT_EQ(1, oc_core_get_num_devices());
    device_ = oc_core_get_num_devices() - 1;
    EXPECT_GE(device_, 0);
    EXPECT_TRUE(
      idcert1_.LoadAndAdd("pki_certs/ee.pem", "pki_certs/key.pem", device_));
    EXPECT_TRUE(
      subca1_.LoadAndAdd("pki_certs/subca1.pem", device_, idcert1_.credid_));
    EXPECT_EQ(idcert1_.credid_, subca1_.credid_);
    EXPECT_TRUE(idcert2_.LoadAndAdd("pki_certs/certification_tests_ee.pem",
                                    "pki_certs/certification_tests_key.pem",
                                    device_));
    EXPECT_TRUE(rootca1_.LoadAndAdd("pki_certs/rootca1.pem", device_));
    EXPECT_TRUE(rootca2_.LoadAndAdd("pki_certs/rootca2.pem", device_));
  }

  void TearDown() override
  {
    oc_connectivity_shutdown(device_);
    oc_network_event_handler_mutex_destroy();
    oc_sec_cred_free();
    oc_tls_shutdown();
    oc_random_destroy();
    oc_core_shutdown();
  }

  int device_{ -1 };
  IdentityCertificate idcert1_;
  IdentityCertificate idcert2_;
  IntermediateCertificate subca1_;
  TrustAnchor rootca1_;
  TrustAnchor rootca2_;

public:
  static time_t now_;
};

time_t TestTlsCertificates::now_{ time(nullptr) };

static size_t
oc_sec_cred_count(size_t device)
{
  size_t count = 0;
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  const oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (c != nullptr) {
    ++count;
    c = c->next;
  }
  return count;
}

TEST_F(TestTlsCertificates, ClearCertificates)
{
  // 4 = 2 root certificates + 2 mfg certs
  EXPECT_EQ(4, oc_sec_cred_count(device_));

  oc_sec_cred_clear(
    device_, [](const oc_sec_cred_t *, void *) { return false; }, nullptr);
  EXPECT_EQ(4, oc_sec_cred_count(device_));

  EXPECT_NE(nullptr, oc_sec_get_cred_by_credid(idcert1_.credid_, device_));
  oc_sec_cred_clear(
    device_,
    [](const oc_sec_cred_t *cred, void *data) {
      const auto *cert = static_cast<IdentityCertificate *>(data);
      return cred->credid == cert->credid_;
    },
    &idcert1_);
  EXPECT_EQ(3, oc_sec_cred_count(device_));
  EXPECT_EQ(nullptr, oc_sec_get_cred_by_credid(idcert1_.credid_, device_));

#ifdef OC_PKI
  EXPECT_NE(nullptr, oc_sec_get_cred_by_credid(idcert2_.credid_, device_));
  auto removeMfgCert = [](const oc_sec_cred_t *cred, void *) {
    return cred->credtype == OC_CREDTYPE_CERT &&
           cred->credusage == OC_CREDUSAGE_MFG_CERT;
  };
  oc_sec_cred_clear(device_, removeMfgCert, nullptr);
  EXPECT_EQ(2, oc_sec_cred_count(device_));
  EXPECT_EQ(nullptr, oc_sec_get_cred_by_credid(idcert2_.credid_, device_));
#endif /* OC_PKI */

  oc_sec_cred_clear(device_, nullptr, nullptr);
  EXPECT_EQ(0, oc_sec_cred_count(device_));
}

#ifdef OC_TEST

TEST_F(TestTlsCertificates, RemoveIdentityCertificates)
{
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(idcert1_.credid_, device_));
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(idcert2_.credid_, device_));
  EXPECT_TRUE(oc_tls_validate_identity_certs_consistency());
}

TEST_F(TestTlsCertificates, RemoveTrustAnchors)
{
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(rootca1_.credid_, device_));
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(rootca2_.credid_, device_));
  EXPECT_TRUE(oc_tls_validate_trust_anchors_consistency());
}

#endif /* OC_TEST */

TEST_F(TestTlsCertificates, VerifyCredCerts)
{
  auto verify_cert_validity = [](const oc_sec_certs_data_t *data,
                                 void *) -> bool {
    return (time_t)data->valid_from <= TestTlsCertificates::now_ &&
           (time_t)data->valid_to > TestTlsCertificates::now_;
  };

  oc_sec_cred_t invalid{};
  EXPECT_EQ((size_t)-1, oc_cred_verify_certificate_chain(
                          &invalid, verify_cert_validity, nullptr));

  // valid - rootca1_ valid_from: 30.11.2018, valid_to: 27.11.2028
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(rootca1_.credid_, device_);
  EXPECT_NE(nullptr, cred);
  EXPECT_EQ(
    0, oc_cred_verify_certificate_chain(cred, verify_cert_validity, nullptr));

  // expired - idcert1_ valid_from: 14.4.2020, valid_to: 14.5.2020
  cred = oc_sec_get_cred_by_credid(idcert1_.credid_, device_);
  EXPECT_NE(nullptr, cred);
  EXPECT_EQ(
    1, oc_cred_verify_certificate_chain(cred, verify_cert_validity, nullptr));
}

#endif /* OC_DYNAMIC_ALLOCATION */
#endif /* OC_SECURITY && OC_PKI */
