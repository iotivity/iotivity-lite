/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_PKI

#include "oc_pki.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_entropy_internal.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/Role.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include "security/oc_obt_internal.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#include "gtest/gtest.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace oc::pki {

bool PKDummyFunctions::freeKeyInvoked = false;
bool PKDummyFunctions::genKeyInvoked = false;
bool PKDummyFunctions::writeKeyDerInvoked = false;
bool PKDummyFunctions::parseKeyInvoked = false;

std::vector<unsigned char>
ReadPem(const std::string &path)
{
  namespace fs = std::filesystem;

  std::ifstream f(path);
  if (!f.is_open()) {
    return {};
  }
  f.unsetf(std::ios_base::skipws);
  std::vector<unsigned char> data{};
  data.assign((std::istream_iterator<char>(f)), std::istream_iterator<char>());
  data.push_back('\0');
  return data;
}

static std::vector<unsigned char>
GetPEM(std::vector<unsigned char> &data)
{
  auto it =
    std::find(data.begin(), data.end(), static_cast<unsigned char>('\0'));
  if (data.end() == it) {
    return {};
  }
  size_t data_len =
    std::distance(data.begin(), it) + 1; // size with NULL terminator
  if (!oc_certs_is_PEM(&data[0], data_len)) {
    return {};
  }
  data.resize(data_len);
  return data;
}

#if defined(OC_DYNAMIC_ALLOCATION) || defined(OC_TEST)

static constexpr std::string_view kRootSubjectName{ "IoTivity-Lite Test" };
static const std::string kRootSubject{ "C=US, O=OCF, CN=" +
                                       std::string(kRootSubjectName) };
static const std::vector<uint8_t> kPersonalizationString{ 'I', 'o', 'T' };
// 12/31/2029 23:59:59 to seconds since epoch
static constexpr int64_t kNotAfter{ 1893455999 };

std::vector<unsigned char>
GenerateCertificate(const oc_certs_generate_t &generate)
{
  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err = oc_certs_generate(&generate, cert_buf.data(), cert_buf.size());
  EXPECT_EQ(0, err);
  if (err != 0) {
    return {};
  }
  return GetPEM(cert_buf);
}

std::vector<unsigned char>
GenerateRootCertificate(const oc::keypair_t &kp)
{
  oc_certs_generate_t root_cert{};
  root_cert.personalization_string = { kPersonalizationString.data(),
                                       kPersonalizationString.size() };
  root_cert.serial_number_size = 20;
  root_cert.validity.not_before = oc_certs_timestamp_now();
  root_cert.validity.not_after = { kNotAfter, 0, 0 };
  root_cert.subject.name = kRootSubject.c_str();
  root_cert.subject.public_key = { kp.public_key.data(), kp.public_key_size };
  root_cert.subject.private_key = { kp.private_key.data(),
                                    kp.private_key_size };
  root_cert.signature_md = MBEDTLS_MD_SHA256;
  root_cert.is_CA = true;
  return GenerateCertificate(root_cert);
}

std::vector<unsigned char>
GeneratIdentityCertificate(const oc::keypair_t &kp,
                           const oc::keypair_t &issuer_kp)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  std::array<char, 50> subject{};
  if (!oc_certs_encode_CN_with_UUID(&uuid, subject.data(), subject.size())) {
    return {};
  }

  oc_certs_generate_t identity_cert{};
  identity_cert.personalization_string = { kPersonalizationString.data(),
                                           kPersonalizationString.size() };
  identity_cert.serial_number_size = 20;
  identity_cert.validity.not_before = oc_certs_timestamp_now();
  identity_cert.validity.not_after = { kNotAfter, 0, 0 };
  identity_cert.subject.name = subject.data();
  identity_cert.subject.public_key = { kp.public_key.data(),
                                       kp.public_key_size };
  identity_cert.issuer.name = kRootSubject.c_str();
  identity_cert.issuer.private_key = { issuer_kp.private_key.data(),
                                       issuer_kp.private_key_size };
  identity_cert.signature_md = MBEDTLS_MD_SHA256;
  return GenerateCertificate(identity_cert);
}

#endif /* OC_DYNAMIC_ALLOCATION || OC_TEST */

KeyParser::KeyParser()
{
  mbedtls_entropy_init(&entropy_ctx_);
  oc_entropy_add_source(&entropy_ctx_);
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx_);
  std::string pers = "test";
  if (mbedtls_ctr_drbg_seed(
        &ctr_drbg_ctx_, mbedtls_entropy_func, &entropy_ctx_,
        reinterpret_cast<const unsigned char *>(pers.c_str()),
        pers.length()) != 0) {
    throw std::string("failed to initialize entropy function");
  }
}

KeyParser::~KeyParser()
{
  mbedtls_entropy_free(&entropy_ctx_);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx_);
}

std::vector<unsigned char>
KeyParser::GetPrivateKey(const unsigned char *key, size_t keylen)
{
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  if (mbedtls_pk_parse_key(&pk, key, keylen, nullptr, 0,
                           mbedtls_ctr_drbg_random, &ctr_drbg_ctx_) != 0) {
    mbedtls_pk_free(&pk);
    return {};
  }

  std::vector<unsigned char> pem{};
  pem.resize(1024);
  if (mbedtls_pk_write_key_pem(&pk, &pem[0], pem.size()) != 0) {
    mbedtls_pk_free(&pk);
    return {};
  }
  mbedtls_pk_free(&pk);

  return GetPEM(pem);
}

PemData::PemData(const std::string &path)
  : path_{ path }
{
  auto pem = ReadPem(path_);
  if (pem.empty()) {
    throw std::string("failed to read PEM string from file ") + path;
  }
  pem_ = std::move(pem);
}

TrustAnchor::TrustAnchor(const std::string &certificatePath, bool isMfg)
  : certificate_{ certificatePath }
  , isMfg_{ isMfg }
{
}

#ifdef OC_SECURITY

bool
TrustAnchor::Add(size_t device)
{
  if (certificate_.DataSize() == 0) {
    OC_ERR("invalid data");
    return false;
  }
  if (device_ != static_cast<size_t>(-1)) {
    OC_ERR("mfg certificate already assigned to a device");
    return false;
  }

  int credid;
  if (isMfg_) {
    credid = oc_pki_add_mfg_trust_anchor(device, certificate_.Data().data(),
                                         certificate_.DataSize());
  } else {
    credid = oc_pki_add_trust_anchor(device, certificate_.Data().data(),
                                     certificate_.DataSize());
  }
  if (credid < 0) {
    return false;
  }
  device_ = device;
  credid_ = credid;
  return true;
}

#endif /* OC_SECURITY */

IdentityCertificate::IdentityCertificate(const std::string &certificatePath,
                                         const std::string &keyPath, bool isMfg)
  : certificate_{ certificatePath }
  , key_{ keyPath }
  , isMfg_{ isMfg }
{
}

#ifdef OC_SECURITY

bool
IdentityCertificate::Add(size_t device)
{
  if (certificate_.DataSize() == 0 || key_.DataSize() == 0) {
    OC_ERR("invalid data");
    return false;
  }
  if (device_ != static_cast<size_t>(-1)) {
    OC_ERR("mfg certificate already assigned to a device");
    return false;
  }

  int credid;
  if (isMfg_) {
    credid = oc_pki_add_mfg_cert(device, certificate_.Data().data(),
                                 certificate_.DataSize(), key_.Data().data(),
                                 key_.DataSize());
  } else {
    credid = oc_pki_add_identity_cert(device, certificate_.Data().data(),
                                      certificate_.DataSize(),
                                      key_.Data().data(), key_.DataSize());
  }
  if (credid < 0) {
    return false;
  }
  device_ = device;
  credid_ = credid;
  return true;
}

#endif /* OC_SECURITY */

IntermediateCertificate::IntermediateCertificate(
  const std::string &certificatePath)
  : certificate_{ certificatePath }
{
}

#ifdef OC_SECURITY

bool
IntermediateCertificate::Add(size_t device, int entity_credid)
{
  if (certificate_.DataSize() == 0 || entity_credid == -1) {
    OC_ERR("invalid data");
    return false;
  }
  if (device_ != static_cast<size_t>(-1)) {
    OC_ERR("mfg certificate already assigned to a device");
    return false;
  }

  int credid = oc_pki_add_mfg_intermediate_cert(
    device, entity_credid, certificate_.Data().data(), certificate_.DataSize());

  if (credid < 0) {
    return false;
  }

  device_ = device;
  entity_credid_ = entity_credid;
  credid_ = credid;
  return true;
}

#endif /* OC_SECURITY */

void
PKDummyFunctions::Clear()
{
  freeKeyInvoked = false;
  genKeyInvoked = false;
  writeKeyDerInvoked = false;
  parseKeyInvoked = false;
}

oc_pki_pk_functions_t
PKDummyFunctions::GetPKFunctions()
{
  oc_pki_pk_functions_t pk_functions;
  pk_functions.mbedtls_pk_parse_key = ParseKey;
  pk_functions.mbedtls_pk_write_key_der = WriteKeyDer;
  pk_functions.mbedtls_pk_ecp_gen_key = GenKey;
  pk_functions.pk_free_key = FreeKey;
  return pk_functions;
}

#ifdef OC_DYNAMIC_ALLOCATION

namespace obt {

int
GenerateSelfSignedRootCertificate(size_t device,
                                  const std::string &subject_name,
                                  const oc::keypair_t &kp,
                                  mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_root_cert_data_t root_cert_data = {
    /*.subject_name = */ subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.private_key =*/kp.private_key.data(),
    /*.private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };
  return oc_obt_generate_self_signed_root_cert(root_cert_data, device);
}

std::vector<unsigned char>
GenerateSelfSignedRootCertificate(const std::string &subject_name,
                                  const oc::keypair_t &kp,
                                  mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_root_cert_data_t cert_data = {
    /*.subject_name = */ subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.private_key =*/kp.private_key.data(),
    /*.private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };

  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err = oc_obt_generate_self_signed_root_cert_pem(
    cert_data, cert_buf.data(), cert_buf.size());
  EXPECT_EQ(0, err);

  return GetPEM(cert_buf);
}

std::vector<unsigned char>
GenerateIdentityCertificate(const std::string &subject_name,
                            const std::string &issuer_name,
                            const oc::keypair_t &kp, mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_identity_cert_data_t cert_data = {
    /*.subject_name =*/subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.issuer_name =*/issuer_name.c_str(),
    /*.issuer_private_key =*/kp.private_key.data(),
    /*.issuer_private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };

  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err = oc_obt_generate_identity_cert_pem(cert_data, cert_buf.data(),
                                              cert_buf.size());
  EXPECT_EQ(0, err);
  return GetPEM(cert_buf);
}

std::vector<unsigned char>
GenerateRoleCertificate(const std::string &subject_name,
                        const std::string &issuer_name, const oc::keypair_t &kp,
                        const oc::Roles &roles, mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_role_cert_data_t cert_data = {
    /*.roles =*/roles.Head(),
    /*.subject_name =*/subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.issuer_name =*/issuer_name.c_str(),
    /*.issuer_private_key =*/kp.private_key.data(),
    /*.issuer_private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };

  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  int err =
    oc_obt_generate_role_cert_pem(cert_data, cert_buf.data(), cert_buf.size());
  EXPECT_EQ(0, err);
  if (err != 0) {
    return {};
  }
  return GetPEM(cert_buf);
}

} // namespace obt

#endif /* OC_DYNAMIC_ALLOCATION */

} // namespace oc::pki

#endif /* OC_PKI */
