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

#include "PKI.h"
#include "oc_pki.h"
#include "port/oc_log_internal.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

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

IdentityCertificate::IdentityCertificate(const std::string &certificatePath,
                                         const std::string &keyPath, bool isMfg)
  : certificate_{ certificatePath }
  , key_{ keyPath }
  , isMfg_{ isMfg }
{
}

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

IntermediateCertificate::IntermediateCertificate(
  const std::string &certificatePath)
  : certificate_{ certificatePath }
{
}

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

} // namespace oc::pki

#endif /* OC_PKI */
