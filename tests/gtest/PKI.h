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

#pragma once

#ifdef OC_PKI

#include <string>
#include <vector>

namespace oc::pki {

std::vector<unsigned char> ReadPem(const std::string &path);

class PemData {
public:
  PemData(const std::string &path);

  const std::string &Path() const { return path_; }
  const std::vector<unsigned char> &Data() const { return pem_; }
  size_t DataSize() const { return pem_.size(); }

private:
  std::string path_{};
  std::vector<unsigned char> pem_{};
};

class TrustAnchor {
public:
  TrustAnchor(const std::string &certificatePath, bool isMfg = false);

  bool Add(size_t device);

  bool IsMfg() const { return isMfg_; }
  int CredentialID() const { return credid_; }
  size_t Device() const { return device_; }

private:
  PemData certificate_;
  int credid_{ -1 };
  size_t device_{ static_cast<size_t>(-1) };
  bool isMfg_{ false };
};

class IdentityCertificate {
public:
  IdentityCertificate(const std::string &certificatePath,
                      const std::string &keyPath, bool isMfg = false);

  bool Add(size_t device);

  bool IsMfg() const { return isMfg_; }
  int CredentialID() const { return credid_; }
  size_t Device() const { return device_; }

private:
  PemData certificate_;
  PemData key_;
  int credid_{ -1 };
  size_t device_{ static_cast<size_t>(-1) };
  bool isMfg_{ false };
};

class IntermediateCertificate {
public:
  IntermediateCertificate(const std::string &certificatePath);

  bool Add(size_t device, int entity_credid);

  int CredentialID() const { return credid_; }
  int EntityCredentialID() const { return entity_credid_; }
  size_t Device() const { return device_; }

private:
  PemData certificate_;
  int entity_credid_{ -1 };
  int credid_{ -1 };
  size_t device_{ static_cast<size_t>(-1) };
};
} // namespace oc::pki

#endif /* OC_PKI */
