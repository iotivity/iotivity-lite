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

#include "oc_config.h"

#ifdef OC_SECURITY

#include <mbedtls/build_info.h>

#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_TIMING_C)

#include "DTLS.h"
#include "Service.h"

#include <chrono>
#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>
#include <string>
#include <vector>

namespace oc::tls {

class DTLSClient : public MbedTLSService {
public:
  DTLSClient();
  ~DTLSClient();

  DTLSClient(DTLSClient &) = delete;
  DTLSClient &operator=(const DTLSClient &) = delete;
  DTLSClient(DTLSClient &&) noexcept = delete;
  DTLSClient &operator=(DTLSClient &&) = delete;

  // MbedTLSService overrides
  mbedtls_ssl_context *GetSSLContext() override { return &ssl_; };
  mbedtls_net_context *GetNetContext() override { return &serverFd_; };

  int SetPresharedKey(const PreSharedKey &psk, const IdentityHint &hint);

  int Connect(const std::string &host, uint16_t port);
  void CloseNotify();
  int Handshake();

  bool ConnectWithHandshake(const std::string &host, uint16_t port);
  int Run() { return service_.Run(); }
  void Stop() { service_.Stop(); }

private:
  static int ConfPSKCb(void *data, mbedtls_ssl_context *ssl,
                       const unsigned char *identity, size_t identity_len);

  Service service_;
  mbedtls_net_context serverFd_;
  mbedtls_ssl_context ssl_;
  mbedtls_ssl_config config_;
  mbedtls_ctr_drbg_context ctrDrbg_;
  mbedtls_entropy_context entropy_;
  mbedtls_ssl_cookie_ctx cookieCtx_;
  mbedtls_timing_delay_context timer_;

  PreSharedKey psk_{};
  IdentityHint hint_{};
  std::vector<int> ciphers_{};
};

} // namespace  oc::tls

#endif /* MBEDTLS_NET_C && MBEDTLS_TIMING_C */

#endif /* OC_SECURITY */
