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

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_TIMING_C)

#include "port/oc_connectivity.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <atomic>
#include <functional>
#include <stddef.h>
#include <stdint.h>

namespace oc::tls {

class MbedTLSService {
public:
  virtual mbedtls_ssl_context *GetSSLContext() = 0;
  virtual mbedtls_net_context *GetNetContext() = 0;
};

using Data = std::vector<unsigned char>;

using OnRead = std::function<void(Data &&)>;

class Service {
public:
  Service(MbedTLSService *mbedtlsCtx, OnRead onRead);
  ~Service();

  long WriteData(const uint8_t *data, size_t dataSize);
  int Run();
  void Stop();

private:
  int Poll();
  void ReadData();

  MbedTLSService *mbedtlsCtx_;
  OnRead onRead_;
  std::atomic<bool> terminate_{ false };
};

} // namespace oc::tls

#endif /* MBEDTLS_NET_C && MBEDTLS_TIMING_C */

#endif /* OC_SECURITY */