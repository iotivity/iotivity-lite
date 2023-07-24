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

#include "oc_config.h"

#ifdef OC_SECURITY

#include <mbedtls/build_info.h>

#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_TIMING_C)

#include "Service.h"

#include "api/oc_message_internal.h"
#include "oc_buffer.h"
#include "port/oc_log_internal.h"

namespace oc::tls {

Service::Service(MbedTLSService *mbedtlsCtx, OnRead onRead)
  : mbedtlsCtx_{ mbedtlsCtx }
  , onRead_{ onRead }
{
}

Service::~Service() {}

int
Service::Poll()
{
  return mbedtls_net_poll(mbedtlsCtx_->GetNetContext(), MBEDTLS_NET_POLL_READ,
                          /*timeout*/ -1);
}

void
Service::ReadData()
{
  std::vector<uint8_t> data{};
  data.resize(oc_message_buffer_size());
  long ret;
  do {
    ret = mbedtls_ssl_read(mbedtlsCtx_->GetSSLContext(), &data[0], data.size());
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret <= 0) {
    switch (ret) {
    case MBEDTLS_ERR_SSL_TIMEOUT:
      OC_DBG("SSL timeout");
      return;

    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      OC_DBG("connection was closed gracefully");
      terminate_.store(true);
      return;

    default:
      OC_DBG("Read returned -0x%x", (unsigned int)-ret);
      return;
    }
  }

  if (onRead_) {
    onRead_(std::move(data));
  }
}

long
Service::WriteData(const uint8_t *data, size_t dataSize)
{
  size_t written = 0;
  while (written < dataSize) {
    int ret = mbedtls_ssl_write(mbedtlsCtx_->GetSSLContext(), &data[written],
                                dataSize - written);
    if (ret < 0) {
      if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
          ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
      return ret;
    }
    written += ret;
  }
  return (long)written;
}

int
Service::Run()
{
  while (!terminate_) {
    int poll = Poll();
    if (poll < 0) {
      OC_ERR("polling failed with error(%d)", poll);
      return -1;
    }
    if ((poll & MBEDTLS_NET_POLL_READ) != 0) {
      ReadData();
    }
  }
  return 0;
}

void
Service::Stop()
{
  terminate_.store(true);
}

} // namespace oc::tls

#endif /* MBEDTLS_NET_C && MBEDTLS_TIMING_C */

#endif /* OC_SECURITY */
