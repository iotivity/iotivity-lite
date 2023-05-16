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

#include "DTLSClient.h"

#include "port/oc_log_internal.h"
#include "security/oc_entropy_internal.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>

namespace oc::tls {

static void
dtls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
  (void)ctx;
  if (level == 1) {
    OC_ERR("%s:%04d: %s", file, line, str);
    return;
  }
  if (level == 2) {
    OC_NOTE("%s:%04d: %s", file, line, str);
    return;
  }
  if (level == 3) {
    OC_INFO("%s:%04d: %s", file, line, str);
    return;
  }
  if (level == 4) {
    OC_DBG("%s:%04d: %s", file, line, str);
    return;
  }
}

int
DTLSClient::ConfPSKCb(void *data, mbedtls_ssl_context *ssl,
                      const unsigned char *identity, size_t identity_len)
{
  (void)identity;
  (void)identity_len;
  DTLSClient *dtls = static_cast<DTLSClient *>(data);
  if (mbedtls_ssl_set_hs_psk(ssl, dtls->psk_.data(), dtls->psk_.size()) != 0) {
    return -1;
  }
  OC_DBG("oc_tls: Set peer credential to SSL handle");
  return 0;
}

DTLSClient::DTLSClient()
  : service_{ this, nullptr }
  , ciphers_{
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
#ifdef OC_PKI
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
#endif /* OC_PKI */
    0,
  }
{
#if defined(MBEDTLS_DEBUG_C)
#if OC_DBG_IS_ENABLED
  mbedtls_debug_set_threshold(4);
#elif OC_NOTE_IS_ENABLED
  mbedtls_debug_set_threshold(3);
#elif OC_INFO_IS_ENABLED
  mbedtls_debug_set_threshold(2);
#elif OC_ERR_IS_ENABLED
  mbedtls_debug_set_threshold(1);
#else
  mbedtls_debug_set_threshold(0);
#endif
#endif

  mbedtls_net_init(&serverFd_);
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_init(&config_);
  mbedtls_ssl_conf_dbg(&config_, dtls_debug, nullptr);
  mbedtls_ctr_drbg_init(&ctrDrbg_);
  mbedtls_entropy_init(&entropy_);
  oc_entropy_add_source(&entropy_);
  mbedtls_ssl_cookie_init(&cookieCtx_);

  // Seeding the random number generator
  std::string pers = "dtls_client";
  if ((mbedtls_ctr_drbg_seed(
        &ctrDrbg_, mbedtls_entropy_func, &entropy_,
        reinterpret_cast<const unsigned char *>(pers.c_str()),
        pers.length())) != 0) {
    throw std::string("cannot seed random number generator");
  }

  if ((mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    throw std::string("cannot configure DTLS");
  }

  if (mbedtls_ssl_cookie_setup(&cookieCtx_, mbedtls_ctr_drbg_random,
                               &ctrDrbg_) != 0) {
    throw std::string("cannot setup DTLS cookie");
  }

  mbedtls_ssl_conf_min_version(&config_, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&config_, mbedtls_ctr_drbg_random, &ctrDrbg_);

  mbedtls_ssl_conf_psk_cb(&config_, ConfPSKCb, this);
  mbedtls_ssl_conf_dtls_cookies(&config_, mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check, &cookieCtx_);
  mbedtls_ssl_conf_handshake_timeout(&config_, 1000, 10000);
  mbedtls_ssl_conf_ciphersuites(&config_, ciphers_.data());

  if ((mbedtls_ssl_setup(&ssl_, &config_)) != 0) {
    throw std::string("cannot assign configuration to SSL");
  }

  mbedtls_ssl_set_timer_cb(&ssl_, &timer_, mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);
  mbedtls_ssl_set_bio(&ssl_, &serverFd_, mbedtls_net_send, mbedtls_net_recv,
                      mbedtls_net_recv_timeout);
}

int
DTLSClient::SetPresharedKey(const std::vector<unsigned char> &key,
                            const std::vector<unsigned char> &identityHint)
{
  psk_ = key;
  identityHint_ = identityHint;
  return mbedtls_ssl_conf_psk(&config_, psk_.data(), psk_.size(),
                              identityHint_.data(), identityHint_.size());
}

int
DTLSClient::Connect(const std::string &host, uint16_t port)
{
  std::string port_str = std::to_string(port);
  return mbedtls_net_connect(&serverFd_, host.c_str(), port_str.c_str(),
                             MBEDTLS_NET_PROTO_UDP);
}

void
DTLSClient::CloseNotify()
{
  int ret;
  /* No error checking, the connection might be closed already */
  do {
    ret = mbedtls_ssl_close_notify(&ssl_);
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
}

int
DTLSClient::Handshake()
{
  int ret;
  do {
    ret = mbedtls_ssl_handshake(&ssl_);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  return ret;
}

DTLSClient::~DTLSClient()
{
  service_.Stop();
  mbedtls_net_close(&serverFd_);

  mbedtls_ssl_cookie_free(&cookieCtx_);
  //   mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl_);
  mbedtls_ctr_drbg_free(&ctrDrbg_);
  mbedtls_ssl_config_free(&config_);
  mbedtls_entropy_free(&entropy_);
  mbedtls_net_free(&serverFd_);
}

} // namespace  oc::tls

#endif /* MBEDTLS_NET_C && MBEDTLS_TIMING_C */

#endif /* OC_SECURITY */
