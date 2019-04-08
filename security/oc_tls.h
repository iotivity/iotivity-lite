/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_TLS_H
#define OC_TLS_H

#include "mbedtls/ssl.h"
#include "oc_uuid.h"
#include "port/oc_connectivity.h"
#include "security/oc_cred.h"
#include "security/oc_keypair.h"
#include "util/oc_etimer.h"
#include "util/oc_list.h"
#include "util/oc_process.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

OC_PROCESS_NAME(oc_tls_handler);

typedef struct
{
  struct oc_etimer fin_timer;
  oc_clock_time_t int_ticks;
} oc_tls_retr_timer_t;

typedef struct oc_tls_peer_t
{
  struct oc_tls_peer_t *next;
  OC_LIST_STRUCT(recv_q);
  OC_LIST_STRUCT(send_q);
  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;
  oc_endpoint_t endpoint;
  int role;
  oc_tls_retr_timer_t timer;
  uint8_t master_secret[48];
  uint8_t client_server_random[64];
  oc_uuid_t uuid;
  oc_clock_time_t timestamp;
#ifdef OC_PKI
  uint8_t public_key[OC_KEYPAIR_PUBKEY_SIZE];
#endif /* OC_PKI */
} oc_tls_peer_t;

int oc_tls_init_context(void);
void oc_tls_shutdown(void);

void oc_tls_close_connection(oc_endpoint_t *endpoint);

bool oc_sec_derive_owner_psk(oc_endpoint_t *endpoint, const uint8_t *oxm,
                             const size_t oxm_len, const uint8_t *server_uuid,
                             const size_t server_uuid_len,
                             const uint8_t *obt_uuid, const size_t obt_uuid_len,
                             uint8_t *key, const size_t key_len);

void oc_tls_remove_peer(oc_endpoint_t *endpoint);
size_t oc_tls_send_message(oc_message_t *message);
oc_uuid_t *oc_tls_get_peer_uuid(oc_endpoint_t *endpoint);
oc_tls_peer_t *oc_tls_get_peer(oc_endpoint_t *endpoint);
bool oc_tls_connected(oc_endpoint_t *endpoint);
bool oc_tls_uses_psk_cred(oc_tls_peer_t *peer);

/* Public APIs for selecting certificate credentials */
void oc_tls_select_cert_ciphersuite(void);
void oc_tls_select_mfg_cert_chain(int credid);
void oc_tls_select_identity_cert_chain(int credid);
void oc_tls_select_psk_ciphersuite(void);

/* Internal interface for generating a random PIN */
void oc_tls_generate_random_pin(void);

/* Internal interface for deriving a PSK for the Random PIN OTM */
int oc_tls_pbkdf2(const unsigned char *pin, size_t pin_len, oc_uuid_t *uuid,
                  unsigned int c, uint8_t *key, uint32_t key_len);

/* Internal interface for refreshing identity certficate chains */
void oc_tls_refresh_identity_certs(void);
void oc_tls_remove_identity_cert(oc_sec_cred_t *cred);

/* Internal interface for refreshing trust anchor credentials */
void oc_tls_refresh_trust_anchors(void);
void oc_tls_remove_trust_anchor(oc_sec_cred_t *cred);

#ifdef __cplusplus
}
#endif

#endif /* OC_TLS_H */
