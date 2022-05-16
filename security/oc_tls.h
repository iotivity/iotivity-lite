/*
// Copyright (c) 2016-2019 Intel Corporation
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
#include "mbedtls/ctr_drbg.h"
#include "oc_uuid.h"
#include "port/oc_connectivity.h"
#include "security/oc_cred_internal.h"
#include "security/oc_keypair.h"
#include "util/oc_etimer.h"
#include "util/oc_list.h"
#include "util/oc_process.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
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
  bool doc;
#ifdef OC_PKI
  oc_string_t public_key;
#endif /* OC_PKI */
#ifdef OC_TCP
  oc_message_t *processed_recv_message;
#endif
} oc_tls_peer_t;

extern mbedtls_ctr_drbg_context g_oc_ctr_drbg_ctx;

int oc_tls_init_context(void);
void oc_tls_shutdown(void);

void oc_tls_close_connection(oc_endpoint_t *endpoint);

bool oc_sec_derive_owner_psk(oc_endpoint_t *endpoint, const uint8_t *oxm,
                             const size_t oxm_len, const uint8_t *server_uuid,
                             const size_t server_uuid_len,
                             const uint8_t *obt_uuid, const size_t obt_uuid_len,
                             uint8_t *key, const size_t key_len);

/**
 * @brief Create a new peer or get an existing peer for endpoint.
 *
 * @note If a peer for the given endpoint already exists then no new peer is
 * created and the existing one is used instead.
 *
 * @param endpoint the endpoint
 * @param role MBEDTLS_SSL_IS_CLIENT or MBEDTLS_SSL_IS_SERVER
 * @return peer for given endpoint on success
 * @return NULL on error
 */
oc_tls_peer_t *oc_tls_add_peer(oc_endpoint_t *endpoint, int role);

/**
 * @brief Remove and deallocate the peer for the endpoint.
 *
 * @param endpoint the endpoint
 */
void oc_tls_remove_peer(oc_endpoint_t *endpoint);

/**
 * @brief Get the peer for the endpoint.
 *
 * @param endpoint the endpoint
 * @return peer for the endpoint if it exists
 * @return NULL if no peer exists for the endpoint
 */
oc_tls_peer_t *oc_tls_get_peer(oc_endpoint_t *endpoint);

/**
 * @brief Get uuid of the peer for the endpoint.
 *
 * @param endpoint the endpoint
 * @return uuid of the peer for the endpoint
 * @return NULL if no peer exists for the endpoint
 */
oc_uuid_t *oc_tls_get_peer_uuid(oc_endpoint_t *endpoint);

/**
 * @brief Count the number of peers in the device.
 *
 * @param device the device
 * @return int number of peers
 */
int oc_tls_num_peers(size_t device);

/**
 * @brief Check if the endpoint has a connected peer.
 *
 * @param endpoint the endpoint
 * @return true if connected peer exists
 * @return false if no connected peer exists
 */
bool oc_tls_connected(oc_endpoint_t *endpoint);

size_t oc_tls_send_message(oc_message_t *message);
bool oc_tls_uses_psk_cred(oc_tls_peer_t *peer);

/* Public APIs for selecting certificate credentials */
void oc_tls_select_cert_ciphersuite(void);
void oc_tls_select_mfg_cert_chain(int credid);
void oc_tls_select_identity_cert_chain(int credid);
void oc_tls_select_psk_ciphersuite(void);
void oc_tls_select_anon_ciphersuite(void);
void oc_tls_select_cloud_ciphersuite(void);

/* Internal interface for checking supported OTMs */
bool oc_tls_is_pin_otm_supported(size_t device);
bool oc_tls_is_cert_otm_supported(size_t device);

/* Internal interface for generating a random PIN */
void oc_tls_generate_random_pin(void);

/* Internal interface for changing psk authority hint */
#ifdef OC_CLIENT
void oc_tls_use_pin_obt_psk_identity(void);
#endif /* OC_CLIENT */

/* Internal interface for deriving a PSK for the Random PIN OTM */
int oc_tls_pbkdf2(const unsigned char *pin, size_t pin_len, oc_uuid_t *uuid,
                  unsigned int c, uint8_t *key, uint32_t key_len);

#ifdef OC_PKI
/**
 * @brief Internal interface for examining credentials for new identity
 * certificate chains.
 *
 * Iterate over all credentials, check if a credential is associated with a leaf
 * identity certificate. If the identity certificate doesn't exist in the global
 * list of identity certificates then create a new identity certificate item and
 * add it to the list.
 */
void oc_tls_resolve_new_identity_certs(void);

/**
 * @brief Remove certificate associated with the credential from the global list
 * of leaf identity certificates and deallocate it.
 *
 * @param cred credential associated with the identity certificate to remove
 * @return true identity certificate was found and removed
 * @return false otherwise
 */
bool oc_tls_remove_identity_cert(oc_sec_cred_t *cred);

/**
 * @brief Get parsed mbedtls x509 certificate for given credential.
 *
 * @param cred credential to seach for
 * @return mbedtls_x509_crt* parsed certificate if credential is found in global
 * list.
 * @return NULL otherwise
 */
mbedtls_x509_crt *oc_tls_get_identity_cert_for_cred(const oc_sec_cred_t *cred);

/**
 * @brief Internal interface for examining credentials for new trust anchors.
 */
void oc_tls_resolve_new_trust_anchors(void);

/**
 * @brief Remove certificate associated with the credential from the global
 * lists of leaf trust anchors.
 *
 * They are two lists that contain trust anchors: a simple linked list and a
 * mbedtls chain. The trust anchor is removed from the linked list in a standard
 * way. The mbedtls chain is thrown away fully and reloaded from the linked
 * list.
 *
 * @param cred credential associated with the trust anchor to remove
 * @return true trust anchor was found, removed the global linked list and the
 * global mbedtls trust anchor chain was reloaded
 * @return false otherwise
 */
bool oc_tls_remove_trust_anchor(oc_sec_cred_t *cred);

/**
 * @brief Get parsed mbedtls x509 certificate for given credential.
 *
 * @param cred credential to seach for
 * @return mbedtls_x509_crt* parsed certificate if credential is found in global
 * list.
 * @return NULL otherwise
 */
mbedtls_x509_crt *oc_tls_get_trust_anchor_for_cred(const oc_sec_cred_t *cred);

/**
 * @brief Get mbedtls container with trust anchors used globally by the
 * application.
 *
 * @return mbedtls_x509_crt* X.509 certificate container with parsed trust
 * anchors
 */
mbedtls_x509_crt *oc_tls_get_trust_anchors(void);

#ifdef OC_TEST
/**
 * @brief Check global lists of credentials and identity certificates that they
 * contain the same items.
 *
 * @return true if the lists of identity certificates are consistent with each
 * other
 * @return false otherwise
 */
bool oc_tls_validate_identity_certs_consistency(void);

/**
 * @brief Check global lists of credentials and trust anchors that they
 * contain the same items.
 *
 * @return true if the lists of trust anchors are consistent with each
 * other
 * @return false otherwise
 */
bool oc_tls_validate_trust_anchors_consistency(void);
#endif /* OC_TEST */

#endif /* OC_PKI */

#ifdef __cplusplus
}
#endif

#endif /* OC_TLS_H */
