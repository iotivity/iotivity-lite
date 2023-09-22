/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#ifndef OC_TLS_INTERNAL_H
#define OC_TLS_INTERNAL_H

#include "oc_pki.h"
#include "oc_uuid.h"
#include "port/oc_connectivity.h"
#include "security/oc_cred_internal.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_list.h"
#include "util/oc_process.h"

#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OC_PROCESS_NAME(oc_tls_handler);

typedef struct
{
  struct oc_etimer fin_timer;
  oc_clock_time_t int_ticks;
} oc_tls_retry_timer_t;

typedef struct oc_tls_peer_t
{
  struct oc_tls_peer_t *next;
  OC_LIST_STRUCT(recv_q);
  OC_LIST_STRUCT(send_q);
  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;
  oc_endpoint_t endpoint;
  int role; // MBEDTLS_SSL_IS_SERVER = device acts as a server
            // MBEDTLS_SSL_IS_CLIENT = device acts as a client
  oc_tls_retry_timer_t timer;
  uint8_t master_secret[48];
  uint8_t client_server_random[64];
  oc_uuid_t uuid;
  oc_clock_time_t timestamp; ///< activity timestamp
  bool doc;                  ///< device onboarding connection
#ifdef OC_PKI
  oc_string_t public_key;
#endif /* OC_PKI */
#ifdef OC_TCP
  oc_message_t *processed_recv_message;
#endif /* OC_TCP */
#ifdef OC_PKI
  oc_pki_user_data_t
    user_data; ///< user data for the peer, can be used by application
  oc_pki_verify_certificate_cb_t
    verify_certificate; ///< callback for certificate verification, filled by
                        ///< default callback
#endif                  /* OC_PKI */
} oc_tls_peer_t;

/**
 * @brief TLS peer filtering function.
 *
 * @param peer peer to check
 * @param user_data user data passed from the caller
 * @return true if the peer matches the filter
 * @return false otherwise
 */
typedef bool (*oc_tls_peer_filter_t)(const oc_tls_peer_t *peer,
                                     void *user_data);

int oc_tls_init_context(void);
void oc_tls_shutdown(void);

/**
 * @brief Get global ctr_dbrg context
 *
 * @note The pointer is valid after initialization by oc_tls_init_context
 */
mbedtls_ctr_drbg_context *oc_tls_ctr_drbg_context(void);

void oc_tls_close_connection(const oc_endpoint_t *endpoint);

bool oc_sec_derive_owner_psk(const oc_endpoint_t *endpoint, const uint8_t *oxm,
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
 * @param role MBEDTLS_SSL_IS_CLIENT or MBEDTLS_SSL_IS_SERVER (ignored if an
 * existing peer was found)
 * @param[out] created true if a new peer was created, false if an existing peer
 * was found (value is valid only on success, ie. if the returned value is
 * non-NULL)
 * @return peer for given endpoint on success
 * @return NULL on error
 */
oc_tls_peer_t *oc_tls_add_or_get_peer(const oc_endpoint_t *endpoint, int role,
                                      bool *created);

typedef struct oc_tls_new_peer_params_t
{
  const oc_endpoint_t *endpoint; ///< endpoint of the peer (cannot be NULL)
  int role;
#ifdef OC_PKI
  oc_pki_user_data_t user_data;
  oc_pki_verify_certificate_cb_t verify_certificate;
#endif /* OC_PKI */
} oc_tls_new_peer_params_t;

/**
 * @brief Create a new peer based on the input parameters
 *
 * @param params parameters for the new peer
 * @return created peer on success
 * @return NULL on error
 */
oc_tls_peer_t *oc_tls_add_new_peer(oc_tls_new_peer_params_t params);

#ifdef OC_PKI

typedef struct oc_tls_pki_verification_params_t
{
  oc_pki_user_data_t user_data;
  oc_pki_verify_certificate_cb_t verify_certificate;
} oc_tls_pki_verification_params_t;

oc_tls_pki_verification_params_t oc_tls_peer_pki_default_verification_params(
  void);

#endif /* OC_PKI */

/**
 * @brief Remove and deallocate the peer for the endpoint.
 *
 * @param endpoint the endpoint
 */
void oc_tls_remove_peer(const oc_endpoint_t *endpoint);

/**
 * @brief Remove TLS peers matching filter.
 *
 * @param filter Filtering function (if NULL all existing peers match)
 * @param user_data User data passed from the caller
 */
void oc_tls_close_peers(oc_tls_peer_filter_t filter, void *user_data);

/**
 * @brief Get the peer for the endpoint.
 *
 * @param endpoint the endpoint
 * @return peer for the endpoint if it exists
 * @return NULL if no peer exists for the endpoint
 *
 * @note if endpoint is NULL then the first peer will be returned regardless of
 * the endpoint on the peer
 */
oc_tls_peer_t *oc_tls_get_peer(const oc_endpoint_t *endpoint);

/**
 * @brief Get uuid of the peer for the endpoint.
 *
 * @param endpoint the endpoint
 * @return uuid of the peer for the endpoint
 * @return NULL if no peer exists for the endpoint
 */
oc_uuid_t *oc_tls_get_peer_uuid(const oc_endpoint_t *endpoint);

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
bool oc_tls_connected(const oc_endpoint_t *endpoint);

/**
 * @brief Send a message to the TLS peer. If the peer is not created or
 * connected then the message is queued and sent when the peer is connected.
 *
 * @param message to send
 *
 * @return > 0 on success
 * @return 0 if peer is not connected but the message was queued
 * @return -1 on error
 */
size_t oc_tls_send_message(oc_message_t *message);
bool oc_tls_uses_psk_cred(const oc_tls_peer_t *peer);

/* Public APIs for selecting certificate credentials */
void oc_tls_select_cert_ciphersuite(void);

/**
 * This function establishes an interface with the aim of selecting manufacturer
 * credentials within the client role, which are consequently applied during the
 * TLS handshake procedure.
 *
 * Internally employed by the stack, these interface methods serve to pinpoint
 * the suitable manufacturer certificate credentials for a specific peer.It's
 * crucial to note that these methods are not designed to be thread-safe.
 *
 * @param credid The designated credential ID: opt for -1 to allow the selection
 * from any credential, or choose a value less than -1 to deactivate credential
 * selection entirely.
 */
void oc_tls_select_mfg_cert_chain(int credid);

/**
 * This function defines an interface aimed at the task of choosing identity
 * credentials within the client role, which are subsequently applied during
 * the TLS handshake procedure.
 *
 * These interface methods are utilized internally by the stack to determine
 * the suitable identity certificate credentials for a given peer. It's crucial
 * to note that these methods are not designed to be thread-safe.
 *
 * @param credid The chosen credential ID; use -1 to allow selection from any
 * credential, and use a value less than -1 to deactivate credential selection.
 *
 * @note If the intention is to enforce the use of the manufacturer's
 * certificate rather than the identity certificate, simply set credid to -2.
 */
void oc_tls_select_identity_cert_chain(int credid);

void oc_tls_select_psk_ciphersuite(void);
void oc_tls_select_anon_ciphersuite(void);
void oc_tls_select_cloud_ciphersuite(void);
void oc_tls_reset_ciphersuite(void);

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
int oc_tls_pbkdf2(const unsigned char *pin, size_t pin_len,
                  const oc_uuid_t *uuid, unsigned int c, uint8_t *key,
                  uint32_t key_len);

/**
 * @brief Check if event is inbound or outbound (i.e. processing this event will
 * create a (D)TLS session)
 *
 * @param event event to check
 * @return true if event is inbound or outbound
 * @return false otherwise
 */
bool oc_tls_event_is_inbound_or_outbound(oc_process_event_t event);

#ifdef OC_TEST
void oc_dtls_set_inactivity_timeout(oc_clock_time_t timeout);
oc_clock_time_t oc_dtls_inactivity_timeout(void);
#endif /* OC_TEST */

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
bool oc_tls_remove_identity_cert(const oc_sec_cred_t *cred);

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
bool oc_tls_remove_trust_anchor(const oc_sec_cred_t *cred);

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

/**
 * @brief Check global lists of credentials and trust anchors that they
 * contain the same items.
 *
 * @return true if the lists of trust anchors are consistent with each
 * other
 * @return false otherwise
 */
int oc_tls_load_mfg_cert_chain(mbedtls_ssl_config *conf, size_t device,
                               int credid);

/**
 * @brief Check global lists of credentials and trust anchors that they
 * contain the same items.
 *
 * @return true if the lists of trust anchors are consistent with each
 * other
 * @return false otherwise
 */
int oc_tls_load_identity_cert_chain(mbedtls_ssl_config *conf, size_t device,
                                    int credid);

/**
 * @brief Set up trust anchor and certificate chain for device to mbedtls ssl
 * config.
 *
 * @param conf mbedtls ssl config
 * @param device device index
 * @param owned true if device is owned
 * @return true success
 * @return false failure
 */
bool oc_tls_load_cert_chain(mbedtls_ssl_config *conf, size_t device,
                            bool owned);

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

#endif /* OC_TLS_INTERNAL_H */
