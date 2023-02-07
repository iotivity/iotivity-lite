/****************************************************************************
 *
 * Copyright (c) 2017-2020 Intel Corporation
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

#ifndef OC_OBT_INTERNAL_H
#define OC_OBT_INTERNAL_H

#ifdef OC_SECURITY

#include "messaging/coap/oscore_constants.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_obt.h"
#include "oc_role.h"
#include "oc_uuid.h"
#include "security/oc_pstat.h"
#include "util/oc_list.h"

#ifdef OC_PKI
#include <mbedtls/build_info.h>
#include <mbedtls/x509_crt.h>
#endif /* OC_PKI */

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Used for tracking owned/unowned devices in oc_obt's internal caches */
typedef struct oc_device_t
{
  struct oc_device_t *next;
  oc_endpoint_t *endpoint;
  oc_uuid_t uuid;
  void *ctx;
} oc_device_t;

/* Context for oc_obt_discover_owned/unowned cbs */
typedef struct oc_discovery_cb_t
{
  struct oc_discovery_cb_t *next;
  oc_obt_discovery_cb_t cb;
  void *data;
} oc_discovery_cb_t;

/* Context for oc_obt_provision_pairwise_credentials and switch_dos cb */
typedef struct
{
  oc_obt_status_cb_t cb;
  void *data;
} oc_status_cb_t;

/* Context for oc_obt_perform_just_works_otm, oc_obt_provision_ace,
 * oc_obt_device_hard_reset, oc_obt_request_random_pin() and
 * oc_obt_perform_random_pin_otm() cbs
 */
typedef struct
{
  oc_obt_device_status_cb_t cb;
  void *data;
} oc_device_status_cb_t;

/* Context to be maintained over OTM sequence */
typedef struct oc_otm_ctx_t
{
  struct oc_otm_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
  bool sdi;
} oc_otm_ctx_t;

/* Context to be maintained over dos transition sequence */
typedef struct oc_switch_dos_ctx_t
{
  struct oc_switch_dos_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device;
  oc_dostype_t dos;
} oc_switch_dos_ctx_t;

/* Context to be maintained over hard RESET sequence */
typedef struct oc_hard_reset_ctx_t
{
  struct oc_hard_reset_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
  oc_switch_dos_ctx_t *switch_dos;
} oc_hard_reset_ctx_t;

/* Context to be maintained over pair-wise credential provisioning
 * sequence
 */
typedef struct oc_credprov_ctx_t
{
  struct oc_credprov_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device1;
  oc_device_t *device2;
  oc_switch_dos_ctx_t *switch_dos;
  uint8_t key[16];
  oc_role_t *roles;
} oc_credprov_ctx_t;

/* Context to be maintained over installing a trust anchor
 * sequence
 */
typedef struct oc_trustanchor_ctx_t
{
  struct oc_trustanchor_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device1;
  oc_switch_dos_ctx_t *switch_dos;
  const char *trustanchor;
  size_t trustanchor_size;
  char trustanchor_subject[64];
} oc_trustanchor_ctx_t;

/* Context to be maintained over the pair-wise OSCORE context provisioning
 * sequence
 */
typedef struct oc_oscoreprov_ctx_t
{
  struct oc_oscoreprov_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device1;
  oc_device_t *device2;
  oc_switch_dos_ctx_t *switch_dos;
  uint8_t sendid[OSCORE_CTXID_LEN];
  uint8_t recvid[OSCORE_CTXID_LEN];
  uint8_t secret[OSCORE_MASTER_SECRET_LEN];
} oc_oscoreprov_ctx_t;

/* Context to be maintained over the group OSCORE context provisioning
 * sequence.
 */
typedef struct oc_oscoregroupprov_ctx_t
{
  struct oc_oscoregroupprov_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
  oc_uuid_t subjectuuid;
  oc_string_t desc;
  oc_switch_dos_ctx_t *switch_dos;
  oc_sec_credtype_t type;
} oc_oscoregroupprov_ctx_t;

/* Context over a RETRIEVE credentials request */
typedef struct oc_credret_ctx_t
{
  struct oc_credret_ctx_t *next;
  oc_obt_creds_cb_t cb;
  void *data;
} oc_credret_ctx_t;

/* Context over a DELETE credentials request */
typedef struct oc_creddel_ctx_t
{
  struct oc_creddel_ctx_t *next;
  oc_status_cb_t cb;
  oc_switch_dos_ctx_t *switch_dos;
  oc_device_t *device;
  int credid;
} oc_creddel_ctx_t;

/* Context to be maintained over ACE provisioning sequence */
typedef struct oc_acl2prov_ctx_t
{
  struct oc_acl2prov_ctx_t *next;
  oc_device_status_cb_t cb;
  oc_device_t *device;
  oc_sec_ace_t *ace;
  oc_switch_dos_ctx_t *switch_dos;
} oc_acl2prov_ctx_t;

/* Context over a RETRIEVE ACL request */
typedef struct oc_aclret_ctx_t
{
  struct oc_aclret_ctx_t *next;
  oc_obt_acl_cb_t cb;
  void *data;
} oc_aclret_ctx_t;

/* Context over a DELETE ACE request */
typedef struct oc_acedel_ctx_t
{
  struct oc_acedel_ctx_t *next;
  oc_status_cb_t cb;
  oc_switch_dos_ctx_t *switch_dos;
  oc_device_t *device;
  int aceid;
} oc_acedel_ctx_t;

typedef enum {
  OC_OBT_OTM_JW = 0,
  OC_OBT_RDP,
  OC_OBT_OTM_RDP,
  OC_OBT_OTM_CERT
} oc_obt_otm_t;

oc_endpoint_t *oc_obt_get_unsecure_endpoint(oc_endpoint_t *endpoint);
oc_endpoint_t *oc_obt_get_secure_endpoint(oc_endpoint_t *endpoint);

oc_device_t *oc_obt_get_cached_device_handle(oc_uuid_t *uuid);
oc_device_t *oc_obt_get_owned_device_handle(oc_uuid_t *uuid);

bool oc_obt_is_owned_device(oc_uuid_t *uuid);
oc_dostype_t oc_obt_parse_dos(oc_rep_t *rep);

oc_otm_ctx_t *oc_obt_alloc_otm_ctx(void);
void oc_obt_free_otm_ctx(oc_otm_ctx_t *ctx, int status, oc_obt_otm_t);
oc_event_callback_retval_t oc_obt_otm_request_timeout_cb(void *data);
bool oc_obt_is_otm_ctx_valid(oc_otm_ctx_t *ctx);

#ifdef OC_PKI

typedef struct oc_obt_generate_root_cert_data_t
{
  const char *subject_name;
  const uint8_t *public_key;
  size_t public_key_size;
  const uint8_t *private_key;
  size_t private_key_size;
} oc_obt_generate_root_cert_data_t;

/**
 * @brief Generate self-signed root certificate in PEM string format.
 *
 * @param cert_data data for self-signed root certificate
 * @param[out] buffer output buffer to store the PEM of the certificate (cannot
 * be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return 0 on success
 * @return -1 on error
 */
int oc_obt_generate_self_signed_root_cert_pem(
  oc_obt_generate_root_cert_data_t cert_data, unsigned char *buffer,
  size_t buffer_size);

/**
 * @brief Generate a self-signed certificate and add it to credentials of given
 * device.
 *
 * @param cert_data data for the self-signed root certificate
 * @param device device index
 * @return >=0 on success, credid of the self-signed certificate
 * @return -1 on error
 */
int oc_obt_generate_self_signed_root_cert(
  oc_obt_generate_root_cert_data_t cert_data, size_t device);

typedef struct oc_obt_generate_identity_cert_data_t
{
  const char *subject_name;
  const uint8_t *public_key;
  size_t public_key_size;
  const char *issuer_name;
  const uint8_t *issuer_private_key;
  size_t issuer_private_key_size;
} oc_obt_generate_identity_cert_data_t;

/**
 * @brief Generate an identity certificate in PEM string format.
 *
 * @param cert_data data for identity certificate
 * @param[out] buffer output buffer to store the PEM of the certificate
 * (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return 0 on success
 * @return -1 on error
 */
int oc_obt_generate_identity_cert_pem(
  oc_obt_generate_identity_cert_data_t cert_data, unsigned char *buffer,
  size_t buffer_size);

/**
 * @brief Encode linked list of role and authority pairs into linked list of
 * mbedtls_x509_general_names*
 *
 * @param[in] roles
 * @param[out] general_names output pointer to store linked list of
 * mbedtls_x509_general_names * (cannot be NULL, must be deallocated by
 * oc_obt_free_encoded_roles)
 * @return >=0 on success, number of encoded roles
 * @return -1 on error
 */
int oc_obt_encode_roles(const oc_role_t *roles,
                        mbedtls_x509_general_names **general_names);

/// @brief Deallocate a linked list of mbedtls_x509_general_names*
void oc_obt_free_encoded_roles(mbedtls_x509_general_names *general_names);

typedef struct oc_obt_generate_role_cert_data_t
{
  const oc_role_t *roles;
  const char *subject_name;
  const uint8_t *public_key;
  size_t public_key_size;
  const char *issuer_name;
  const uint8_t *issuer_private_key;
  size_t issuer_private_key_size;
} oc_obt_generate_role_cert_data_t;

/**
 * @brief Generate a role certificate in PEM string format.
 *
 * @param cert_data data for role certificate
 * @param[out] buffer output buffer to store the PEM of the certificate
 * (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return 0 on success
 * @return -1 on error
 */
int oc_obt_generate_role_cert_pem(oc_obt_generate_role_cert_data_t cert_data,
                                  unsigned char *buffer, size_t buffer_size);

#endif /* OC_PKI */

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY */

#endif /* OC_OBT_INTERNAL_H */
