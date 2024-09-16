/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifndef PLGD_DPS_PKI_INTERNAL_H
#define PLGD_DPS_PKI_INTERNAL_H

#include "plgd/plgd_dps.h" // plgd_dps_context_t

#include "oc_client_state.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLGD_DPS_CREDS_URI "/api/v1/provisioning/credentials"

/**
 * @brief Send Certificate Signing Request request using POST to the DPS
 * service.
 *
 * @param ctx dps context (cannot be NULL)
 * @param handler response handler (cannot be NULL)
 * @return true request has been send
 * @return false on error
 */
OC_NO_DISCARD_RETURN
bool dps_pki_send_csr(plgd_dps_context_t *ctx, oc_response_handler_t handler)
  OC_NONNULL();

/**
 * @brief Possible validity state of a certificate.
 */
typedef enum {
  DPS_CERTIFICATE_VALID = 0,
  DPS_CERTIFICATE_NOT_YET_VALID,
  DPS_CERTIFICATE_EXPIRING,
  DPS_CERTIFICATE_EXPIRED,
} dps_certificate_state_t;

typedef struct dps_pki_configuration_t
{
  uint16_t expiring_limit; ///< interval in seconds within which a certificate
                           ///< is considered as expiring
} dps_pki_configuration_t;

/// @brief Initialize PKI configuration
void dps_pki_init(dps_pki_configuration_t *pki) OC_NONNULL();

/// @brief Return string representation of certificate state
OC_NO_DISCARD_RETURN
const char *dps_pki_certificate_state_to_str(dps_certificate_state_t state);

/**
 * @brief Check validity state of a certificate based on its valid-from and
 * valid-to timestamps.
 *
 * @param cfg PKI configuration
 * @param valid_from valid-from UNIX timestamp of a certificate
 * @param valid_to valid-to UNIX timestamp of a certificate
 * @return -1 on error
 * @return dps_certificate_state_t resolved validity state of the certificate
 */
OC_NO_DISCARD_RETURN
int dps_pki_validate_certificate(dps_pki_configuration_t cfg,
                                 uint64_t valid_from, uint64_t valid_to);

/// @brief Check if the device is in a valid state to renew certificates
/// (without needing to do full reprovisioning)
OC_NO_DISCARD_RETURN
bool dps_pki_can_replace_certificates(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Schedule renewal of certificates based on the valid-to timestamp of
 * the certificate that expires the earliest.
 *
 * @param ctx dps context (cannot be NULL)
 * @param valid_to valid-to of the certificate that expires the earliest
 * @param min_interval minimal interval allowed (if the calculated interval is
 * lower then it will be subsituted for this minimal interval) in milliseconds
 */
void dps_pki_schedule_renew_certificates(plgd_dps_context_t *ctx,
                                         uint64_t valid_to,
                                         uint64_t min_interval) OC_NONNULL();

/**
 * @brief Calculate interval in which to renewal of certificate should be.
 *
 * @param valid_to the valid_to timestamp of the certificate closest to
 * expiration
 * @return interval in milliseconds after which certificates should be rechecked
 */
OC_NO_DISCARD_RETURN
uint64_t dps_pki_calculate_renew_certificates_interval(
  dps_pki_configuration_t cfg, uint64_t valid_to);

/// @brief Delayed callback to renew DPS certificates.
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_pki_renew_certificates_async(void *user_data)
  OC_NONNULL();

/// @brief Delayed callback to renew DPS certificates and increment retry
/// counter.
OC_NO_DISCARD_RETURN
oc_event_callback_retval_t dps_pki_renew_certificates_retry_async(
  void *user_data) OC_NONNULL();

/**
 * @brief Replace credentials with new credentials received from the DPS
 * service.
 *
 * @param device device index
 * @param rep data with certificates retrieved from the DPS service (cannot be
 * NULL)
 * @param endpoint endpoint of the credentials owner
 * @return true if certificates were successfully replace
 * @return false on failure
 */
OC_NO_DISCARD_RETURN
bool dps_pki_replace_certificates(size_t device, const oc_rep_t *rep,
                                  const oc_endpoint_t *endpoint) OC_NONNULL();

/// @brief Try replacing current (expiring) DPS certificates with newer
/// certificates retrieved from the DPS service.
bool dps_pki_try_renew_certificates(plgd_dps_context_t *ctx) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_PKI_INTERNAL_H */
