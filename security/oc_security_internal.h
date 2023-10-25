/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_SECURITY_INTERNAL_H
#define OC_SECURITY_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include <mbedtls/platform_time.h>
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configure mbedTLS for IoTivity-lite.
 */
void oc_mbedtls_init(void);

/**
 * @brief Perform self-onboarding.
 *
 * @param device device index
 * @return 0 on success
 * @return -1 on failure
 */
int oc_sec_self_own(size_t device);

/**
 * @brief Reverts self-onboarding.
 *
 * @note This function only reverts all operations performed by oc_sec_self_own,
 * it does not clean-up everything that was done after self-onboarding. To do
 * that the device must be reset.
 *
 * @see oc_pstat_reset_device
 *
 * @param device device index
 */
void oc_sec_self_disown(size_t device);

#ifdef OC_HAS_FEATURE_PLGD_TIME

/**
 * @brief Configure mbedTLS to use plgd time to get current time.
 */
void oc_mbedtls_platform_time_init(void);

/**
 * @brief Reset mbedTLS to use standard function (time) to get current time.
 */
void oc_mbedtls_platform_time_deinit(void);

/**
 * @brief Wrapper over plgd_time_seconds to match desired function signature for
 * mbedtls_platform_set_time.
 */
mbedtls_time_t oc_mbedtls_platform_time(mbedtls_time_t *timer);

#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY_INTERNAL_H */
