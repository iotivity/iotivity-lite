/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

/**
 * @file
 *
 * OCF security profiles
 *
 */
#ifndef OC_SP_H
#define OC_SP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * OCF defined security profiles
 *
 * Security Profiles differentiate devices based on requirements from different
 * verticals such as industrial, health care, or smart home.
 *
 * See oc_pki_set_security_profile() for a description of the each of the
 * security profiles or reference the security profiles section of the OCF
 * Security Specification.
 */
typedef enum {
  OC_SP_BASELINE = 1 << 1, ///< The OCF Baseline Security Profile
  OC_SP_BLACK = 1 << 2,    ///< The OCF Black Security Profile
  OC_SP_BLUE = 1 << 3,     ///< The OCF Blue Security Profile
  OC_SP_PURPLE = 1 << 4    ///< The OCF Purple Security Profile
} oc_sp_types_t;

/**
 * Set the OCF Security Profile
 *
 * The OCF Security Specification defines several Security Profiles that can be
 * selected based on the security requirements of different verticals such as
 * such as industrial, health care, or smart home.
 *
 * There are currently five types of Security Profiles specified by OCF.
 *
 * Following, is a non-exhaustive summary of each Security Profile type. For
 * more details see OCF Security Specification section regarding Security
 * Profiles.
 *
 * 1. Unspecified or `0`
 *  -  reserved for future use.
 * 2. OC_SP_BASELINE Baseline: indicates the OCF device satisfies normative
 *    security requirements as specified by the OCF Security Specification.
 *    Baseline Security Profile is the default security profile if no other
 *    profile is provided.
 * 3. OC_SP_BLACK Black: healthcare and industrial devices with additional
 *    security requirements are the initial target for the Black Security
 *    Profile. Black Security Profile is for edge devices with exceptional
 *    profiles of trust bestowed upon them. Black Security Profile must support
 *    the following
 *      - The device satisfies all normative security requirements
 *      - Onboarding via OCF Rooted Certificate Chain, including PKI chain
 *        validation
 *      - Support for AES 128 encryption for data at rest and in transit
 *      - Manufacturer assertion of secure credential storage
 *      - Resource should contain credential(s) if required by the selected OTM
 *      - The OCF Device shall include an X.509v3 certificate and the
 *        extension's 'securityProfile' field shall specify it is an OCF Black
 *        Security Profile
 * 4. OC_SP_BLUE Blue: indicates the OCF device has been issued a certificate
 *    authority from OCF. The Blue Security Profile is for an ecosystem where
 *    platform vendors may be using devices from a different vendor. The Blue
 *    profile gives a way to assure quality devices on a different vendors
 *    platform. Blue Security Profile must support the following
 *      - The device satisfies all normative security requirements
 *      - Vender attestation that the device satisfies platform security and
 *        privacy functionality requirements.
 *      - The device is registered with OCF.
 *      - The Security Profile may be digitally signed by an OCF owner signing
 *        key.
 *      - The OCF Device shall include an X.509v3 certificate and the
 * extension's 'securityProfile' field shall specify it is an OCF Blue Security
 *        Profile
 *      - The OCF Device shall include an X.509v3 OCF CPL Attributes Extension
 *        in its certificate.
 *      - The device shall perform a check on the certification status of the
 *        device and platform.
 *      - The device shall be hosted on a secure platform.
 *      - The device shall use AES128 equivalent or better protection for
 *        transmitted and stored data.
 * 5. OC_SP_PURPLE Purple: indicates the device shall be able to update its
 *    firmware in a secure manner. Purple Security Profile must support the
 *    following:
 *      - Secure credential storage
 *      - Software integrity validation
 *      - Secure update
 *      - If a certificate is used the OCF Device shall include an X.509v3
 *        certificate and the extension's 'securityProfile' field shall specify
 *        it is an OCF Purple Security Profile.
 *      - If a certificate is used the OCF Device shall include an X.509v3
 *        OCFCPLAttributes Extension in its End-Entity Certificate when
 *        manufacturer certificate is used.
 *
 * @param[in] device index of the logical device the security profile is be set
 * on
 * @param[in] supported_profiles a bitwise OR list of oc_sp_types_t that are
 *                               supported by the device. The current_profile
 *                               value may be changed to one of the other
 *                               supported_profiles during the onboarding
 *                               process.
 * @param[in] current_profile the currently selected security profile
 * @param[in] mfg_credid the credential ID of the /oic/sec/cred entry containing
 *                       the manufactures end-entity certificate
 */
void oc_pki_set_security_profile(size_t device, unsigned supported_profiles,
                                 oc_sp_types_t current_profile, int mfg_credid);

#ifdef __cplusplus
}
#endif
#endif /* OC_SP_H */
