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

#ifdef __cplusplus
}
#endif
#endif /* OC_SP_H */
