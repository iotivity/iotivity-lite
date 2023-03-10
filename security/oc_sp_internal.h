/****************************************************************************
 *
 * Copyright (c) 2018-2019 Intel Corporation
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

#ifndef OC_SP_INTERNAL_H
#define OC_SP_INTERNAL_H

#include "oc_sp.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SP_BASELINE_OID "1.3.6.1.4.1.51414.0.0.1.0"
#define OC_SP_BLACK_OID "1.3.6.1.4.1.51414.0.0.2.0"
#define OC_SP_BLUE_OID "1.3.6.1.4.1.51414.0.0.3.0"
#define OC_SP_PURPLE_OID "1.3.6.1.4.1.51414.0.0.4.0"

typedef struct
{
  unsigned supported_profiles; // mask of supported oc_sp_types_t
  oc_sp_types_t current_profile;
  int credid;
} oc_sec_sp_t;

void oc_sec_sp_init(void);
void oc_sec_sp_free(void);
bool oc_sec_decode_sp(const oc_rep_t *rep, size_t device);
void oc_sec_encode_sp(size_t device, oc_interface_mask_t iface_mask,
                      bool to_storage);

oc_sec_sp_t *oc_sec_get_sp(size_t device);
void oc_sec_sp_default(size_t device);
void oc_sec_sp_copy(oc_sec_sp_t *dst, const oc_sec_sp_t *src);
void oc_sec_sp_clear(oc_sec_sp_t *sp);

/**
 * @brief Parse security profile type from string
 *
 * @param str string to parse (cannot be NULL)
 * @param str_len length of \p str
 *
 * @return oc_sp_types_t on success
 * @return 0 on failure
 */
oc_sp_types_t oc_sec_sp_type_from_string(const char *str, size_t str_len);

/**
 * @brief Encode security profile type to string
 *
 * @param sp_type type to encode
 * @return encoded C-string on success
 * @return NULL on failure
 */
const char *oc_sec_sp_type_to_string(oc_sp_types_t sp_type);

void get_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);
void post_sp(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_SP_INTERNAL_H */
