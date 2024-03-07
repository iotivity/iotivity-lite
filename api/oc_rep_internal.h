/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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

#ifndef OC_REP_INTERNAL_H
#define OC_REP_INTERNAL_H

#include "oc_rep.h"
#include "util/oc_compiler.h"
#include "util/oc_memb.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum oc_rep_error_t {
  OC_REP_NO_ERROR = 0,

  OC_REP_ERROR_INTERNAL = -1,
  OC_REP_ERROR_OUT_OF_MEMORY = -2,
} oc_rep_error_t;

/** @brief Allocate a new oc_rep_t object */
oc_rep_t *oc_alloc_rep(void);

/** @brief Free an oc_rep_t object */
void oc_free_rep(oc_rep_t *rep);

/** @brief Set the object pool from which to allocate oc_rep_t objects
 *
 * @param rep_objects_pool object pool to use
 *
 * @note The rep pool is only used when dynamic memory allocation is disabled.
 */
void oc_rep_set_pool(oc_memb_t *rep_objects_pool);

/** @brief Set the object pool from which to allocate oc_rep_t objects and
 * return the previously set pool */
oc_memb_t *oc_rep_reset_pool(oc_memb_t *pool);

typedef enum {
  OC_REP_PARSE_RESULT_REP,
  OC_REP_PARSE_RESULT_EMPTY_ARRAY,
  OC_REP_PARSE_RESULT_NULL,
} oc_rep_parse_result_type_t;

typedef struct
{
  oc_rep_parse_result_type_t type;
  oc_rep_t *rep;
} oc_rep_parse_result_t;

/** @brief Get the value of a property by name. */
const oc_rep_t *oc_rep_get(const oc_rep_t *rep, oc_rep_value_type_t type,
                           const char *key, size_t key_len) OC_NONNULL(3);

/**
 * @brief Decode the payload into a oc_rep_t object using the global decoder.
 *
 * @param payload payload to decode
 * @param payload_size size of payload
 * @param[out] result output parameter for the decoded object (if result->type
 * is OC_REP_PARSE_RESULT_REP then result->rep must be freed with oc_free_rep,
 * cannot be NULL)
 * @return CborNoError on success
 */
int oc_rep_parse_payload(const uint8_t *payload, size_t payload_size,
                         oc_rep_parse_result_t *result) OC_NONNULL(3);

/** Convenience wrapper over oc_rep_parse_payload */
oc_rep_t *oc_parse_rep(const uint8_t *payload, size_t payload_size);

/**
 * @brief Get the size of the cbor encoded data.
 *
 * @param truncateEmpty truncate empty objects ("{}") to zero size
 * @return size of the cbor encoded data
 * @return -1 on error
 */
int oc_rep_get_encoded_payload_size_v1(bool truncateEmpty);

/**
 * @brief Check whether property matches by name.
 *
 * @param rep object to check (cannot be NULL)
 * @param propname property name (cannot be NULL)
 * @param propname_len length of property name
 * @return true if property name matches
 * @return false otherwise
 */
bool oc_rep_is_property(const oc_rep_t *rep, const char *propname,
                        size_t propname_len) OC_NONNULL();

/**
 * @brief Check whether property matches by type and name.
 *
 * @param rep object to check (cannot be NULL)
 * @param proptype property type
 * @param propname property name (cannot be NULL)
 * @param propname_len length of property name
 * @return true
 * @return false
 */
bool oc_rep_is_property_with_type(const oc_rep_t *rep,
                                  oc_rep_value_type_t proptype,
                                  const char *propname, size_t propname_len)
  OC_NONNULL();

/**
 * @brief Check whether the name and type of the property object matches one of
 * the Common resource properties.
 *
 * @param rep object to check (cannot be NULL)
 * @return true if property name matches
 * @return false otherwise
 *
 * @see oc_process_baseline_interface
 */
bool oc_rep_is_baseline_interface_property(const oc_rep_t *rep) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_INTERNAL_H */
