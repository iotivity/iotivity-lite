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
