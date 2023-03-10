/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam
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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether the name of the property object matches parameters.
 *
 * @param rep object to check (cannot be NULL)
 * @param propname property name (cannot be NULL)
 * @param propname_len length of property name
 * @return true if property name matches
 * @return false otherwise
 */
bool oc_rep_is_property(const oc_rep_t *rep, const char *propname,
                        size_t propname_len);

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
bool oc_rep_is_baseline_interface_property(const oc_rep_t *rep);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_INTERNAL_H */
