/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#ifndef OC_ENUMS_INTERNAL_H
#define OC_ENUMS_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_enums.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Convert enum value to string view */
oc_string_view_t oc_enum_to_string_view(oc_enum_t val);

/** @brief Convert string to enum value */
bool oc_enum_from_str(const char *enum_str, size_t enum_strlen, oc_enum_t *val)
  OC_NONNULL(3);

/** @brief Convert the position description to string view */
oc_string_view_t oc_enum_pos_desc_to_string_view(oc_pos_description_t pos);

/** @brief Convert string to position description */
bool oc_enum_pos_desc_from_str(const char *pos_str, size_t pos_strlen,
                               oc_pos_description_t *pos) OC_NONNULL(3);

/** @brief Convert the location to string view */
oc_string_view_t oc_enum_locn_to_string_view(oc_locn_t locn);

/** @brief Convert string to location */
bool oc_enum_locn_from_str(const char *locn_str, size_t locn_strlen,
                           oc_locn_t *locn) OC_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENUMS_INTERNAL_H */
