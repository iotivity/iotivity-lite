/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef HAWKBIT_JSON_H
#define HAWKBIT_JSON_H

#include <cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Get json array at given path
const cJSON *hawkbit_json_get_array(const cJSON *node, const char *path);

/// Get integer at given path
double hawkbit_json_get_number(const cJSON *node, const char *path,
                               double defaultValue);

/// Get object at given path
const cJSON *hawkbit_json_get_object(const cJSON *node, const char *path);

/// Get string at given path
const char *hawkbit_json_get_string(const cJSON *node, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_JSON_H */
