/* ****************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#ifndef _ES_UTILS_H_
#define _ES_UTILS_H_

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Some type conversion helpers
 * For all *enum_tostring(...) functions: They take the Enum Type Value as input (val), and return
 * the corresponding string representation, which conforms to the OCF specification.
 * For all *string_toenum(...) functions: They take the string representation, as per the OCF
 * specification as input (val_in). And return the Enum Value in val_out. If conversion fails,
 * false is returned by the function.
 */

/**
 * convert wifi mode value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_mode_enum_tostring(wifi_mode val);

/**
 * convert wifi freq value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_freq_enum_tostring(wifi_freq val);

/**
 * convert wifi auth type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_authtype_enum_tostring(wifi_authtype val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool wifi_authtype_string_toenum(const char *val, wifi_authtype *val_out);

/**
 * convert wifi enc type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_enctype_enum_tostring(wifi_enctype val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool wifi_enctype_string_toenum(const char *val, wifi_enctype *val_out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _ES_UTILS_H_
