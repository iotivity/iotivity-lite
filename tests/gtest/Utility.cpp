/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "Utility.h"

namespace oc {

std::vector<std::string>
GetVector(const oc_string_array_t &array)
{
  std::vector<std::string> vector;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(array); ++i) {
    const char *str = (const char *)oc_string_array_get_item(array, i);
    if (str != nullptr && str[0] != '\0') {
      vector.push_back(str);
    }
  }
  return vector;
}

} // namespace oc
