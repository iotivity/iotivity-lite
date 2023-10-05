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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#pragma once

#include "oc_helpers.h"

#include <string>
#include <vector>

namespace oc {

/** Convert oc_string_array_t to a vector<string> */
std::vector<std::string> GetVector(const oc_string_array_t &array);

template<typename To>
std::vector<To>
GetVector(const std::string &str, bool includeTerminator = false)
{
  std::vector<To> arr;
  arr.resize(str.length());
  for (size_t i = 0; i < str.length(); ++i) {
    arr[i] = static_cast<To>(str[i]);
  }
  if (includeTerminator) {
    arr.push_back(static_cast<To>('\0'));
  }
  return arr;
}

template<typename From>
std::string
GetString(From *arr, size_t arrSize)
{
  std::string str{};
  str.resize(arrSize);
  for (size_t i = 0; i < arrSize; ++i) {
    str[i] = static_cast<char>(arr[i]);
  }
  // add null-terminator if not present
  if (arrSize > 0 && arr[arrSize - 1] != '\0') {
    str.push_back('\0');
  }
  return str;
}

} // namespace oc
