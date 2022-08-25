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

#include "oc_config.h"

#ifdef OC_STORAGE

#include "Storage.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"

#include <filesystem>
#include <gtest/gtest.h>

namespace oc {

Storage TestStorage{ "./storage_test" };

Storage::Storage(const std::string &path)
  : path_{ path }
{
}

Storage::~Storage()
{
  Clear();
}

int
Storage::Config()
{
  return oc_storage_config(path_.c_str());
}

int
Storage::Clear()
{
  for (const auto &entry : std::filesystem::directory_iterator(path_)) {
    std::filesystem::remove_all(entry.path());
  }
  return oc_storage_reset();
}

} // namespace oc

#endif /* OC_STORAGE */
