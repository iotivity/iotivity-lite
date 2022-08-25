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

#pragma once

#include "oc_config.h"

#ifdef OC_STORAGE

#include <string>

namespace oc {

class Storage {
public:
  Storage(const std::string &path);
  ~Storage();

  std::string Path() const { return path_; }
  int Config();
  int Clear();

  Storage(Storage &other) = delete;
  Storage &operator=(const Storage &Role) = delete;
  Storage(Storage &&fp) noexcept = delete;
  Storage &operator=(Storage &&fp) noexcept = delete;

private:
  std::string path_;
};

extern Storage TestStorage;

} // namespace oc

#endif /* OC_STORAGE */
