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

#include "oc_role.h"

#include <memory>
#include <string>
#include <stddef.h>
#include <vector>

namespace oc {

class Role {
public:
  Role(const std::string &role, const std::string &authority = "");
  ~Role();

  Role(Role &other) = delete;
  Role &operator=(const Role &Role) = delete;
  Role(Role &&fp) noexcept = delete;
  Role &operator=(Role &&fp) = delete;

  oc_role_t *Data() { return &role_; }

private:
  oc_role_t role_{};
};

class Roles {
public:
  void Add(const std::string &role, const std::string &authority = "");
  oc_role_t *Head() const;
  oc_role_t *Get(size_t index) const;
  void Clear() { roles_.clear(); };

private:
  std::vector<std::unique_ptr<Role>> roles_{};
};

} // namespace oc
