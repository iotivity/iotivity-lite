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

#include "Role.h"

namespace oc {

Role::Role(const std::string &role, const std::string &authority = "")
{
  if (!role.empty()) {
    oc_new_string(&role_.role, role.c_str(), role.length());
  }
  if (!authority.empty()) {
    oc_new_string(&role_.authority, authority.c_str(), authority.length());
  }
}

Role::~Role()
{
  oc_free_string(&role_.role);
  oc_free_string(&role_.authority);
}

void
Roles::Add(const std::string &role, const std::string &authority)
{
  roles_.push_back(std::unique_ptr<Role>(new Role(role, authority)));

  for (size_t i = 1; i < roles_.size(); ++i) {
    roles_[i - 1]->Data()->next = roles_[i]->Data();
  }
  roles_.back()->Data()->next = nullptr;
}

oc_role_t *
Roles::Get(size_t index) const
{
  return roles_.at(index)->Data();
}

oc_role_t *
Roles::Head() const
{
  return roles_.front()->Data();
}

} // namespace oc
