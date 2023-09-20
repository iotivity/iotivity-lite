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

#include "Endpoint.h"

#include "api/oc_endpoint_internal.h"
#include "oc_helpers.h"

#include <array>
#include <gtest/gtest.h>

namespace oc::endpoint {

oc_endpoint_t
FromString(const std::string &ep_str)
{
  oc_string_t ep_ocstr;
  oc_new_string(&ep_ocstr, ep_str.c_str(), ep_str.length());
  oc_endpoint_t ep{};
  int ret = oc_string_to_endpoint(&ep_ocstr, &ep, nullptr);
  oc_free_string(&ep_ocstr);
  EXPECT_EQ(0, ret) << "cannot convert endpoint " << ep_str;
  return ep;
}

int
FromString(const std::string &addr, oc_endpoint_t *ep, oc_string_t *uri)
{
  oc_string_t s;
  oc_new_string(&s, addr.c_str(), addr.length());
  int ret = oc_string_to_endpoint(&s, ep, uri);
  oc_free_string(&s);
  return ret;
}

std::string
ToAddress(const oc_endpoint_t &ep)
{
  oc_string64_t ep_str{};
  oc_endpoint_to_string64(&ep, &ep_str);
  std::string s(oc_string(ep_str));
  return s;
}

std::string
ToHost(const oc_endpoint_t &ep)
{
  std::array<char, 50> buffer{};
  EXPECT_LT(0, oc_endpoint_host(&ep, buffer.data(), buffer.size()));
  return std::string(buffer.data());
}

} // namespace oc::endpoint
