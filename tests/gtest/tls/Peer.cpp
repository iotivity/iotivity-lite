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

#ifdef OC_SECURITY

#include "Peer.h"

#include "oc_uuid.h"

#include <iostream>
#include <iomanip>
#include <sstream>

namespace oc::tls {

Peer
MakePeer(const std::string &addr, int role)
{
  static size_t peerCount = 0;
  std::ostringstream ostr;
  ostr << std::setfill('0') << std::setw(12) << peerCount;

  std::string uuid = "00000000-0000-0000-0000-" + ostr.str();
  ++peerCount;

  Peer peer{};
  peer.address = addr;
  oc_str_to_uuid(uuid.c_str(), &peer.uuid);
  peer.role = role;
  return peer;
}

} // namespace  oc::tls

#endif /* OC_SECURITY */
