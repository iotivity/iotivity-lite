/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

/**
  @brief Internal discovery API
  @file
*/


#ifndef OC_DISCOVERY_H
#define OC_DISCOVERY_H
#include "oc_endpoint.h"

#ifdef __cplusplus
extern "C"
{
#endif

void oc_create_discovery_resource(int resource_idx, size_t device);

/**
  @brief Gets the pseudo device number at the specified endpoint.
  @note The device number is only based on the discovery sequence
   of devices and not related to any internal device setup with
   the stack.
  @param endpoint endpoint to retrieve the device number for
  @return The pseudo device number of the specified endpoint
   or zero if not known or \c endpoint is NULL.
*/
uint8_t oc_discovery_get_device(oc_endpoint_t *endpoint);

/**
  @brief Adds all specified endpoints to the endpoint cache.

  The function adds \c source (without next) and all endpoints listed
  in \c eps to the internal endpoint cache. These are associated together
  as single device to be finally queried via
  \c oc_discovery_get_device().

  If any of the endpoints is already registered, then the so far unknown
  endpoints are associated with the already known device number.

  @param source typically the origin of an incoming packet, ignored if NULL
  @param eps typically the eps provided in the discovery response,
   ignored if NULL
*/
void oc_discovery_add_eps_to_cache(oc_endpoint_t *source, oc_endpoint_t *eps);

#ifdef __cplusplus
}
#endif

#endif /* OC_DISCOVERY_H */
