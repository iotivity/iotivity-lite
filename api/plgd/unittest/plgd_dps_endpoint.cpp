/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/plgd/device-provisioning-client/plgd_dps_endpoint_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_uuid.h"

#include "gtest/gtest.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

TEST(DPSApiTest, EndpointIsEmpty)
{
  oc_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(oc_endpoint_t));
  EXPECT_TRUE(dps_endpoint_is_empty(&endpoint));

  std::string ep_str{ "coap://224.0.1.187:5683" };
  oc_string_t ep_ocstr;
  oc_new_string(&ep_ocstr, ep_str.c_str(), ep_str.length());
  oc_string_to_endpoint(&ep_ocstr, &endpoint, nullptr);
  oc_free_string(&ep_ocstr);
  EXPECT_FALSE(dps_endpoint_is_empty(&endpoint));
}

TEST(DPSApiTest, EndpointToString)
{
  EXPECT_FALSE(dps_endpoint_log_string(nullptr, nullptr, 0));

  std::vector<char> out;
  out.resize(5);
  EXPECT_FALSE(dps_endpoint_log_string(nullptr, out.data(), out.size()));

  std::string ep_str = "coap://224.0.1.187:5683";
  oc_string_t ep_ocstr;
  oc_new_string(&ep_ocstr, ep_str.c_str(), ep_str.length());
  oc_endpoint_t endpoint;
  EXPECT_EQ(0, oc_string_to_endpoint(&ep_ocstr, &endpoint, nullptr));
  oc_free_string(&ep_ocstr);

  out.resize(ep_str.size() - 1);
  EXPECT_FALSE(dps_endpoint_log_string(&endpoint, out.data(), out.size()));

#if DPS_DBG_IS_ENABLED
  std::string exp_str = "endpoint(addr=" + ep_str + ", session_id=-1)";
#else  // !DPS_DBG_IS_ENABLED
  std::string exp_str = "endpoint(" + ep_str + ")";
#endif // DPS_DBG_IS_ENABLED
  out.resize(exp_str.size() + 1);
  EXPECT_TRUE(dps_endpoint_log_string(&endpoint, out.data(), out.size()));
  EXPECT_STREQ(exp_str.c_str(), out.data());
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */
