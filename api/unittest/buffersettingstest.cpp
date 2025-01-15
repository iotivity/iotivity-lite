/****************************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#include "messaging/coap/conf.h"
#include "oc_buffer_settings.h"
#include "util/oc_features.h"

#include "gtest/gtest.h"

#ifdef OC_DYNAMIC_ALLOCATION

TEST(TestBufferSettings, SetMTUSize)
{
#ifdef OC_INOUT_BUFFER_SIZE
  EXPECT_EQ(-1, oc_set_mtu_size(42));
#else /* !OC_INOUT_BUFFER_SIZE */
#ifdef OC_BLOCK_WISE
  EXPECT_EQ(-1, oc_set_mtu_size(42));
  EXPECT_EQ(0, oc_set_mtu_size(oc_get_mtu_size()));
#endif /* OC_BLOCK_WISE */
#endif /* OC_INOUT_BUFFER_SIZE */
}

#ifndef OC_APP_DATA_BUFFER_SIZE

TEST(TestBufferSettings, SetMaxAppDataSize)
{
  auto max_app_size = static_cast<size_t>(oc_get_max_app_data_size());
  oc_set_max_app_data_size(42);
  EXPECT_EQ(42, oc_get_max_app_data_size());

  oc_set_max_app_data_size(max_app_size);
}

#ifdef OC_REP_ENCODING_REALLOC

TEST(TestBufferSettings, SetMinAppDataSize)
{
  auto min_app_size = static_cast<size_t>(oc_get_min_app_data_size());
  oc_set_min_app_data_size(42);
  EXPECT_EQ(42, oc_get_min_app_data_size());

  oc_set_min_app_data_size(min_app_size);
}

#endif /* OC_REP_ENCODING_REALLOC */

#endif /* !OC_APP_DATA_BUFFER_SIZE */

#else /* !OC_DYNAMIC_ALLOCATION  */

TEST(TestBufferSettings, SetMTUSize)
{
  EXPECT_EQ(-1, oc_set_mtu_size(42));
  EXPECT_EQ(-1, oc_get_mtu_size());
}

TEST(TestBufferSettings, SetMaxAppDataSize)
{
  oc_set_max_app_data_size(42);
  EXPECT_EQ(-1, oc_get_max_app_data_size());
}

TEST(TestBufferSettings, SetMinAppDataSize)
{
  oc_set_min_app_data_size(42);
  EXPECT_EQ(-1, oc_get_min_app_data_size());
}

TEST(TestBufferSettings, GetBlockSize)
{
  EXPECT_EQ(-1, oc_get_block_size());
}

#endif /* OC_DYNAMIC_ALLOCATION */
