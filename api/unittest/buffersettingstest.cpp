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

TEST(BufferSettings, SetMTUSize)
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

TEST(BufferSettings, SetMaxAppDataSize)
{
  size_t max_app_size = static_cast<size_t>(oc_get_max_app_data_size());
  oc_set_max_app_data_size(42);
  EXPECT_EQ(42, oc_get_max_app_data_size());

  oc_set_max_app_data_size(max_app_size);
}

#if !defined(OC_APP_DATA_BUFFER_SIZE) && defined(OC_REP_ENCODING_REALLOC)

TEST(BufferSettings, SetMinAppDataSize)
{
  size_t min_app_size = static_cast<size_t>(oc_get_min_app_data_size());

  oc_set_min_app_data_size(42);
  EXPECT_EQ(42, oc_get_min_app_data_size());

  oc_set_min_app_data_size(max_app_size);
}

#endif /* !OC_APP_DATA_BUFFER_SIZE && OC_REP_ENCODING_REALLOC */

#else /* !OC_DYNAMIC_ALLOCATION  */

TEST(BufferSettings, SetMTUSize)
{
  EXPECT_EQ(-1, oc_set_mtu_size(42));
  EXPECT_EQ(-1, oc_get_mtu_size());
}

TEST(BufferSettings, SetMaxAppDataSize)
{
  oc_set_max_app_data_size(42);
  EXPECT_EQ(-1, oc_get_max_app_data_size());
}

TEST(BufferSettings, SetMinAppDataSize)
{
  oc_set_min_app_data_size(42);
  EXPECT_EQ(-1, oc_get_min_app_data_size());
}

TEST(BufferSettings, GetBlockSize)
{
  EXPECT_EQ(-1, oc_get_block_size());
}

#endif /* OC_DYNAMIC_ALLOCATION */
