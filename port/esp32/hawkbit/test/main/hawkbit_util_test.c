/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "../../hawkbit_util.h"

#include "unity.h"
#include <string.h>

TEST_CASE("sha256 hash to hex string", "[hawkbit][util]")
{
  hawkbit_sha256_hash_t hash = {
    .data = "0bf474896363505e5ea5e5d6ace8ebfb13a760a409b1fb467d428fc716f9f284",
  };
  hawkbit_sha256_digest_t digest = hawkbit_sha256_hash_to_digest(hash);
  char data[HAWKBIT_SHA256_DIGEST_SIZE + 1];
  memcpy(data, digest.data, sizeof(digest.data));
  data[HAWKBIT_SHA256_DIGEST_SIZE] = 0;
  //   printf("digest: %s\n", data);
  hawkbit_sha256_hash_t hash2 = hawkbit_sha256_digest_to_hash(digest);
  //   printf("hash: %s\n", hash.data);
  //   printf("hash2: %s\n", hash2.data);
  TEST_ASSERT_EQUAL_MEMORY(hash.data, hash2.data, sizeof(hash.data));
}

TEST_CASE("parse hawkbit url", "[hawkbit][util]")
{
  TEST_ASSERT_FALSE(hawkbit_parse_package_url("test", NULL));

  hawkbit_url_t url;
  TEST_ASSERT_TRUE(
    hawkbit_parse_package_url("https://hawkbit.try.plgd.cloud", &url));
  TEST_ASSERT_EQUAL_STRING("https://hawkbit.try.plgd.cloud", url.server_url);
  TEST_ASSERT_NULL(url.controller_id);
  TEST_ASSERT_NULL(url.tenant);

#define BASE_URL "https://hawkbit.try.plgd.cloud"
#define TENANT_ID "TENANT_ID"
#define CONTROLLER_ID "CONTROLLER_ID"

  TEST_ASSERT_TRUE(hawkbit_parse_package_url(BASE_URL "/" TENANT_ID, &url));
  TEST_ASSERT_EQUAL(url.server_url_length, sizeof(BASE_URL) - 1);
  TEST_ASSERT_EQUAL_MEMORY(BASE_URL, url.server_url, url.server_url_length);
  TEST_ASSERT_EQUAL(url.tenant_length, sizeof(TENANT_ID) - 1);
  TEST_ASSERT_EQUAL_MEMORY(TENANT_ID, url.tenant, url.tenant_length);
  TEST_ASSERT_NULL(url.controller_id);

  TEST_ASSERT_TRUE(hawkbit_parse_package_url(
    BASE_URL "/" TENANT_ID "/controller/v1/" CONTROLLER_ID, &url));
  TEST_ASSERT_EQUAL(url.server_url_length, sizeof(BASE_URL) - 1);
  TEST_ASSERT_EQUAL_MEMORY(BASE_URL, url.server_url, url.server_url_length);
  TEST_ASSERT_EQUAL(url.tenant_length, sizeof(TENANT_ID) - 1);
  TEST_ASSERT_EQUAL_MEMORY(TENANT_ID, url.tenant, url.tenant_length);
  TEST_ASSERT_EQUAL(url.controller_id_length, sizeof(CONTROLLER_ID) - 1);
  TEST_ASSERT_EQUAL_MEMORY(CONTROLLER_ID, url.controller_id,
                           url.controller_id_length);
}
