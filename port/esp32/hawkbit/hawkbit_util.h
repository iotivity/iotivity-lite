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

#ifndef HAWKBIT_UTIL_H
#define HAWKBIT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAWKBIT_MAC_ADDRESS_SIZE 18

typedef struct
{
  char address[HAWKBIT_MAC_ADDRESS_SIZE];
} hawkbit_mac_address_t;

/**
 * @brief Get MAC address of the device.
 *
 * @param[out] address output variable to store the obtained address (cannot be
 * NULL)
 * @return true on success
 * @return false otherwise
 */
bool hawkbit_get_mac_address(hawkbit_mac_address_t *address);

#define HAWKBIT_SHA1_DIGEST_SIZE 20
#define HAWKBIT_SHA1_HASH_SIZE ((20 * 2) + 1)

typedef struct
{
  uint8_t data[HAWKBIT_SHA1_DIGEST_SIZE];
} hawkbit_sha1_digest_t;

typedef struct
{
  char data[HAWKBIT_SHA1_HASH_SIZE];
} hawkbit_sha1_hash_t;

/** Convert sha1 hex string to byte array */
hawkbit_sha1_digest_t hawkbit_sha1_hash_to_digest(hawkbit_sha1_hash_t hash);

/** Convert sha1 byte array to hex string */
hawkbit_sha1_hash_t hawkbit_sha1_digest_to_hash(hawkbit_sha1_digest_t digest);

#define HAWKBIT_SHA256_DIGEST_SIZE 32
#define HAWKBIT_SHA256_HASH_SIZE ((32 * 2) + 1)

typedef struct
{
  uint8_t data[HAWKBIT_SHA256_DIGEST_SIZE];
} hawkbit_sha256_digest_t;

typedef struct
{
  char data[HAWKBIT_SHA256_HASH_SIZE];
} hawkbit_sha256_hash_t;

/** Convert sha256 hex string to byte array */
hawkbit_sha256_digest_t hawkbit_sha256_hash_to_digest(
  hawkbit_sha256_hash_t hash);

/** Convert sha256 byte array to hex string */
hawkbit_sha256_hash_t hawkbit_sha256_digest_to_hash(
  hawkbit_sha256_digest_t digest);

typedef struct
{
  const char *server_url;
  size_t server_url_length;
  const char *tenant;
  size_t tenant_length;
  const char *controller_id;
  size_t controller_id_length;
} hawkbit_url_t;

/**
 * @brief Verify package url and parse it to Hawkbit url components.
 *
 * @param[in] purl package url
 * @param[out] url offsets (from the input package url) and lengths of expected
 * Hawkbit url components
 * @return true on success
 * @return false on failure
 */
bool hawkbit_parse_package_url(const char *purl, hawkbit_url_t *url);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_UTIL_H */
