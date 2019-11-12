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
 * @file
 * Generate and work with UUIDs as specified in RFC 4122.
 *
 * This module implements the generation of version-4 UUIDs
 * based on its specification in RFC 4122, along with routines
 * to convert between their string and binary representations.
 */
#ifndef OC_UUID_H
#define OC_UUID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * The length of a UUID string.
 *
 * This is the length of UUID string as specified by RFC 4122.
 * @see oc_uuid_to_str
 */
#define OC_UUID_LEN (37)

typedef struct
{
  uint8_t id[16];
} oc_uuid_t;

/**
 * Convert a UUID string representation to a 128-bit oc_uuid_t
 *
 * @note oc_str_to_uuid has a special case that does not conform to RFC 4122
 *       if the first character of the `str` is '*' then the first byte of the
 *       oc_uuid_t will be set to '*' (0x2A) and the other bytes will be set
 *       to zero.
 *
 * Example
 * ```
 * oc_uuid_t uuid;
 * oc_str_to_uuid("1628fbcc-13ce-4e37-b883-1fd8d2ad945d", &uuid);
 * ```
 * @param[in] str the UUID string
 * @param[out] uuid the oc_uuid_t to hold the UUID bits.
 */
void oc_str_to_uuid(const char *str, oc_uuid_t *uuid);

/**
 * Convert the 128 bit oc_uuid_t to a sting representation.
 *
 * The string representation of the UUID will be as specified in RFC 4122.
 *
 * @note oc_uuid_to_str has a special case that does not conform to RFC 4122
 *       if the first byte of oc_uuid_t is set to '*' (0x2A) this will return a
 *       string "*".
 *
 * Example
 * ```
 * oc_uuid_t device_uuid = { { 0 } };
 * oc_gen_uuid(&device_uuid);
 * char uuid_str[OC_UUID_LEN] = { 0 };
 * oc_uuid_to_str(&device_uuid, uuid_str, OC_UUID_LEN);
 * ```
 *
 * @param[in] uuid A oc_uuid_t to convert to a string
 * @param[out] buffer A char array that will hold the string representation of
 * the UUID
 * @param [in] buflen The size of the input buffer.
 *                    Recommend always using OC_UUID_LEN for buflen.
 */
void oc_uuid_to_str(const oc_uuid_t *uuid, char *buffer, int buflen);
/**
 * Generate a random Universally Unique IDentifier (UUID)
 *
 * This will return a 128 bit version 4 UUID as specified by RFC 4122.
 *
 * Version 4 UUID is created using random or pseudo-random numbers
 *
 * Example
 * ```
 * oc_uuid_t device_uuid = { { 0 } };
 * oc_gen_uuid(&device_uuid);
 * ```
 *
 * @param[out] uuid the randomly generated UUID
 */
void oc_gen_uuid(oc_uuid_t *uuid);

#ifdef __cplusplus
}
#endif

#endif /* OC_UUID_H */
