/*
// Copyright (c) 2017 Intel Corporation
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
  @file
*/
#ifndef OC_BASE64_H
#define OC_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * encode byte buffer to base64 string. The base64 encoder does not NUL terminate
 * its output. User the return value to add '\0' to the end of the string.
 *
 * Output is uint8_t casting is needed to use value as a string.
 *
 * Example:
 *
 *    // calculate the space required for the output
 *    size_t b64_buf_size = (sizeof(input) / 3) * 4;
 *    if (sizeof(input) % 3 != 0) {
 *      b64_buf_size += 4;
 *    }
 *    // one extra byte for terminating NUL character.
 *    b64_buf_size++;
 *    // allocate space
 *    char *b64_buf = (char *)calloc(1, b64_buf_size);
 *    int output_len = oc_base64_encode(input, sizeof(input), (uint8_t *)b64_buf, b64_buf_size);
 *    if (output_len < 0) {
 *       //handle error
 *    }
 *    // append NUL character to end of string.
 *    b64Buf[output_len] = '\0';
 *
 * @param[in]  input pointer to input byte array to be encoded
 * @param[in]  input_len size of input byte array
 * @param[out] output_buffer buffer to hold the base 64 encoded string
 * @param[in]  output_buffer_len size of the output_buffer
 *
 * @return
 *    - the size of the base64 encoded string
 *    - `-1` if the output buffer provided was not large enough
 */
int oc_base64_encode(const uint8_t *input, size_t input_len,
                     uint8_t *output_buffer, size_t output_buffer_len);

/**
 * In place decoding of base 64 string. Size of a base 64 input string will
 * always be larger than the resulting byte array. Unused trailing bytes will
 * be set to zero. Use the return value to know the size of the output array.
 *
 * Example:
 *    output_len = oc_base64_decode(b64_buf, strlen(b64_buf));
 *    if (output_len < 0) {
 *      //handle error
 *    }
 *
 * @param[in,out] str base 64 encoded string that will be decoded in place.
 * @param[in] len size of the base 64 encoded string.
 * @return
 *   - The size the the decoded byte array
 *   - '-1' if unable to decode string. This should only happen if the string
 *     is not a properly encoded base64 string.
 */
int oc_base64_decode(uint8_t *str, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* OC_BASE64_H */
