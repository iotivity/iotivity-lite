/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
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
/**
  @file
*/
#ifndef OC_BASE64_H
#define OC_BASE64_H

#include "oc_export.h"
#include "util/oc_compiler.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode byte buffer to base64 string. The base64 encoder does not NUL
 * terminate its output. User the return value to add '\0' to the end of the
 * string.
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
 *    int output_len = oc_base64_encode(input, sizeof(input), (uint8_t
 * *)b64_buf, b64_buf_size); if (output_len < 0) {
 *       //handle error
 *    }
 *    // append NUL character to end of string.
 *    b64Buf[output_len] = '\0';
 *
 * @param[in] input pointer to input byte array to be encoded
 * @param[in] input_size size of input byte array
 * @param[out] output_buffer buffer to hold the base 64 encoded string
 * @param[in] output_buffer_size size of the output_buffer
 *
 * @return
 *    - the size of the base64 encoded string
 *    - `-1` if the output buffer provided was not large enough
 */
OC_API
int oc_base64_encode(const uint8_t *input, size_t input_size,
                     uint8_t *output_buffer, size_t output_buffer_size);

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
OC_API
int oc_base64_decode(uint8_t *str, size_t len);

typedef enum {
  OC_BASE64_ENCODING_STD, // encode using standard base64 encoding
  OC_BASE64_ENCODING_URL, // encode using URL safe base64 encoding
} oc_base64_encoding_t;

/**
 * Calculate the size of the output buffer required to encode a byte array to
 * base64.
 *
 * @param size size of the input byte array
 * @param padding true if padding should be used
 *
 * @return size of the output buffer required to encode the input byte array
 */
OC_API
size_t oc_base64_encoded_output_size(size_t size, bool padding);

/**
 * Encode byte buffer to base64 string. The base64 encoder does not NUL
 * terminate its output. User the return value to add '\0' to the end of the
 * string.
 *
 * @param encoding type of encoding to use
 * @param padding true if padding should be used
 * @param input pointer to input byte array to be encoded
 * @param input_size size of input byte array
 * @param[out] output_buffer buffer to hold the base 64 encoded string
 * @param output_buffer_size size of the output_buffer
 *
 * @return
 *    - the size of the base64 encoded string
 *    - `-1` if the output buffer provided was not large enough
 */
OC_API
int oc_base64_encode_v1(oc_base64_encoding_t encoding, bool padding,
                        const uint8_t *input, size_t input_size,
                        uint8_t *output_buffer, size_t output_buffer_size);

/**
 * Calculate the size of the output buffer required to store a decoded base64
 * array.
 *
 * @param input input base64-encoded array
 * @param input_size size of the input base64-encoded array
 * @param padding true if the input array is padded with '=' characters at the
 * end
 *
 * @return -1 if the input array is not a valid base64-encoded array
 * @return size of the output buffer required to decode the input array
 */
OC_API
int oc_base64_decoded_output_size(const uint8_t *input, size_t input_size,
                                  bool padding);

/**
 * Decode a base64 array to a byte array.
 *
 * @param encoding type of encoding to use
 * @param padding true if the input array is padded with '=' characters at the
 * end
 * @param input pointer to base64 encoded string
 * @param input_size size of base64 encoded string
 * @param[out] output_buffer buffer to hold the decoded byte array
 * @param output_buffer_size size of the output_buffer
 *
 * @return -1 on failure
 * @return >=0 the size of the decoded byte array on success
 */
OC_API
int oc_base64_decode_v1(oc_base64_encoding_t encoding, bool padding,
                        const uint8_t *input, size_t input_size,
                        uint8_t *output_buffer, size_t output_buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_BASE64_H */
