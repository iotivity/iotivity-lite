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

#include "oc_base64.h"

/* This module implements routines for Base64 encoding/decoding
 * based on their definitions in RFC 4648.
 */

int
oc_base64_encode(const uint8_t *input, int input_len, uint8_t *output_buffer,
                 int output_buffer_len)
{
  /* The Base64 alphabet. This table provides a mapping from 6-bit binary
   * values to Base64 characters.
   */
  uint8_t alphabet[65] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                           'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                           'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
                           'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                           'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                           'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', '+', '/', '=' };
  uint8_t val = 0;
  int i, j = 0;

  /* Calculate the length of the Base64 encoded output.
   * Every sequence of 3 bytes (with padding, if necessary)
   * is represented as 4 bytes (characters) in Base64.
   */
  int output_len = (input_len / 3) * 4;
  if (input_len % 3 != 0) {
    output_len += 4;
  }

  /* If the output buffer provided was not large enough, return an error. */
  if (output_buffer_len < output_len)
    return -1;

  /* Process every byte of input by keeping state across 3 byte blocks
   * to capture 4 6-bit binary blocks that each map to a Base64 character.
   */
  for (i = 0; i < input_len; i++) {
    /* This is the first byte of a 3 byte block of input. Its first
     * 6 bits would be encoded into a character from the Base64 alphabet.
     * Its last 2 bits would be the first 2 bits of the following 6-bit binary
     * block.
     * Explicitly zero out the remaining bits.
     */
    if (i % 3 == 0) {
      val = (input[i] >> 2);
      output_buffer[j++] = alphabet[val];
      val = input[i] << 4;
      val &= 0x30;
    }
    /* This is the second byte of a 3 byte block of input. Combine
     * the last 2 bits of the previous byte of input with the first 4 bits
     * of the current byte of input to encode the next Base64 character.
     * Its last 4 bits would be the first 4 bits of the following 6-bit binary
     * block.
     * Explicitly zero out the remaining bits.
     */
    else if (i % 3 == 1) {
      val |= (input[i] >> 4);
      output_buffer[j++] = alphabet[val];
      val = input[i] << 2;
      val &= 0x3D;
    }
    /* This is the last byte of a 3 byte block of input. Combine
     * the last 4 bits of the previous byte of input with the first 2 bits
     * of the current byte of input to encode the next Base64 character.
     * Its last 6 bits directly map to the following Base64 character
     * thereby completing a 4 byte encoding of the preceeding 3 byte
     * block of input.
     */
    else {
      val |= (input[i] >> 6);
      output_buffer[j++] = alphabet[val];
      val = input[i] & 0x3F;
      output_buffer[j++] = alphabet[val];
    }
  }

  /* If the input size wasn't a multiple of 3, we would
   * have leftover bits to encode into the next Base64 character.
   */
  if (i % 3 != 0) {
    output_buffer[j++] = alphabet[val];
  }

  /* Any leftover space in the encoded string is padded with the
   * = character.
   */
  while (j < output_len) {
    output_buffer[j++] = '=';
  }

  return j;
}

int
oc_base64_decode(uint8_t *str, int len)
{
  /* The Base64 input string is decoded in-place. */
  int i = 0, j = 0;
  unsigned char val_c = 0, val_s = 0;

  /* Process every input character */
  for (i = 0; i < len; i++) {
    val_s = str[i];

    /* Perform a reverse-mapping from Base64 character to
     * a 6-bit binary sequence.
     */
    if (val_s >= 'A' && val_s <= 'Z')
      val_s -= 65;
    else if (val_s >= 'a' && val_s <= 'z')
      val_s -= 71;
    else if (val_s >= '0' && val_s <= '9')
      val_s += 4;
    else if (val_s == '+')
      val_s = 62;
    else if (val_s == '/')
      val_s = 63;
    /* Break if we encounter the padding character.
     * The input buffer str now contains the fully decoded string.
     */
    else if (val_s == '=')
      break;
    /* Return an error if we encounter a character that is outside
     * of the Base64 alphabet.
     */
    else
      return -1;

    /* Decode all 4 byte blocks to 3 bytes of binary output by
     * laying out their 6-bit blocks into a sequence of 3 bytes.
     */
    if (i % 4 == 0) {
      /* 1st 6 bits of output byte 1 */
      val_c = val_s << 2;
      val_c &= 0xFD;
    } else if (i % 4 == 1) {
      /* Last 2 bits of output byte 1 */
      val_c |= (val_s >> 4);
      str[j++] = val_c;
      /* 1st 4 bits of output byte 2 */
      val_c = val_s << 4;
      val_c &= 0xF0;
    } else if (i % 4 == 2) {
      /* Last 4 bits of output byte 2 */
      val_c |= (val_s >> 2);
      str[j++] = val_c;
      /* 1st 2 bits of output byte 3 */
      val_c = val_s << 6;
      val_c &= 0xD0;
    } else {
      /* Last 6 bits of output byte 3 */
      val_c |= val_s;
      str[j++] = val_c;
    }
  }

  for (i = j; i < len; i++) {
    str[i] = 0;
  }

  return j;
}
