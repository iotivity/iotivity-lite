/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "coap_options_iterator.h"
#include "port/oc_log_internal.h"

#include <assert.h>
#include <stdint.h>

coap_options_iterator_t
coap_options_iterator_init(uint8_t *options, const uint8_t *packetEndOffset)
{
  assert(options <= packetEndOffset);
  return (coap_options_iterator_t){
    .options = options,
    .packetEndOffset = packetEndOffset,

    .current = { 
        .value = NULL,
        .length = 0,
        .number = 0,
        .payload = false,
    },
  };
}

void
coap_options_iterator_reset(coap_options_iterator_t *it)
{
  it->current.value = NULL;
  it->current.length = 0;
  it->current.number = 0;
  it->current.payload = false;
}

coap_option_data_t *
coap_options_iterator_get_option(coap_options_iterator_t *it)
{
  return &it->current;
}

static uint8_t *
coap_options_iterator_next_offset(coap_options_iterator_t *it)
{
  uint8_t *next;
  if (it->current.value == NULL) {
    next = it->options;
  } else {
    if (it->current.payload) {
      return NULL;
    }
    next = it->current.value + it->current.length;
  }
  if (next >= it->packetEndOffset) {
    return NULL;
  }
  return next;
}

coap_option_iterator_result_t
coap_options_iterator_next(coap_options_iterator_t *it)
{
  // move to the next offset
  uint8_t *next = coap_options_iterator_next_offset(it);
  if (next == NULL) {
    return COAP_OPTION_ITERATOR_NO_MORE_OPTIONS;
  }

  uint8_t *current_option = next;
  /* payload marker 0xFF, currently only checking for 0xF* because rest is
   * reserved */
  if ((current_option[0] & 0xF0) == 0xF0) {
    OC_DBG("Payload marker found");
    // skip past the payload marker
    it->current.value = current_option + 1;
    it->current.number = 0;
    it->current.length = it->packetEndOffset - it->current.value;
    it->current.payload = true;
    return COAP_OPTION_ITERATOR_PAYLOAD;
  }

  unsigned option_delta = current_option[0] >> 4;
  size_t option_length = current_option[0] & 0x0F;
  ++current_option;

  if (option_delta == 13) {
    option_delta += current_option[0];
    ++current_option;
  } else if (option_delta == 14) {
    option_delta += 255;
    option_delta += current_option[0] << 8;
    ++current_option;
    option_delta += current_option[0];
    ++current_option;
  }

  if (option_length == 13) {
    option_length += current_option[0];
    ++current_option;
  } else if (option_length == 14) {
    option_length += 255;
    option_length += current_option[0] << 8;
    ++current_option;
    option_length += current_option[0];
    ++current_option;
  }

  if (current_option + option_length > it->packetEndOffset) {
    OC_ERR("Invalid option - option length exceeds packet length");
    return COAP_OPTION_ITERATOR_ERROR;
  }

  it->current.number += option_delta;
  it->current.value = current_option;
  it->current.length = option_length;
  OC_DBG("OPTION %u (delta %u, len %zu):", it->current.number, option_delta,
         it->current.length);
  return COAP_OPTION_ITERATOR_OK;
}

bool
coap_options_iterator_next_option(coap_options_iterator_t *it,
                                  coap_option_t opt)
{
  coap_option_iterator_result_t result = coap_options_iterator_next(it);
  while (result == COAP_OPTION_ITERATOR_OK) {
    if (it->current.number == opt) {
      return true;
    }
    result = coap_options_iterator_next(it);
  }
  return false;
}
