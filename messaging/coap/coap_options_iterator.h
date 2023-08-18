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

#ifndef COAP_OPTIONS_ITERATOR_H
#define COAP_OPTIONS_ITERATOR_H

#include "messaging/coap/constants.h"
#include <util/oc_compiler.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coap_option_data_s
{
  //   uint8_t *offset; ///< offset of option value in options buffer
  uint8_t *value;  ///< pointer to the options value in the CoAP packet
  size_t length;   ///< length of the option value
  unsigned number; ///< option number
  bool payload;    ///< true if this is the payload marker
} coap_option_data_t;

typedef struct coap_options_iterator_s
{
  uint8_t *options; ///< start of the options buffer in the CoAP packet
  const uint8_t *packetEndOffset; ///< end of the CoAP packet

  coap_option_data_t current; ///< current option
} coap_options_iterator_t;

typedef enum coap_option_iterator_result_e {
  COAP_OPTION_ITERATOR_NO_MORE_OPTIONS = 0,
  COAP_OPTION_ITERATOR_OK = 1,
  COAP_OPTION_ITERATOR_PAYLOAD = 2,
  COAP_OPTION_ITERATOR_ERROR = -1,
} coap_option_iterator_result_t;

/**
 * @brief Initialize options iterator.
 *
 * @param options CoAP options buffer (cannot be NULL)
 * @param packetEndOffset end of the CoAP packet (cannot be NULL); both options
 * and packetEndOffset must be in the same memory block and the end offset is
 * used to terminate the iteration or abort in case of a malformed option
 * @return coap_options_iterator_t
 */
coap_options_iterator_t coap_options_iterator_init(
  uint8_t *options, const uint8_t *packetEndOffset) OC_NONNULL();

/** @brief Reset options iterator to the first option. */
void coap_options_iterator_reset(coap_options_iterator_t *it) OC_NONNULL();

/**
 * @brief Get the next option.
 *
 * @param it options iterator (cannot be NULL)
 *
 * @return COAP_OPTION_ITERATOR_NO_MORE_OPTIONS if there are no more options to
 * iterate
 * @return COAP_OPTION_ITERATOR_OK if the next option was successfully parsed
 * @return COAP_OPTION_ITERATOR_PAYLOAD if the payload marker was found
 * @return COAP_OPTION_ITERATOR_ERROR an error occurred
 *
 * @sa coap_options_iterator_get_option
 */
coap_option_iterator_result_t coap_options_iterator_next(
  coap_options_iterator_t *it) OC_NONNULL();

/**
 * @brief Get the current option parsed by coap_options_iterator_next.
 *
 * @param it options iterator (cannot be NULL)
 */
coap_option_data_t *coap_options_iterator_get_option(
  coap_options_iterator_t *it) OC_NONNULL();

/**
 * @brief Move the iterator to the next option with the given number.
 *
 * @param it options iterator (cannot be NULL)
 * @param opt option number
 * @return true if the option was found
 * @return false if the option was not found
 */
bool coap_options_iterator_next_option(coap_options_iterator_t *it,
                                       coap_option_t opt);

#ifdef __cplusplus
}
#endif

#endif /* COAP_OPTIONS_ITERATOR_H */
