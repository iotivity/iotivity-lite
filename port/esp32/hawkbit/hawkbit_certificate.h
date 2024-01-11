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

#ifndef HAWKBIT_CERTIFICATE_H
#define HAWKBIT_CERTIFICATE_H

#if defined(OC_SECURITY) || defined(OC_PKI)

#include "hawkbit_buffer.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get concatenated PEM strings of all CA certificates on given device
 *
 * @param device device index
 * @param[out] hb output buffer (cannot be NULL, the buffer must have enough
 * space to write the certificates and the nul-terminator at the end)
 *
 * @return -1 on failure
 * @return >=0 length of the written data (not including the nul-terminator)
 */
long hawkbit_certificate_get_CA(size_t device, hawkbit_buffer_t *hb)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY || OC_PKI */

#endif /* HAWKBIT_CERTIFICATE_H */
