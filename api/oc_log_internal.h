
/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

/**
  @file oc_log_internal.h

  @brief Internal logging API
*/

#ifndef OC_LOG_INTERNAL_H
#define OC_LOG_INTERNAL_H

#include "oc_log.h"
#include "util/oc_atomic.h"

#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_logger_t
{
  oc_print_log_fn_t fn;          ///< logging function
  OC_ATOMIC_INT8_T level;        ///< mask of enabled log levels
  OC_ATOMIC_UINT32_T components; ///< mask of enabled log components
} oc_logger_t;

#define OC_LOG_COMPONENT_ALL (0xFFFFFFFF)

/** Get global logger */
oc_logger_t *oc_log_get_logger(void);

/** Set globally enabled log components */
void oc_log_set_components(uint32_t components);

#ifdef __cplusplus
}
#endif

#endif /* OC_LOG_INTERNAL_H */
