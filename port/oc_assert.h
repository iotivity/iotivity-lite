/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
  @file
*/
#ifndef OC_PORT_ASSERT_H
#define OC_PORT_ASSERT_H

#include "oc_log.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief abort application
 *
 */
void abort_impl(void) OC_NO_RETURN;

/**
 * @brief exit the application
 *
 * @param status the exist status
 */
void exit_impl(int status) OC_NO_RETURN;

/**
 * @brief abort with message
 *
 * @param msg the message to be printed
 */
OC_NO_RETURN
static inline void
oc_abort(const char *msg)
{
  OC_PRINTF("\n%s\nAbort.\n", msg);
  abort_impl();
}

/**
 * @brief assert the condition and if it fails abort with message (reason)
 *
 */
#define oc_assert(cond)                                                        \
  do {                                                                         \
    if (!(cond)) {                                                             \
      oc_abort("Assertion (" #cond ") failed.");                               \
    }                                                                          \
  } while (0)

/**
 * @brief exit the application with status
 *
 * @param status the exist status
 */
OC_NO_RETURN
static inline void
oc_exit(int status)
{
  exit_impl(status);
}

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_ASSERT_H */
