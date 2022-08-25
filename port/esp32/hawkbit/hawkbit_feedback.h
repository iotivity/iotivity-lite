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

#ifndef HAWKBIT_FEEDBACK_H
#define HAWKBIT_FEEDBACK_H

#include "hawkbit_context.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

typedef enum {
  HAWKBIT_FEEDBACK_EXECUTION_CLOSED,
  HAWKBIT_FEEDBACK_EXECUTION_PROCEEDING,
  HAWKBIT_FEEDBACK_EXECUTION_CANCELED,
  HAWKBIT_FEEDBACK_EXECUTION_SCHEDULED,
  HAWKBIT_FEEDBACK_EXECUTION_REJECTED,
  HAWKBIT_FEEDBACK_EXECUTION_RESUMED,
} hawkbit_feedback_execution_t;

typedef enum {
  HAWKBIT_FEEDBACK_RESULT_NONE,
  HAWKBIT_FEEDBACK_RESULT_SUCCESS,
  HAWKBIT_FEEDBACK_RESULT_FAILURE,
} hawkbit_feedback_result_t;

/**
 * @brief Send deployment feedback to Hawkbit server
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param id deployment id (cannot be NULL)
 * @param execution feedback execution
 * @param result feedback result
 * @return true on success
 * @return false on failure
 */
bool hawkbit_send_deploy_feedback(const hawkbit_context_t *ctx, const char *id,
                                  hawkbit_feedback_execution_t execution,
                                  hawkbit_feedback_result_t result);

#endif /* HAWKBIT_FEEDBACK_H */
