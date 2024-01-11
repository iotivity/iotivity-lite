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

#ifndef HAWKBIT_ACTION_H
#define HAWKBIT_ACTION_H

#include "hawkbit_deployment.h"
#include "oc_helpers.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  HAWKBIT_ACTION_NONE = 0,
  HAWKBIT_ACTION_CONFIGURE = 1,
  HAWKBIT_ACTION_DEPLOY = 2,
  HAWKBIT_ACTION_CANCEL = 3
} hawkbit_action_type_t;

typedef struct
{
  oc_string_t url;
} hawkbit_action_configure_t;

typedef struct
{
  oc_string_t id;
} hawkbit_action_cancel_t;

typedef struct
{
  hawkbit_deployment_t deployment;
} hawkbit_action_deploy_t;

/**
 * @brief Representation of actions received from Hawkbit server
 */
typedef struct
{
  union {
    hawkbit_action_configure_t configure;
    hawkbit_action_cancel_t cancel;
    hawkbit_action_deploy_t deploy;
  } data;
  hawkbit_action_type_t type;
} hawkbit_action_t;

const char *hawkbit_action_type_to_string(hawkbit_action_type_t action);

/** Create no-op action */
hawkbit_action_t hawkbit_action_none();

/** Create cancel action */
hawkbit_action_t hawkbit_action_cancel(const char *id) OC_NONNULL();

/** Create configure action */
hawkbit_action_t hawkbit_action_configure(const char *url) OC_NONNULL();

/** Create deploy action */
hawkbit_action_t hawkbit_action_deploy(hawkbit_deployment_t deployment);

/**
 * @brief Deallocate data for given action type
 *
 * @param action action to free
 */
void hawkbit_action_free(hawkbit_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_ACTION_H */
