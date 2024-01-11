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

#include "hawkbit_action.h"

#define HAWKBIT_ACTION_NONE_STR "no action"
#define HAWKBIT_ACTION_CONFIGURE_STR "configure"
#define HAWKBIT_ACTION_DEPLOY_STR "deploy"
#define HAWKBIT_ACTION_CANCEL_STR "cancel"

const char *
hawkbit_action_type_to_string(hawkbit_action_type_t action)
{
  if (action == HAWKBIT_ACTION_NONE) {
    return HAWKBIT_ACTION_NONE_STR;
  }
  if (action == HAWKBIT_ACTION_CONFIGURE) {
    return HAWKBIT_ACTION_CONFIGURE_STR;
  }
  if (action == HAWKBIT_ACTION_DEPLOY) {
    return HAWKBIT_ACTION_DEPLOY_STR;
  }
  if (action == HAWKBIT_ACTION_CANCEL) {
    return HAWKBIT_ACTION_CANCEL_STR;
  }
  return "";
}

hawkbit_action_t
hawkbit_action_none()
{
  hawkbit_action_t action = {
    .type = HAWKBIT_ACTION_NONE,
  };
  return action;
}

hawkbit_action_t
hawkbit_action_cancel(const char *id)
{
  hawkbit_action_t action = {
    .type = HAWKBIT_ACTION_CANCEL,
  };
  oc_new_string(&action.data.cancel.id, id, strlen(id));
  return action;
}

hawkbit_action_t
hawkbit_action_configure(const char *url)
{
  hawkbit_action_t action = {
    .type = HAWKBIT_ACTION_CONFIGURE,
  };
  oc_new_string(&action.data.configure.url, url, strlen(url));
  return action;
}

hawkbit_action_t
hawkbit_action_deploy(hawkbit_deployment_t deployment)
{
  hawkbit_action_t action = {
    .type = HAWKBIT_ACTION_DEPLOY,
  };
  action.data.deploy.deployment = deployment;
  return action;
}

void
hawkbit_action_free(hawkbit_action_t *action)
{
  if (action == NULL) {
    return;
  }

  if (action->type == HAWKBIT_ACTION_CANCEL) {
    oc_free_string(&action->data.cancel.id);
    return;
  }
  if (action->type == HAWKBIT_ACTION_CONFIGURE) {
    oc_free_string(&action->data.configure.url);
    return;
  }
  if (action->type == HAWKBIT_ACTION_DEPLOY) {
    hawkbit_deployment_free(&action->data.deploy.deployment);
    return;
  }
  if (action->type == HAWKBIT_ACTION_NONE) {
    return;
  }
}
