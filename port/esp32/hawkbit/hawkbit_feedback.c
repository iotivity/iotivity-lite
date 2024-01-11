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

#include "debug_print.h"
#include "hawkbit_buffer.h"
#include "hawkbit_certificate.h"
#include "hawkbit_feedback.h"
#include "hawkbit_http.h"
#include "hawkbit_internal.h"

#include "api/oc_helpers_internal.h"

#include <assert.h>
#include <cJSON.h>

static const char *
hawkbit_feedback_execution_to_string(hawkbit_feedback_execution_t execution)
{
#define HAWKBIT_FEEDBACK_EXECUTION_CLOSED_STR "closed"
#define HAWKBIT_FEEDBACK_EXECUTION_PROCEEDING_STR "proceeding"
#define HAWKBIT_FEEDBACK_EXECUTION_CANCELED_STR "canceled"
#define HAWKBIT_FEEDBACK_EXECUTION_SCHEDULED_STR "scheduled"
#define HAWKBIT_FEEDBACK_EXECUTION_REJECTED_STR "rejected"
#define HAWKBIT_FEEDBACK_EXECUTION_RESUMED_STR "resumed"

  switch (execution) {
  case HAWKBIT_FEEDBACK_EXECUTION_CLOSED:
    return HAWKBIT_FEEDBACK_EXECUTION_CLOSED_STR;
  case HAWKBIT_FEEDBACK_EXECUTION_PROCEEDING:
    return HAWKBIT_FEEDBACK_EXECUTION_PROCEEDING_STR;
  case HAWKBIT_FEEDBACK_EXECUTION_CANCELED:
    return HAWKBIT_FEEDBACK_EXECUTION_CANCELED_STR;
  case HAWKBIT_FEEDBACK_EXECUTION_SCHEDULED:
    return HAWKBIT_FEEDBACK_EXECUTION_SCHEDULED_STR;
  case HAWKBIT_FEEDBACK_EXECUTION_REJECTED:
    return HAWKBIT_FEEDBACK_EXECUTION_REJECTED_STR;
  case HAWKBIT_FEEDBACK_EXECUTION_RESUMED:
    return HAWKBIT_FEEDBACK_EXECUTION_RESUMED_STR;
  }

  return "";
}

static const char *
hawkbit_feedback_result_to_string(hawkbit_feedback_result_t result)
{
#define HAWKBIT_FEEDBACK_RESULT_NONE_STR "none"
#define HAWKBIT_FEEDBACK_RESULT_SUCCESS_STR "success"
#define HAWKBIT_FEEDBACK_RESULT_FAILURE_STR "failure"

  switch (result) {
  case HAWKBIT_FEEDBACK_RESULT_NONE:
    return HAWKBIT_FEEDBACK_RESULT_NONE_STR;
  case HAWKBIT_FEEDBACK_RESULT_SUCCESS:
    return HAWKBIT_FEEDBACK_RESULT_SUCCESS_STR;
  case HAWKBIT_FEEDBACK_RESULT_FAILURE:
    return HAWKBIT_FEEDBACK_RESULT_FAILURE_STR;
  }

  return "";
}

static bool
hawkbit_send_feedback(const hawkbit_context_t *ctx, oc_string_view_t url,
                      oc_string_view_t id,
                      hawkbit_feedback_execution_t execution,
                      hawkbit_feedback_result_t result)
{
  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    APP_ERR("send feedback error: cannot create root JSON object");
    return false;
  }
  if (!cJSON_AddItemToObject(root, "id", cJSON_CreateString(id.data))) {
    APP_ERR("send feedback error: cannot set 'id' property object");
    return false;
  }
  cJSON *status = cJSON_CreateObject();
  if (status == NULL) {
    APP_ERR("send feedback error: cannot create 'status' JSON object");
    return false;
  }
  if (!cJSON_AddItemToObject(root, "status", status)) {
    APP_ERR("send feedback error: cannot append 'status' JSON object");
    return false;
  }
  cJSON *status_execution =
    cJSON_CreateString(hawkbit_feedback_execution_to_string(execution));
  if (status == NULL) {
    APP_ERR("send feedback error: cannot create 'execution' JSON object");
    return false;
  }
  if (!cJSON_AddItemToObject(status, "execution", status_execution)) {
    APP_ERR("send feedback error: cannot append 'execution' JSON object");
    return false;
  }
  cJSON *status_result = cJSON_CreateObject();
  if (status_result == NULL) {
    APP_ERR("send feedback error: cannot create 'result' JSON object");
    return false;
  }
  if (!cJSON_AddItemToObject(status, "result", status_result)) {
    APP_ERR("send feedback error: cannot append 'result' JSON object");
    return false;
  }
  cJSON *finished =
    cJSON_CreateString(hawkbit_feedback_result_to_string(result));
  if (finished == NULL) {
    APP_ERR("send feedback error: cannot create 'finished' JSON object");
    return false;
  }
  if (!cJSON_AddItemToObject(status_result, "finished", finished)) {
    APP_ERR("send feedback error: cannot append 'finished' JSON object");
    return false;
  }

  char *body = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (body == NULL) {
    APP_ERR("send feedback error: cannot render JSON object");
    return false;
  }

#if defined(OC_SECURITY) && defined(OC_PKI)
  hawkbit_buffer_t hb;
  long pem_len = hawkbit_certificate_get_CA(hawkbit_get_device(ctx), &hb);
  if (pem_len < 0) {
    APP_ERR("cannot obtain certificate");
    free(body);
    return false;
  }
  oc_string_view_t pem = oc_string_view(hb.buffer, (size_t)pem_len);
#else  /* !OC_SECURITY || !OC_PKI */
  (void)ctx;
  oc_string_view_t pem = OC_STRING_VIEW_NULL;
#endif /* OC_SECURITY && OC_PKI */

  APP_DBG("send feedback payload: %s", body);

  hawkbit_buffer_t output;
  if (!hawkbit_buffer_init(&output, HAWKBIT_HTTP_MAX_OUTPUT_BUFFER)) {
    APP_ERR("send feedback error: failed to allocate output buffer");
#if defined(OC_SECURITY) && defined(OC_PKI)
    hawkbit_buffer_free(&hb);
#endif /* OC_SECURITY && OC_PKI */
    free(body);
    return false;
  }
  int code = hawkbit_http_perform_post(url, body, pem, output.buffer,
                                       hawkbit_buffer_size(&output));
  hawkbit_buffer_free(&output);
  free(body);
#if defined(OC_SECURITY) && defined(OC_PKI)
  hawkbit_buffer_free(&hb);
#endif /* OC_SECURITY && OC_PKI */
  if (code != HAWKBIT_HTTP_CODE_OK) {
    APP_ERR("send feedback error: unexpected HTTP code(%d)", code);
    return false;
  }
  return true;
}

static int
hawkbit_feedback_get_url(const hawkbit_context_t *ctx, const char *action,
                         const char *actionId, char *buffer, size_t buffer_size)
{
  assert(action != NULL);
  assert(actionId != NULL);
  assert(buffer != NULL);

  char server_url[256] = { '\0' };
  char tenant[128] = { '\0' };
  char controller_id[128] = { '\0' };
  if (hawkbit_get_url(ctx, server_url, sizeof(server_url), tenant,
                      sizeof(tenant), controller_id,
                      sizeof(controller_id)) != HAWKBIT_OK) {
    return -1;
  }
  int len =
    snprintf(buffer, buffer_size, "%s/%s/controller/v1/%s/%s/%s/feedback",
             server_url, tenant, controller_id, action, actionId);

  if (len < 0 || (size_t)len >= buffer_size) {
    APP_ERR("get feedback URL failed: %s", "cannot get URL");
    return -1;
  }
  return len;
}

bool
hawkbit_send_deploy_feedback(const hawkbit_context_t *ctx, oc_string_view_t id,
                             hawkbit_feedback_execution_t execution,
                             hawkbit_feedback_result_t result)
{
  char url[512];
  int url_len =
    hawkbit_feedback_get_url(ctx, "deploymentBase", id.data, url, sizeof(url));
  if (url_len < 0) {
    return false;
  }
  oc_string_view_t urlview = oc_string_view(url, url_len);
  return hawkbit_send_feedback(ctx, urlview, id, execution, result);
}
