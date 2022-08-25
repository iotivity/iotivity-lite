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

#ifndef HAWKBIT_INTERNAL_H
#define HAWKBIT_INTERNAL_H

#include "hawkbit_action.h"
#include "hawkbit_context.h"
#include "hawkbit_deployment.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  uint64_t pollingInterval;
} hawkbit_configuration_t;

typedef enum {
  HAWKBIT_OK = 0,
  HAWKBIT_ERROR_GENERAL = -1,
  HAWKBIT_ERROR_PACKAGE_URL_NOT_SET = -2,
} hawkbit_error_t;

/**
 * @brief Poll base Hawkbit server resource.
 *
 * When the Hawkbit is successfully polled and the on_action parameter was
 * non-NULL in the hawkbit_start_polling call then on_action is invoked.
 *
 * @param[in] ctx hawkbit context (cannot be NULL)
 * @param[out] cfg hawkbit configuration which is part of response sent by the
 * base resource
 * @return HAWKBIT_OK on success
 * @return HAWKBIT_ERROR_PACKAGE_URL_NOT_SET package url is not set in swupdate
 * resource
 * @return HAWKBIT_ERROR_GENERAL on other errors
 *
 * @see hawkbit_start_polling
 * @see hawkbit_stop_polling
 */
hawkbit_error_t hawkbit_poll(hawkbit_context_t *ctx,
                             hawkbit_configuration_t *cfg);

/**
 * @brief Invoke hawkbit_poll function and reschedule polling interval if
 * necessary.
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param forceReschedule force rescheduling of hawkbit polling
 * @return true polling was rescheduled
 * @return false polling was not rescheduled
 */
bool hawkbit_poll_and_reschedule(hawkbit_context_t *ctx, bool forceReschedule);

/**
 * @brief Start device with Hawkbit.
 *
 * @param ctx hawkbit context (cannot be NULL)
 */
void hawkbit_start(hawkbit_context_t *ctx);

/**
 * @brief Start polling Hawkbit base resource
 *
 * The polling interval is set to value returned by Hawkbit during
 * configuration.
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param on_action callback to be invoked after the base resource is succefully
 * polled
 */
void hawkbit_start_polling(hawkbit_context_t *ctx,
                           hawkbit_on_polling_action_cb_t on_action);

/**
 * @brief Stop polling Hawkbit base resource
 *
 * @param ctx hawkbit context (cannot be NULL)
 */
void hawkbit_stop_polling(hawkbit_context_t *ctx);

void hawkbit_reschedule_polling(hawkbit_context_t *ctx);

/**
 * @brief Poll the base resource to obtain the current actions for the device.
 *
 * @param[in] ctx hawkbit context (cannot be NULL)
 * @param[out] action current action (cannot be NULL)
 * @param[out] cfg current configuration
 * @return HAWKBIT_OK on success
 * @return HAWKBIT_ERROR_PACKAGE_URL_NOT_SET package url is not set in swupdate
 * resource
 * @return HAWKBIT_ERROR_GENERAL on other errors
 */
hawkbit_error_t hawkbit_poll_base_resource(hawkbit_context_t *ctx,
                                           hawkbit_action_t *action,
                                           hawkbit_configuration_t *cfg);

/**
 * @brief Download upgrade from Hawkbit server and store it to currently unused
 * OTA partition.
 *
 * The execution is invoked asyncronously as a delayed callback, to handle
 * download result use the download_action parameter, which gets invoked when
 * the download has finished (either succesfully or with an error)
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param download_action callback invoked after download finishes
 */
void hawkbit_download(hawkbit_context_t *ctx,
                      hawkbit_on_download_done_cb_t download_action);

/**
 * @brief Check whether on currently unused OTA partition contains a valid
 * upgrade. Switch booting to this partition if is it valid.
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @return true on success
 * @return false on error
 */
bool hawkbit_update(hawkbit_context_t *ctx);

/**
 * @brief Save resources to storage and restart ESP.
 *
 * @param ctx hawkbit context (cannot be NULL)
 */
void hawkbit_restart_device(hawkbit_context_t *ctx);

/**
 * @brief Parse purl property of the /oc/swupdate resource to expected Hawkbit
 * server url components
 *
 * @param ctx hawkbit context (cannot be NULL)
 * @param[out] server_url buffer for the server url
 * @param server_url_size size of the buffer for the server url
 * @param[out] tenant buffer for the tenant id
 * @param tenant_size size of the buffer for the tenant id
 * @param[out] controller_id buffer for the controller id
 * @param controller_id_size size of the buffer for the controller id
 * @return HAWKBIT_OK on success
 * @return HAWKBIT_ERROR_PACKAGE_URL_NOT_SET package url is not set in swupdate
 * resource
 * @return HAWKBIT_ERROR_GENERAL on other errors
 */
hawkbit_error_t hawkbit_get_url(const hawkbit_context_t *ctx, char *server_url,
                                size_t server_url_size, char *tenant,
                                size_t tenant_size, char *controller_id,
                                size_t controller_id_size);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_INTERNAL_H */
