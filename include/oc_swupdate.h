/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

/**
 * @defgroup swupdate Software Update
 *
 * Notify the application of a new software update and perform the update.
 *
 * @{
 */

#ifndef OC_SWUPDATE_H
#define OC_SWUPDATE_H

#include "oc_ri.h"
#include "port/oc_clock.h"
#include "util/oc_compiler.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * OCF defined software update results
 */
typedef enum {
  OC_SWUPDATE_RESULT_IDLE = 0,         ///< Idle
  OC_SWUPDATE_RESULT_SUCCESS,          ///< software update successful
  OC_SWUPDATE_RESULT_LESS_RAM,         ///< not enough RAM
  OC_SWUPDATE_RESULT_LESS_FLASH,       ///< not enough FLASH
  OC_SWUPDATE_RESULT_CONN_FAIL,        ///< connection failure
  OC_SWUPDATE_RESULT_SVV_FAIL,         ///< version failure
  OC_SWUPDATE_RESULT_INVALID_URL,      ///< invalid URL
  OC_SWUPDATE_RESULT_UNSUPPORTED_PROT, ///< unsupported protocol for URL
  OC_SWUPDATE_RESULT_UPGRADE_FAIL,     ///< upgrade failure
} oc_swupdate_result_t;

/**
 * @brief Load device swupdate from storage.
 *
 * @param device index of the device
 * @return <0 on error
 * @return >=0 on success, number of bytes read from storage
 */
OC_API
long oc_swupdate_load(size_t device);

/**
 * @brief Save device swupdate to storage.
 *
 * @param device index of the device
 * @return <0 on error
 * @return >=0 on success, number of bytes written to storage
 */
OC_API
long oc_swupdate_dump(size_t device);

/**
 * @brief callback to notify if a new software version is available
 *
 * @param device the device identifier
 * @param version version of the software (cannot be NULL)
 * @param result status
 */
OC_API
void oc_swupdate_notify_new_version_available(size_t device,
                                              const char *version,
                                              oc_swupdate_result_t result)
  OC_NONNULL();

/**
 * @brief callback to notify if a new software version is downloaded
 *
 * @param device the device identifier
 * @param version version of the software (cannot be NULL)
 * @param result status
 */
OC_API
void oc_swupdate_notify_downloaded(size_t device, const char *version,
                                   oc_swupdate_result_t result) OC_NONNULL();

/**
 * @brief callback to notify if a new software version is upgrading
 *
 * @param device the device identifier
 * @param version version of the software (cannot be NULL)
 * @param timestamp timestamp when the upgrade starts
 * @param result status
 */
OC_API
void oc_swupdate_notify_upgrading(size_t device, const char *version,
                                  oc_clock_time_t timestamp,
                                  oc_swupdate_result_t result) OC_NONNULL();

/**
 * @brief callback to notify if a new software version is complete
 *
 * @param device the device identifier
 * @param result status
 */
OC_API
void oc_swupdate_notify_done(size_t device, oc_swupdate_result_t result);

typedef struct
{
  int (*validate_purl)(const char *url);
  int (*check_new_version)(size_t device, const char *url, const char *version);
  int (*download_update)(size_t device, const char *url);
  int (*perform_upgrade)(size_t device, const char *url);
} oc_swupdate_cb_t;

/**
 * @brief sets the callbacks for software upgrade
 *
 * @param swupdate_impl the structure with the software update callbacks
 *
 * @note the callbacks are copied to runtime variable, so the validity of the
 * structure is only required during the call to this function
 */
OC_API
void oc_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl);

/// @brief Validation error codes
typedef enum {
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_IMPLEMENTATION =
    -1, ///< software update callbacks not assigned correctly

  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY = -8, ///< invalid property
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY =
    -9, ///< trying to update a read-only property
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY_VALUE =
    -10, ///< invalid property value

  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_UPDATETIME_NOT_SET =
    -16, ///< updatetime property is not set
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_UPDATETIME_INVALID =
    -17, ///< updatetime property has invalid value
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_PURL_NOT_SET =
    -18, ///< purl property not set
  OC_SWUPDATE_VALIDATE_UPDATE_ERROR_PURL_INVALID =
    -19, ///< purl property has invalid value
} oc_swupdate_validate_update_error_t;

/**
 * @brief callback invoked by oc_swupdate_validate_update when an error is
 * encountered
 *
 * @param rep property that caused the error (for
 * OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY,
 * OC_SWUPDATE_VALIDATE_UPDATE_ERROR_READONLY_PROPERTY,
 * OC_SWUPDATE_VALIDATE_UPDATE_ERROR_INVALID_PROPERTY_VALUE), NULL for other
 * errors
 * @param error error code
 * @param data user data
 *
 * @return true if oc_swupdate_validate_update should continue
 * @return false if oc_swupdate_validate_update should stop
 */
typedef bool (*oc_swupdate_on_validate_update_error_fn_t)(
  const oc_rep_t *rep, oc_swupdate_validate_update_error_t error, void *data);

/**
 * @brief validates the payload of a software update request
 *
 * @param device device index
 * @param rep parsed payload of sofware update request to verify
 * @param on_error callback invoked when an error is encountered
 * @param data custom user data passed to on_error
 * @return true if the payload is valid
 * @return false if the payload is invalid
 */
OC_API
bool oc_swupdate_validate_update(
  size_t device, const oc_rep_t *rep,
  oc_swupdate_on_validate_update_error_fn_t on_error, void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_SWUPDATE_H */

/** @} */
