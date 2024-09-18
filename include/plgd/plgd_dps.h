/****************************************************************************
 *
 * Copyright (c) 2022 plgd.dev s.r.o.
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
 * @file plgd_dps.h
 *
 * @brief Device provisioning
 *
 * @author Daniel Adam
 */

#ifndef PLGD_DPS_H
#define PLGD_DPS_H

#include "oc_config.h"

#ifndef OC_SECURITY
#error "OC_SECURITY must be defined"
#endif

#ifndef OC_PKI
#error "OC_PKI must be defined"
#endif

#ifndef OC_CLOUD
#error "OC_CLOUD must be defined"
#endif

#ifndef OC_IPV4
#error "OC_IPV4 must be defined"
#endif

#ifndef OC_STORAGE
#error "OC_STORAGE must be defined"
#endif

/**
 * \defgroup dps Device provisioning
 *
 * A facitility to securely provision and preconfigure devices.
 *
 * @{
 */

#include "oc_export.h"
#include "oc_client_state.h"
#include "oc_cloud.h"
#include "oc_ri.h"
#include "oc_session_events.h"
#include "util/oc_compiler.h"

#include "mbedtls/md.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Custom logging function
 *
 * @param level log level of the message
 * @param file file of the log message call
 * @param line line of the log message call in \p file
 * @param func_name function name in which the log message call is invoked
 * @param format format of the log message
 */
typedef void (*plgd_dps_print_log_fn_t)(oc_log_level_t level, const char *file,
                                        int line, const char *func_name,
                                        const char *format, ...)
  OC_PRINTF_FORMAT(5, 6) OC_NONNULL();

/// @brief Set global logging function
OC_API
void plgd_dps_set_log_fn(plgd_dps_print_log_fn_t log_fn);

/// @brief Get global logging function
OC_API
plgd_dps_print_log_fn_t plgd_dps_get_log_fn(void) OC_RETURNS_NONNULL;

/**
 * @brief Set log level of the global logger, logs with lower importance will be
 * ignored. It is thread safe.
 *
 * @param level Log level
 * @note If log level is not set, the default log level is OC_LOG_LEVEL_INFO.
 */
OC_API
void plgd_dps_log_set_level(oc_log_level_t level);

/**
 * @brief Get log level of the global logger. It is thread safe.
 *
 * @return Log level
 */
OC_API
oc_log_level_t plgd_dps_log_get_level(void);

typedef struct plgd_dps_context_t plgd_dps_context_t;

/**
 * @brief DPS provisioning status flags.
 */
typedef enum {
  /* UNINITIALIZED = 0 */
  PLGD_DPS_INITIALIZED = 1 << 0,
  PLGD_DPS_GET_CREDENTIALS = 1 << 1,
  PLGD_DPS_HAS_CREDENTIALS = 1 << 2,
  PLGD_DPS_GET_ACLS = 1 << 3,
  PLGD_DPS_HAS_ACLS = 1 << 4,
  PLGD_DPS_GET_CLOUD = 1 << 6,
  PLGD_DPS_HAS_CLOUD = 1 << 7,
  PLGD_DPS_CLOUD_STARTED = 1 << 8,
  PLGD_DPS_RENEW_CREDENTIALS = 1 << 9,
  PLGD_DPS_GET_OWNER = 1 << 10,
  PLGD_DPS_HAS_OWNER = 1 << 11,
  PLGD_DPS_GET_TIME = 1 << 12,
  PLGD_DPS_HAS_TIME = 1 << 13,
  PLGD_DPS_TRANSIENT_FAILURE = 1 << 29,
  PLGD_DPS_FAILURE = 1 << 30,
} plgd_dps_status_t;

/**
 * @brief DPS errors.
 */
typedef enum {
  PLGD_DPS_OK = 0,
  PLGD_DPS_ERROR_RESPONSE = 1,
  PLGD_DPS_ERROR_CONNECT = 2,
  PLGD_DPS_ERROR_GET_CREDENTIALS = 3,
  PLGD_DPS_ERROR_GET_ACLS = 4,
  PLGD_DPS_ERROR_SET_CLOUD = 5,
  PLGD_DPS_ERROR_START_CLOUD = 6,
  PLGD_DPS_ERROR_GET_OWNER = 7,
  PLGD_DPS_ERROR_GET_TIME = 8,
} plgd_dps_error_t;

/**
  @brief A function pointer for handling the dps status.
  @param ctx dps context
  @param status Current status of the dps.
  @param data user data provided to the callback
*/
typedef void (*plgd_dps_on_status_change_cb_t)(plgd_dps_context_t *ctx,
                                               plgd_dps_status_t status,
                                               void *data);

/**
 * @brief Allocate and initialize data.
 *
 * @return int  0   on success
 *              <0  on failure
 */
OC_API
int plgd_dps_init(void);

/**
 * @brief Stop all devices and deallocate data.
 */
OC_API
void plgd_dps_shutdown(void);

/// Get context for given device
OC_API
plgd_dps_context_t *plgd_dps_get_context(size_t device);

/**
 * @brief Get device from context.
 *
 * @param ctx dps context (cannot be NULL)
 *
 * @return size_t index of device
 */
OC_API
size_t plgd_dps_get_device(const plgd_dps_context_t *ctx) OC_NONNULL();

typedef struct
{
  plgd_dps_on_status_change_cb_t
    on_status_change; ///< callback executed on DPS status change
  void *
    on_status_change_data; ///< user data provided to DPS status change callback
  oc_cloud_cb_t
    on_cloud_status_change; ///< callback executed when cloud status change
  void *on_cloud_status_change_data; ///< user data provided to cloud status
                                     ///< change callback
} plgd_dps_manager_callbacks_t;

/**
 * @brief Set DPS manager callbacks.
 *
 * @param ctx dps context (cannot be NULL)
 * @param callbacks callbacks with data
 *
 * Example of plgd_dps_on_status_change_cb_t function:
 * @code{.c}
 * static void
 * on_change_cb(plgd_dps_context_t *ctx, plgd_dps_status_t status, void
 * *on_change_data) { printf("DPS Manager Status:\n"); if (status &
 * PLGD_DPS_INITIALIZED) { printf("\t-Initialized\n");
 *   }
 *   ...
 * }
 * @endcode
 *
 * Example of oc_cloud_cb_t function:
 * @code{.c}
 * static void
 * on_cloud_change_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void
 * *on_cloud_change_data) { printf("Cloud Manager Status:\n"); if (status &
 * OC_CLOUD_REGISTERED) { printf("\t-Registered\n");
 *   }
 *   ...
 * }
 * @endcode
 */
OC_API
void plgd_dps_set_manager_callbacks(plgd_dps_context_t *ctx,
                                    plgd_dps_manager_callbacks_t callbacks)
  OC_NONNULL(1);

/**
 * @brief Start DPS manager to provision device.
 *
 * Setup context, global session handlers and start DPS manager.
 *
 * Starting DPS also starts the retry mechanism, which will remain active until
 * the device is successfully provisioned. If a provisioning step fails, it will
 * be tried again after a time interval. The time interval depends on the retry
 * counter (which is incremented on each retry) and uses the following values [
 * 10, 20, 40, 80, 120 ] in seconds. Meaning that the first retry is scheduled
 * after 10 seconds after a failure, the second retry after 20 seconds, etc.
 * After the interval reaches the maximal value (120 seconds) it resets back to
 * the first value (10 seconds).
 *
 * @note Before starting the DPS manager, an endpoint must be added by
 * plgd_dps_add_endpoint_address (if you add multiple endpoints then use
 * plgd_dps_select_endpoint_address to select the endpoint that will be used to
 * provision). Without an endpoint selected the provisioning will not start.
 *
 * @note The function examines the state of storage and some provisioning steps
 * might be skipped if the stored data is evaluated as still valid. To force
 * full reprovisioning call plgd_force_reprovision before this function. At the
 * end of this call forced reprovisioning is disabled.
 * @see plgd_force_reprovision
 *
 * @param ctx dps context (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 */
OC_API
int plgd_dps_manager_start(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Check whether DPS manager has been started.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true DPS manager has been started
 * @return false DPS manager has not been started
 *
 * @see plgd_dps_manager_start
 */
OC_API
bool plgd_dps_manager_is_started(const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Stop DPS manager.
 *
 * Deregister handlers, clear context, stop DPS manager, close connection to DPS
 * endpoint and remove identity certificates retrieved from DPS endpoint.
 *
 * @param ctx dps context (cannot be NULL)
 */
OC_API
void plgd_dps_manager_stop(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Restart DPS manager to provision device by given server.
 *
 * A convenience function equivalent to calling plgd_dps_manager_stop and
 * plgd_dps_manager_start.
 *
 * @param ctx dps context (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 *
 * @see plgd_dps_manager_start
 * @see plgd_dps_manager_stop
 */
OC_API
int plgd_dps_manager_restart(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Start cloud manager with previously set server and callbacks.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true on success
 * @return false otherwise
 */
OC_API
bool plgd_cloud_manager_start(const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Clean-up of DPS provisioning on factory reset.
 *
 * The function must be called from the factory reset handler to clean-up data
 * that has been invalidated by a factory reset. The clean-up includes:
 *   - stopping of DPS provisioning and resetting the provisioning status
 *   - disconnecting from DPS endpoint and resetting the endpoint address
 *   - resetting data in storage and committing the empty data to storage files
 *   - removing identifiers of identity certificates that have been deleted by
 * factory reset
 *
 * @param ctx dps context (cannot be NULL)
 * @return 0 on success
 * @return -1 on failure
 */
OC_API
int plgd_dps_on_factory_reset(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Controls whether a dps client verifies the device provision service's
 * certificate chain against trust anchor in the device. To set skip verify, it
 * must be called before plgd_dps_manager_start.
 *
 * @param ctx dps context (cannot be NULL)
 * @param skip_verify skip verification of the DPS service
 */
OC_API
void plgd_dps_set_skip_verify(plgd_dps_context_t *ctx, bool skip_verify)
  OC_NONNULL();

/**
 * @brief Get `skip verify` value from context.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true `skip verify` is enabled
 * @return false `skip verify` is disabled
 *
 * @see plgd_dps_set_skip_verify
 */
OC_API
bool plgd_dps_get_skip_verify(const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Force all steps of the provisioning process to be executed.
 *
 * A step that was successfully executed stores data in the storage and on the
 * next start this data is still valid the step would be automatically skipped.
 *
 * @param ctx dps context (cannot be NULL)
 *
 * @see plgd_dps_manager_start
 */
OC_API
void plgd_dps_force_reprovision(plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Check if force reprovision flag is set.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true force reprovision is set
 * @return false force reprovision is not set
 */
OC_API
bool plgd_dps_has_forced_reprovision(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Configuration resource
 *
 * Description:
 *  - Resource type: x.plgd.dps.conf
 *  - Resource structure in json format:
 *    {
 *      endpoint: string;
 *      lastErrorCode: int;
 *      provisionStatus: string;
 *      forceReprovision: bool;
 *    }
 */
#define PLGD_DPS_URI "/plgd/dps"

/**
 * @brief Controls whether a dps client creates configuration resource for
 * managing dps client via COAPs API.
 *
 * @param ctx dps context (cannot be NULL)
 * @param create set true for creating resource. set false to free memory of
 * created resource.
 */
OC_API
void plgd_dps_set_configuration_resource(plgd_dps_context_t *ctx, bool create)
  OC_NONNULL();

enum {
  /**
   * @brief Maximal size of the retry configuration array
   */
  PLGD_DPS_MAX_RETRY_VALUES_SIZE = 8
};

/**
 * @brief Configure retry counter.
 *
 * @param ctx dps context (cannot be NULL)
 * @param cfg array with new timeout values (must have [1,
 * PLGD_DPS_MAX_RETRY_VALUES_SIZE> number of non-zero values)
 * @param cfg_size size of the array with timeout values
 * @return true on success
 * @return false on failure
 */
OC_API
bool plgd_dps_set_retry_configuration(plgd_dps_context_t *ctx,
                                      const uint8_t cfg[], size_t cfg_size)
  OC_NONNULL(1);

/**
 * @brief Callback invoked by the dps manager when the dps wants to schedule
 * an action.
 *
 * @param ctx dps context
 * @param action One of PLGD_DPS_GET actions or PLGD_DPS_RENEW_CREDENTIALS to
 * schedule, or 0 for reinitialization.
 * @param retry_count Retries count - 0 means the first attempt to perform the
 * action.
 * @param delay Delay the action in milliseconds before executing it.
 * @param timeout Timeout in seconds for the action.
 * @param user_data User data passed from the caller.
 *
 * @return true if the dps manager should continue to schedule the action,
 *         false if the dps manager should restarts from the beginning.
 */
typedef bool (*plgd_dps_schedule_action_cb_t)(
  plgd_dps_context_t *ctx, plgd_dps_status_t action, uint8_t retry_count,
  uint64_t *delay, uint16_t *timeout, void *user_data) OC_NONNULL(1, 4, 5);

/**
 * @brief Set a custom scheduler for actions in the cloud manager. By default,
 * the cloud manager uses its own scheduler.
 *
 * This function allows you to set a custom scheduler to define delay and
 * timeout for actions.
 *
 * @param ctx Cloud context to update. Must not be NULL.
 * @param on_schedule_action Callback invoked by the cloud manager when the
 * cloud wants to schedule an action.
 * @param user_data User data passed from the caller to be provided during the
 * callback.
 *
 * @note The provided cloud context (`ctx`) must not be NULL.
 * @see oc_cloud_schedule_action_cb_t
 */
OC_API
void plgd_dps_set_schedule_action(
  plgd_dps_context_t *ctx, plgd_dps_schedule_action_cb_t on_schedule_action,
  void *user_data) OC_NONNULL(1);

/**
 * @brief Get retry counter configuration.
 *
 * @param ctx dps context (cannot be NULL)
 * @param[out] buffer output buffer into which the configuration will be copied
 * (cannot be NULL, and must be large enough to contain the current
 * configuration)
 * @param buffer_size size of the output buffer
 * @return >0 the size of the configuration array copied to buffer
 * @return <0 on failure
 */
OC_API
int plgs_dps_get_retry_configuration(const plgd_dps_context_t *ctx,
                                     uint8_t *buffer, size_t buffer_size)
  OC_NONNULL();

/**
 * @brief Get last provisioning error.
 *
 * @param ctx dps context (cannot be NULL)
 * @return plgd_dps_error_t last provisioning error
 */
OC_API
plgd_dps_error_t plgd_dps_get_last_error(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Get provision status.
 *
 * @param ctx dps context (cannot be NULL)
 * @return uint16_t current provision status
 */
OC_API
uint32_t plgd_dps_get_provision_status(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Check whether the device has been provisioned at least once since the
 * last DPS reset initiated by a factory reset or by setting the endpoint to an
 * empty value in the DPS resource.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true if DPS has been successfully provisioned at least once since the
 * DPS context reset.
 * @return false for otherwise
 */
OC_API
bool plgd_dps_has_been_provisioned_since_reset(const plgd_dps_context_t *ctx)
  OC_NONNULL();

typedef struct
{
  uint8_t
    max_count; ///< the maximal number of retries with the same endpoint before
               ///< retrying is stopped; if a previously untried endpoint is
               ///< available then it is selected and the retrying is restarted
               ///< with it; if no previously untried endpoint is available then
               ///< a full reprovisioning of the client is triggered (default:
               ///< 30)
  uint8_t interval_s; ///< retry interval in seconds (default: 1)
} plgd_cloud_status_observer_configuration_t;

/**
 * @brief Configure cloud observer.
 *
 * @param ctx dps context (cannot be NULL)
 * @param max_retry_count maximal number of retries, set to 0 to disable cloud
 * status observer
 * @param retry_interval_s retry interval in seconds (must be >0)
 * @return true on success
 * @return false on error caused by invalid parameters
 */
OC_API
bool plgd_dps_set_cloud_observer_configuration(plgd_dps_context_t *ctx,
                                               uint8_t max_retry_count,
                                               uint8_t retry_interval_s)
  OC_NONNULL();

/**
 * @brief Get cloud observer configuration
 *
 * @param ctx dps context (cannot be NULL)
 * @return plgd_cloud_status_observer_configuration_t current cloud observer
 * configuration
 */
OC_API
plgd_cloud_status_observer_configuration_t
plgd_dps_get_cloud_observer_configuration(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Set expiring-in limit of DPS certificates.
 *
 * If a certificate's valid-to timestamp is within the expiring-in limit
 * (current time < valid_to and current time + expiring-in limit > valid_to)
 * then the certificate is considered as expiring. Expiring certificates are not
 * accepted during the get credentials step of DPS provisioning. If a expiring
 * certificates is received then the step is retried to receive a newer
 * certificate with longer expiration.
 *
 * @param ctx dps context (cannot be NULL)
 * @param expiring_limit limit value in seconds
 */
OC_API
void plgd_dps_pki_set_expiring_limit(plgd_dps_context_t *ctx,
                                     uint16_t expiring_limit) OC_NONNULL();

/**
 * @brief Get expiring-in limit of DPS certificates
 *
 * @param ctx dps context (cannot be NULL)
 * @return expiring-in limit in seconds
 */
OC_API
uint16_t plgd_dps_pki_get_expiring_limit(const plgd_dps_context_t *ctx)
  OC_NONNULL();

/**
 * @brief Set certificate fingerprint of the provisioning server.
 *
 * If the fingerprint is set then the DPS client
 * will verify the fingerprint of the provisioning server certificate during the
 * TLS handshake. If any certificate matching the fingerprint in the chain is
 * found then the handshake is successful.
 *
 * @param ctx dps context (cannot be NULL)
 * @param md_type hash algorithm used for fingerprint
 * @param fingerprint fingerprint of the provisioning server certificate
 * @param size size of the fingerprint
 * @return true on success
 */
OC_API
bool plgd_dps_set_certificate_fingerprint(plgd_dps_context_t *ctx,
                                          mbedtls_md_type_t md_type,
                                          const uint8_t *fingerprint,
                                          size_t size) OC_NONNULL(1);

/**
 * @brief Copy certificate fingerprint of the DPS service to output buffer.
 *
 * @param ctx dps context (cannot be NULL)
 * @param[out] md_type hash algorithm used for fingerprint
 * @param[out] buffer output buffer (cannot be NULL and must be large enough to
 * contain the endpoint in a string format)
 * @param buffer_size size of output buffer
 * @return >0 on success, number of copied bytes to buffer
 * @return 0 endpoint is not set, thus nothing was copied
 * @return <0 on error
 */
OC_API
int plgd_dps_get_certificate_fingerprint(const plgd_dps_context_t *ctx,
                                         mbedtls_md_type_t *md_type,
                                         uint8_t *buffer, size_t buffer_size)
  OC_NONNULL();

/**
 * @brief Set the vendor encapsulated option code for the DPS endpoint. Used
 * during call
 * plgd_dps_set_dhcp_vendor_encapsulated_option_code_dps_certificate_fingerprint.
 *
 * @param ctx dps context (cannot be NULL)
 * @param code vendor encapsulated option code for the DPS endpoint
 */
OC_API
void plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_endpoint(
  plgd_dps_context_t *ctx, uint8_t code) OC_NONNULL();

/**
 * @brief Get the vendor encapsulated option code for the DPS endpoint. Used
 * during call
 * plgd_dps_set_dhcp_vendor_encapsulated_option_code_dps_certificate_fingerprint.
 *
 * @param ctx dps context (cannot be NULL)
 * @return uint8_t vendor encapsulated option code for the DPS endpoint
 */
OC_API
uint8_t plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_endpoint(
  const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Set the vendor encapsulated option code for the DPS certificate
 * fingerprint. Used during call
 * plgd_dps_set_dhcp_vendor_encapsulated_option_code_dps_certificate_fingerprint.
 *
 * @param ctx dps context (cannot be NULL)
 * @param code vendor encapsulated option code for the DPS certificate
 * fingerprint.
 */
OC_API
void
plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_certificate_fingerprint(
  plgd_dps_context_t *ctx, uint8_t code) OC_NONNULL();

/**
 * @brief Get the vendor encapsulated option code for the DPS certificate
 * fingerprint. Used during call
 * plgd_dps_set_dhcp_vendor_encapsulated_option_code_dps_certificate_fingerprint.
 *
 * @param ctx dps context (cannot be NULL)
 * @return uint8_t vendor encapsulated option code for the DPS certificate
 * fingerprint.
 */
OC_API
uint8_t
plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_certificate_fingerprint(
  const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Convert isc-dhcp leases file vendor encapsulated options to byte
 * array.
 *
 * @param hex_string input hex string (cannot be NULL) in format "01:a:3:14" or
 * "010a0314"
 * @param hex_string_size vendor encapsulated options size in dhcp leases file.
 * @param buffer output buffer into which the byte array will be copied or NULL
 * to get the needed size
 * @param buffer_size size of the output buffer
 * @return >0 the size of used or needed to copy to buffer, -1 on error
 */
OC_API
ssize_t plgd_dps_hex_string_to_bytes(const char *hex_string,
                                     size_t hex_string_size, uint8_t *buffer,
                                     size_t buffer_size) OC_NONNULL(1);

/**
 * @brief DPS dhcp plgd_dps_dhcp_set_values_from_vendor_encapsulated_options
 * return values.
 */
typedef enum {
  PLGD_DPS_DHCP_SET_VALUES_ERROR = -1,      // error or parsing values failed
  PLGD_DPS_DHCP_SET_VALUES_NOT_CHANGED = 0, // nothing changed
  PLGD_DPS_DHCP_SET_VALUES_UPDATED = 1,     // just updated
  PLGD_DPS_DHCP_SET_VALUES_NEED_REPROVISION =
    2, // need to force reprovision with restart manager
} plgd_dps_dhcp_set_values_t;

/**
 * @brief Set DPS endpoint and certificate fingerprint that will be used in
 * establishment of secure connection.
 *
 * @param ctx dps context (cannot be NULL)
 * @param vendor_encapsulated_options vendor encapsulated options in byte array
 * @param vendor_encapsulated_options_size vendor encapsulated options size in
 * byte array
 * @return one of plgd_dps_dhcp_set_values_t
 */
OC_API
plgd_dps_dhcp_set_values_t
plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
  plgd_dps_context_t *ctx, const uint8_t *vendor_encapsulated_options,
  size_t vendor_encapsulated_options_size) OC_NONNULL();

/**
 * \defgroup dps_endpoints Support for multiple DPS endpoint addresses
 * @{
 */

/**
 * @brief Set endpoint address of the DPS service.
 *
 * Expected format of the endpoint is "coaps+tcp://${HOST}:${PORT}". For
 * example: coaps+tcp://localhost:40030
 *
 * If there are multiple endpoint addresses set then a successful call to this
 * function will remove all other endpoint addresses and set the new endpoint
 * address as the only one in the list of DPS endpoint addresses.
 *
 * @param ctx dps context (cannot be NULL)
 * @param endpoint endpoint of the provisioning server (cannot be NULL)
 *
 * @deprecated replaced by plgd_dps_add_endpoint_address in v2.2.5.15
 */
OC_API
void plgd_dps_set_endpoint(plgd_dps_context_t *ctx, const char *endpoint)
  OC_NONNULL()
    OC_DEPRECATED("replaced by plgd_dps_add_endpoint_address in v2.2.5.15");

/**
 * @brief Copy the selected endpoint address of the DPS service to output
 * buffer.
 *
 * @param ctx dps context (cannot be NULL)
 * @param[out] buffer output buffer (cannot be NULL and must be large enough to
 * contain the endpoint in a string format)
 * @param buffer_size size of output buffer
 * @return >0 on success, number of copied bytes to buffer
 * @return 0 endpoint is not set, thus nothing was copied
 * @return <0 on error
 */
OC_API
int plgd_dps_get_endpoint(const plgd_dps_context_t *ctx, char *buffer,
                          size_t buffer_size) OC_NONNULL();

/**
 * @brief Check if no DPS service endpoint is set.
 *
 * @param ctx dps context (cannot be NULL)
 * @return true if no endpoint is set
 * @return false otherwise
 */
OC_API
bool plgd_dps_endpoint_is_empty(const plgd_dps_context_t *ctx) OC_NONNULL();

/**
 * @brief Allocate and add an address to the list of DPS endpoint addresses.
 *
 * @param ctx dps context (cannot be NULL)
 * @param uri endpoint address (cannot be NULL; the uri must be at least 1
 * character long and less than OC_ENDPOINT_MAX_ENDPOINT_URI_LENGTH characters
 * long, otherwise the call will fail)
 * @param uri_len length of \p uri
 * @param name name of the DPS endpoint
 * @param name_len length of \p name
 *
 * @return oc_endpoint_address_t* pointer to the allocated DPS endpoint address
 * @return NULL on failure
 */
OC_API
oc_endpoint_address_t *plgd_dps_add_endpoint_address(
  plgd_dps_context_t *ctx, const char *uri, size_t uri_len, const char *name,
  size_t name_len) OC_NONNULL(1, 2);

/**
 * @brief Remove an address from the list of DPS endpoint addresses.
 *
 * @param ctx dps context (cannot be NULL)
 * @param address endpoint address to remove
 *
 * @return true if the endpoint address was removed from the list of DPS
 * endpoints
 * @return false on failure
 *
 * @note The endpoints are stored in a list. If the selected server address is
 * removed, then next server address in the list will be selected. If the
 * selected server address is the last item in the list, then the first server
 * address in the list will be selected (if it exists).
 *
 * @note The server is cached in the DPS context, so if you remove the selected
 * endpoint address during provisioning then it might be necessary to restart
 * the DPS manager for the change to take effect.
 * @see plgd_dps_manager_restart
 */
OC_API
bool plgd_dps_remove_endpoint_address(plgd_dps_context_t *ctx,
                                      const oc_endpoint_address_t *address)
  OC_NONNULL();

/**
 * @brief Iterate over DPS endpoint addresses.
 *
 * @param ctx dps context (cannot be NULL)
 * @param iterate_fn callback function invoked for each DPS endpoint address
 * (cannot be NULL)
 * @param iterate_fn_data custom user data provided to \p iterate_fn
 *
 * @note The callback function \p iterate_fn must not modify the list of DPS
 * endpoint addresses.
 */
OC_API
void plgd_dps_iterate_server_addresses(
  const plgd_dps_context_t *ctx, oc_endpoint_addresses_iterate_fn_t iterate_fn,
  void *iterate_fn_data) OC_NONNULL(1, 2);

/**
 * @brief Select an address from the list of DPS endpoint addresses.
 *
 * @param ctx dps context (cannot be NULL)
 * @param address DPS endpoint address to select (cannot be NULL; must be in the
 * list of DPS endpoints)
 *
 * @return true if the address was selected
 * @return false on failure to select the address, because it is not in the list
 * of DPS endpoint addresses
 *
 * @note The server is cached in the DPS context, so if you remove the selected
 * endpoint address during provisioning then it might be necessary to restart
 * the DPS manager for the change to take effect.
 * @see plgd_dps_manager_restart
 */
OC_API
bool plgd_dps_select_endpoint_address(plgd_dps_context_t *ctx,
                                      const oc_endpoint_address_t *address)
  OC_NONNULL();

/**
 * @brief Get the selected DPS endpoint address.
 *
 * @param ctx dps context (cannot be NULL)
 * @return oc_endpoint_address_t* pointer to the selected DPS endpoint address
 * @return NULL if no DPS endpoint address is selected
 */
OC_API
const oc_endpoint_address_t *plgd_dps_selected_endpoint_address(
  const plgd_dps_context_t *ctx) OC_NONNULL();

/** @} */ // end of dps_endpoints

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* PLGD_DPS_H */
