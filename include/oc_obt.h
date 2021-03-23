/*
// Copyright (c) 2017-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
/**
 * @file
 * Collection of functions to onboard and provision clients and servers.
 *
 * This collection of functions is intended to be used by an onboarding tool
 * (OBT)
 */
#ifndef OC_OBT_H
#define OC_OBT_H

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_cred.h"
#include "oc_pki.h"
#include "oc_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The amount of time the stack will wait for a response from a discovery
 * request.
 */
#define DISCOVERY_CB_PERIOD (60)

/**
 * Callback invoked in response to device discovery.
 *
 * Example:
 * ```
 * static void
 * get_device(oc_client_response_t *data)
 * {
 *   oc_rep_t *rep = data->payload;
 *   char *di = NULL, *n = NULL;
 *   size_t di_len = 0, n_len = 0;
 *
 *   if (oc_rep_get_string(rep, "di", &di, &di_len)) {
 *     printf("Device id: %s\n", di);
 *   }
 *   if (oc_rep_get_string(rep, "n", &n, &n_len)) {
 *     printf("Device name: %s\n", n);
 *   }
 * }
 *
 * static void
 * unowned_device_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *data)
 * {
 *   (void)data;
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *   oc_endpoint_t *ep = eps;
 *
 *   printf("\nDiscovered unowned device: %s at:\n", di);
 *   while (eps != NULL) {
 *     PRINTipaddr(*eps);
 *     printf("\n");
 *     eps = eps->next;
 *   }
 *
 *   oc_do_get("/oic/d", ep, NULL, &get_device, HIGH_QOS, NULL);
 * }
 *
 * oc_obt_discover_unowned_devices(unowned_device_cb, NULL);
 * ```
 * @param[in] uuid the uuid of the discovered device
 * @param[in] eps list of endpoints that can be used to connect with the
 *                discovered device
 * @param[in] data context pointer
 *
 * @see oc_obt_discover_unowned_devices
 * @see oc_obt_discover_unowned_devices_realm_local_ipv6
 * @see oc_obt_discover_unowned_devices_site_local_ipv6
 * @see oc_obt_discover_owned_devices
 * @see oc_obt_discover_owned_devices_realm_local_ipv6
 * @see oc_obt_discover_owned_devices_site_local_ipv6
 */
typedef void (*oc_obt_discovery_cb_t)(oc_uuid_t *uuid, oc_endpoint_t *eps,
                                      void *data);

/**
 * Callback invoked to report the status resulting from many of the onboarding
 * tools actions on a device.
 *
 * @param[in] uuid of the device status is being reported on
 * @param[in] status number indicating success or failure of action that invoked
 *                   this callback. Typically `status >= 0` indicates success
 * @param[in] data context pointer
 *
 * @see oc_obt_perform_just_works_otm
 * @see oc_obt_request_random_pin
 * @see oc_obt_perform_random_pin_otm
 * @see oc_obt_perform_cert_otm
 * @see oc_obt_device_hard_reset
 * @see oc_obt_provition_ace
 * @see oc_obt_provision_role_wilecard_ace
 * @see oc_obt_provision_auth_wildcard_ace
 */
typedef void (*oc_obt_device_status_cb_t)(oc_uuid_t *uuid, int status,
                                          void *data);

/**
 * Callback invoked to report the status resulting from many of the onboarding
 * tools actions.
 *
 * @param[in] status number indicating success or failure of action that invoked
 *                   this callback. Typically `status >= 0` indicates success
 * @param[in] data context pointer
 *
 * @see oc_obt_provision_pairwise_credentials
 * @see oc_obt_provision_identity_certificate
 * @see oc_obt_provision_role_certificate
 * @see oc_obt_delete_cred_by_credid
 * @see oc_obt_delete_ace_by_aceid
 */
typedef void (*oc_obt_status_cb_t)(int status, void *data);

/**
 * Initialize the IoTivity stack so it can be used as an onboarding tool (OBT)
 *
 * Call once at startup for OBT initialization
 *
 * Persistent storage must be initialized before calling oc_obt_init()
 *
 * example:
 * ```
 * static int
 *  app_init(void)
 *  {
 *    int ret = oc_init_platform("OCF", NULL, NULL);
 *    ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.0.5",
 *                         "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
 *    oc_device_bind_resource_type(0, "oic.d.ams");
 *    oc_device_bind_resource_type(0, "oic.d.cms");
 *    return ret;
 *  }
 *
 * static void
 * issue_requests(void)
 * {
 *   oc_obt_init();
 * }
 *
 * static void
 * signal_event_loop(void)
 * {
 *   // code not shown
 * }
 * static const oc_handler_t handler = { .init = app_init,
 *                                       .signal_event_loop = signal_event_loop,
 *                                       .requests_entry = issue_requests };
 *
 * #ifdef OC_STORAGE
 *   oc_storage_config("./onboarding_tool_creds");
 * #endif // OC_STORAGE
 *   if (oc_main_init(&handler) < 0)
 *     return init;
 * ```
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_init(void);

/**
 * Free all resources associated with the onboarding tool
 *
 * Called when the OBT terminates.
 */
void oc_obt_shutdown(void);

/* Device discovery */
/**
 * Discover all unowned devices
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after the
 *                 oc_obt_discover_unowned_devices function returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data);

/**
 * Discover all unowned devices using the realm-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                     void *data);

/**
 * Discover all unowned devices using the site-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_unowned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                    void *data);

/**
 * Discover all devices owned by the onboarding tool
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data);

/**
 * Discover all devices owned by the onboarding tool
 * using the realm-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                   void *data);

/**
 * Discover all devices owned by the onboarding tool
 * using the site-local address scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] cb the oc_obt_discovery_cb_t that will be called for each
 *               discovered device
 * @param[in] data context pointer that is passed to the oc_obt_discovery_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes. The context pointer must be valid for
 *                 DISCOVERY_CB_PERIOD seconds after
 *                 oc_obt_discover_unowned_devices returns.
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_discover_owned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                  void *data);
/**
 * Discover all resources on the device identified by its uuid.
 *
 * @param[in] uuid the uuid of the device the resources are being discovered on
 * @param[in] handler the oc_discovery_all_handler_t invoked in responce to this
 *                    discovery request
 * @param[in] data context pointer that is passed to the
 *                 oc_discovery_all_handler_t callback function. The pointer
 *                 must remain valid till the `more` parameter of the
 *                 oc_discovery_all_handler_t invoked in response to this
 *                 discover request is false.
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_discover_all_resources(oc_uuid_t *uuid,
                                  oc_discovery_all_handler_t handler,
                                  void *data);
/* Perform ownership transfer */
/**
 * Perform ownership transfer method (OTM) on the device using Just-Works
 *
 * Just-Works OTM creates a symmetric key credential that is a pre-shared key
 * used to establish a secure connection.
 *
 * OTM using this method is subject to a man-in-the-middle attacker. This method
 * assumes onboarding happens in a relatively safe environment absent of an
 * attack device.
 *
 * Example:
 * ```
 * static void
 * otm_just_works_cb(oc_uuid_t *uuid, int status, void *data)
 * {
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *
 *   if (status >= 0) {
 *     printf("Successfully performed OTM on device with UUID %s\n", di);
 *   } else {
 *     printf("ERROR performing ownership transfer on device %s\n", di);
 *   }
 * }
 *
 * int ret = oc_obt_perform_just_works_otm(uuid, otm_just_works_cb, NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to perform ownership transfer\n");
 * } else {
 *   printf("ERROR issuing request to perform ownership transfer\n");
 * }
 * ```
 *
 * @param[in] uuid the uuid of the device the OTM is being run on. The uuid is
 *                 typically obtained in response to an
 *                 oc_obt_discover_unowned_devices* call.
 * @param[in] cb callback invoked to indicate the success or failure of the OTM
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_device_status_cb_t. The pointer must remain valid till
 *                 the end of the oc_obt_device_status_cb_t function.
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                                  void *data);

/**
 * Ask device being onboarded to produce a random PIN for PIN ownership transfer
 * method (OTM).
 *
 * This will cause the oc_random_pin_cb_t to be invoked on the remote device.
 * The remote device is expected to generate and communicate a random PIN using
 * an Out-of-Band communication channel. For example display the pin on a screen
 * that the user can read. The Out-of-band communication is an implementation
 * detail that is left up to the developer.
 *
 * The Random PIN establishes physical proximity between the new device and the
 * onboarding tool (OBT).
 *
 * * @param[in] uuid the uuid of the device the oc_random_pin_cb_t is being run
 *                 on. The uuid is typically obtained in response to an
 *                 oc_obt_discover_unowned_devices* call
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               random PIN request
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_device_status_cb_t. The pointer must remain valid till
 *                 the end of the oc_obt_device_status_cb_t function
 *
 * @see oc_set_random_pin_callback
 * @see oc_random_pin_cb_t
 * @see oc_obt_perform_random_pin_otm
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 *
 * @see oc_obt_perform_random_pin_otm
 * @see oc_obt_device_status_cb_t
 * @see oc_set_random_pin_callback
 * @see oc_random_pin_cb_t
 */
int oc_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                              void *data);

/**
 * Perform ownership transfer method (OTM) using Random PIN based OTM
 *
 * Since the Random PIN establishes physical proximity between the new device
 * and the onboarding tool (OBT) it helps prevent man-in-the-middle attacks.
 *
 * Example:
 * ```
 * static void
 * otm_rdp_cb(oc_uuid_t *uuid, int status, void *data)
 * {
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *
 *   if (status >= 0) {
 *     printf("Successfully performed OTM on device %s\n", di);
 *   } else {
 *     printf("ERROR performing ownership transfer on device %s\n", di);
 *   }
 * }
 *
 * static void
 * random_pin_cb(oc_uuid_t *uuid, int status, void *data)
 * {
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *
 *   if (status >= 0) {
 *     printf("Successfully requested device %s to generate a Random PIN\n",
 * di);
 *
 *     printf("Enter Random PIN: ");
 *     unsigned char pin[24];
 *     if ("%10s", pin) <= 0) {
 *       printf("Error Invalid input\n");
 *     }
 *     size_t pin_len = strlen((const char *)pin);
 *     int ret = oc_obt_perform_random_pin_otm(uuid, pin, pin_len, otm_rdp_cb,
 *                                             NULL);
 *   if (ret >= 0) {
 *     printf("Successfully issued request to perform Random PIN OTM\n");
 *   } else {
 *     printf("ERROR issuing request to perform Random PIN OTM\n");
 *   }
 *   } else {
 *     printf("ERROR requesting device %s to generate a Random PIN\n", di);
 *   }
 * }
 *
 * int ret = oc_obt_request_random_pin(uuid, random_pin_cb, NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to generate a random PIN\n");
 * } else {
 *   printf("ERROR issuing request to generate random PIN\n");
 * }
 * ```
 * @param[in] uuid the device the Random PIN based OTM is being done on
 * @param[in] pin the PIN obtained from the remote device in response to the
 *                oc_obt_request_random_pin
 * @param[in] pin_len the length of the PIN
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               Random PIN OTM operation
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_device_status_cb_t. The pointer must remain valid till
 *                 the end of the oc_obt_device_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 *
 * @see oc_obt_request_random_pin
 * @see oc_obt_device_status_cb_t
 * @see oc_set_random_pin_callback
 * @see oc_random_pin_cb_t
 */
int oc_obt_perform_random_pin_otm(oc_uuid_t *uuid, const unsigned char *pin,
                                  size_t pin_len, oc_obt_device_status_cb_t cb,
                                  void *data);

/**
 * Perform ownership transfer method (OTM) using Manufacturer Certificate
 *
 * The manufacturer certificate-based OTM uses a certificate embedded into the
 * device by the manufacturer to perform the OTM.
 *
 * @param[in] uuid the device to certificate based OTM is being done on
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               Manufacturer Certificate Based OTM
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_device_status_cb_t. The pointer must remain valid till
 *                 the end of the oc_obt_device_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                            void *data);

/* RESET device state */
/**
 * RESET the remote device back to the ready for ownership transfer method
 * (RFOTM) state.
 *
 * Example:
 * ```
 * static void
 * reset_device_cb(oc_uuid_t *uuid, int status, void *data)
 * {
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *   if (status >= 0) {
 *     printf("Successfully performed hard RESET to device %s\n", di);
 *   } else {
 *     printf("ERROR performing hard RESET to device %s\n", di);
 *   }
 * }
 *
 * int ret = oc_obt_device_hard_reset(uuid, reset_device_cb, NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to perform hard RESET\n");
 * } else {
 *   printf("ERROR issuing request to perform hard RESET\n");
 * }
 * ```
 *
 * @param[in] uuid the device being reset
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               hard reset action
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_device_status_cb_t. The pointer must remain valid till
 *                 the end of the oc_obt_device_status_cb_t function
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                             void *data);

/**
 * Provision pair-wise 128-bit pre-shared key (PSK) credentials to a Client
 * and Server so they may establish a secure (D)TLS session.
 *
 * Example:
 * ```
 * static void
 * provision_credentials_cb(int status, void *data)
 * {
 *   if (status >= 0) {
 *     printf("Successfully provisioned pair-wise credentials\n");
 *   } else {
 *     printf("ERROR provisioning pair-wise credentials\n");
 *   }
 * }
 *
 * int ret = oc_obt_provision_pairwise_credentials(uuid1, uuid2,
 *                                provision_credentials_cb, NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to provision credentials\n");
 * } else {
 *   printf("ERROR issuing request to provision credentials\n");
 * }
 * ```
 * @param[in] uuid1 uuid of the first device to pair
 * @param[in] uuid2 uuid of the second device to pair
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               pairwise credentials provisioning
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_status_cb_t. The pointer must remain valid till the
 *                 end of the oc_obt_status_cb_t function
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2,
                                          oc_obt_status_cb_t cb, void *data);
/**
 * Provision identity certificates
 *
 * To provision identity certificates the IoTivity stack must be built with
 * OC_PKI defined.
 *
 * Example:
 * ```
 * static void
 * provision_id_cert_cb(int status, void *data)
 * {
 *   if (status >= 0) {
 *     printf("Successfully provisioned identity certificate\n");
 *   } else {
 *     printf("ERROR provisioning identity certificate\n");
 *   }
 * }
 *
 * int ret = oc_obt_provision_identity_certificate(uuid, provision_id_cert_cb,
 *                                                 NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to provision identity certificate\n");
 * } else {
 *   printf("ERROR issuing request to provision identity certificate\n");
 * }
 * ```
 *
 * @param[in] uuid the uuid of the device to provision
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               provisioning
 * @param[in] data context pointer that is passed to the oc_obt_status_cb_t. The
 *                 pointer must remain valid till the end of the
 *                 oc_obt_status_cb_t function
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 */
int oc_obt_provision_identity_certificate(oc_uuid_t *uuid,
                                          oc_obt_status_cb_t cb, void *data);

/**
 * Provision a role certificate to a Client application.
 *
 * Example:
 * ```
 * static void
 * provision_role_cert_cb(int status, void *data)
 * {
 *   if (status >= 0) {
 *     printf("Successfully provisioned role certificate\n");
 *   } else {
 *     printf("ERROR provisioning role certificate\n");
 *   }
 * }
 *
 * oc_role_t *roles = NULL;
 * char *role = "admin";
 * roles = oc_obt_add_roleid(roles, role, NULL);
 * int ret = oc_obt_provision_role_certificate(roles, uuid,
 *                                             provision_role_cert_cb, NULL);
 * if (ret >= 0) {
 *   printf("\nSuccessfully issued request to provision role certificate\n");
 * } else {
 *   printf("ERROR issuing request to provision role certificate\n");
 * }
 * ```
 *
 * @param roles the role(s) to provision
 * @param uuid the uuid of the device to provision
 * @param cb callback invoked to indicate the success or failure of the
 *           provisioning
 * @param data context pointer that is passed to the oc_obt_status_cb_t. The
 *             pointer must remain valid till the end of the oc_obt_status_cb_t
 *             function
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see oc_obt_status_cb_t
 * @see oc_obt_add_roleid
 * @see oc_obt_free_roleid
 */
int oc_obt_provision_role_certificate(oc_role_t *roles, oc_uuid_t *uuid,
                                      oc_obt_status_cb_t cb, void *data);

/**
 * Build a linked list of roles to provision a role certificate.
 *
 * This function will add a single role (role name and authroity) to a list of
 * rules. If the provided list of roles is empty, it will create a new list with
 * the added role.
 *
 * Example:
 * ```
 * oc_role_t *roles = NULL;
 * roles = oc_obt_add_roleid(roles, "admin", NULL);
 * roles = oc_obt_add_roleid(roles, "user", NULL);
 * ```
 *
 * @param[in] roles head of the oc_role_t linked list. NULL if the list has not
 *                  yet been created
 * @param[in] role the role for the role id
 * @param[in] authority the role authority for the role id. The role authority
 *                      is optional if no authority is provided pass in NULL
 *
 * @return The new head of the oc_role_t list of roles
 */
oc_role_t *oc_obt_add_roleid(oc_role_t *roles, const char *role,
                             const char *authority);

/**
 * Free the oc_role_t list
 *
 * @param roles the head of the oc_role_t list
 */
void oc_obt_free_roleid(oc_role_t *roles);

/* Provision access-control entries (ace2) */
/**
 * Create a new Access Control Entry (ACE) with device UUID as subject.
 *
 * @param[in] uuid the uuid of the device
 *
 * @return
 *   - A pointer to a new oc_sec_ace_t with an OC_SUBJECT_UUID subject_type and
 *     the subject id will be set to the passed in device uuid
 *   - NULL if unable to allocate a new oc_sec_ace_t
 *
 * @see oc_obt_new_ace_for_connection
 * @see oc_obt_new_ace_for_role
 * @see oc_obt_ace_add_permission
 * @see oc_obt_provision_ace
 */
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);

/**
 * Create a new Access Control Entry (ACE) with connection type as the subject.
 *
 * @param[in] conn the connection type for the ACE
 *
 * @return
 *   - A new oc_sec_ace_t with an OC_SUBJECT_CONN subject_type and the conn
 *     property set to the provided connection type
 *   - NULL if unable to allocate a new oc_sec_ace_t
 *
 * @see oc_obt_new_ace_for_subject
 * @see oc_obt_new_ace_for_role
 * @see oc_obt_ace_add_permission
 * @see oc_obt_provision_ace
 */
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);

/**
 * Create a new Access Control Entry (ACE) with a role as the subject.
 *
 * @param[in] role the role associated with the ACE
 * @param[in] authority the role authority for the ACE. The role authority
 *                      is optional if no authority is provided pass in NULL
 *
 * @return
 *   - A new oc_sec_ace_t with an OC_SUBJECT_ROLE subject_type and the role
 *     property set to the provided role and authority
 *   - NULL if unable to allocate a new oc_sec_ace_t
 *
 * @see oc_obt_new_ace_for_subject
 * @see oc_obt_new_ace_for_connection
 * @see oc_obt_ace_add_permission
 * @see oc_obt_provision_ace
 */
oc_sec_ace_t *oc_obt_new_ace_for_role(const char *role, const char *authority);

/**
 * Add an ACE resource (`oc_ace_res_t`) to the ACE.
 *
 * @param[in,out] ace the ACE that the ACE resource will be added to
 *
 * @return
 *   - A new oc_ace_res_t
 *   - NULL if unable to allocate a new ACE resource
 *
 * @see oc_obt_new_ace_for_subject
 * @see oc_obt_new_ace_for_connection
 * @see oc_obt_new_ace_for_role
 * @see oc_obt_ace_resource_set_href
 * @see oc_obt_ace_resource_set_wc
 */
oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);

/**
 * Set the href on the ACE resource.
 *
 * @param[in,out] resource the ACE resource that the href URL will be added to
 * @param[in] href the URL being added to the ACE resource
 */
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);

/**
 * Set the wildcard type on the ACE resource
 *
 * Provisioning of Device Configuration Resources (DCRs) are not affected by the
 * wildcard ACE. Only Non-Configuration Resources (NCRs) are affected by the
 * wildcard resource.
 *
 * The following resources are DCRs
 *  - A Discovery Core Resource
 *  - A Security Virtual Resource
 *  - A Wi-Fi Easy Setup Resource (oic.r.easysetup, oic.r.wificonf,
 * oic.r.devconf)
 *  - A Software Update Resource (oic.r.softwareupdate)
 *  - A Maintenance Resource (oic.r.wk.mnt)
 *
 * The possible values for oc_ace_wildcard_t are:
 *  - OC_ACE_NO_WC : no wildcard
 *  - OC_ACE_WC_ALL : all NCRs "*"
 *  - OC_ACE_WC_ALL_SECURED : all NCRs that are secure "+"
 *  - OC_ACE_WC_ALL_PUBLIC : all NCRs that are not secure "-"
 *
 * @param[in,out] resource the ACE resource to set the wildcard value on
 * @param[in] wc the wildcard value
 */
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);

/**
 * Set the access permissions the ACE will grant.
 *
 * The function oc_obt_ace_add_permission can be called multiple times to add
 * additional permissions.
 *
 * calling:
 * ```
 * oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE);
 * oc_obt_ace_add_permission(ace, OC_PERM_UPDATE);
 * oc_obt_ace_add_permission(ace, OC_PERM_NOTIFY);
 * ```
 *
 * will set the same permissions as calling:
 * ```
 * oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE | OC_PERM_UPDATE |
 *                                OC_PERM_NOTIFY);
 * ```
 *
 * The possible values for the oc_ace_permissions_t bitmask are:
 * - OC_PERM_NONE : no permissions. Never expected to show up in an ACE entry
 * - OC_PERM_CREATE : permission to add a new resource to the client or server
 * - OC_PERM_RETRIEVE : permission to read the properties of a resource
 * - OC_PERM_UPDATE : permission to update the writable properties of a resource
 * - OC_PERM_DELETE : permission to delete a resource on the client or server
 * - OC_PERM_NOTIFY : permission to see notifications sent by the client or
 * server
 *
 * @param[in,out] ace the ACE the permissions are being added to
 * @param[in] permission the permissions granted to the `ace`
 *
 * @see oc_obt_new_ace_for_subject
 * @see oc_obt_new_ace_for_connection
 * @see oc_obt_new_ace_for_role
 * @see oc_obt_provision_ace
 */
void oc_obt_ace_add_permission(oc_sec_ace_t *ace,
                               oc_ace_permissions_t permission);

/**
 * Provision an ACE to a device.
 *
 * Example:
 * ```
 * static void
 * provision_ace2_cb(oc_uuid_t *uuid, int status, void *data)
 * {
 *   char di[OC_UUID_LEN];
 *   oc_uuid_to_str(uuid, di, OC_UUID_LEN);
 *   if (status >= 0) {
 *     printf("Successfully provisioned ACE to device %s\n", di);
 *   } else {
 *     printf("ERROR provisioning ACE to device %s\n", di);
 *   }
 * }
 *
 * oc_sec_ace_t *ace = NULL;
 * ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);
 * oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
 *
 * if (!res) {
 *   printf("ERROR: Could not allocate new resource for ACE\n");
 *   oc_obt_free_ace(ace);
 *   return;
 * }
 * oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL);
 * oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE | OC_PERM_UPDATE |
 *                                OC_PERM_NOTIFY);
 * int ret = oc_obt_provision_ace(uuid, ace, provision_ace2_cb, NULL);
 * if (ret >= 0) {
 *   printf("Successfully issued request to provision ACE\n");
 * } else {
 *   printf("ERROR issuing request to provision ACE\n");
 * }
 * ```
 *
 * @param[in] subject the uuid of the device being provisioned
 * @param[in] ace the ACE being added to the `subject`
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               provisioning
 * @param[in] data context pointer that is passed to the oc_obt_status_cb_t. The
 *                 pointer must remain valid till the end of the
 *                 oc_obt_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace,
                         oc_obt_device_status_cb_t cb, void *data);

/**
 * Free the memory associated with the ACE object.
 *
 * @param ace the ACE that will be freed
 */
void oc_obt_free_ace(oc_sec_ace_t *ace);

/**
 * Provision a role ACE for the wildcard "*" resource with RW permissions.
 *
 * This is a helper function to quickly provision a role ACE for wildcard
 * access.
 *
 * @param[in] subject the uuid or the device being provisioned
 * @param[in] role the role for the ACE
 * @param[in] authority the role authority for the ACE. The role authority
 *                      is optional if no authority is provided pass in NULL
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               provisioning
 * @param[in] data context pointer that is passed to the oc_obt_status_cb_t. The
 *                 pointer must remain valid till the end of the
 *                 oc_obt_status_cb_t function
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see oc_obt_new_ace_for_role
 * @see oc_obt_ace_new_resource
 * @see oc_obt_ace_resource_set_wc
 * @see oc_obt_ace_add_permission
 * @see oc_obt_provision_ace
 */
int oc_obt_provision_role_wildcard_ace(oc_uuid_t *subject, const char *role,
                                       const char *authority,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

/**
 * Provision auth-crypt ACE for the wildcard "*" resource with RW permissions.
 *
 * This is a helper function to quickly provision an ACE for wildcard access
 * over secure connections.
 *
 * @param[in] subject the uuid or the device being provisioned
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               provisioning
 * @param[in] data context pointer that is passed to the oc_obt_status_cb_t. The
 *                 pointer must remain valid till the end of the
 *                 oc_obt_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 *
 * @see oc_obt_new_ace_for_connection
 * @see oc_obt_ace_new_resource
 * @see oc_obt_ace_resource_set_wc
 * @see oc_obt_ace_add_permission
 * @see oc_obt_provision_ace
 */
int oc_obt_provision_auth_wildcard_ace(oc_uuid_t *subject,
                                       oc_obt_device_status_cb_t cb,
                                       void *data);

/**
 * Retrieve a list of the onboarding tools own credentials.
 *
 * The credentials returned by oc_obt_retrieve_own_creds() point to an internal
 * data structures that store the security context of the OBT. **DO NOT** free
 * them. Use oc_obt_delete_own_cred_by_credid() to remove credentials from the
 * OBT.
 *
 * @return A struct containing the onboarding tools uuid and a linked list of
 * oc_sec_cred_t credentials owned by the onboarding tool.
 */
oc_sec_creds_t *oc_obt_retrieve_own_creds(void);

/**
 * Delete a one of the onboarding tools credentials by credid.
 *
 * @param[in] credid number identifying the credential to delete
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_delete_own_cred_by_credid(int credid);

/**
 * Callback containing the credentials owned by a remote device.
 *
 * This callback is invoked in response to the oc_obt_retrieve_creds()
 * function. If there was a failure obtaining the credentials the `creds`
 * parameter will be NULL.
 *
 * @param[in] creds A struct containing a linked list of oc_sec_cred_t
 *                  credentials owned by a remote device
 * @param[in] data context pointer
 *
 * @see oc_obt_retrieve_creds
 */
typedef void (*oc_obt_creds_cb_t)(struct oc_sec_creds_t *creds, void *data);

/**
 * Retrieve a list of credentials from a remote device owned by the onboarding
 * tool.
 *
 * @param[in] subject uuid of the device the credentials will be fetched from
 * @param[in] cb callback that will contain the list of credentials from the
 *               remote device
 * @param[in] data context pointer that is passed to the oc_obt_creds_cb_t. The
 *                 pointer must remain valid till after the oc_obt_creds_cb_t
 *                 has completed.
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_retrieve_creds(oc_uuid_t *subject, oc_obt_creds_cb_t cb, void *data);

/**
 * Free a list of credentials
 *
 * @param creds the list of credentials to free
 */
void oc_obt_free_creds(oc_sec_creds_t *creds);

/**
 * Delete a credential identified by its credid off a remote device.
 *
 * @param[in] uuid the uuid of the device the credential is being deleted from
 * @param[in] credid the credid of the credential being deleted
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               oc_obt_delete_cred_by_credid call
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_status_cb_t. The pointer must remain valid till the
 *                 end of the oc_obt_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_delete_cred_by_credid(oc_uuid_t *uuid, int credid,
                                 oc_obt_status_cb_t cb, void *data);

/**
 * Callback containing the Access Control List (ACL) owned by a remote device.
 *
 * This callback is invoked in response to the oc_obt_retrieve_acl()
 * function. If there was a failure obtaining the ACL, the `acl`
 * parameter will be NULL.
 *
 * @param[in] acl A struct containing ACL installed on a remote device
 * @param[in] data context pointer
 *
 * @see oc_obt_retrieve_acl
 */
typedef void (*oc_obt_acl_cb_t)(oc_sec_acl_t *acl, void *data);

/**
 * Retrieve an Access Control List (ACL) from a remote device
 *
 * @param[in] uuid the uuid of the remote device
 * @param[in] cb callback that will deliver the requested ACL
 * @param[in] data context pointer that is passed to the oc_obt_acl_cb_t. The
 *                 pointer must remain valid till after the oc_obt_acl_cb_t
 *                 has completed.
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_retrieve_acl(oc_uuid_t *uuid, oc_obt_acl_cb_t cb, void *data);

/**
 * Free an Access Control List (ACL)
 *
 * This will free all Access Control Entries (ACE) in the ACL as well as the
 * ACL itself
 *
 * @param acl pointer to the head of an ACL
 */
void oc_obt_free_acl(oc_sec_acl_t *acl);

/**
 * Remove an Access Control Entry (ACE) from a remote device's Access Control
 * List (ACL)
 *
 * @param[in] uuid the uuid of the remote device
 * @param[in] aceid the id of the Access Control Entry
 * @param[in] cb callback invoked to indicate the success or failure of the
 *               ACE delete request
 * @param[in] data context pointer that is passed to the
 *                 oc_obt_status_cb_t. The pointer must remain valid till the
 *                 end of the oc_obt_status_cb_t function
 *
 * @return
 *  - `0` on success
 *  - `-1` on failure
 */
int oc_obt_delete_ace_by_aceid(oc_uuid_t *uuid, int aceid,
                               oc_obt_status_cb_t cb, void *data);
void oc_obt_set_sd_info(char *name, bool priv);
#ifdef __cplusplus
}
#endif

#endif /* OC_OBT_H */
