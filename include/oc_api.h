/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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
  @brief Main API of IoTivity-Lite for client and server.
  @file
*/

/**
  \mainpage IoTivity-Lite API

  The file \link oc_api.h \endlink is the main entry for all
  server and client related OCF functions.
*/

#ifndef OC_API_H
#define OC_API_H

#include "messaging/coap/oc_coap.h"
#include "oc_buffer_settings.h"
#include "oc_cloud.h"
#include "oc_config.h"
#include "oc_export.h"
#include "oc_link.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_role.h"
#include "oc_signal_event_loop.h"
#include "port/oc_storage.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#ifdef OC_COLLECTIONS
#include "oc_collection.h"
#endif /* OC_COLLECTIONS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Call back handlers that are invoked in response to oc_main_init()
 *
 * @see oc_main_init
 */
typedef struct
{
  /**
   * Device initialization callback that is invoked to initialize the platform
   * and device(s).
   *
   * At a minimum the platform should be initialized and at least one device
   * added.
   *
   *  - oc_init_platform()
   *  - oc_add_device()
   *
   * Multiple devices can be added by making multiple calls to oc_add_device().
   *
   * Other actions may be taken in the init handler
   *  - The immutable device identifier can be set `piid`
   *    (a.k.a Protocol Independent ID) oc_set_immutable_device_identifier()
   *  - Set introspection data oc_set_introspection_data()
   *  - Set up an interrupt handler oc_activate_interrupt_handler()
   *  - Initialize application specific variables
   *
   * @return
   *  - 0 to indicate success initializing the application
   *  - value less than zero to indicate failure initializing the application
   *
   * @see oc_activate_interrupt_handler
   * @see oc_add_device
   * @see oc_init_platform
   * @see oc_set_immutable_device_identifier
   * @see oc_set_introspection_data
   */
  int (*init)(void);

  /**
   * Function to signal the event loop
   * so that incomming events are being processed.
   *
   * @see oc_main_poll
   */
  void (*signal_event_loop)(void);

#ifdef OC_SERVER
  /**
   * Resource registration callback.
   *
   * Callback is invoked after the device initialization callback.
   *
   * Use this callback to add resources to the devices added during the device
   * initialization.  This where the properties and callbacks associated with
   * the resources are typically done.
   *
   * Note: Callback is only invoked when OC_SERVER macro is defined.
   *
   * Example:
   * ```
   * static void register_resources(void)
   * {
   *   oc_resource_t *bswitch = oc_new_resource(NULL, "/switch", 1, 0);
   *   oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
   *   oc_resource_bind_resource_interface(bswitch, OC_IF_A);
   *   oc_resource_set_default_interface(bswitch, OC_IF_A);
   *   oc_resource_set_discoverable(bswitch, true);
   *   oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
   *   oc_resource_set_request_handler(bswitch, OC_PUT, put_switch, NULL);
   *   oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
   *   oc_add_resource(bswitch);
   * }
   * ```
   *
   * @see init
   * @see oc_new_resource
   * @see oc_resource_bind_resource_interface
   * @see oc_resource_set_default_interface
   * @see oc_resource_bind_resource_type
   * @see oc_resource_make_public
   * @see oc_resource_set_discoverable
   * @see oc_resource_set_observable
   * @see oc_resource_set_periodic_observable
   * @see oc_resource_set_properties_cbs
   * @see oc_resource_set_request_handler
   * @see oc_add_resource
   */
  void (*register_resources)(void);
#endif /* OC_SERVER */

#ifdef OC_CLIENT
  /**
   * Callback invoked when the stack is ready to issue discovery requests.
   *
   * Callback is invoked after the device initialization callback.
   *
   * Example:
   * ```
   * static void issue_requests(void)
   * {
   *   oc_do_ip_discovery("oic.r.switch.binary", &discovery, NULL);
   * }
   * ```
   *
   * @see init
   * @see oc_do_ip_discovery
   * @see oc_do_ip_discovery_at_endpoint
   * @see oc_do_site_local_ipv6_discovery
   * @see oc_do_realm_local_ipv6_discovery
   */
  void (*requests_entry)(void);
#endif /* OC_CLIENT */
} oc_handler_t;

/**
 * Callback invoked during oc_init_platform(). The purpose is to add any
 * additional platform properties that are not supplied to oc_init_platform()
 * function call.
 *
 * Example:
 * ```
 * static void set_additional_platform_properties(void *data)
 * {
 *   (void)data;
 *   // Manufactures Details Link
 *   oc_set_custom_platform_property(mnml,
 * "http://www.example.com/manufacture");
 *   // Model Number
 *   oc_set_custom_platform_property(mnmo, "Model No1");
 *   // Date of Manufacture
 *   oc_set_custom_platform_property(mndt,"2020/01/17");
 *   //Serial Number
 *   oc_set_custom_platform_property(mnsel, "1234567890");
 * }
 *
 * static int app_init(void)
 * {
 *   int ret = oc_init_platform("My Platform",
 * set_additional_platform_properties, NULL); ret |= oc_add_device("/oic/d",
 * "oic.d.light", "My light", "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL); return
 * ret;
 * }
 * ```
 *
 * @param[in] data context pointer that comes from the oc_add_device() function
 *
 * @see oc_add_device
 * @see oc_set_custom_device_property
 */
typedef void (*oc_init_platform_cb_t)(void *data);

/**
 * Callback invoked during oc_add_device(). The purpose is to add any additional
 * device properties that are not supplied to oc_add_device() function call.
 *
 * Example:
 * ```
 * static void set_device_custom_property(void *data)
 * {
 *   (void)data;
 *   oc_set_custom_device_property(purpose, "desk lamp");
 * }
 *
 * static int app_init(void)
 * {
 *   int ret = oc_init_platform("My Platform", NULL, NULL);
 *   ret |= oc_add_device("/oic/d", "oic.d.light", "My light", "ocf.1.0.0",
 *                        "ocf.res.1.0.0", set_device_custom_property, NULL);
 *   return ret;
 * }
 * ```
 *
 * @param[in] data context pointer that comes from the oc_init_platform()
 * function
 *
 * @see oc_add_device
 * @see oc_set_custom_device_property
 */
typedef void (*oc_add_device_cb_t)(void *data);

/**
 * Register and call handler functions responsible for controlling the
 * IoTivity-lite stack.
 *
 * This will initialize the IoTivity-lite stack.
 *
 * Before initializing the stack, a few setup functions may need to be called
 * before calling oc_main_init those functions are:
 *
 * - oc_set_con_res_announced()
 * - oc_set_factory_presets_cb()
 * - oc_set_max_app_data_size()
 * - oc_set_random_pin_callback()
 * - oc_storage_config()
 *
 * Not all of the listed functions must be called before calling oc_main_init.
 *
 * @param[in] handler struct containing pointers callback handler functions
 *                    responsible for controlling the IoTivity-lite application
 * @return
 *  - `0` if stack has been initialized successfully
 *  - a negative number if there is an error in stack initialization
 *
 * @see oc_set_con_res_announced
 * @see oc_set_factory_presets_cb
 * @see oc_set_max_app_data_size
 * @see oc_set_random_pin_callback
 * @see oc_storage_config
 */
OC_API
int oc_main_init(const oc_handler_t *handler);

/**
 * @brief Poll to process tasks
 *
 * @return Time for the next poll event in monotonic time
 *
 * @note The underlying implementation uses monotonic to keep track of time. To
 * calculate the remaining time until the next poll event use
 * oc_clock_time_monotonic().
 *
 * \see oc_clock_time_monotonic
 */
OC_API
oc_clock_time_t oc_main_poll_v1(void);

/**
 * Poll to process tasks
 *
 * @return Time for the next poll event in absolute time
 *
 * @deprecated replaced by oc_main_poll_v1 in v2.2.5.6
 */
OC_API
oc_clock_time_t oc_main_poll(void)
  OC_DEPRECATED("replaced by oc_main_poll_v1 in v2.2.5.6");

/**
 * @brief Check if process polling was requested
 *
 * @return true A polling of processes was requested by a call to
 * oc_process_poll and oc_main_poll_v1 should be called.
 * @return false Otherwise
 *
 * @sa oc_main_poll
 * @sa oc_process_poll
 */
OC_API
bool oc_main_needs_poll(void);

/**
 * Shutdown and free all stack related resources
 */
OC_API
void oc_main_shutdown(void);

/**
 * Callback invoked by the stack initialization to perform any
 * "factory settings", e.g., this may be used to load a manufacturer
 * certificate.
 *
 * The following example illustrates the method of loading a manufacturer
 * certificate chain (end-entity certificate, intermediate CA certificate, and
 * root CA certificate) using oc_pki_xxx APIs.
 *
 * Example:
 * ```
 * void factory_presets_cb(size_t device, void *data)
 * {
 *   (void)device;
 *   (void)data;
 * #if defined(OC_SECURITY) && defined(OC_PKI)
 *   char cert[8192];
 *   size_t cert_len = 8192;
 *   if (read_pem("pki_certs/ee.pem", cert, &cert_len) < 0) {
 *     OC_PRINTF("ERROR: unable to read certificates\n");
 *     return;
 *   }
 *
 *   char key[4096];
 *   size_t key_len = 4096;
 *   if (read_pem("pki_certs/key.pem", key, &key_len) < 0) {
 *     OC_PRINTF("ERROR: unable to read private key");
 *     return;
 *   }
 *
 *   int ee_credid = oc_pki_add_mfg_cert(0, (const unsigned char *)cert,
 * cert_len, (const unsigned char *)key, key_len);
 *
 *   if (ee_credid < 0) {
 *     OC_PRINTF("ERROR installing manufacturer EE cert\n");
 *     return;
 *   }
 *
 *   cert_len = 8192;
 *   if (read_pem("pki_certs/subca1.pem", cert, &cert_len) < 0) {
 *     OC_PRINTF("ERROR: unable to read certificates\n");
 *     return;
 *   }
 *
 *   int subca_credid = oc_pki_add_mfg_intermediate_cert(
 *     0, ee_credid, (const unsigned char *)cert, cert_len);
 *
 *   if (subca_credid < 0) {
 *     OC_PRINTF("ERROR installing intermediate CA cert\n");
 *     return;
 *   }
 *
 *   cert_len = 8192;
 *   if (read_pem("pki_certs/rootca1.pem", cert, &cert_len) < 0) {
 *     OC_PRINTF("ERROR: unable to read certificates\n");
 *     return;
 *   }
 *
 *   int rootca_credid =
 *     oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
 *   if (rootca_credid < 0) {
 *     OC_PRINTF("ERROR installing root cert\n");
 *     return;
 *   }
 *
 *   oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, ee_credid);
 * #endif // OC_SECURITY && OC_PKI
 * }
 * ```
 * @param[in] device number of the device
 * @param[in] data context pointer that comes from the
 *                 oc_set_factory_presets_cb() function
 *
 * @see oc_set_factory_presets_cb
 * @see oc_pki_add_mfg_cert
 * @see oc_pki_add_mfg_intermediate_cert
 * @see oc_pki_add_mfg_trust_anchor
 * @see oc_pki_set_security_profile
 */
typedef void (*oc_factory_presets_cb_t)(size_t device, void *data);

/**
 * Set the factory presets callback.
 *
 * The factory presets callback is called by the stack to enable per-device
 * presets.
 *
 * @note oc_set_factory_presets_cb() must be called before oc_main_init().
 *
 * @param[in] cb oc_factory_presets_cb_t function pointer to be called
 * @param[in] data context pointer that is passed to the oc_factory_presets_cb_t
 *                 the pointer must be a valid pointer till after oc_main_init()
 *                 call completes.
 */
OC_API
void oc_set_factory_presets_cb(oc_factory_presets_cb_t cb, void *data);

/**
 * Add an ocf device to the the stack.
 *
 * This function is typically called as part of the stack initialization
 * process from inside the `init` callback handler.
 *
 * The `oc_add_device` function may be called as many times as needed.
 * Each call will add a new device to the stack with its own port address.
 * Each device is automatically assigned a number starting with zero and
 * incremented by one each time the function is called. This number is not
 * returned therefore it is important to know the order devices are added.
 *
 * Example:
 * ```
 * //app_init is an instance of the `init` callback handler.
 * static int app_init(void)
 * {
 *   int ret = oc_init_platform("Refrigerator", NULL, NULL);
 *   ret |= oc_add_device("/oic/d", "oic.d.refrigeration", "My fridge",
 *                        "ocf.2.0.5", "ocf.res.1.0.0,ocf.sh.1.0.0",
 *                        NULL, NULL);
 *   ret |= oc_add_device("/oic/d", "oic.d.thermostat", "My thermostat",
 *                        "ocf.2.0.5", "ocf.res.1.0.0,ocf.sh.1.0.0",
 *                        NULL, NULL);
 *   return ret;
 * }
 * ```
 *
 * @param[in] uri the The device URI.  The wellknown default URI "/oic/d"
 *            is hosted by every server. Used to expose device specific
 *            information
 * @param[in] rt the resource type
 * @param[in] name the user readable name of the device
 * @param[in] spec_version The version of the OCF Server.  This is the "icv"
 *                         device property
 * @param[in] data_model_version Spec version of the resource and device
 * specifications to which this device data model is implemtned. This is the
 * "dmv" device property
 * @param[in] add_device_cb callback function invoked during oc_add_device().
 * The purpose is to add additional device properties that are not supplied to
 * oc_add_device() function call.
 * @param[in] data context pointer that is passed to the oc_add_device_cb_t
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 */
OC_API
int oc_add_device(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, void *data);

typedef enum oc_connectivity_listening_port_flags_e {
  OC_CONNECTIVITY_DISABLE_IPV6_PORT = 0x01, /**< Disable port on IPv6 */
#ifdef OC_IPV4
  OC_CONNECTIVITY_DISABLE_IPV4_PORT = 0x02, /**< Disable port on IPv4 */
#endif                                      /* OC_IPV4 */
#ifdef OC_SECURITY
  OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT = 0x04, /**< Disable port on
                                    IPv6 for secure connections */
#ifdef OC_IPV4
  OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT = 0x08, /**< Disable port on
                                    IPv4 for secure connections */
#endif                                             /* OC_IPV4 */
#endif                                             /* OC_SECURITY */
  OC_CONNECTIVITY_DISABLE_ALL_PORTS = 0x0F         /**< Disable all ports */
} oc_connectivity_listening_port_flags_t;

/**
 * @brief The structure includes flags that can be used to disable listening on
 * certain IP interfaces. If a port is set to 0, the system will determine which
 * port to open by default. On the other hand, if a port is specified, the stack
 * will open that particular port.
 */
typedef struct oc_connectivity_listening_ports_s
{
  oc_connectivity_listening_port_flags_t
    flags;       /**< Flags for the listening ports. */
  uint16_t port; /**< The IPv6 port for unsecure connections. */
#ifdef OC_SECURITY
  uint16_t secure_port; /**< The IPv6 port for secure connections. */
#endif                  /* OC_SECURITY */
#ifdef OC_IPV4
  uint16_t port4; /**< The IPv4 port for unsecure connections. */
#ifdef OC_SECURITY
  uint16_t secure_port4; /**< The IPv4 port for secure connections. */
#endif                   /* OC_SECURITY */
#endif                   /* OC_IPV4 */
} oc_connectivity_listening_ports_t;

typedef struct oc_connectivity_ports_s
{
  oc_connectivity_listening_ports_t
    udp; /**< Define the UDP ports. When unsecure/secure ports are disabled, the
            stack also disables the client-side because it uses the same socket
            for both server and client. Port 5683 is reserved for multicast
            binding for both IPv4 and IPv6. */
#ifdef OC_TCP
  oc_connectivity_listening_ports_t
    tcp; /**< Define the TCP listening ports. The clients are not affected
            because each connection has its own socket. */
#endif   /* OC_TCP */
} oc_connectivity_ports_t;

typedef struct oc_add_new_device_s
{
  const char *uri;  ///< The device URI. The wellknown default URI "/oic/d" is
                    ///< hosted by every server. Used to expose device specific
                    ///< information (cannot be NULL).
  const char *rt;   ///< The resource type (cannot be NULL).
  const char *name; ///< User readable name of the device (cannot be NULL).
  const char *spec_version; ///< The version of the OCF Server. This is the
                            ///< "icv" device property (cannot be NULL).
  const char *data_model_version; ///< Spec version of the resource and device
                                  ///< specifications to which this device data
                                  ///< model is implemented. This is the "dmv"
                                  ///< device property (cannot be NULL).
  oc_add_device_cb_t
    add_device_cb; ///< Callback function invoked during oc_add_device() The
                   ///< purpose is to add additional device properties that are
                   ///< not supplied to oc_add_device() function call.
  void *add_device_cb_data; ///< Data context pointer that is passed to the
                            ///< oc_add_device_cb_t

  oc_connectivity_ports_t ports; ///< The UDP and TCP ports configuration.
} oc_add_new_device_t;

/**
 * Add an ocf device to the the stack.
 *
 * This function is typically called as part of the stack initialization
 * process from inside the `init` callback handler.
 *
 * The `oc_add_device_v1` function may be called as many times as needed.
 * Each call will add a new device to the stack with its own port address.
 * Each device is automatically assigned a number starting with zero and
 * incremented by one each time the function is called. This number is not
 * returned therefore it is important to know the order devices are added.
 *
 * Example:
 * ```
 * //app_init is an instance of the `init` callback handler.
 * static int app_init(void)
 * {
 *   int ret = oc_init_platform("Refrigerator", NULL, NULL);
 *   ret |= oc_add_device_v1(device1);
 *   ret |= oc_add_device_v1(device2);
 *   return ret;
 * }
 * ```
 *
 * @param[in] cfg the configuration of the new device
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 */
OC_API
int oc_add_device_v1(oc_add_new_device_t cfg);

/**
 * Set custom device property
 *
 * The purpose is to add additional device properties that are not supplied to
 * oc_add_device() function call. This function will likely only be used inside
 * the oc_add_device_cb_t().
 *
 * @param[in] prop the name of the custom property being added to the device
 * @param[in] value the value of the custom property being added to the device
 *
 * @see oc_add_device_cb_t for example code using this function
 * @see oc_add_device
 */
#define oc_set_custom_device_property(prop, value)                             \
  oc_rep_set_text_string(root, prop, value)

/**
 * Initialize the platform.
 *
 * This function is typically called as part of the stack initialization
 * process from inside the `init` callback handler.
 *
 * @param[in] mfg_name the name of the platform manufacture
 * @param[in] init_platform_cb callback function invoked during
 *                             oc_init_platform(). The purpose is to add
 *                             additional device properties that are not
 *                             supplied to oc_init_platform() function call.
 * @param[in] data context pointer that is passed to the oc_init_platform_cb_t
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 * @see oc_init_platform_cb_t
 */
OC_API
int oc_init_platform(const char *mfg_name,
                     oc_init_platform_cb_t init_platform_cb, void *data);

/**
 * Set custom platform property.
 *
 * The purpose is to add additional platfrom properties that are not supplied to
 * oc_init_platform() function call. This function will likely only be used
 * inside the oc_init_platform_cb_t().
 *
 * @param[in] prop the name of the custom property being added to the platform
 * @param[in] value the value of the custom property being added to the platform
 *
 * @see oc_init_platform_cb_t for example code using this function
 * @see oc_init_platform
 */
#define oc_set_custom_platform_property(prop, value)                           \
  oc_rep_set_text_string(root, prop, value)

/**
 * Callback invoked when an onboarding client requests device ownership via the
 * Random PIN Ownership Transfer Method (OTM).  The purpose of the callback is
 * to allow the device to display the random PIN to the user onboarding the
 * device.
 *
 * Example:
 * ```
 * #ifdef OC_SECURITY
 * static void random_pin_cb(const unsigned char *pin, size_t pin_len, void
 * *data)
 * {
 *  (void)data;
 *  OC_PRINTF("\n\nRandom PIN: %.*s\n\n", (int)pin_len, pin);
 * }
 * #endif // OC_SECURITY
 *
 * int main(void) {
 *   ...
 * #ifdef OC_SECURITY
 *   oc_storage_config("./server_creds");
 *   oc_set_random_pin_callback(random_pin_cb, NULL);
 * #endif // OC_SECURITY
 *   // handler code omitted from example code see oc_main_init
 *   oc_main_init(&handler)
 *   ...
 *   return 0;
 * }
 * ```
 *
 * @param[in] pin random pin
 * @param[in] pin_len length of the random pin
 * @param[in] data context pointer that comes from the oc_init_platform()
 *                 function
 *
 * @see oc_set_random_pin_callback
 */
typedef void (*oc_random_pin_cb_t)(const unsigned char *pin, size_t pin_len,
                                   void *data);

/**
 * Set the random pin callback for Random PIN Ownership Transfer Method (OTM)
 *
 * @note This should be set before invoking oc_main_init().
 *
 * @param[in] cb callback function invoked when client requests Random PIN OTM
 * @param[in] data context pointer that is passed to the oc_random_pin_cb_t the
 *                 context pointer must be a valid pointer as long as the device
 *                 is in 'Ready For Ownership Transfer Method' (RFOTM) state.
 *
 * @see oc_random_pin_cb_t
 * @see oc_main_init
 */
OC_API
void oc_set_random_pin_callback(oc_random_pin_cb_t cb, void *data);

/**
 * Returns whether the oic.wk.con resource is advertised.
 *
 * @return
 *  - true if advertised (default)
 *  - false if not
 *
 * @see oc_set_con_res_announced
 * @see oc_set_con_write_cb
 */
OC_API
bool oc_get_con_res_announced(void);

/**
 * Sets whether the oic.wk.con resource is announced.
 *
 * @note This should be set before invoking oc_main_init().
 *
 * @param[in] announce true to announce (default) or false if not
 *
 * @see oc_get_con_res_announced
 * @see oc_set_con_write_cb
 */
OC_API
void oc_set_con_res_announced(bool announce);

/**
 * Reset all logical devices to the RFOTM state and close all opened TLS
 * connections immediately.
 *
 * All devices will be placed in the 'Ready For Ownership Transfer Mode'
 * (RFOTM). This is the initial startup state for for all devices that have not
 * yet been onboarded.  After this call all devices will need to be onboarded
 * and provisioned again.
 *
 * @note The function oc_reset() deals only with security and provisioning it
 *       does not reset any other device settings.
 *
 * @note Use of this function requires building with OC_SECURITY defined.
 * @note A device connected to a cloud is not unregistered from the cloud since
 * the connection has been closed immediately.
 */
OC_API
void oc_reset(void);

/**
 * Reset all logical devices to the RFOTM state.
 *
 * All devices will be placed in the 'Ready For Ownership Transfer Mode'
 * (RFOTM). This is the initial startup state for for all devices that have not
 * yet been onboarded.  After this call all devices will need to be onboarded
 * and provisioned again.
 *
 * @note The function oc_reset_v1() deals only with security and provisioning it
 *       does not reset any other device settings.
 *
 * @note Use of this function requires building with OC_SECURITY defined.
 *
 * @param[in] force true to close all TLS
 *            connections immediately, false to close them after the 2 second
 * delay. Set to false if the device is connected to a cloud and you want to
 * unregister it.
 */
OC_API
void oc_reset_v1(bool force);

/**
 * Reset logical device to the RFOTM state and close all opened TLS connections
 * immediately.
 *
 * The device will be placed in the 'Ready For Ownership Transfer Mode' (RFOTM).
 * This is the initial state startup state for for all devices that have not yet
 * been onboarded.  After this call the device will need to be onboarded and
 * provisioned again.
 *
 * @note The function oc_reset_device() deals only with security and
 *       provisioning it does not reset any other device settings.
 *
 * @note Use of this function requires building the stack with OC_SECURITY
 *       defined.
 *
 * @param[in] device index of the logical device to reset
 */
OC_API
void oc_reset_device(size_t device);

/**
 * Reset logical device to the RFOTM state.
 *
 * The device will be placed in the 'Ready For Ownership Transfer Mode' (RFOTM).
 * This is the initial state startup state for for all devices that have not yet
 * been onboarded.  After this call the device will need to be onboarded and
 * provisioned again.
 *
 * @note The function oc_reset_device() deals only with security and
 *       provisioning it does not reset any other device settings.
 *
 * @note Use of this function requires building the stack with OC_SECURITY
 *       defined.
 *
 * @param[in] device index of the logical device to reset
 * @param[in] force true to reset immediately, false to reset after the 2 second
 * for terminate the connections (eg cloud unregistration)
 *
 */
OC_API
bool oc_reset_device_v1(size_t device, bool force);

/**
 * Callback invoked when the "owned" property of the doxm is changed
 *
 * @param[in] device_uuid the UUID of the device that change ownership
 * @param[in] device_index of the logical device that changed ownership
 * @param[in] owned if true the device has been claimed by an onboarding tool
 * @param[in] user_data context pointer
 */
typedef void (*oc_ownership_status_cb_t)(const oc_uuid_t *device_uuid,
                                         size_t device_index, bool owned,
                                         void *user_data);
/**
 * Add callback that is invoked when the doxm "owned" property is changed
 *
 * If oc_add_ownership_status_cb is called before oc_main_init or inside
 * one of the , the oc_handler_t callback funtions the oc_ownership_status_cb_t
 * will be invoked when the stack is initilized giving the startup ownership
 * value. If oc_add_ownership_status_cb is called after oc_main_init the
 * oc_add_ownership_status_cb will not be invoked for the startup ownership
 * value.
 *
 * @note Use of this function requires building the stack with OC_SECURITY
 *       defined.
 *
 * @param[in] cb callback function that will be invoked
 * @param[in] user_data context pointer passed to the oc_ownership_status_cb_t
 * callback the pointer must remain valid till callback is removed.
 */
OC_API
void oc_add_ownership_status_cb(oc_ownership_status_cb_t cb, void *user_data);

/**
 * Remove the ownership changed callback
 *
 * @note Use of this function requires building the stack with OC_SECURITY
 *       defined.
 *
 * @param[in] cb callback function to remove
 * @param[in] user_data the context pointer used when the callback was added
 */
OC_API
void oc_remove_ownership_status_cb(oc_ownership_status_cb_t cb,
                                   const void *user_data);

/**
 * Get the ownership status of the logical device this is the value of the
 * doxm "owned" property
 *
 * If oc_is_owned_device() is called before oc_main_init() has completed it will
 * always return false because stack security has not been initialized.
 *
 * @note Use of this function requires building the stack with OC_SECURITY
 *       defined.
 *
 * @param[in] device_index the index of the logical device
 *
 * @return true if the device is owned by an onboarding tool
 */
OC_API
bool oc_is_owned_device(size_t device_index);

/**
 * Callback to filter out unsupported ownership methods when they are evaluated.
 *
 * For example, if you want to support only the manufacturer certificate based
 * owner transfer method, you will set oxms[0] to OC_OXMTYPE_MFG_CERT and
 * *num_oxms to 1.
 *
 * @param[in] device_index of the logical device that changed ownership
 * @param[in,out] oxms array of supported ownership types(oc_sec_doxmtype_t).
 * Filters out non-supported methods.
 * @param[in,out] num_oxms number of supported ownership methods.
 * @param[in] user_data context pointer
 */
typedef void (*oc_select_oxms_cb_t)(size_t device_index, int *oxms,
                                    int *num_oxms, void *user_data);

/**
 * Sets the callback to filter out unsupported ownership methods.
 *
 * The function can be used to set or unset the callback. For example,
 * if you want to support only the manufacturer certificate based owner transfer
 * method.
 *
 * @param callback The callback to register or NULL to unset it. If the function
 *                 is invoked a second time, then the previously set callback is
 *                 simply replaced.
 * @param[in] user_data context pointer
 */
OC_API
void oc_set_select_oxms_cb(oc_select_oxms_cb_t callback, void *user_data);

/* Server side */
/**
  @defgroup doc_module_tag_server_side Server side
  Optional group of functions OCF server support.
  @{
*/
/**
 * Allocate and populate a new oc_resource_t.
 *
 * Resources are the primary interface between code and real world devices.
 *
 * Each resource has a Uniform Resource Identifier (URI) that identifies it.
 * All resources **must** specify one or more Resource Types to be considered a
 * valid resource. The number of Resource Types is specified by the
 * `num_resource_types` the actual Resource Types are added later using the
 * oc_resource_bind_resource_type() function.
 *
 * The resource is populated with a default interface OC_IF_BASELINE.
 *
 * Many properties associated with a resource are set or modified after the
 * new resource has been created.
 *
 * The resource is not added to the device till oc_add_resource() is called.
 *
 * Example:
 * ```
 * static void register_resources(void)
 * {
 *   oc_resource_t *bswitch = oc_new_resource("light switch", "/switch", 1, 0);
 *   oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
 *   oc_resource_bind_resource_interface(bswitch, OC_IF_A);
 *   oc_resource_set_default_interface(bswitch, OC_IF_A);
 *   oc_resource_set_observable(bswitch, true);
 *   oc_resource_set_discoverable(bswitch, true);
 *   oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
 *   oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
 *   oc_resource_set_request_handler(bswitch, OC_PUT, put_switch, NULL);
 *   oc_add_resource(bswitch);
 * }
 * ```
 *
 * @param[in] name the name of the new resource this will set the property `n`
 * @param[in] uri the Uniform Resource Identifier for the resource (cannot be
 * NULL)
 * @param[in] num_resource_types the number of Resource Types that will be
 *                               added/bound to the resource
 * @param[in] device index of the logical device the resource will be added to
 *
 * @see oc_resource_bind_resource_interface
 * @see oc_resource_set_default_interface
 * @see oc_resource_bind_resource_type
 * @see oc_process_baseline_interface
 * @see oc_resource_set_discoverable
 * @see oc_resource_set_periodic_observable
 * @see oc_resource_set_request_handler
 */
OC_API
oc_resource_t *oc_new_resource(const char *name, const char *uri,
                               uint8_t num_resource_types, size_t device)
  OC_NONNULL(2);

/**
 * Add the supported interface(s) to the resource.
 *
 * Resource interfaces specify how the code is able to interact with the
 * resource
 *
 * The `iface_mask` is bitwise OR of the following interfaces:
 *  - `OC_IF_BASELINE` ("oic.if.baseline") baseline interface allow GET,
 *                      PUT/POST, and notify/observe operations.
 *  - `OC_IF_LL` ("oic.if.ll") The links list interface is a specifically
 *               designed to provide a list of links pointing to other
 * resources. Links list interfaces allow GET, and notify/observe operations.
 *  - `OC_IF_B` ("oic.if.b") batch interface. The batch interface is used to
 *              interact with a collection of resources at the same time.
 *  - `OC_IF_R` ("oic.if.r") a read-only interface.  A read-only interface
 * allows GET, and notify/observe operations.
 *  - `OC_IF_RW` ("oir.if.rw") a read-write interface.  A read-write interface
 *                allows GET, PUT/POST, and notify/observe operations.
 *  - `OC_IF_A` ("oic.if.a") an actuator interface. An actuator interface allows
 *              GET, PUT/POST, and notify/observe operations.
 *  - `OC_IF_S` ("oic.if.s") a sensor interface.  A sensor interface allows GET,
 *              and notify/observe operations.
 *  - `OC_IC_CREATE` ("oic.if.create") used to create new resources in a
 *                   collection.
 *
 * The read-write and actuator interfaces are very similar and sometimes hard to
 * differentiate when one should be used over another.  In general an actuator
 * interface is used when it modifies the real world value. e.g. turn on light,
 * increase temperature, open vent.
 *
 * The read-only and sensor are also very similar in general a sensor value is
 * read directly or indirectly from a real world sensor.
 *
 * @param resource the resource that the interface(s) will be added to (cannot
 * be NULL)
 * @param iface_mask a bitwise ORed list of all interfaces supported by the
 * resource.
 * @see oc_interface_mask_t
 * @see oc_resource_set_default_interface
 */
OC_API
void oc_resource_bind_resource_interface(oc_resource_t *resource,
                                         oc_interface_mask_t iface_mask)
  OC_NONNULL();

/**
 * Select the default interface.
 *
 * The default interface must be one of the resources specified in the
 * oc_resource_bind_resource_interface() function.
 *
 * If a request to the resource comes in and the interface is not specified
 * then the default interface will be used to service the request.
 *
 * If the default interface is not set then the OC_IF_BASELINE will be used
 * by the stack.
 *
 * @param resource the resource that the default interface will be set on
 * (cannot be NULL)
 * @param iface_mask a single interface that will will be used as the default
 * interface
 */
OC_API
void oc_resource_set_default_interface(oc_resource_t *resource,
                                       oc_interface_mask_t iface_mask)
  OC_NONNULL();

/**
 * Add a Resource Type "rt" property to the resource.
 *
 * All resources require at least one Resource Type. The number of Resource
 * Types the resource contains is declared when the resource it created using
 * oc_new_resource() function.
 *
 * Resource Types use a dot "." naming scheme e.g. `oic.r.switch.binary`.
 * Resource Types starting with `oic` are reserved for a OCF defined Resource
 * Types.  Developers are strongly encouraged to try and use an OCF defined
 * Resource Type vs. creating their own. A repository of OCF defined resources
 * can be found on https://github.com/openconnectivityfoundation/IoTDataModels.
 *
 * Multi-value "rt" Resource means a resource with multiple Resource Types. i.e.
 * oc_resource_bind_resource_type() is called multiple times for a single
 * resource. When using a Mulit-value Resource the different resources
 * properties must not conflict.
 *
 * @param resource the resource that the Resource Type will be set on (cannot be
 * NULL)
 * @param type the Resource Type to add to the Resource Type "rt" property
 * (cannot be NULL)
 *
 * @see oc_new_resource
 * @see oc_device_bind_resource_type
 */
OC_API
void oc_resource_bind_resource_type(oc_resource_t *resource, const char *type)
  OC_NONNULL();

/**
 * Add a Resource Type "rt" property to the an `/oic/d` resource.
 *
 * This function can be used to bind a new Resource Type to a logical device's
 * `/oic/d` resource.
 *
 * @param device index of a logical device
 * @param type the Resource type to add to the Resource Type "rt" property
 * (cannot be NULL)
 */
OC_API
void oc_device_bind_resource_type(size_t device, const char *type) OC_NONNULL();

/**
 * @brief Sets the tag value for tag "tag-pos-desc" on the resource
 *
 * @param resource the resource (cannot be NULL)
 * @param pos the descriptive text for the tag
 */
OC_API
void oc_resource_tag_pos_desc(oc_resource_t *resource, oc_pos_description_t pos)
  OC_NONNULL();

/**
 * @brief Sets the value for the relative position "tag-pos-rel" tag
 *
 * @param resource the resource to apply the tag too (cannot be NULL).
 * @param x the x value in 3D space
 * @param y the y value in 3D space
 * @param z the z value in 3D space
 */
OC_API
void oc_resource_tag_pos_rel(oc_resource_t *resource, double x, double y,
                             double z) OC_NONNULL();

/**
 * @brief Sets the tag value for the relatvie position "tag_func_rel" tag
 *
 * @param resource the resource to apply the tag too (cannot be NULL).
 * @param func the function description
 */
OC_API
void oc_resource_tag_func_desc(oc_resource_t *resource, oc_enum_t func)
  OC_NONNULL();

/**
 * @brief sets the value of the "tag_locn" tag
 *
 * @param resource the resource to apply the tag too (cannot be NULL).
 * @param locn the location
 */
OC_API
void oc_resource_tag_locn(oc_resource_t *resource, oc_locn_t locn) OC_NONNULL();

/**
 * Helper function used when responding to a GET request to add Common
 * Properties to a GET response.
 *
 * This add Common Properties name ("n"), Interface ("if"), and Resource Type
 * ("rt") to a GET response.
 *
 * Example:
 * ```
 * bool bswitch_state = false;
 *
 * void get_bswitch(oc_resource_t *resource, oc_interface_mask_t iface_mask,
 *                  void *data)
 * {
 *   oc_rep_start_root_object();
 *   switch (iface_mask) {
 *   case OC_IF_BASELINE:
 *     oc_process_baseline_interface(resource);
 *   // fall through
 *   case OC_IF_A:
 *     oc_rep_set_boolean(root, value, bswitch_state);
 *     break;
 *   default:
 *     break;
 *   }
 *   oc_rep_end_root_object();
 *   oc_send_response(request, OC_STATUS_OK);
 * }
 * ```
 *
 * @param resource the resource the baseline Common Properties will be read
 * from to respond to the GET request (cannot be NULL)
 */
OC_API
void oc_process_baseline_interface(const oc_resource_t *resource) OC_NONNULL();

/**
 * Expose unsecured coap:// endpoints (in addition to secured coaps://
 * endpoints) for this resource in /oic/res.
 *
 * @note While the resource may advertise unsecured endpoints, the resource
 * shall remain inaccessible until the hosting device is configured with an
 * anon-clear Access Control Entry (ACE).
 *
 * @param resource the resource to make public (cannot be NULL)
 *
 * @see oc_new_resource
 */
OC_API
void oc_resource_make_public(oc_resource_t *resource) OC_NONNULL();

/**
 * Specify if a resource can be found using OCF discover mechanisms.
 *
 * @param resource to specify as discoverable or non-discoverable (cannot be
 * NULL)
 * @param state if true the resource will be discoverable if false the resource
 * will be non-discoverable
 *
 * @see oc_new_resource for example code using this function
 */
OC_API
void oc_resource_set_discoverable(oc_resource_t *resource, bool state)
  OC_NONNULL();

#ifdef OC_HAS_FEATURE_PUSH
/**
 * Specify if a resource can be pushable.
 *
 * @param resource to specify as pushable or non-pushable (cannot be NULL)
 * @param state if true the resource will be pushable if false the resource will
 * be non-pushable
 */
OC_API
void oc_resource_set_pushable(oc_resource_t *resource, bool state) OC_NONNULL();

#endif /* OC_HAS_FEATURE_PUSH */

/**
 * Specify that a resource should notify clients when a property has been
 * modified.
 *
 * @note this function can be used to make a periodic observable resource
 *       unobservable.
 *
 * @param resource the resource to specify the observability (cannot be NULL)
 * @param state true to make resource observable, false to make resource
 * unobservable
 *
 * @see oc_new_resource to see example code using this function
 * @see oc_resource_set_periodic_observable
 */
OC_API
void oc_resource_set_observable(oc_resource_t *resource, bool state)
  OC_NONNULL();

/**
 * The resource will periodically notify observing clients of is property
 * values.
 *
 * The oc_resource_set_observable() function can be used to turn off a periodic
 * observable resource.
 *
 * Setting a `seconds` frequency of zero `0` is invalid and will result in an
 * invalid resource.
 *
 * @param resource the resource to specify the periodic observability (cannot be
 * NULL)
 * @param seconds the frequency in seconds that the resource will send out
 *                    an notification of is property values.
 */
OC_API
void oc_resource_set_periodic_observable(oc_resource_t *resource,
                                         uint16_t seconds) OC_NONNULL();

/**
 * Specify a request_callback for GET, PUT, POST, and DELETE methods
 *
 * All resources must provide at least one request handler to be a valid
 * resource.
 *
 * method types:
 * - `OC_GET` the `oc_request_callback_t` is responsible for returning the
 * current value of all of the resource properties.
 * - `OC_PUT` the `oc_request_callback_t` is responsible for updating one or
 * more of the resource properties.
 * - `OC_POST` the `oc_request_callback_t` is responsible for updating one or
 * more of the resource properties. The callback may also be responsible for
 *         creating new resources.
 * - `OC_DELETE` the `oc_request_callback_t` is responsible for deleting a
 * resource
 *
 * @note Some methods may never by invoked based on the resources Interface as
 *       well as the provisioning permissions of the client.
 *
 * @param resource the resource the callback handler will be registered to
 * (cannot be NULL)
 * @param method specify if type method the callback is responsible for handling
 * @param callback the callback handler that will be invoked when a the method
 * is called on the resource.
 * @param user_data context pointer that is passed to the oc_request_callback_t.
 * The pointer must remain valid as long as the resource exists.
 *
 * @see oc_new_resource to see example code using this function
 */
OC_API
void oc_resource_set_request_handler(oc_resource_t *resource,
                                     oc_method_t method,
                                     oc_request_callback_t callback,
                                     void *user_data) OC_NONNULL(1);
#ifdef OC_OSCORE
/**
 * @brief sets the support of the secure multicast feature
 *
 * @param resource the resource
 * @param supported true: supported
 */
OC_API
void oc_resource_set_secure_mcast(oc_resource_t *resource, bool supported);
#endif /* OC_OSCORE */

/**
 * Add a resource to the IoTivity stack.
 *
 * The resource will be validated then added to the stack.
 *
 * @param resource the resource to add to the stack
 *
 * @return
 *  - true: the resource was successfully added to the stack.
 *  - false: the resource can not be added to the stack.
 */
OC_API
bool oc_add_resource(oc_resource_t *resource);

/**
 * Remove a resource from the IoTivity stack and delete the resource.
 *
 * Any resource observers will automatically be removed.
 *
 * This will free the memory associated with the resource.
 *
 * @param resource the resource to delete
 *
 * @return
 *  - true: when the resource has been deleted and memory freed.
 *  - false: there was an issue deleting the resource.
 */
OC_API
bool oc_delete_resource(oc_resource_t *resource);

/**
 * Schedule a callback to remove a resource.
 *
 * @param resource the resource to delete
 */
OC_API
void oc_delayed_delete_resource(oc_resource_t *resource);

/**
  @brief Callback for change notifications from the oic.wk.con resource.

  This callback is invoked to notify a change of one or more properties
  on the oic.wk.con resource. The `rep` parameter contains all properties,
  the function is not invoked for each property.

  When the function is invoked, all properties handled by the stack are
  already updated. The callee can use the invocation to optionally store
  the new values persistently.

  Once the callback returns, the response will be sent to the client
  and observers will be notified.

  @note As of now only the attribute "n" is supported.
  @note The callee shall not block for too long as the stack is blocked
        during the invocation.

  @param device_index index of the device to which the change was
                      applied, 0 is the first device
  @param rep list of properties and their new values
*/
typedef void (*oc_con_write_cb_t)(size_t device_index, const oc_rep_t *rep);

/**
 * Sets the callback to receive change notifications for
 * the `oic.wk.con` resource.
 *
 * The function can be used to set or unset the callback. Whenever
 * an attribute of the `oic.wk.con` resource is changed, the callback
 * will be invoked.
 *
 * @param callback The callback to register or NULL to unset it. If the function
 *                 is invoked a second time, then the previously set callback is
 *                 simply replaced.
 */
OC_API
void oc_set_con_write_cb(oc_con_write_cb_t callback);

/**
 * This resets the query iterator to the start of the URI query parameter
 *
 * This is used together with oc_iterate_query_get_values() or
 * oc_iterate_query() to iterate through query parameter of a URI that are part
 * of an `oc_request_t`
 */
OC_API
void oc_init_query_iterator(void);

/**
 * Iterate through the URI query parameters and get each key=value pair
 *
 * Before calling oc_iterate_query() the first time oc_init_query_iterator()
 * must be called to reset the query iterator to the first query parameter.
 *
 * @note the char pointers returned are pointing to the string location in the
 *       query string.  Do not rely on a nul terminator to find the end of the
 *       string since there may be additional query parameters.
 *
 * Example:
 * ```
 * char *value = NULL;
 * int value_len = -1;
 * char *key
 * oc_init_query_iterator();
 * while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0) {
 *   printf("%.*s = %.*s\n", key_len, key, query_value_len, query_value);
 * }
 * ```
 *
 * @param[in] request the oc_request_t that contains the query parameters
 * (cannot be NULL)
 * @param[out] key pointer to the location of the the key of the key=value pair
 * (cannot be NULL)
 * @param[out] key_len the length of the key string (cannot be NULL)
 * @param[out] value pointer the location of the value string assigned to the
 *             key=value pair
 * @param[out] value_len the length of the value string
 *
 * @return
 *   - The position in the query string of the next key=value string pair
 *   - `-1` if there are no additional query parameters
 */
OC_API
int oc_iterate_query(const oc_request_t *request, const char **key,
                     size_t *key_len, const char **value, size_t *value_len)
  OC_NONNULL(1, 2, 3);

/**
 * @brief Iterate though the URI query parameters for a specific key.
 *
 * Before calling oc_iterate_query_get_values_v1() the first time
 * oc_init_query_iterator() must be called to reset the query iterator to the
 * first query parameter.
 *
 * @note The char pointer returned is pointing to the string location in the
 *       query string. Do not rely on a nul terminator to find the end of the
 *       string since there may be additional query parameters.
 *
 * Example:
 * ```
 * bool more_query_params = false;
 * const char* expected_value = "world";
 * const char *value = NULL;
 * int value_len = -1;
 * oc_init_query_iterator();
 * do {
 *   more_query_params = oc_iterate_query_get_values_v1(request, "hello",
 *                         strlen("hello"), &value, &value_len);
 *   if (rt_len > 0) {
 *     printf("Found %s = %.*s\n", "hello", value_len, value);
 *   }
 * } while (more_query_params);
 * ```
 *
 * @param[in] request the oc_request_t that contains the query parameters
 * (cannot be NULL)
 * @param[in] key the key being searched for (cannot be NULL)
 * @param[in] key_len the length of the key
 * @param[out] value pointer to the value string for to the key=value pair
 * (cannot be NULL)
 * @param[out] value_len the length of the value string (cannot be NULL)
 *
 * @return True if there are more query parameters to iterate through
 */
OC_API
bool oc_iterate_query_get_values_v1(const oc_request_t *request,
                                    const char *key, size_t key_len,
                                    const char **value, int *value_len)
  OC_NONNULL();

/**
 * @brief Iterate though the URI query parameters for a specific key.
 *
 * @deprecated replaced by oc_iterate_query_get_values_v1 in v2.2.5.9
 */
OC_API
bool oc_iterate_query_get_values(const oc_request_t *request, const char *key,
                                 const char **value, int *value_len)
  OC_NONNULL()
    OC_DEPRECATED("replaced by oc_iterate_query_get_values_v1 in v2.2.5.9");

/**
 * @brief Get a pointer to the start of the value in a URL query parameter
 * key=value pair.
 *
 * @note The char pointer returned is pointing to the string location in the
 *       query string. Do not rely on a nul terminator to find the end of the
 *       string since there may be additional query parameters.
 *
 * @param[in] request the oc_request_t that contains the query parameters
 * @param[in] key the key being searched for (cannot be NULL)
 * @param[in] key_len the length of the key
 * @param[out] value pointer to the value string assigned to the key
 *
 * @return
 *   - The position in the query string of the next key=value string pair
 *   - `-1` if there are no additional query parameters
 */
OC_API
int oc_get_query_value_v1(const oc_request_t *request, const char *key,
                          size_t key_len, const char **value) OC_NONNULL(2);

/**
 * @brief Get a pointer to the start of the value in a URL query parameter
 * key=value pair.
 *
 * @deprecated replaced by oc_get_query_value_v1 in v2.2.5.9
 */
OC_API
int oc_get_query_value(const oc_request_t *request, const char *key,
                       const char **value) OC_NONNULL(2)
  OC_DEPRECATED("replaced by oc_get_query_value_v1 in v2.2.5.9");

/**
 * @brief Checks if a query parameter 'key' exist in the URL query parameter
 *
 * @param request the oc_request_t that contains the query parameters
 * @param key the key being searched for (cannot be NULL)
 * @param key_len the length of the key
 *
 * @return true if the key exist in the query parameter
 * @return false if the key does not exist in the query parameter
 */
OC_API
bool oc_query_value_exists_v1(const oc_request_t *request, const char *key,
                              size_t key_len) OC_NONNULL(2);

/**
 * @brief Checks if a query parameter 'key' exist in the URL query parameter
 *
 * @return 1 if the key exist in the query parameter
 * @return -1 if the key does not exist in the query parameter
 *
 * @deprecated replaced by oc_query_value_exists_v1 in v2.2.5.9
 */
OC_API
int oc_query_value_exists(const oc_request_t *request, const char *key)
  OC_NONNULL(2)
    OC_DEPRECATED("replaced by oc_query_value_exists_v1 in v2.2.5.9");

/**
 * Called after the response to a GET, PUT, POST or DELETE call has been
 * prepared completed
 *
 * The function oc_send_response is called at the end of a
 * oc_request_callback_t to inform the caller about the status of the requested
 * action.
 *
 *
 * @param[in] request the request being responded to
 * @param[in] response_code the status of the response
 * @param[in] trigger_cb if true, the send response callback will be triggered
 *
 * @note For libraries it is recommended to set trigger_cb to true to allow
 * modify the response body.
 *
 * @see oc_request_callback_t
 * @see oc_ignore_request
 * @see oc_indicate_separate_response
 */
OC_API
void oc_send_response_with_callback(oc_request_t *request,
                                    oc_status_t response_code, bool trigger_cb);

/**
 * Called after the response to a GET, PUT, POST or DELETE call has been
 * prepared completed
 *
 * The function oc_send_response is called at the end of a
 * oc_request_callback_t to inform the caller about the status of the requested
 * action.
 *
 * @note This function just calls oc_send_response_with_callback with trigger_cb
 * set to false.
 *
 * @param[in] request the request being responded to
 * @param[in] response_code the status of the response
 *
 * @see oc_request_callback_t
 * @see oc_ignore_request
 * @see oc_indicate_separate_response
 * @see oc_send_response_with_callback
 */
OC_API
void oc_send_response(oc_request_t *request, oc_status_t response_code);

/**
 * @brief Callback function is triggered by oc_send_response before the response
 * is set. In this callback, the application can set/override the response
 * payload.
 *
 * @note For separate message, pong message, and notification, this callback is
 * not triggered.
 *
 * @param request the request being responded to
 * @param response_code the status of the response
 */
typedef void (*oc_send_response_cb_t)(oc_request_t *request,
                                      oc_status_t response_code);

/**
 * @brief Set the send response callback function.
 *
 * @note This function is not thread safe. It should be called before
 * oc_main_init().
 *
 * @param cb that will be triggered by oc_send_response_with_callback when the
 * trigger_cb is true.
 */
OC_API
void oc_set_send_response_callback(oc_send_response_cb_t cb);

#ifdef OC_HAS_FEATURE_ETAG

/**
 * @brief Set the ETag for the response to a OC_GET request.
 *
 * @param request the request being responded to (cannot be NULL)
 * @param etag ETag value (cannot be NULL)
 * @param etag_len length of the ETag value
 *
 * @return 0 if successful,
 * @return -EINVAL if the request method is not OC_GET or the etag_len is
 * longer than COAP_ETAG_LEN
 */
OC_API
int oc_set_send_response_etag(oc_request_t *request, const uint8_t *etag,
                              uint8_t etag_len) OC_NONNULL();

#endif /* OC_HAS_FEATURE_ETAG */

/**
 * @brief retrieve the payload from the request, no processing
 *
 * @param request the request
 * @param payload the payload of the request
 * @param size the size in bytes of the payload
 * @param content_format the content format of the payload
 * @return true
 * @return false
 */
OC_API
bool oc_get_request_payload_raw(const oc_request_t *request,
                                const uint8_t **payload, size_t *size,
                                oc_content_format_t *content_format);

/**
 * @brief send the request, no processing
 *
 * @param request the request to send
 * @param payload the payload for the request
 * @param size the payload size
 * @param content_format the content format
 * @param response_code the response code to send
 */
OC_API
void oc_send_response_raw(oc_request_t *request, const uint8_t *payload,
                          size_t size, oc_content_format_t content_format,
                          oc_status_t response_code);

/**
 * @brief retrieve the response payload, without processing
 *
 * @param response the response
 * @param payload the payload of the response
 * @param size the size of the payload
 * @param content_format the content format of the payload
 * @return true - retrieved payload
 * @return false
 */
OC_API
bool oc_get_response_payload_raw(const oc_client_response_t *response,
                                 const uint8_t **payload, size_t *size,
                                 oc_content_format_t *content_format);

/**
 * @brief send a diagnostic payload
 *
 * @param request the request
 * @param msg the message in ascii
 * @param msg_len the length of the message
 * @param response_code the coap response code
 */
OC_API
void oc_send_diagnostic_message(oc_request_t *request, const char *msg,
                                size_t msg_len, oc_status_t response_code);

/**
 * @brief retrieve the diagnostic payload from a response
 *
 * @param response the response to get the diagnostic payload from
 * @param msg the diagnotic payload
 * @param size the size of the diagnostic payload
 * @return true - retrieved payload
 * @return false
 */
OC_API
bool oc_get_diagnostic_message(const oc_client_response_t *response,
                               const char **msg, size_t *size);

/**
 * Ignore the request
 *
 * The GET, PUT, POST or DELETE requests can be ignored. For example a
 * oc_request_callback_t may only want to respond to multicast requests. Thus
 * any request that is not over multicast endpoint could be ignored.
 *
 * Using `oc_ignore(request)` is preferred over
 * `oc_send_response(request, OC_IGNORE)` since it does not attempt to fill the
 * response buffer before sending the response.
 *
 * @param[in] request the request being responded to (cannot be NULL)
 *
 * @see oc_request_callback_t
 * @see oc_send_response
 */
OC_API
void oc_ignore_request(oc_request_t *request) OC_NONNULL();

/**
 * Respond to an incoming request asynchronously.
 *
 * If for some reason the response to a request would take a
 * long time or is not immediately available, then this function may be used
 * defer responding to the request.
 *
 * Example:
 * ```
 * static oc_separate_response_t sep_response;
 *
 * static oc_event_callback_retval_t
 * handle_separate_response(void *data)
 * {
 * if (sep_response.active) {
 *   oc_set_separate_response_buffer(&sep_response);
 *   printf("Handle separate response for GET handler:\n");
 *   oc_rep_start_root_object();
 *   oc_rep_set_boolean(root, value, true);
 *   oc_rep_set_int(root, dimmingSetting, 75);
 *   oc_rep_end_root_object();
 *   oc_send_separate_response(&sep_response, OC_STATUS_OK);
 * }
 * return OC_EVENT_DONE;
 * }
 *
 * static void
 * get_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
 *             void *user_data)
 * {
 *   printf("GET handler:\n");
 *   oc_indicate_separate_response(request, &sep_response);
 *   oc_set_delayed_callback(NULL, &handle_separate_response, 10);
 * }
 * ```
 * @param[in] request the request that will be responded to as a separate
 *                    response (cannot be NULL)
 * @param[in] response instance of an internal struct that is used to track the
 *                     state of the separate response. (cannot be NULL)
 *
 * @see oc_set_separate_response_buffer
 * @see oc_send_separate_response
 */
OC_API
void oc_indicate_separate_response(oc_request_t *request,
                                   oc_separate_response_t *response)
  OC_NONNULL();

/**
 * Set a response buffer for holding the response payload.
 *
 * When a deferred response is ready, pass in the same `oc_separate_response_t`
 * that was handed to oc_indicate_separate_response() for delaying the
 * initial response.
 *
 * @param[in] handle instance of the oc_separate_response_t that was passed to
 *                   the oc_indicate_separate_response() function (cannot be
 * NULL)
 *
 * @see oc_indicate_separate_response
 * @see oc_send_separate_response
 */
OC_API
void oc_set_separate_response_buffer(oc_separate_response_t *handle)
  OC_NONNULL();

/**
 * Called to send the deferred response to a GET, PUT, POST or DELETE request.
 *
 * The function oc_send_separate_response is called to initiate transfer of the
 * response.
 *
 * @param[in] handle instance of the internal struct that was passed to
                     oc_indicate_separate_response()
 * @param[in] response_code the status of the response
 *
 * @see oc_indicate_separate_response
 * @see oc_send_separate_response
 * @see oc_send_response
 * @see oc_ignore_request
 */
OC_API
void oc_send_separate_response(oc_separate_response_t *handle,
                               oc_status_t response_code) OC_NONNULL();

/**
 * Notify all observers of a change to a given resource's property
 *
 * @note no need to call oc_notify_observers about resource changes that
 *       result from a PUT, or POST oc_request_callback_t.
 *
 * @param[in] resource the oc_resource_t that has a modified property (cannot be
 * NULL)
 *
 * @return
 *  - the number observers notified on success
 *  - `0` on failure could also mean no registered observers
 */
OC_API
int oc_notify_observers(oc_resource_t *resource) OC_NONNULL();

/**
 * Schedule notify all observers to invoke after a set number of seconds.
 *
 * @note no need to call oc_notify_observers about resource changes that
 *       result from a PUT, or POST oc_request_callback_t.
 *
 * @param[in] resource the oc_resource_t that has a modified property (cannot be
 * NULL)
 * @param[in] seconds the number of seconds to wait till the callback is invoked
 */
OC_API
void oc_notify_observers_delayed(oc_resource_t *resource, uint16_t seconds)
  OC_NONNULL();

/**
 * Schedule notify all observers to invoke after a set number of milliseconds.
 *
 * @note no need to call oc_notify_observers about resource changes that
 *       result from a PUT, or POST oc_request_callback_t.
 *
 * @param[in] resource the oc_resource_t that has a modified property (cannot be
 * NULL)
 * @param[in] milliseconds the number of milliseconds to wait till the callback
 * is invoked
 */
OC_API
void oc_notify_observers_delayed_ms(oc_resource_t *resource,
                                    uint16_t milliseconds) OC_NONNULL();

/**
 * @brief Notify all relevant mechanisms of a change to a given resource.
 *
 * @param resource resource that has a modified property (cannot be NULL)
 */
OC_API
void oc_notify_resource_changed(oc_resource_t *resource) OC_NONNULL();

#ifdef __cplusplus
}
#endif
/** @} */ // end of doc_module_tag_server_side

/**
  @defgroup doc_module_tag_client_state Client side
  Client side support functions
  @{
*/
#include "oc_client_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Discover all servers that have a resource type using the site-local scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] rt the resource type the client is trying to discover
 * @param[in] handler the oc_discovery_handler_t that will be called once a
 *                    server containing the resource type is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_site_local_ipv6_discovery(const char *rt,
                                     oc_discovery_handler_t handler,
                                     void *user_data);

/**
 * Discover all servers using the realm-local scope
 *
 * The discovery request will make a muli-cast request to the IPv6 site-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] handler the oc_discovery_all_handler_t that will be called once a
 *                    server is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_all_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_site_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                         void *user_data);

/**
 * Discover all servers that have a resource type using the realm-local scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.

 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] rt the resource type the client is trying to discover
 * @param[in] handler the oc_discovery_handler_t that will be called once a
 *                    server containing the resource type is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_realm_local_ipv6_discovery(const char *rt,
                                      oc_discovery_handler_t handler,
                                      void *user_data);

/**
 * Discover all servers using the realm-local scope
 *
 * The discovery request will make a muli-cast request to the IPv6 realm-local
 * multicast address scope.  The address scope is the domain in which the
 * multicast discovery packet should be propagated.

 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] handler the oc_discovery_all_handler_t that will be called once a
 *                    server is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_all_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_realm_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                          void *user_data);

/**
 * Discover all servers that have a resource type
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] rt the resource type the client is trying to discover
 * @param[in] handler the oc_discovery_handler_t that will be called once a
 *                    server containing the resource type is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                        void *user_data);

/**
 * Discover all servers
 *
 * The discovery request will make a muli-cast request to the IPv6 link-local
 * multicast address scope and over IPv4.
 *
 * Multicast discovery over IPv4 will only happen if the stack is built with
 * the OC_IPV4 build flag.
 *
 * Read RFC4291 and RFC7346 for more information about IPv6 Reference Scopes.
 *
 * @param[in] handler the oc_discovery_all_handler_t that will be called once a
 *                    server is discovered
 * @param[in] user_data context pointer that is passed to the
 *                      oc_discovery_all_handler_t.
 *
 * @return true on success
 */
OC_API
bool oc_do_ip_discovery_all(oc_discovery_all_handler_t handler,
                            void *user_data);

/**
 * Discover resources in a specific endpoint.
 *
 * @param  rt         Resource type query to discover.
 * @param  handler    The callback for discovered resources. Must not be NULL.
 * @param  endpoint   Endpoint at which to discover resources. Must not be NULL.
 * @param  user_data  Callback parameter for user defined value.
 *
 * @return Returns true if it successfully makes and dispatches a coap packet.
 */
OC_API
bool oc_do_ip_discovery_at_endpoint(const char *rt,
                                    oc_discovery_handler_t handler,
                                    const oc_endpoint_t *endpoint,
                                    void *user_data);

/**
 * Discover all resources in a specific endpoint.
 *
 * @param  handler    The callback for discovered resources. Must not be NULL.
 * @param  endpoint   Endpoint at which to discover resources. Must not be NULL.
 * @param  user_data  Callback parameter for user defined value.
 *
 * @return Returns true if it successfully makes and dispatches a coap packet.
 */
OC_API
bool oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler,
                                        const oc_endpoint_t *endpoint,
                                        void *user_data);

/**
 * Issue a GET request to obtain the current value of all properties a resource
 *
 * Example:
 * ```
 * statuc bool value;
 *
 * static void
 * get_light(oc_client_response_t *data)
 * {
 *   OC_PRINTF("GET_light:\n");
 *   oc_rep_t *rep = data->payload;
 *   while (rep != NULL) {
 *     OC_PRINTF("key %s, value ", oc_string(rep->name));
 *     switch (rep->type) {
 *     case OC_REP_BOOL:
 *       OC_PRINTF("%d\n", rep->value.boolean);
 *       value = rep->value.boolean;
 *       break;
 *     default:
 *       break;
 *     }
 *     rep = rep->next;
 *   }
 * }
 * //the server uri and server endpoint obtained from oc_discovery_handler_t
 * // as a result of an oc_do_ip_discovery call
 * oc_do_get(server_uri, server_ep, NULL, &get_switch, LOW_QOS, NULL);
 * ```
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] handler function invoked once the client has received the servers
 *                    response to the GET request
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the CoAP GET request
 */
OC_API
bool oc_do_get(const char *uri, const oc_endpoint_t *endpoint,
               const char *query, oc_response_handler_t handler, oc_qos_t qos,
               void *user_data);

/**
 * Issue a GET request to obtain the current value of all properties a resource.
 *
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] timeout_seconds timeout for the get
 * @param[in] handler function invoked once the client has received the servers
 *                    response to the GET request
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the CoAP GET request
 *
 * @note If a response is not received before @p timeout_seconds expires then
 * the response handler is invoked with OC_REQUEST_TIMEOUT code
 */
OC_API
bool oc_do_get_with_timeout(const char *uri, const oc_endpoint_t *endpoint,
                            const char *query, uint16_t timeout_seconds,
                            oc_response_handler_t handler, oc_qos_t qos,
                            void *user_data);

/**
 * Issue a DELETE request to delete a resource
 *
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] handler function invoked once the client has received the servers
 *                    response to the DELETE request (cannot be NULL)
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the CoAP DELETE request
 */
OC_API
bool oc_do_delete(const char *uri, const oc_endpoint_t *endpoint,
                  const char *query, oc_response_handler_t handler,
                  oc_qos_t qos, void *user_data);

/**
 * Issue a DELETE request to delete a resource
 *
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] timeout_seconds timeout for the get
 * @param[in] handler function invoked once the client has received the servers
 *                    response to the DELETE request (cannot be NULL)
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the CoAP DELETE
 *
 * @note If a response is not received before @p timeout_seconds expires then
 * the response handler is invoked with OC_REQUEST_TIMEOUT code
 */
OC_API
bool oc_do_delete_with_timeout(const char *uri, const oc_endpoint_t *endpoint,
                               const char *query, uint16_t timeout_seconds,
                               oc_response_handler_t handler, oc_qos_t qos,
                               void *user_data);

/**
 * Prepare the stack to issue a PUT request
 *
 * After oc_init_put has been called a CoAP message can be built using
 * `oc_rep_*` functions. Then oc_do_put is called to dispatch the CoAP request.
 *
 * Example:
 * ```
 *
 * static void
 * put_switch(oc_client_response_t *data)
 * {
 *   if (data->code == OC_STATUS_CHANGED)
 *     printf("PUT response: CHANGED\n");
 *   else
 *     printf("PUT response code %d\n", data->code);
 * }
 *
 * if (oc_init_put(server_uri, server_ep, NULL, &put_switch, LOW_QOS, NULL)) {
 *   oc_rep_start_root_object();
 *   oc_rep_set_boolean(root, value, true);
 *   oc_rep_end_root_object();
 *   if (oc_do_put())
 *     printf("Sent PUT request\n");
 *   else
 *     printf("Could not send PUT request\n");
 * } else
 *   printf("Could not init PUT request\n");
 * ```
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] handler function invoked once the client has received the servers
 *                    response to the PUT request
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully prepared the CoAP PUT request
 *
 * @see oc_do_put
 * @see oc_init_post
 */
OC_API
bool oc_init_put(const char *uri, const oc_endpoint_t *endpoint,
                 const char *query, oc_response_handler_t handler, oc_qos_t qos,
                 void *user_data);

/**
 * Dispatch the CoAP PUT request
 *
 * Before the PUT request is dispatched it must be initialized using
 * oc_init_put
 *
 * @return True if the client successfully dispatched the CoAP request
 *
 * @see oc_init_put
 */
OC_API
bool oc_do_put(void);

/**
 * Dispatch the CoAP POST request
 *
 * Before the POST request is dispatched it must be initialized using
 * oc_init_put.
 *
 * @param[in] timeout_seconds timeout for the PUT response
 *
 * @return True if the client successfully dispatched the CoAP PUT request
 *
 * @note If a response is not received before @p timeout_seconds expires then
 * the response handler is invoked with OC_REQUEST_TIMEOUT code
 *
 * @see oc_init_put
 */
OC_API
bool oc_do_put_with_timeout(uint16_t timeout_seconds);

/**
 * Prepare the stack to issue a POST request
 *
 * After oc_init_post has been called a CoAP message can be built using
 * `oc_rep_*` functions. Then oc_do_post is called to dispatch the CoAP request.
 *
 * Example:
 * ```
 *
 * static void
 * post_switch(oc_client_response_t *data)
 * {
 *   if (data->code == OC_STATUS_CHANGED)
 *     printf("POST response: CHANGED\n");
 *   else
 *     printf("POST response code %d\n", data->code);
 * }
 *
 * if (oc_init_post(server_uri, server_ep, NULL, &put_switch, LOW_QOS, NULL)) {
 *   oc_rep_start_root_object();
 *   oc_rep_set_boolean(root, value, true);
 *   oc_rep_end_root_object();
 *   if (oc_do_put())
 *     printf("Sent POST request\n");
 *   else
 *     printf("Could not send POST request\n");
 * } else
 *   printf("Could not init POST request\n");
 * ```
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] handler function invoked once the client has received the servers
 *                     response to the POST request
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully prepared the CoAP PUT request
 *
 * @see oc_do_post
 * @see oc_init_put
 */
OC_API
bool oc_init_post(const char *uri, const oc_endpoint_t *endpoint,
                  const char *query, oc_response_handler_t handler,
                  oc_qos_t qos, void *user_data);

/**
 * Dispatch the CoAP POST request
 *
 * Before the POST request is dispatched it must be initialized using
 * oc_init_post
 *
 * @return True if the client successfully dispatched the CoAP POST request
 *
 * @see oc_init_post
 */
OC_API
bool oc_do_post(void);

/**
 * Dispatch the CoAP POST request
 *
 * @note Before the POST request is dispatched it must be initialized using
 * oc_init_post
 *
 * @param[in] timeout_seconds timeout for the POST response
 *
 * @return True if the client successfully dispatched the CoAP POST request
 *
 * @note If a response is not received before @p timeout_seconds expires then
 * the response handler is invoked with OC_REQUEST_TIMEOUT code
 *
 * @see oc_init_post
 */
OC_API
bool oc_do_post_with_timeout(uint16_t timeout_seconds);

/**
 * Dispatch a GET request with the CoAP Observe option to subscribe for
 * notifications from a resource.
 *
 * The oc_response_handler_t will be invoked each time upon receiving a
 * notification.
 *
 * The handler will continue to be invoked till oc_stop_observe() is called.
 *
 * @param[in] uri the uri of the resource
 * @param[in] endpoint the endpoint of the server
 * @param[in] query a query parameter that will be sent to the server's
 *                  oc_request_callback_t.
 * @param[in] handler function invoked once the client has received the servers
 *                     response to the POST request
 * @param[in] qos the quality of service current options are HIGH_QOS or LOW_QOS
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the CaAP observer request
 */
OC_API
bool oc_do_observe(const char *uri, const oc_endpoint_t *endpoint,
                   const char *query, oc_response_handler_t handler,
                   oc_qos_t qos, void *user_data);

/**
 * Unsubscribe for notifications from a resource.
 *
 * @param[in] uri the uri of the resource being observed
 * @param[in] endpoint the endpoint of the server
 *
 * @return True if the client successfully dispatched the CaAP stop observer
 *         request
 */
OC_API
bool oc_stop_observe(const char *uri, const oc_endpoint_t *endpoint);

/**
 * invoke multicast discovery of devices
 *
 * @param[in] uri the uri for multicast command to be used
 * @param[in] query the query of the multicast command
 * @param[in] handler function invoked once the client has received the servers
 *                     response to the discovery request
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the multicast discovery
 *         request
 */
OC_API
bool oc_do_ip_multicast(const char *uri, const char *query,
                        oc_response_handler_t handler, void *user_data);

/**
 * invoke multicast discovery of devices on IPV6 realm local scope
 *
 * @param[in] uri the uri for multicast command to be used
 * @param[in] query the query of the multicast command
 * @param[in] handler function invoked once the client has received the servers
 *                     response to the discovery request
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the multicast discovery
 *         request
 */
OC_API
bool oc_do_realm_local_ipv6_multicast(const char *uri, const char *query,
                                      oc_response_handler_t handler,
                                      void *user_data);

/**
 * invoke multicast discovery of devices on IPV6 site local scope
 *
 * @param[in] uri the uri for multicast command to be used
 * @param[in] query the query of the multicast command
 * @param[in] handler function invoked once the client has received the servers
 *                     response to the discovery request
 * @param[in] user_data context pointer that will be sent to the
 *                      oc_response_handler_t
 *
 * @return True if the client successfully dispatched the multicast discovery
 *         request
 */
OC_API
bool oc_do_site_local_ipv6_multicast(const char *uri, const char *query,
                                     oc_response_handler_t handler,
                                     void *user_data);

/**
 * stop the multicast update (e.g. do not handle the responses)
 *
 * @param[in] response the response that should not be handled.
 */
OC_API
void oc_stop_multicast(oc_client_response_t *response);

#ifdef OC_OSCORE
/**
 * @brief initialize the multicast update
 *
 * @param uri the uri to be used
 * @param query the query of uri
 * @return true
 * @return false
 */
OC_API
bool oc_init_multicast_update(const char *uri, const char *query);

/**
 * @brief initiate the multicast update
 *
 * @return true
 * @return false
 */
OC_API
bool oc_do_multicast_update(void);
#endif /* OC_OSCORE */

/**
 * Free a list of endpoints from the oc_endpoint_t
 *
 * note: oc_endpoint_t is a linked list. This will walk the list an free all
 * endpoints found in the list. Even if the list only consists of a single
 * endpoint.
 *
 * @param[in,out] endpoint the endpoint list to free
 */
OC_API
void oc_free_server_endpoints(oc_endpoint_t *endpoint);

/**
 * @brief close the tls session on the indicated endpoint
 *
 * @param endpoint endpoint indicating a session
 */
OC_API
void oc_close_session(const oc_endpoint_t *endpoint);

#ifdef OC_TCP
/**
 * @brief send CoAP ping over the TCP connection
 *
 * @param custody custody on/off
 * @param endpoint endpoint to be used
 * @param timeout_seconds timeout for the ping
 * @param handler the response handler
 * @param user_data the user data to be conveyed to the response handler
 * @return true
 * @return false
 */
OC_API
bool oc_send_ping(bool custody, const oc_endpoint_t *endpoint,
                  uint16_t timeout_seconds, oc_response_handler_t handler,
                  void *user_data);
#endif    /* OC_TCP */
/** @} */ // end of doc_module_tag_client_state

/**  */
/**
  @defgroup doc_module_tag_common_operations Common operations
  @{
*/
/**
 * Set the immutable device identifier
 *
 * This will set the `piid` device property (a.k.a Protocol Independent ID)
 *
 * Unlike device id `di` device property the `piid` will remain the same even
 * after device resets.
 *
 * @param[in] device the logical device index
 * @param[in] piid the UUID for the immutable device identifier
 */
OC_API
void oc_set_immutable_device_identifier(size_t device, const oc_uuid_t *piid);

/**
 * Schedule a callback to be invoked after a set number of seconds.
 *
 * @param[in] cb_data user defined context pointer that is passed to the
 *                    oc_trigger_t callback
 * @param[in] callback the callback invoked after the set number of seconds
 * @param[in] seconds the number of seconds to wait till the callback is invoked
 */
OC_API
void oc_set_delayed_callback(void *cb_data, oc_trigger_t callback,
                             uint16_t seconds);

/**
 * Schedule a callback to be invoked after a set number of milliseconds.
 *
 * @param[in] cb_data user defined context pointer that is passed to the
 *                    oc_trigger_t callback
 * @param[in] callback the callback invoked after the set number of milliseconds
 * @param[in] milliseconds the number of milliseconds to wait till the callback
 * is invoked
 *
 * @deprecated replaced by oc_set_delayed_callback_ms_v1 in v2.2.5.4
 */
OC_API
void oc_set_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                                uint16_t milliseconds)
  OC_DEPRECATED("replaced by oc_set_delayed_callback_ms_v1 in v2.2.5.4");

/**
 * Schedule a callback to be invoked after a set number of milliseconds.
 *
 * @param[in] cb_data user defined context pointer that is passed to the
 *                    oc_trigger_t callback
 * @param[in] callback the callback invoked after the set number of milliseconds
 * @param[in] milliseconds the number of milliseconds to wait till the callback
 * is invoked
 */
OC_API
void oc_set_delayed_callback_ms_v1(void *cb_data, oc_trigger_t callback,
                                   uint64_t milliseconds);

/**
 * @brief Check if given delayed callback has already been scheduled.
 *
 * To match a delayed callback:
 * 1) function pointers must be equal
 * 2) the user defined context pointers must be equal or ignore_cb_data must be
 * true
 *
 * @param cb_data the user defined context pointer
 * @param callback the delayed callback to look for
 * @param ignore_cb_data don't compare the user defined context pointers
 * @return true matching delayed callback was found
 * @return false otherwise
 */
OC_API
bool oc_has_delayed_callback(const void *cb_data, oc_trigger_t callback,
                             bool ignore_cb_data);

/**
 * @brief Cancel a scheduled delayed callback by matching it by the provided
 * filtering function.
 *
 * @param[in] cb the delayed callback that is being removed
 * @param[in] filter filtering function (cannot be NULL)
 * @param[in] filter_data user data provided to the filtering function
 * @param[in] match_all iterate over all delayed callbacks (otherwise the
 * iteration will stop after the first match)
 * @param[in] on_delete function invoked with the context data of the delayed
 * callback, before the callback is deallocated
 *
 * @note if the matched timed event is currently being processed then the \p
 * on_delete callback will be invoked when the processing is finished. So it
 * might occurr some time after the call to
 * oc_ri_remove_timed_event_callback_by_filter has finished.
 *
 * @see oc_ri_timed_event_filter_t
 * @see oc_ri_timed_event_on_delete_t
 */
OC_API
void oc_remove_delayed_callback_by_filter(
  oc_trigger_t cb, oc_ri_timed_event_filter_t filter, const void *filter_data,
  bool match_all, oc_ri_timed_event_on_delete_t on_delete);

/**
 * Cancel a scheduled delayed callback.
 *
 * @param[in] cb_data the user defined context pointer that was passed to the
 *                   oc_set_delayed_callback() function
 * @param[in] callback the delayed callback that is being removed
 */
OC_API
void oc_remove_delayed_callback(const void *cb_data, oc_trigger_t callback);

/** API for setting handlers for interrupts */

#define oc_signal_interrupt_handler(name)                                      \
  do {                                                                         \
    oc_process_poll(&(name##_interrupt_x));                                    \
    _oc_signal_event_loop();                                                   \
  } while (0)

/** activate the interrupt handler */
#define oc_activate_interrupt_handler(name)                                    \
  (oc_process_start(&(name##_interrupt_x), 0))

/** define the interrupt handler */
#define oc_define_interrupt_handler(name)                                      \
  void name##_interrupt_x_handler(void);                                       \
  OC_PROCESS(name##_interrupt_x, "");                                          \
  OC_PROCESS_THREAD(name##_interrupt_x, ev, data)                              \
  {                                                                            \
    (void)data;                                                                \
    OC_PROCESS_POLLHANDLER(name##_interrupt_x_handler());                      \
    OC_PROCESS_BEGIN();                                                        \
    while (oc_process_is_running(&(name##_interrupt_x))) {                     \
      OC_PROCESS_YIELD();                                                      \
    }                                                                          \
    OC_PROCESS_END();                                                          \
  }                                                                            \
  void name##_interrupt_x_handler(void)
/** @} */ // end of doc_module_tag_common_operations
#ifdef __cplusplus
}
#endif

#endif /* OC_API_H */
