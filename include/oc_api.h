/*
// Copyright (c) 2016-2019 Intel Corporation
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
  @brief Main API of IoTivity-Lite for client and server.
  @file
*/

/**
  \mainpage IoTivity-Lite API

  The file \link oc_api.h\endlink is the main entry for all
  server and client related OCF functions.
*/

#ifndef OC_API_H
#define OC_API_H

#include "messaging/coap/oc_coap.h"
#include "oc_buffer_settings.h"
#include "oc_cloud.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_signal_event_loop.h"
#include "port/oc_storage.h"

#ifdef __cplusplus
extern "C"
{
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
 * @param data context pointer that comes from the oc_add_device() function
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
int oc_main_init(const oc_handler_t *handler);
oc_clock_time_t oc_main_poll(void);

/**
 * Shutdown and free all stack related resources
 */
void oc_main_shutdown(void);

typedef void (*oc_factory_presets_cb_t)(size_t device, void *data);
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
 * @param uri the The device URI.  The wellknown default URI "/oic/d" is hosted
 *            by every server. Used to device specific information.
 * @param rt the resource type
 * @param name the user readable name of the device
 * @param spec_version The version of the OCF Server.  This is the "icv" device
 *                     property
 * @param data_model_version Spec version of the resource and device
 * specifications to which this device data model is implemtned. This is the
 * "dmv" device property
 * @param add_device_cb callback function invoked during oc_add_device(). The
 *                      purpose is to add additional device properties that are
 *                      not supplied to oc_add_device() function call.
 * @param data context pointer that is passed to the oc_add_device_cb_t
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 */
int oc_add_device(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, void *data);

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
 * oc_init_platform(). The purpose is to add additional device properties that
 * are not supplied to oc_init_platform() function call.
 * @param data context pointer that is passed to the oc_init_platform_cb_t
 *
 * @return
 *   - `0` on success
 *   - `-1` on failure
 *
 * @see init
 * @see oc_init_platform_cb_t
 */
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

typedef void (*oc_random_pin_cb_t)(const unsigned char *pin, size_t pin_len,
                                   void *data);
void oc_set_random_pin_callback(oc_random_pin_cb_t cb, void *data);

/**
  @brief Returns whether the oic.wk.con res is announced.
  @return true if announced (default) or false if not
  @see oc_set_con_res_announced
  @see oc_set_con_write_cb
*/
bool oc_get_con_res_announced(void);

/**
  @brief Sets whether the oic.wk.con res is announed.
  @note This should be set before invoking \c oc_main_init().
  @param announce true to announce (default) or false if not
  @see oc_get_con_res_announced
  @see oc_set_con_write_cb
*/
void oc_set_con_res_announced(bool announce);

void oc_reset();

void oc_reset_device(size_t device);

/** Server side */
/**
  @defgroup doc_module_tag_server_side Server side
  Optional group of functions OCF server support.
  @{
*/
oc_resource_t *oc_new_resource(const char *name, const char *uri,
                               uint8_t num_resource_types, size_t device);
void oc_resource_bind_resource_interface(oc_resource_t *resource,
                                         oc_interface_mask_t iface_mask);
void oc_resource_set_default_interface(oc_resource_t *resource,
                                       oc_interface_mask_t iface_mask);
void oc_resource_bind_resource_type(oc_resource_t *resource, const char *type);

void oc_device_bind_resource_type(size_t device, const char *type);

void oc_process_baseline_interface(oc_resource_t *resource);

/**
  @defgroup doc_module_tag_collections Collection Support
  Optional group of functions to support OCF compliant collections.
  @{
*/

/**
  @brief Creates a new empty collection.

  The collection is created with interfaces \c OC_IF_BASELINE,
  \c OC_IF_LL (also default) and \c OC_IF_B. Initially it is neither
  discoverable nor observable.

  The function only allocates the collection. Use
  \c oc_add_collection() after the setup of the collection
  is complete.
  @param name name of the collection
  @param uri Unique URI of this collection. Must not be NULL.
  @param num_resource_types Number of resources the caller will
   bind with this resource (e.g. by invoking
   \c oc_resource_bind_resource_type(col, OIC_WK_COLLECTION)). Must
   be 1 or higher.
  @param device The internal device that should carry this collection.
   This is typically 0.
  @return A pointer to the new collection (actually oc_collection_t*)
   or NULL if out of memory.
  @see oc_add_collection
  @see oc_collection_add_link
*/
oc_resource_t *oc_new_collection(const char *name, const char *uri,
                                 uint8_t num_resource_types, size_t device);

/**
  @brief Deletes the specified collection.

  The function removes the collection from the internal list of collections
  and releases all direct resources and links associated with this collection.

  @note The function does not delete the resources set in the links.
   The caller needs to do this on her/his own in case these are
   no longer required.

  @param collection The pointer to the collection to delete.
   If this is NULL, the function does nothing.
  @see oc_collection_get_links
  @see oc_delete_link
*/
void oc_delete_collection(oc_resource_t *collection);

/**
  @brief Creates a new link for collections with the specified resource.
  @param resource Resource to set in the link. The resource is not copied.
   Must not be NULL.
  @return The created link or NULL if out of memory or \c resource is NULL.
  @see oc_delete_link
  @see oc_collection_add_link
  @see oc_new_resource
*/
oc_link_t *oc_new_link(oc_resource_t *resource);

/**
  @brief Deletes the link.
  @note The function neither removes the resource set on this link
   nor does it remove it from any collection.
  @param link The link to delete. The function does nothing, if
   the parameter is NULL.
*/
void oc_delete_link(oc_link_t *link);

/**
  @brief Adds a relation to the link.
  @param link Link to add the relation to. Must not be NULL.
  @param rel Relation to add. Must not be NULL.
*/
void oc_link_add_rel(oc_link_t *link, const char *rel);

/**
  @brief Adds a link parameter with specified key and value.
  @param link Link to which to add a link parameter. Must not be NULL.
  @param key Key to identify the link parameter. Must not be NULL.
  @param value Link parameter value. Must not be NULL.
*/
void oc_link_add_link_param(oc_link_t *link, const char *key,
                            const char *value);

/**
  @brief Adds the link to the collection.
  @param collection Collection to add the link to. Must not be NULL.
  @param link Link to add to the collection. The link is not copied.
   Must not be NULL. Must not be added again to this or a different
   collection or a list corruption will occur. To re-add it, remove
   the link first.
  @see oc_new_link
  @see oc_collection_remove_link
*/
void oc_collection_add_link(oc_resource_t *collection, oc_link_t *link);

/**
  @brief Removes a link from the collection.
  @param collection Collection to remove the link from. Does nothing
   if this is NULL.
  @param link The link to remove. Does nothing if this is NULL or not
   part of the collection. The link and its resource are not freed.
*/
void oc_collection_remove_link(oc_resource_t *collection, oc_link_t *link);

/**
  @brief Returns the list of links belonging to this collection.
  @param collection Collection to get the links from.
  @return All links of this collection. The links are not copied. Returns
   NULL if the collection is NULL or contains no links.
  @see oc_collection_add_link
*/
oc_link_t *oc_collection_get_links(oc_resource_t *collection);

/**
  @brief Adds a collection to the list of collections.

  If the caller makes the collection discoverable, then it will
  be included in the collection discovery once it has been added
  with this function.
  @param collection Collection to add to the list of collections.
   Must not be NULL. Must not be added twice or a list corruption
   will occur. The collection is not copied.
  @see oc_resource_set_discoverable
  @see oc_new_collection
*/
void oc_add_collection(oc_resource_t *collection);

/**
  @brief Gets all known collections.
  @return All collections that have been added via
   \c oc_add_collection(). The collections are not copied.
   Returns NULL if there are no collections. Collections created
   only via \c oc_new_collection() but not added will not be
   returned by this function.
*/
oc_resource_t *oc_collection_get_collections(void);

bool oc_collection_add_supported_rt(oc_resource_t *collection, const char *rt);

bool oc_collection_add_mandatory_rt(oc_resource_t *collection, const char *rt);

#ifdef OC_COLLECTIONS_IF_CREATE
typedef oc_resource_t *(*oc_resource_get_instance_t)(const char *,
                                                     oc_string_array_t *,
                                                     oc_resource_properties_t,
                                                     oc_interface_mask_t,
                                                     size_t);

typedef void (*oc_resource_free_instance_t)(oc_resource_t *);

bool oc_collections_add_rt_factory(const char *rt,
                                   oc_resource_get_instance_t get_instance,
                                   oc_resource_free_instance_t free_instance);
#endif    /* OC_COLLECTIONS_IF_CREATE */
/** @} */ // end of doc_module_tag_collections

void oc_resource_make_public(oc_resource_t *resource);

void oc_resource_set_discoverable(oc_resource_t *resource, bool state);
void oc_resource_set_observable(oc_resource_t *resource, bool state);
void oc_resource_set_periodic_observable(oc_resource_t *resource,
                                         uint16_t seconds);
void oc_resource_set_request_handler(oc_resource_t *resource,
                                     oc_method_t method,
                                     oc_request_callback_t callback,
                                     void *user_data);
void oc_resource_set_properties_cbs(oc_resource_t *resource,
                                    oc_get_properties_cb_t get_properties,
                                    void *get_propr_user_data,
                                    oc_set_properties_cb_t set_properties,
                                    void *set_props_user_data);
bool oc_add_resource(oc_resource_t *resource);
bool oc_delete_resource(oc_resource_t *resource);

/**
  @brief Callback for change notifications from the oic.wk.con resource.

  This callback is invoked to notify a change of one or more properties
  on the oic.wk.con resource. The \c rep parameter contains all properties,
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
typedef void (*oc_con_write_cb_t)(size_t device_index, oc_rep_t *rep);

/**
  @brief Sets the callback to receive change notifications for
   the oic.wk.con resource.

  The function can be used to set or unset the callback. Whenever
  an attribute of the oic.wk.con resource is changed, the callback
  will be invoked.

  @param callback The callback to register or NULL to unset it.
   If the function is invoked a second time, then the previously
   set callback is simply replaced.
*/
void oc_set_con_write_cb(oc_con_write_cb_t callback);

void oc_init_query_iterator(void);
int oc_iterate_query(oc_request_t *request, char **key, size_t *key_len,
                     char **value, size_t *value_len);
bool oc_iterate_query_get_values(oc_request_t *request, const char *key,
                                 char **value, int *value_len);
int oc_get_query_value(oc_request_t *request, const char *key, char **value);

void oc_send_response(oc_request_t *request, oc_status_t response_code);
void oc_ignore_request(oc_request_t *request);

void oc_indicate_separate_response(oc_request_t *request,
                                   oc_separate_response_t *response);
void oc_set_separate_response_buffer(oc_separate_response_t *handle);
void oc_send_separate_response(oc_separate_response_t *handle,
                               oc_status_t response_code);

int oc_notify_observers(oc_resource_t *resource);

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

bool oc_do_site_local_ipv6_discovery(const char *rt,
                                     oc_discovery_handler_t handler,
                                     void *user_data);

bool oc_do_site_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                         void *user_data);

bool oc_do_realm_local_ipv6_discovery(const char *rt,
                                      oc_discovery_handler_t handler,
                                      void *user_data);

bool oc_do_realm_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                          void *user_data);

bool oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                        void *user_data);

bool oc_do_ip_discovery_all(oc_discovery_all_handler_t handler,
                            void *user_data);

/**
  @brief  Discover resources in specific endpoint.
  @param  rt         Resource type query to discover.
  @param  handler    The callback for discovered resources. Must not be NULL.
  @param  endpoint   Endpoint at which to discover resources. Must not be NULL.
  @param  user_data  Callback parameter for user defined value.
  @return Returns true if it successfully makes and dispatches a coap packet.
*/
bool oc_do_ip_discovery_at_endpoint(const char *rt,
                                    oc_discovery_handler_t handler,
                                    oc_endpoint_t *endpoint, void *user_data);

bool oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler,
                                        oc_endpoint_t *endpoint,
                                        void *user_data);

bool oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
               oc_response_handler_t handler, oc_qos_t qos, void *user_data);

bool oc_do_delete(const char *uri, oc_endpoint_t *endpoint, const char *query,
                  oc_response_handler_t handler, oc_qos_t qos, void *user_data);

bool oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
                 oc_response_handler_t handler, oc_qos_t qos, void *user_data);

bool oc_do_put(void);

bool oc_init_post(const char *uri, oc_endpoint_t *endpoint, const char *query,
                  oc_response_handler_t handler, oc_qos_t qos, void *user_data);

bool oc_do_post(void);

bool oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, oc_qos_t qos,
                   void *user_data);

bool oc_stop_observe(const char *uri, oc_endpoint_t *endpoint);

bool oc_do_ip_multicast(const char *uri, const char *query,
                        oc_response_handler_t handler, void *user_data);

bool oc_do_realm_local_ipv6_multicast(const char *uri, const char *query,
                                      oc_response_handler_t handler,
                                      void *user_data);

bool oc_do_site_local_ipv6_multicast(const char *uri, const char *query,
                                     oc_response_handler_t handler,
                                     void *user_data);

void oc_stop_multicast(oc_client_response_t *response);

void oc_free_server_endpoints(oc_endpoint_t *endpoint);

void oc_close_session(oc_endpoint_t *endpoint);

/**
  @defgroup doc_module_tag_asserting_roles Asserting roles
  Asserting roles support functions
  @{
*/
typedef struct oc_role_t
{
  struct oc_role_t *next;
  oc_string_t role;
  oc_string_t authority;
} oc_role_t;

oc_role_t *oc_get_all_roles(void);

bool oc_assert_role(const char *role, const char *authority,
                    oc_endpoint_t *endpoint, oc_response_handler_t handler,
                    void *user_data);
void oc_auto_assert_roles(bool auto_assert);

void oc_assert_all_roles(oc_endpoint_t *endpoint, oc_response_handler_t handler,
                         void *user_data);
/** @} */ // end of doc_module_tag_asserting_roles
#ifdef OC_TCP
bool oc_send_ping(bool custody, oc_endpoint_t *endpoint,
                  uint16_t timeout_seconds, oc_response_handler_t handler,
                  void *user_data);
#endif    /* OC_TCP */
/** @} */ // end of doc_module_tag_client_state

/**  */
/**
  @defgroup doc_module_tag_common_operations Common operations
  @{
*/
void oc_set_immutable_device_identifier(size_t device, oc_uuid_t *piid);

void oc_set_delayed_callback(void *cb_data, oc_trigger_t callback,
                             uint16_t seconds);
void oc_remove_delayed_callback(void *cb_data, oc_trigger_t callback);

/** API for setting handlers for interrupts */

#define oc_signal_interrupt_handler(name)                                      \
  do {                                                                         \
    oc_process_poll(&(name##_interrupt_x));                                    \
    _oc_signal_event_loop();                                                   \
  } while (0)

#define oc_activate_interrupt_handler(name)                                    \
  (oc_process_start(&(name##_interrupt_x), 0))

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
