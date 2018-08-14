/*
// Copyright (c) 2016 Intel Corporation
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
  @brief Main API of IoTivity-constrained for client and server.
  @file
*/

/**
  \mainpage IoTivity-constrained API

  The file <strong>\link oc_api.h\endlink</strong> is the main entry for all
  server and client related OCF functions.

  @warning Avoid using internal functions. The main API often does additional
   setups and checks before using internal API.

  \page apps Example Apps
  \section scene_apps Scene Apps
  \subsection server_scene_app Scene Server Linux App
  \include server_scenes_linux.c
  \subsection client_scene_app Scene Client Linux App
  \include client_scenes_linux.c
  \section collection_apps Collection Apps
  \subsection server_collections_app Collection Server Linux App
  \include server_collections_linux.c
  \subsection client_collections_app Collection Client Linux App
  \include client_collections_linux.c
*/

#ifndef OC_API_H
#define OC_API_H

#include "messaging/coap/oc_coap.h"
#include "oc_buffer_settings.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_signal_event_loop.h"
#include "port/oc_storage.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
  int (*init)(void);
  void (*signal_event_loop)(void);

#ifdef OC_SERVER
  void (*register_resources)(void);
#endif /* OC_SERVER */

#ifdef OC_CLIENT
  void (*requests_entry)(void);
#endif /* OC_CLIENT */
} oc_handler_t;

typedef void (*oc_init_platform_cb_t)(void *data);
typedef void (*oc_add_device_cb_t)(void *data);

int oc_main_init(const oc_handler_t *handler);
oc_clock_time_t oc_main_poll(void);
void oc_main_shutdown(void);

void oc_set_device_id(oc_uuid_t *uuid);
int oc_add_device(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, void *data);

#define oc_set_custom_device_property(prop, value)                             \
  oc_rep_set_text_string(root, prop, value)

int oc_init_platform(const char *mfg_name,
                     oc_init_platform_cb_t init_platform_cb, void *data);

#define oc_set_custom_platform_property(prop, value)                           \
  oc_rep_set_text_string(root, prop, value)

/**
  @brief Returns whether the oic.wk.con res is announed.
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

/**
  @brief Callback to notify about updated IDs.
  @note Unchanged IDs are set to NULL.
  @note The callback shall not block for too long.
  @param device_index zero based index of the device
   for which the update happened (irrelevant for pi)
  @param di updated device ID or NULL
  @param piid updated protocol independent ID or NULL
  @param pi updated platform ID or NULL
 */
typedef void (*oc_id_updated_t)(int device_index,
                                const char *di,
                                const char *piid,
                                const char *pi);

/**
  @brief Sets the ID updated callback.

  This is especially useful in case of security to notify
  about updated IDs in case of onboarding.
  @param callback Callback handler to receive the updated
   IDs. May be NULL to unregister.
 */
void oc_set_id_updated_callback(oc_id_updated_t callback);

/** Server side */
oc_resource_t *oc_new_resource(const char *name, const char *uri,
                               uint8_t num_resource_types, size_t device);
void oc_resource_bind_resource_interface(oc_resource_t *resource,
                                         uint8_t interface);
void oc_resource_set_default_interface(oc_resource_t *resource,
                                       oc_interface_mask_t interface);
void oc_resource_bind_resource_type(oc_resource_t *resource, const char *type);

void oc_process_baseline_interface(oc_resource_t *resource);

/**
  @defgroup oc_collections Collection Support
  Optional group of functions to support OCF compliant collections.

  Examples: See \ref collection_apps
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

  @note Making collections observable is not supported.
  @param name name of the collection
  @param uri Unique URI of this collection. Must not be NULL.
  @param num_resource_types Number of resources the caller will
   bind with this resource (e.g. by invoking
   \c oc_resource_bind_resource_type(col, OIC_WK_COLLECTION)). Must
   be 1 or higher.
  @param device The internal device that should carry this collection.
   This is typically 0.
  @return A pointer to the new collection (actually \c oc_collection_t*)
   or NULL if out of memory.
  @see oc_add_collection
  @see oc_collection_add_link
  @see oc_delete_collection
  @see oc_resource_set_discoverable
  @see oc_new_scene_collection
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
   The pointer needs to be actually of type \c oc_collection_t.
   If this is NULL, the function does nothing.
  @see oc_collection_get_links
  @see oc_delete_scene_collection
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
  @brief Sets the unique link instance on the link.
  @param link The link to set the instance on. Must not be NULL.
  @param ins The link instance to set. Must not be NULL.
*/
void oc_link_set_ins(oc_link_t *link, const char *ins);

/**
  @brief Adds the link to the collection.
  @param collection Collection to add the link to. Must not be NULL.
   The pointer needs to be actually of type \c oc_collection_t.
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
   The pointer needs to be actually of type \c oc_collection_t.
  @param link The link to remove. Does nothing if this is NULL or not
   part of the collection. The link and its resource are not freed.
*/
void oc_collection_remove_link(oc_resource_t *collection, oc_link_t *link);

/**
  @brief Returns the list of links belonging to this collection.
  @param collection Collection to get the links from.
   The pointer needs to be actually of type \c oc_collection_t.
  @return All links of this collection. The links are not copied. Returns
   NULL if the collection is NULL or contains no links.
  @see oc_collection_add_link
*/
oc_link_t *oc_collection_get_links(oc_resource_t* collection);

/**
  @brief Adds the collection to the list of collections.

  If the caller makes the collection discoverable, then it will
  be included in the collection discovery once it has been added
  with this function.

  @param collection Collection to add to the list of collections.
   The pointer needs to be actually of type \c oc_collection_t.
   Must not be NULL. Must not be added twice or a list corruption
   will occur. The collection is not copied.
  @see oc_set_discoverable
  @see oc_new_collection
  @see oc_add_scene_collection
*/
void oc_add_collection(oc_resource_t *collection);

/**
  @brief Gets all known collections.
  @note If scene support is enabled, then the list also includes
   the scene list. The scene collections are not directly part
   of the list, but are referenced by the scene list.
  @return All collections that have been added via
   \c oc_add_collection(). The collections are not copied.
   Returns NULL if there are no collections. Collections created
   only via \c oc_new_collection() but not added will not be
   returned by this function. The returned pointer is actually of type
   \c oc_collection_t.
*/
oc_resource_t *oc_collection_get_collections(void);
/** @} */ // end of oc_collections

/**
  @defgroup oc_scenes Scene Support
  Optional group of functions to support OCF compliant scenes.

  The layout of scenes is this:
  - Scene List:
    - structure: oc_collection_t (is an \c oc_resource_t)
    - rt: oic.wk.scenelist
    - URI: /OCSceneListURI (see \c OC_SCENELIST_URI)
    - not discoverable by default
    - is simply in the list of collections in \c oc_collection.h
  - Scene Collection:
    - structure: oc_collection_t (is an \c oc_resource_t)
    - rt: oic.wk.scenecollection
    - URI: (specified by app)
    - not discoverable by default
    - is linked as resource in oc_link_t in the scene list
  - Scene Member
    - structure: oc_scene_member_t (is an \c oc_resource_t)
    - rt: oic.wk.scenemember
    - URI: (specified by app)
    - not discoverable by default
    - is linked as resource in oc_link_t in a scene collection
  - Scene Mapping
    - structure: oc_scene_mapping_t (is NOT an \c oc_resource_t)
    - rt: (none)
    - URI (none)
    - discoverability is based on the setting of the parent scene member
    - is simply in the list of mappings in a scene member

  @warning Use the according scene functions where available instead
   of the corresponding collection functions. Otherwise the internal
   lists may become corrupted.

  Comparison to OCF 1.0 and IoTivity:
  - Scene list, collection and member have interfaces oic.if.a, oic.if.ll
    and oic.if.baseline as specified in OCF 1.0. IoTivitiy uses oic.if.b
    instead of oic.if.a.
  - Property sceneValues is a string array instead of a string just like
    in IoTivity. OCF 1.0 specifies here a string, but there is already a
    change request to change this to a string array.
  - There is currently no support to setup scene collections, members and
    mappings remotely. Only the local app can create and modify these.
    Only the property lastScene can also be set remotely.

  @note In case of multiple devices: As of now there is at most one
   scene list and this is assigned to device 0.
  @note When a new scene is triggered, then the stack does not update the
  resource properties by itself yet. This needs to be done by the app.

  To have the app receive the notifications when the value of lastScene
  changes, register a post handler with each scene collection:
  \code oc_resource_set_request_handler(
  <scene collection>, OC_POST, <post callback>, NULL);\endcode
  The post callback will be called after the lastScene value has been updated.
  The handler shall NOT send any response. The according scene collection is
  set as request resource.

  Examples: See \ref scene_apps
  @{
*/

/**
  @brief Creates a new empty scene collection.

  The collection is created with interfaces \c OC_IF_BASELINE,
  \c OC_IF_A (also default) and \c OC_IF_LL. The resource type
  "oic.wk.scenecollection" is added.
  Initially it is neither discoverable nor observable.

  @note Making scene collections observable is not supported.

  @param uri Unique URI of this scene collection. Must not be NULL.
  @param device The internal device that should carry this scene collection.
   This is typically 0 (also currently used for the scene list).
  @return A pointer to the new collection (actually \c oc_collection_t*)
   or NULL if out of memory.
  @see oc_add_scene_collection
  @see oc_delete_scene_collection
  @see oc_resource_set_discoverable
  @see oc_new_collection
*/
oc_resource_t *oc_new_scene_collection(const char *uri,
                                       int device);

/**
  @brief Deletes the specified scene collection.

  The function removes the scene collection from the scene list
  and releases all direct resources and links associated with this
  collection including the link holding this collection.

  @note The function does not delete the scene members set in the links.
   The caller needs to do this on her/his own in case these are
   no longer required.

  @param scene_collection The pointer to the collection to delete.
   If this is NULL, the function does nothing.
   The pointer needs to be actually of type \c oc_collection_t.
  @see oc_collection_get_links
  @see oc_delete_collection
*/
void oc_delete_scene_collection(oc_resource_t *scene_collection);

/**
  @brief Adds the scene collection to the scene list.

  If the caller makes the scene collection discoverable, then it will
  be included in the discovery once it has been added
  with this function.

  @param scene_collection Scene ollection to add to the scene list.
   Must not be added twice or a list corruption will occur.
   The pointer needs to be actually of type \c oc_collection_t.
   The scene collection is not copied.
  @return true if the scene collection was added, false if out of
   memory or if the parameter is NULL.
  @see oc_set_discoverable
  @see oc_new_scene_collection
  @see oc_add_scene_member
  @see oc_add_collection
*/
bool oc_add_scene_collection(oc_resource_t *scene_collection);

/**
  @brief Creates a new empty scene member.

  The collection is created with interfaces \c OC_IF_BASELINE,
  \c OC_IF_A (also default) and \c OC_IF_LL. The resource type
  "oic.wk.scenemember" is added.
  Initially it is neither discoverable nor observable.

  @note Making scene members observable is not supported.

  @param uri Unique URI of this scene member. Must not be NULL.
  @param resource The resource to assign to the member. All scene
   mappings will operate on this resource.
  @return A pointer to the new member (actually \c oc_scene_member_t*)
   or NULL if out of memory.
  @see oc_add_scene_member
  @see oc_delete_scene_member
  @see oc_resource_set_discoverable
  @see oc_add_scene_mapping
*/
oc_resource_t *oc_new_scene_member(const char *uri,
                                   oc_resource_t *resource);

/**
  @brief Deletes the scene member.

  The function deletes the scene member and scene mappings.
  The resource hold by the member is not released.

  @note If the scene member is part of a scene collection, then
   it must be removed from it before deleting it.
  @param scene_member Scene member to delete. The function does
   nothing if this is NULL.
   The pointer needs to be actually of type \c oc_scene_member_t.
  @see oc_remove_scene_member
*/
void oc_delete_scene_member(oc_resource_t *scene_member);

/**
  @brief Adds the scene member to the scene collection.

  If the caller makes the scene member discoverable, then it will
  be included in the discovery once it has been added
  with this function.

  @param scene_collection Scene collection to add the member to.
   The pointer needs to be actually of type \c oc_collection_t.
   If this is NULL, then the function does nothing.
  @param scene_member Scene member to add to the scene collection.
   Must not be added twice or a list corruption will occur.
   The pointer needs to be actually of type \c oc_scene_member_t.
   The scene member is not copied.
   If this is NULL, then the function does nothing.
  @return true if the scene member was added, false if out of
   memory or if any parameter is NULL.
  @see oc_set_discoverable
  @see oc_new_scene_member
  @see oc_remove_scene_member
  @see oc_add_scene_mapping
*/
bool oc_add_scene_member(oc_resource_t *scene_collection,
                         oc_resource_t *scene_member);

/**
  @brief Removes the scene member from the scene collection.

  The function removes the scene member from the collection and
  deletes the holding link. The member and the mappings are not
  deleted.
  @param scene_collection Scene collection to remove the member
   from. If this is NULL, then the function does nothing.
   The pointer needs to be actually of type \c oc_collection_t.
  @param scene_member Scene member to remove.
  The pointer needs to be actually of type \c oc_scene_member_t.
  If this is NULL, then the function does nothing.
  @see oc_delete_scene_member
*/
void oc_remove_scene_member(oc_resource_t *scene_collection,
                            oc_resource_t *scene_member);

/**
  @brief Adds the scene mapping to the scene member.

  Adds the mapping to the scene member. If the specified scene
  is triggered, then the property is set to the value on
  the resource of the scene member.

  The function can be called on a member before and after
  it has been added to a scene collection. If a new scene
  is specified, then it will be listed in the sceneValues
  of the parent scene collection as soon as the member
  is added to the collection.

  @note The function does not check, if the according
   scene and property combination already exists. The
   mapping is simply added to the list.

  @note The function does neither verify that the property
   is available on the resource not that the value
   makes sense for the property. This is the responsibility
   of the caller.

  @param scene_member Scene member to add the mapping to.
   The pointer needs to be actually of type \c oc_scene_member_t.
   The function does nothing if this is NULL.
  @param scene Name of the scene.
   The function does nothing if this is NULL or empty.
  @param property Name of the property to modify on the resource
   if the scene is triggered.
   The function does nothing if this is NULL or empty.
  @param value Value to change the property to.
   The function does nothing if this is NULL or empty.
  @return true if the mapping was added, false if out
   of memory or if the parameters are invalid
*/
bool oc_add_scene_mapping(oc_resource_t *scene_member,
                          const char *scene,
                          const char *property,
                          const char *value);
/** @} */ // end of oc_scenes

void oc_resource_make_public(oc_resource_t *resource);

/**
   @brief Specifies whether the oic.wk.res resource is discoverable.
   @note This function must be invoked after \c oc_main_init() and
    should be invoked before the first \c oc_main_poll().
   @param state true for discoverable, false for non-discoverable
    (default). Setting the same value again has no effect.
   @param device_index the resource of the specified zero-based
    device, typically 0
   @return true if the resource was found, false if not (usually means
    that the function was invoked before \c oc_main_init() or that
    a non existing index exists).
 */
bool oc_wk_res_set_discoverable(bool state, int device_index);

void oc_resource_set_discoverable(oc_resource_t *resource, bool state);
void oc_resource_set_observable(oc_resource_t *resource, bool state);
void oc_resource_set_periodic_observable(oc_resource_t *resource,
                                         uint16_t seconds);
void oc_resource_set_request_handler(oc_resource_t *resource,
                                     oc_method_t method,
                                     oc_request_callback_t callback,
                                     void *user_data);
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
typedef void(*oc_con_write_cb_t)(size_t device_index, oc_rep_t *rep);

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

/** Client side */
#include "oc_client_state.h"

#ifdef __cplusplus
extern "C"
{
#endif

bool oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
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

void oc_stop_multicast(oc_client_response_t *response);

void oc_free_server_endpoints(oc_endpoint_t *endpoint);

void oc_close_session(oc_endpoint_t *endpoint);

/** Common operations */

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

#ifdef __cplusplus
}
#endif

#endif /* OC_API_H */
