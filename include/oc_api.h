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

  The file \link oc_api.h\endlink is the main entry for all
  server and client related OCF functions.
*/

#ifndef OC_API_H
#define OC_API_H

#include "messaging/coap/oc_coap.h"
#include "oc_buffer_settings.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_signal_event_loop.h"
#include "port/oc_storage.h"

typedef struct
{
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

/** Server side */
oc_resource_t *oc_new_resource(const char *name, const char *uri,
                               uint8_t num_resource_types, int device);
void oc_resource_bind_resource_interface(oc_resource_t *resource,
                                         uint8_t interface);
void oc_resource_set_default_interface(oc_resource_t *resource,
                                       oc_interface_mask_t interface);
void oc_resource_bind_resource_type(oc_resource_t *resource, const char *type);

void oc_process_baseline_interface(oc_resource_t *resource);

/**
  @defgroup oc_collections Collection Support
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
                                 uint8_t num_resource_types, int device);

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
  @brief Sets the unique link instance on the link.
  @param link The link to set the instance on. Must not be NULL.
  @param ins The link instance to set. Must not be NULL.
*/
void oc_link_set_ins(oc_link_t *link, const char *ins);

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
oc_link_t * oc_collection_get_links(oc_resource_t* collection);

/**
  @brief Adds a collection to the list of collections.

  If the caller makes the collection discoverable, then it will
  be included in the collection discovery once it has been added
  with this function.
  @param collection Collection to add to the list of collections.
   Must not be NULL. Must not be added twice or a list corruption
   will occur. The collection is not copied.
  @see oc_set_discoverable
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
/** @} */ // end of oc_collections

void oc_resource_make_public(oc_resource_t *resource);

void oc_resource_set_discoverable(oc_resource_t *resource, bool state);
void oc_resource_set_observable(oc_resource_t *resource, bool state);
void oc_resource_set_periodic_observable(oc_resource_t *resource,
                                         uint16_t seconds);
void oc_resource_set_request_handler(oc_resource_t *resource,
                                     oc_method_t method,
                                     oc_request_callback_t callback,
                                     void *user_data);
bool oc_add_resource(oc_resource_t *resource);
void oc_delete_resource(oc_resource_t *resource);

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
typedef void(*oc_con_write_cb_t)(int device_index, oc_rep_t *rep);

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
int oc_iterate_query(oc_request_t *request, char **key, int *key_len,
                     char **value, int *value_len);
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

/** Client side */
#include "oc_client_state.h"

bool oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                        void *user_data);

bool oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
               oc_response_handler_t handler, oc_qos_t qos, void *user_data);

bool oc_do_delete(const char *uri, oc_endpoint_t *endpoint,
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

void oc_free_server_endpoints(oc_endpoint_t *endpoint);

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
    OC_PROCESS_POLLHANDLER(name##_interrupt_x_handler());                      \
    OC_PROCESS_BEGIN();                                                        \
    while (oc_process_is_running(&(name##_interrupt_x))) {                     \
      OC_PROCESS_YIELD();                                                      \
    }                                                                          \
    OC_PROCESS_END();                                                          \
  }                                                                            \
  void name##_interrupt_x_handler(void)

#endif /* OC_API_H */
