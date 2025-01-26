/****************************************************************************
 *
 * Copyright (c) 2025 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#ifndef OC_NETIF_H
#define OC_NETIF_H

#include "util/oc_features.h"

#include <esp_netif.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function pointer type for iterating over network interfaces.
 *
 * A function of this type is called for each network interface. The iteration
 * stops if the function returns `false`; otherwise, it continues to the next
 * interface.
 *
 * @param netif     A pointer to the current network interface being
 * iterated.
 * @param user_data A pointer to user-defined data passed to the iteration
 * function.
 *
 * @return true to continue iterating,
 * @return false to stop.
 */
typedef bool (*oc_netif_iterate_interfaces_fn_t)(esp_netif_t *netif,
                                                 void *user_data);

/**
 * @brief Iterates over all network interfaces and applies a callback function.
 *
 * This function traverses all available network interfaces and invokes the
 * provided callback function for each interface. The iteration stops if the
 * callback function returns `false`.
 *
 * @param fn        A callback function of type
 * ::oc_netif_iterate_interfaces_fn_t that is invoked for each network
 * interface.
 * @param user_data A pointer to user-defined data passed to the callback
 * function.
 *
 * @return `ESP_OK` on success.
 *          Appropriate error code from the ESP-IDF framework on failure.
 *
 * @note This function internally uses `esp_netif_tcpip_exec()` for execution on
 *       ESP v3.6.2 or later.
 */
esp_err_t oc_netif_iterate_interfaces(oc_netif_iterate_interfaces_fn_t fn,
                                      void *user_data);

#ifdef OC_TCP

/**
 * @brief Retrieve the network interface index associated with a socket.
 *
 * This function determines the network interface associated with the given
 * socket by querying its address information. It then returns the index of
 * the network interface if found.
 *
 * @param sock The socket file descriptor for which the interface index
 *             is to be retrieved.
 *
 * @return The interface index (non-negative integer) if the associated network
 * interface is found.
 * @return `0` if no matching network interface is found.
 * @return `-1` on error (e.g., if `getsockname` fails), with the error logged.
 */
int oc_netif_get_interface_index(int sock);

#endif /* OC_TCP */

#ifdef OC_NETWORK_MONITOR

/**
 * @brief Add a new IP interface to the interface list.
 *
 * This function adds a new IP interface to the global interface list if it
 * does not already exist. The new interface is identified by its index.
 *
 * @param target_index The index of the network interface to add.
 *
 * @return `true` if the interface was successfully added.
 * @return `false` if the interface already exists or memory allocation fails.
 */
bool oc_netif_add_ip_interface(int target_index);

/**
 * @brief Remove an IP interface from the interface list.
 *
 * This function removes an existing IP interface from the global interface list
 * based on its index.
 *
 * @param target_index The index of the network interface to remove.
 *
 * @return `true` if the interface was successfully removed.
 * @return `false` if the interface was not found.
 */
bool oc_netif_remove_ip_interface(int target_index);

/**
 * @brief Check for and add new network interfaces.
 *
 * This function iterates over all available network interfaces and adds any
 * new interfaces to the global interface list.
 *
 * @return `true` on success.
 * @return `false` on error.
 */
bool oc_netif_check_new_ip_interfaces(void);

#endif /* OC_NETWORK_MONITOR */

/** Clean-up allocated interfaces or callbacks. */
void oc_netif_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_NETIF_H */
