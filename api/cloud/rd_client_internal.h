/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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
  @brief Resource Directory API of IoTivity-Lite for RD clients.
  @file
*/

#ifndef RD_CLIENT_H
#define RD_CLIENT_H

#include "api/oc_helpers_internal.h"
#include "oc_client_state.h"
#include "oc_endpoint.h"
#include "oc_link.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Resource Directory URI used to Discover RD and Publish resources.*/
#define OC_RSRVD_RD_URI "/oic/rd"

/** @brief Encode publish request payload to root encoder. */
bool rd_publish_encode(const oc_link_t *links, oc_string_view_t id,
                       oc_string_view_t name, uint32_t ttl);

/**
  @brief Publish RD resource to Resource Directory.

  @param links This is the resource which we need to register to RD.
    If null, oic/p and oic/d resources will be published.
  @param endpoint The endpoint of the RD. (cannot be NULL)
  @param device Index of the device for an unique identifier.
  @param ttl Time in seconds to indicate a RD, i.e. how long to keep this
    published item.
  @param handler To refer to the request sent out on behalf of calling this API.
  (cannot be NULL)
  @param qos Quality of service.
  @param user_data The user data passed from the registration function.

  @return Returns true if success.
*/
bool rd_publish(const oc_link_t *links, const oc_endpoint_t *endpoint,
                size_t device, uint32_t ttl, oc_response_handler_t handler,
                oc_qos_t qos, void *user_data) OC_NONNULL(2, 5);

typedef struct
{
  oc_link_t *deleted;     /// Linked list of deleted resource links.
  oc_link_t *not_deleted; /// Linked list of not deleted resource links.
} rd_links_partition_t;

typedef enum {
  RD_DELETE_ALL = 0,     ///< All resource links were deleted successfully.
  RD_DELETE_PARTIAL = 1, ///< Not all resource links were deleted
                         ///< successfully.

  RD_DELETE_ERROR = -1,
} rd_delete_result_t;

typedef bool (*rd_delete_on_packet_ready_t)(const oc_endpoint_t *endpoint,
                                            oc_string_view_t query, void *data);

/**
 * @brief Iterate resource links, write query to buffer until the buffer or
 * packet is full and then invoke on_packet_ready.
 *
 * @note Only single packet is sent, invoke this function multiple times to sent
 * all the resource links.
 *
 * @param links List of resource links which to iterate (cannot be NULL).
 * @param endpoint The endpoint of the RD (cannot be NULL).
 * @param id The id of the device to delete.
 * @param buffer The buffer to write the query to (cannot be NULL).
 * @param buffer_size The size of the buffer.
 * @param on_packet_ready The callback to invoke when the buffer or packet is
 * full (cannot be NULL).
 * @param on_packet_ready_data The data to pass to the callback.
 * @param links_partition The partition of links into deleted and not deleted
 * (cannot be NULL). The input links list is split into two lists, one for
 * deleted and one for not deleted links.
 *
 * @return rd_delete_result_t Result of the delete operation.
 */
rd_delete_result_t rd_delete_fill_and_send_single_packet(
  oc_link_t *links, const oc_endpoint_t *endpoint, oc_string_view_t id,
  char *buffer, size_t buffer_size, rd_delete_on_packet_ready_t on_packet_ready,
  void *on_packet_ready_data, rd_links_partition_t *links_partition)
  OC_NONNULL(1, 2, 4, 6, 8);

/**
  @brief Delete RD resource from Resource Directory.

  @param links List of resource links which we need to delete in RD (cannot be
  NULL).
  @param endpoint The endpoint of the RD (cannot be NULL).
  @param device Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API
  (cannot be NULL).
  @param qos Quality of service.
  @param user_data The user data passed from the registration function.
  @param links_partition The partition of links into deleted and not deleted.
  (valid only if result is RD_DELETE_ALL or RD_DELETE_PARTIAL,
  cannot be NULL)

  @return rd_delete_result_t Result of the delete operation.
*/
rd_delete_result_t rd_delete(oc_link_t *links, const oc_endpoint_t *endpoint,
                             size_t device, oc_response_handler_t handler,
                             oc_qos_t qos, void *user_data,
                             rd_links_partition_t *links_partition)
  OC_NONNULL(1, 2, 4, 7);

#ifdef __cplusplus
}
#endif

#endif /* RD_CLIENT_H */
