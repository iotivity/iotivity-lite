/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2023 ETRI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this fi le except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "oc_rep.h"
#include "oc_bridge.h"
#include "util/oc_list.h"
#include <stdint.h>
#include <stdbool.h>

#ifndef OC_VOD_MAP_H
#define OC_VOD_MAP_H

#ifdef __cplusplus
extern "C" {
#endif
/*
{
  "vods" : [
  {"vod_id":"virtual_device_id-1", "econame": "UPnP", "index":1},
  {"vod_id":"virtual_device_id-2", "econame": "ZigBee", "index":2}
  ],
  "next_index": 3
}
*/

/**
 * @struct oc_vod_mapping_list_t
 * - vods : list of VOD (oc_virtual_device_t)
 * - next_index : index of g_oc_device_info[].
 *                next new VOD will be added to g_oc_device_info[next_index]
 */
typedef struct oc_vod_mapping_list_s
{
  OC_LIST_STRUCT(vods);
  size_t next_index;        ///< index of g_oc_device_info[]. new VOD will be added to this position
} oc_vod_mapping_list_t;

/*
 * open vod_map file from creds directory and populate `oc_vod_mapping_list_t`
 * initilize this from the add_bridge
 */
/**
 * @brief
 * - initialize VOD list : `g_vod_mapping_list.vods`
 * - initialize next_index with `g_device_count`
 * - load existing `g_vod_mapping_list` from disk
 */
void oc_vod_map_init(void);

/*
 * release all of the memory
 */
void oc_vod_map_free(void);

/*
 * Reset the vod map as if no VODs had been discovered.
 */
void oc_vod_map_reset(void);

/**
 * @brief find Device in `g_vod_mapping_list.vods` list and return
 *        Device index of it (index of g_oc_device_info[]).
 *
 * @param vod_id id to be used as VOD's ID
 *        (UUID, serial number, or any other identifier that can
 *        identify the VOD)
 * @param vod_id_size size of vod_id
 * @param econame econame string
 *
 * @return index of the vod
 * @return 0 if not found
 */
size_t oc_vod_map_get_vod_index(const uint8_t *vod_id, size_t vod_id_size,
                               const char *econame);

/**
 *
 * @brief add new VOD mapping entry (identified by vod_id) to the proper position of
 *        `g_vod_mapping_list.vods` list,
 *        and update `g_vod_mapping_list.next_index`.
 *        finally, write updated vod_map file.
 *
 * @param vod_id id to be used as VOD's ID
 *        (UUID, serial number, or any other identifier that can
 *        identify the VOD)
 * @param vod_id_size size of vod_id
 * @param econame econame string
 *
 * @return index of just added vod (index of `g_oc_device_info[]`)
 */
size_t oc_vod_map_add_mapping_entry(const uint8_t *vod_id, const size_t vod_id_size,
                         const char *econame);

/*
 * Remove the vod_id at the given device index
 * This will update the next_index so freed indexes
 * can be reused.  The virtual device associated
 * with this index should
 */
void oc_vod_map_remove_mapping_entry(size_t device_index);

/*
 * Walk the vodmap and return the econame at the given index
 */
void oc_vod_map_get_econame(oc_string_t *econame, size_t device_index);

/**
 * @brief retrieve oc_virtual_device_t entry mapped to `device_index`
 * @param device_index device index
 * @return
 *    - oc_virtual_device_t *
 *    - NULL on error
 */
oc_virtual_device_t *oc_vod_map_get_mapping_entry(size_t device_index);

/**
 * @brief retrieve list of all oc_virtual_device_t instances
 *
 * @return head of g_vod_mapping_list.vods
 */
oc_virtual_device_t * oc_vod_map_get_mapping_list(void);

#ifdef __cplusplus
}
#endif

#endif // OC_VOD_MAP_H
