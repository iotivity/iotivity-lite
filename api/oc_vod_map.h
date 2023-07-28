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

typedef struct oc_vod_mapping_list_s
{
  OC_LIST_STRUCT(vods);
  size_t next_index; // index of g_oc_device_info[]
} oc_vod_mapping_list_t;

/*
 * open vod_map file from creds directory and populate `oc_vod_list_t`
 * initilize this from the add_bridge
 */
/**
 * @brief
 * - initialize VOD list : g_vod_list.vods
 * - initialize next_index with `g_device_count`
 * - load existing g_vod_list from disk
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
/*
 * returns index of the vod or 0 if not found
 */
size_t oc_vod_map_get_id_index(const uint8_t *vod_id, size_t vod_id_size,
                               const char *econame);

/*
 * add the vod_id to the the oc_vod_list_t
 * update next_index
 * write updated vod_map file
 * return index of just added vod
 */
size_t oc_vod_map_add_id(const uint8_t *vod_id, const size_t vod_id_size,
                         const char *econame);

/*
 * Remove the vod_id at the given device index
 * This will update the next_index so freed indexes
 * can be reused.  The virtual device associated
 * with this index should
 */
void oc_vod_map_remove_id(size_t device_index);

/*
 * Walk the vodmap and return the econame at the given index
 */
void oc_vod_map_get_econame(oc_string_t *econame, size_t device_index);

oc_virtual_device_t *oc_vod_map_get_virtual_device(size_t device_index);
#ifdef __cplusplus
}
#endif

#endif // OC_VOD_MAP_H
