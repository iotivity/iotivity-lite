/*
// Copyright (c) 2020 Intel Corporation
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

#include "oc_vod_map.h"
#include "oc_rep.h"
#include "oc_core_res.h"
#include "port/oc_connectivity.h"
#include "port/oc_storage.h"

static oc_vod_list_t vod_list;
static size_t reset_index;

#define SVR_TAG_MAX (32)


static bool
oc_vod_map_decode(oc_rep_t *rep, bool from_storage)
{
  // TODO use the from_storage param or drop it from the map_decode
  (void)from_storage;
  size_t len = 0;

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_INT:
      if (len == 10 && memcmp(oc_string(rep->name), "next_index", 10) == 0) {
        vod_list.next_index = (size_t)rep->value.integer;
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *v; // = rep->value.object_array;
      if (!oc_rep_get_object_array(rep, "vods", &v)) {
        OC_DBG("oc_vod_map: decode 'vods' object array not found.");
        return false;
      }
      while (NULL != v) {
        oc_virtual_device_t *vod =
          (oc_virtual_device_t *)malloc(sizeof(oc_virtual_device_t));
        char *v_id = NULL;
        if (!oc_rep_get_byte_string(v->value.object, "vod_id", &v_id,
                                    &vod->v_id_size)) {
          OC_DBG("oc_vod_map: decode 'vod_id' not found.");
          return false;
        }
        if (NULL != v_id) {
          vod->v_id = (uint8_t *)malloc(vod->v_id_size * sizeof(uint8_t));
          memcpy(vod->v_id, v_id, vod->v_id_size);
        } else {
          OC_DBG("oc_vod_map: decode failed to find 'vod_id'");
          return false;
        }
        char *en = NULL;
        size_t en_size = 0;
        if (!oc_rep_get_string(v->value.object, "econame", &en, &en_size)) {
          OC_DBG("oc_vod_map: decode 'econame' not found.");
          return false;
        }
        if (NULL != en) {
          oc_new_string(&vod->econame, en, en_size);
        } else {
          return false;
        }
        int64_t temp = 0;
        if (!oc_rep_get_int(v->value.object, "index", &temp)) {
          OC_DBG("oc_vod_map: decode 'index' not found.");
          return false;
        }
        vod->index = (size_t)temp;
        oc_list_add(vod_list.vods, vod);
        v = v->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

/*
 * load vod_map file and pass bytes to decode to populate oc_vod_list_t
 *
 * reference oc_sec_load_acl(size_t device) in oc_store.c
 */
static void
oc_vod_map_load()
{
  long ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  ret = oc_storage_read("vod_map", buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
    oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                   rep_objects_alloc, (void *)rep_objects_pool,
                                   0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)ret, &rep);
    oc_vod_map_decode(rep, true);
    oc_free_rep(rep);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

/*
 * responsible for encoding the oc_vod_list_t to cbor
 * function will be used by dump_vod_map()
 */
static void
oc_vod_map_encode()
{
  oc_rep_begin_root_object();
  oc_rep_set_int(root, next_index, vod_list.next_index);
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);

  oc_rep_open_array(root, vods);
  // oc_rep_object_array_begin_item(vods);
  while (v != NULL) {
    oc_rep_object_array_begin_item(vods);
    oc_rep_set_byte_string(vods, vod_id, v->v_id, v->v_id_size);
    oc_rep_set_text_string(vods, econame, oc_string(v->econame));
    oc_rep_set_int(vods, index, v->index);
    oc_rep_object_array_end_item(vods);
    v = v->next;
  }
  oc_rep_close_array(root, vods);
  oc_rep_end_root_object();
}

/*
 * convert the oc_vod_list_t to cbor
 * dump cbor bytes to vod_map file
 *
 * reference oc_sec_dump_acl(size_t device) in oc_store.c
 */
static void
oc_vod_map_dump()
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_vod_map_encode();
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_vod_map: encoded vod_map size %d", size);
    oc_storage_write("vod_map", buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

/*
 * open vod_map file from creds directory and populate
 * oc_vod_list_t
 */
void
oc_vod_map_init()
{
  OC_LIST_STRUCT_INIT(&vod_list, vods);
  reset_index = vod_list.next_index = oc_core_get_num_devices();
  oc_vod_map_load();
}

/*
 * release the resouces.
 */
void
oc_vod_map_free()
{
  if (vod_list.vods) {
    oc_virtual_device_t *v = oc_list_head(vod_list.vods);
    oc_virtual_device_t *v_to_free;
    while (v != NULL) {
      free(v->v_id);
      oc_free_string(&v->econame);
      v_to_free = v;
      v = v->next;
      oc_list_remove(vod_list.vods, v_to_free);
      free(v_to_free);
      v_to_free = NULL;
    }
  }
}

/*
 * Reset the vod map as if no VODs had been discovered.
 */
void
oc_vod_map_reset()
{
  oc_vod_map_free();
  vod_list.next_index = reset_index;
  oc_vod_map_dump();
}

/*
 * returns index of the vod or 0 if not found
 */
size_t
oc_vod_map_get_id_index(const uint8_t *vod_id, size_t vod_id_size,
                        const char *econame)
{
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);
  while (v != NULL) {
    if (v->v_id_size == vod_id_size &&
        memcmp(vod_id, v->v_id, vod_id_size) == 0 &&
        (v->econame.size - 1) == strlen(econame) &&
        memcmp(econame, oc_string(v->econame), v->econame.size) == 0) {
      return v->index;
    }
    v = v->next;
  }
  return 0;
}

/*
 * add the vod_id to the the oc_vod_list_t
 * update next_index
 * write updated vod_map file
 * return index of just added vod
 */
size_t
oc_vod_map_add_id(const uint8_t *vod_id, const size_t vod_id_size,
                  const char *econame)
{
  size_t v_index = oc_vod_map_get_id_index(vod_id, vod_id_size, econame);

  if (v_index != 0) {
    return v_index;
  }
  oc_virtual_device_t *vod =
    (oc_virtual_device_t *)malloc(sizeof(oc_virtual_device_t));
  vod->v_id = (uint8_t *)malloc(vod_id_size * sizeof(uint8_t));
  memcpy(vod->v_id, vod_id, vod_id_size);
  vod->v_id_size = vod_id_size;
  oc_new_string(&vod->econame, econame, strlen(econame));
  vod->index = vod_list.next_index;
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);
  if (v == NULL) {
    oc_list_add(vod_list.vods, vod);
    vod_list.next_index++;
  }
  while (v != NULL) {
    if (v->index == (vod_list.next_index - 1)) {
      oc_list_insert(vod_list.vods, v, vod);
      vod_list.next_index++;
      // continue walking the vods list till an open next_index is found
      while (v != NULL) {
        if (v->next != NULL && v->next->index == vod_list.next_index) {
          vod_list.next_index++;
        }
        v = v->next;
      }
      break;
    }
    v = v->next;
  }
  oc_vod_map_dump();
  return vod->index;
}

void
oc_vod_map_remove_id(size_t device_index)
{
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      free(v->v_id);
      oc_free_string(&v->econame);
      oc_virtual_device_t *v_to_free = v;
      oc_list_remove(vod_list.vods, v);
      if (device_index < vod_list.next_index) {
        vod_list.next_index = device_index;
      }
      // v = v->next;
      // oc_list_remove(vod_list.vods, v_to_free);
      free(v_to_free);
      v_to_free = NULL;
      break;
    }
    v = v->next;
  }
  oc_vod_map_dump();
}

void
oc_vod_map_get_econame(oc_string_t *econame, size_t device_index)
{
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      *econame = v->econame;
      return;
    }
    v = v->next;
  }
}

oc_virtual_device_t *
oc_vod_map_get_virtual_device(size_t device_index)
{
  oc_virtual_device_t *v = oc_list_head(vod_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      return v;
    }
    v = v->next;
  }
  return NULL;
}
