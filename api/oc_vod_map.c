/******************************************************************
 *
 * Copyright 2020 Intel Corporation
 * Copyright 2023 ETRI Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_BRIDGE

#include "oc_vod_map.h"
#include "oc_rep.h"
#include "oc_rep_internal.h"
#include "oc_core_res.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "port/oc_storage.h"

/*
 * g_reset_index :
 * - it stores the index of g_oc_device_info[] where the first VOD was added
 */
static size_t g_reset_index;

/*
 * g_vod_mapping_list :
 * - vods : list of VOD (oc_virtual_device_t)
 * - next_index : index of g_oc_device_info[]. new VOD will be added to g_oc_device_info[next_index]
 */
static oc_vod_mapping_list_t g_vod_mapping_list;

#define SVR_TAG_MAX (32)


static bool
oc_vod_map_decode(oc_rep_t *rep, bool from_storage)
{
  // TODO use the from_storage param or drop it from the map_decode
  (void)from_storage;
  size_t len = 0;

  /*
   * TODO4ME <2023/8/14> This could make a bug because Devices array (g_oc_device_info[])
   *                     can not be loaded now.
   *                     so currently disable loading of `g_vod_mapping_list`
   */
  if (from_storage == false)
    return true;

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_INT:
      if (len == 10 && memcmp(oc_string(rep->name), "next_index", 10) == 0) {
        g_vod_mapping_list.next_index = (size_t)rep->value.integer;
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
        /*
         * TODO4ME <Oct 24, 2023> oc_vod_map_decode() : insert codes to restore `is_removed` value
         */
        // vod->is_removed = true;
        oc_list_add(g_vod_mapping_list.vods, vod);
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
oc_vod_map_load(void)
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
    rep = oc_parse_rep(buf, (size_t)ret);
//    oc_vod_map_decode(rep, true);
    /*
     * TODO4ME <2023/8/14> This could make a bug because Devices (g_oc_device_info[])
     *                     can not be loaded now.
     *                     so, currently disable loading of `g_vod_mapping_list`
     */
    oc_vod_map_decode(rep, false);
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
oc_vod_map_encode(void)
{
  oc_rep_begin_root_object();
  oc_rep_set_int(root, next_index, g_vod_mapping_list.next_index);
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);

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
oc_vod_map_dump(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new_v1(buf, OC_MAX_APP_DATA_SIZE);
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

void
oc_vod_map_init(void)
{
  OC_LIST_STRUCT_INIT(&g_vod_mapping_list, vods);
  g_reset_index = g_vod_mapping_list.next_index = oc_core_get_num_devices();
  oc_vod_map_load();
}

/*
 * release the resouces.
 */
void
oc_vod_map_free(void)
{
  if (g_vod_mapping_list.vods) {
    oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);
    oc_virtual_device_t *v_to_free;
    while (v != NULL) {
      free(v->v_id);
      oc_free_string(&v->econame);
      v_to_free = v;
      v = v->next;
      oc_list_remove(g_vod_mapping_list.vods, v_to_free);
      free(v_to_free);
      v_to_free = NULL;
    }
  }
}

/*
 * Reset the vod map as if no VODs had been discovered.
 */
void
oc_vod_map_reset(void)
{
  oc_vod_map_free();
  g_vod_mapping_list.next_index = g_reset_index;
  oc_vod_map_dump();
}

size_t
oc_vod_map_get_vod_index(const uint8_t *vod_id, size_t vod_id_size,
                        const char *econame)
{
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);

  while (v != NULL) {
    if (v->v_id_size == vod_id_size && memcmp(vod_id, v->v_id, vod_id_size) == 0
        && (v->econame.size - 1) == strlen(econame)
        && memcmp(econame, oc_string(v->econame), v->econame.size) == 0) {
      return v->index;
    }
    v = v->next;
  }
  return 0;
}

size_t
oc_vod_map_add_mapping_entry(const uint8_t *vod_id, const size_t vod_id_size, const char *econame)
{
  /*
   * try to find this VOD mapping entry is already in `g_vod_mapping_list.vods` or not
   */
  size_t v_index = oc_vod_map_get_vod_index(vod_id, vod_id_size, econame);

  /*
   * if this vod mapping entry is already in `g_vod_mapping_list.vods`,
   * return corresponding index of Device in g_oc_device_info[].
   */
  if (v_index != 0) {
    return v_index;
  }

  /*
   * if this VOD mapping entry has not been added to `g_vod_mapping_list.vods`,
   * insert it to g_vod_mapping_list.vods.
   */
  oc_virtual_device_t *vod = (oc_virtual_device_t *)malloc(sizeof(oc_virtual_device_t));
  vod->v_id = (uint8_t *)malloc(vod_id_size * sizeof(uint8_t));
  memcpy(vod->v_id, vod_id, vod_id_size);
  vod->v_id_size = vod_id_size;
  oc_new_string(&vod->econame, econame, strlen(econame));
  vod->is_vod_online = false;

  /*
   * save corresponding index of Device in `g_oc_device_info[]` into `vod->index`
   * (this Device has not been added to g_oc_device_info[] yet.)
   */
  vod->index = g_vod_mapping_list.next_index;

  /*
   * if this is the first VOD mapping entry (`g_vod_list.vods` is empty)...
   * add new VOD mapping entry to `g_vod_mapping_list.vods` list
   */
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);
  if (v == NULL) {
    oc_list_add(g_vod_mapping_list.vods, vod);
    g_vod_mapping_list.next_index++;
  } else {
    /*
     * if this is not the first VOD mapping entry of `g_vod_mapping_list.vods` list (`g_vod_mapping_list.vods` is not empty)..
     * Traverse g_vod_mapping_list.vods to find `v` whose index is (g_vod_mapping_list.next_index - 1),
     * and insert new VOD mapping entry after `v`.
     *
     * After that, continue to increase `next_index` until no `v->index` matching `next_index` is found.
     * After that, next_index will be updated
     * And therefore,`g_vod_mapping_list.vods` list is always sorted in the order of `oc_virtual_device_t.index`...
     */
    while (v != NULL) {
      if ((g_vod_mapping_list.next_index == g_reset_index)
          || (v->index == (g_vod_mapping_list.next_index - 1))) {

        if (g_vod_mapping_list.next_index == g_reset_index) {
         /*
          * if `next_index` points the first node of `oc_vod_mapping_list.vods`,
          * (v->index == (g_vod_mapping_list.next_index - 1)) can't be satisfied ever...
          * because there is no VOD mapping entry pointing Device before the first VOD.
          *
          * therefore, insert new VOD mapping entry as the the first item in the list in this case.
          */
          oc_list_insert(g_vod_mapping_list.vods, NULL, vod);
          v = oc_list_head(g_vod_mapping_list.vods);
        } else {
         /*
          * if `next_index` points the middle node of `oc_vod_mapping_list.vods`,
          * finds `v` whose index is (g_vod_mapping_list.next_index - 1).
          * and insert new VOD mapping entry after `v`.
          */
          oc_list_insert(g_vod_mapping_list.vods, v, vod);
        }

        g_vod_mapping_list.next_index++;

        /*
         * continue walking the vods mapping entry list till an open next_index is found
         *
         * if the new VOD mapping entry is inserted in the middle of `g_vod_mapping_list.vods` list,
         * find next available index of `g_oc_device_info[]` and save index value
         * into the `g_vod_mapping_list.next_index`
         */
        while (v != NULL) {
          if (v->next != NULL && v->next->index == g_vod_mapping_list.next_index) {
            g_vod_mapping_list.next_index++;
          }
          v = v->next;
        }
        break;
      }
      v = v->next;
    } /* while */
  }

  oc_vod_map_dump();
  return vod->index;
}

void
oc_vod_map_remove_mapping_entry(size_t device_index)
{
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      free(v->v_id);
      oc_free_string(&v->econame);
      oc_virtual_device_t *v_to_free = v;
      oc_list_remove(g_vod_mapping_list.vods, v);
      if (device_index < g_vod_mapping_list.next_index) {
        g_vod_mapping_list.next_index = device_index;
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
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      *econame = v->econame;
      return;
    }
    v = v->next;
  }
}

oc_virtual_device_t *
oc_vod_map_get_mapping_entry(size_t device_index)
{
  oc_virtual_device_t *v = oc_list_head(g_vod_mapping_list.vods);
  while (v != NULL) {
    if (v->index == device_index) {
      return v;
    }
    v = v->next;
  }
  return NULL;
}


oc_virtual_device_t *
oc_vod_map_get_mapping_list(void)
{
  return oc_list_head(g_vod_mapping_list.vods);
}

#endif /* OC_HAS_FEATURE_BRIDGE */
