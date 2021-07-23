/*
// Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifdef OC_SECURITY

#include <stddef.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#include "oc_ael.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_pstat.h"
#include "oc_store.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_sec_ael_t *ael;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_ael_t ael[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */
// Can set specific capacity limits to the below allocators for static builds
OC_MEMB(events_s, oc_sec_ael_event_t, 1);
OC_MEMB(aux_s, oc_sec_ael_aux_info_t, 1);

// Theoretical maximum number of entries in the auxiliaryinfo
#define AEL_AUX_INFO_MAX_ITEMS (256)

static void oc_sec_ael_reset(size_t device);

static bool oc_sec_ael_add_event(size_t device, uint8_t category,
                                 uint8_t priority, oc_clock_time_t timestamp,
                                 const char *aeid, const char *message,
                                 const char **aux, size_t aux_len,
                                 bool write_to_storage);

static size_t oc_sec_ael_calc_event_size(const char *aeid, const char *message,
                                         const char **aux_info,
                                         size_t aux_size);

static oc_sec_ael_event_t *oc_sec_ael_create_event(
  size_t device, uint8_t category, uint8_t priority, oc_clock_time_t timestamp,
  const char *aeid, const char *message, const char **aux_info, size_t aux_size,
  size_t event_sz);
static inline void
oc_sec_ael_free_event(oc_sec_ael_event_t *event)
{
  if (event) {
    if (oc_string_len(event->aeid) > 0) {
      oc_free_string(&event->aeid);
    }
    if (oc_string_len(event->message) > 0) {
      oc_free_string(&event->message);
    }
    oc_sec_ael_aux_info_t *aux =
      (oc_sec_ael_aux_info_t *)oc_list_pop(event->aux_info);
    while (aux) {
      oc_free_string(&aux->aux_info);
      oc_memb_free(&aux_s, aux);
      aux = (oc_sec_ael_aux_info_t *)oc_list_pop(event->aux_info);
    }
    oc_memb_free(&events_s, event);
  }
}

static inline size_t
oc_sec_ael_max_space(size_t device)
{
  oc_sec_ael_t *a = &ael[device];
  size_t res = OC_SEC_AEL_MAX_SIZE;
  switch (a->unit) {
  case OC_SEC_AEL_UNIT_BYTE:
    res = a->maxsize;
    break;
  case OC_SEC_AEL_UNIT_KBYTE:
    res = a->maxsize / 1024;
    break;
  }
  return res;
}
static inline size_t
oc_sec_ael_used_space(size_t device)
{
  oc_sec_ael_t *a = &ael[device];
  size_t res = 0;
  switch (ael->unit) {
  case OC_SEC_AEL_UNIT_BYTE:
    res = a->events_size;
    break;
  case OC_SEC_AEL_UNIT_KBYTE:
    res = a->events_size / 1024;
    break;
  }
  return res;
}

void
oc_sec_ael_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  ael = (oc_sec_ael_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_ael_t));
  if (!ael) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    OC_LIST_STRUCT_INIT(&ael[device], events);
  }
}

void
oc_sec_ael_free(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_ael_reset(device);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(ael);
  ael = NULL;
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_ael_default(size_t device)
{
  oc_sec_ael_reset(device);
  oc_sec_ael_t *a = &ael[device];
  a->categoryfilter = OC_SEC_AEL_CATEGORYFILTER_DEFAULT;
  a->priorityfilter = OC_SEC_AEL_PRIORITYFILTER_DEFAULT;
  a->maxsize = OC_SEC_AEL_MAX_SIZE;
  a->unit = OC_SEC_AEL_UNIT_DEFAULT;
  a->events_size = 0;
  oc_sec_dump_ael(device);
}

bool
oc_sec_ael_add(size_t device, uint8_t category, uint8_t priority,
               const char *aeid, const char *message, const char **aux,
               size_t aux_len)
{
  return oc_sec_ael_add_event(device, category, priority, oc_clock_time(), aeid,
                              message, aux, aux_len, true);
}

void
get_ael(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  if (request) {
    switch (iface_mask) {
    case OC_IF_BASELINE:
    case OC_IF_RW:
      if (oc_sec_ael_encode(request->resource->device, iface_mask, false)) {
        oc_send_response(request, OC_STATUS_OK);
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
      }
      break;
    default:
      break;
    }
  }
}
void
post_ael(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  if (request) {
    oc_sec_pstat_t *ps = oc_sec_get_pstat(request->resource->device);
    if (ps->s == OC_DOS_RFNOP) {
      OC_ERR("oc_ael: Cannot UPDATE AEL in RFNOP");
      oc_send_response(request, OC_STATUS_FORBIDDEN);
      return;
    }
    switch (iface_mask) {
    case OC_IF_BASELINE:
    case OC_IF_RW:
      if (oc_sec_ael_decode(request->resource->device, request->request_payload,
                            false)) {
        oc_send_response(request, OC_STATUS_CHANGED);
        oc_sec_dump_ael(request->resource->device);
      } else {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
      }
      break;
    default:
      break;
    }
  }
}

bool
oc_sec_ael_encode(size_t device, oc_interface_mask_t iface_mask,
                  bool to_storage)
{
  oc_sec_ael_t *a = &ael[device];
  char tmpstr[64];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_AEL, device));
  }
  /* categoryfilter */
  oc_rep_set_int(root, categoryfilter, a->categoryfilter);
  /* priorityfilter */
  oc_rep_set_int(root, priorityfilter, a->priorityfilter);
  /* maxspace */
  if (!to_storage) {
    oc_rep_set_int(root, maxspace, oc_sec_ael_max_space(device));
  } else {
    oc_rep_set_int(root, maxspace, a->maxsize);
  }
  /* usedspace */
  if (!to_storage) {
    oc_rep_set_int(root, usedspace, oc_sec_ael_used_space(device));
  }
  /* unit */
  if (to_storage) {
    oc_rep_set_int(root, unit, a->unit);
  }
  /* events */
  oc_rep_set_array(root, events);
  for (oc_sec_ael_event_t *e = (oc_sec_ael_event_t *)oc_list_head(a->events); e;
       e = e->next) {
    oc_rep_object_array_start_item(events);
    /* category */
    oc_rep_set_int(events, category, e->category);
    /* priority */
    oc_rep_set_int(events, priority, e->priority);
    /* timestamp */
    if (!to_storage) {
      if (oc_clock_encode_time_rfc3339(e->timestamp, tmpstr, 64) != 0) {
        oc_rep_set_text_string(events, timestamp, tmpstr);
      }
    } else {
      oc_rep_set_int(events, timestamp, e->timestamp);
    }
    /* aeid */
    if (oc_string_len(e->aeid) > 0) {
      oc_rep_set_text_string(events, aeid, oc_string(e->aeid));
    }
    /* message */
    if (oc_string_len(e->message) > 0) {
      oc_rep_set_text_string(events, message, oc_string(e->message));
    }
    /* auxiliaryinfo */
    oc_rep_open_array(events, auxiliaryinfo);
    if (oc_list_length(e->aux_info) > 0) {
      oc_sec_ael_aux_info_t *aux =
        (oc_sec_ael_aux_info_t *)oc_list_head(e->aux_info);
      while (aux) {
        oc_rep_add_text_string(auxiliaryinfo, oc_string(aux->aux_info));
        aux = aux->next;
      }
    }
    oc_rep_close_array(events, auxiliaryinfo);
    oc_rep_object_array_end_item(events);
  }
  oc_rep_close_array(root, events);
  oc_rep_end_root_object();
  return true;
}

bool
oc_sec_ael_decode(size_t device, oc_rep_t *rep, bool from_storage)
{
  oc_sec_ael_t *a = &ael[device];
  oc_rep_t *repc = rep;
  for (; repc; repc = repc->next) {
    size_t len = oc_string_len(repc->name);
    switch (repc->type) {
    /* categoryfilter, priorityfilter, maxspace, unit */
    case OC_REP_INT:
      if (len == 14 &&
          memcmp(oc_string(repc->name), "categoryfilter", 14) == 0) {
        a->categoryfilter = (uint8_t)repc->value.integer;
      } else if (len == 14 &&
                 memcmp(oc_string(repc->name), "priorityfilter", 14) == 0) {
        a->priorityfilter = (uint8_t)repc->value.integer;
      } else if (from_storage && len == 8 &&
                 memcmp(oc_string(repc->name), "maxspace", 8) == 0) {
        a->maxsize = (size_t)repc->value.integer;
      } else if (from_storage && len == 4 &&
                 memcmp(oc_string(repc->name), "unit", 4) == 0) {
        a->unit = (oc_sec_ael_unit_t)repc->value.integer;
      }
      break;
    default:
      break;
    }
  }
  for (; rep; rep = rep->next) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    /* events */
    case OC_REP_OBJECT_ARRAY:
      if (from_storage && len == 6 &&
          memcmp(oc_string(rep->name), "events", 6) == 0) {
        for (oc_rep_t *event = rep->value.object_array; event;
             event = event->next) {
          uint8_t category = 0;
          uint8_t priority = 0;
          oc_clock_time_t timestamp = 0;
          char *aeid = NULL;
          char *message = NULL;
          size_t aux_sz = 0;
          char *aux[AEL_AUX_INFO_MAX_ITEMS] = { 0 };
          for (oc_rep_t *r = event->value.object; r; r = r->next) {
            size_t l = oc_string_len(r->name);
            switch (r->type) {
            /* category, priority, timestamp */
            case OC_REP_INT:
              if (l == 8 && memcmp(oc_string(r->name), "category", 8) == 0) {
                category = (uint8_t)r->value.integer;
              } else if (l == 8 &&
                         memcmp(oc_string(r->name), "priority", 8) == 0) {
                priority = (uint8_t)r->value.integer;
              } else if (l == 9 &&
                         memcmp(oc_string(r->name), "timestamp", 9) == 0) {
                timestamp = (oc_clock_time_t)r->value.integer;
              }
              break;
            /* aeid, message */
            case OC_REP_STRING:
              if (l == 4 && memcmp(oc_string(r->name), "aeid", 4) == 0) {
                aeid = oc_string(r->value.string);
              } else if (l == 7 &&
                         memcmp(oc_string(r->name), "message", 7) == 0) {
                message = oc_string(r->value.string);
              }
              break;
            /* auxiliaryinfo */
            case OC_REP_STRING_ARRAY:
              if (l == 13 &&
                  memcmp(oc_string(r->name), "auxiliaryinfo", 13) == 0) {
                aux_sz = oc_string_array_get_allocated_size(r->value.array);
                if (aux_sz != 0) {
                  for (size_t i = 0; i < aux_sz; i++) {
                    aux[i] = oc_string_array_get_item(r->value.array, i);
                  }
                }
              }
              break;
            default:
              break;
            }
          }
          oc_sec_ael_add_event(device, category, priority, timestamp, aeid,
                               message, (const char **)aux, aux_sz, false);
        }
      }
      break;
    default:
      break;
    }
  }
  return true;
}

static void
oc_sec_ael_reset(size_t device)
{
  oc_sec_ael_t *a = &ael[device];
  oc_sec_ael_event_t *e = (oc_sec_ael_event_t *)oc_list_pop(a->events);
  while (e) {
    oc_sec_ael_free_event(e);
    e = (oc_sec_ael_event_t *)oc_list_pop(a->events);
  }
}

static bool
oc_sec_ael_add_event(size_t device, uint8_t category, uint8_t priority,
                     oc_clock_time_t timestamp, const char *aeid,
                     const char *message, const char **aux, size_t aux_len,
                     bool write_to_storage)
{
  bool res = false;
  oc_sec_ael_t *a = &ael[device];

  if (!(a->categoryfilter & category) || (a->priorityfilter < priority)) {
    OC_DBG("Event category %d or priority %d not matching", category, priority);
    return false;
  }

  // calculate total event size
  size_t event_sz = oc_sec_ael_calc_event_size(aeid, message, aux, aux_len);
  // check size
  if (event_sz > a->maxsize) {
    OC_ERR("event size exceeds available size!");
  } else {
    // delete old events if needed
    while ((event_sz + a->events_size) > a->maxsize &&
           oc_list_length(a->events) > 0) {
      oc_sec_ael_event_t *t = (oc_sec_ael_event_t *)oc_list_pop(a->events);
      a->events_size -= t->size;
      oc_sec_ael_free_event(t);
    }
    // create/add event
    oc_sec_ael_event_t *e =
      oc_sec_ael_create_event(device, category, priority, timestamp, aeid,
                              message, aux, aux_len, event_sz);
    if (!e) {
      OC_ERR("Can't create event!");
    } else {
      a->events_size += e->size;
      // write to storage
      if (write_to_storage) {
        oc_sec_dump_ael(device);
      }
      res = true;
    }
  }
  return res;
}

static size_t
oc_sec_ael_calc_event_size(const char *aeid, const char *message,
                           const char **aux_info, size_t aux_size)
{
  size_t res = sizeof(oc_sec_ael_event_t);

  if (aeid) {
    res += (strlen(aeid) + 1);
  }
  if (message) {
    res += (strlen(message) + 1);
  }
  if (aux_info && aux_size != 0) {
    res += (aux_size * sizeof(char *));
    for (size_t i = 0; i < aux_size; i++) {
      res += (strlen(aux_info[i]) + 1);
    }
  }
  return res;
}

static oc_sec_ael_event_t *
oc_sec_ael_create_event(size_t device, uint8_t category, uint8_t priority,
                        oc_clock_time_t timestamp, const char *aeid,
                        const char *message, const char **aux_info,
                        size_t aux_size, size_t event_sz)
{
  // allocate memory
  oc_sec_ael_event_t *res = (oc_sec_ael_event_t *)oc_memb_alloc(&events_s);
  if (!res) {
    OC_ERR("Out of memory!");
    return NULL;
  }
  OC_LIST_STRUCT_INIT(res, aux_info);
  res->size = event_sz;
  res->category = category;
  res->priority = priority;
  res->timestamp = timestamp;
  if (aeid && strlen(aeid) > 0) {
    oc_new_string(&res->aeid, aeid, strlen(aeid));
  }
  if (message && strlen(message) > 0) {
    oc_new_string(&res->message, message, strlen(message));
  }
  if (aux_info && aux_size > 0) {
    size_t i;
    for (i = 0; i < aux_size; i++) {
      oc_sec_ael_aux_info_t *a_info =
        (oc_sec_ael_aux_info_t *)oc_memb_alloc(&aux_s);
      if (a_info) {
        oc_new_string(&a_info->aux_info, aux_info[i], strlen(aux_info[i]));
        oc_list_add(res->aux_info, a_info);
      }
    }
  }

  oc_sec_ael_t *a = &ael[device];
  oc_list_add(a->events, res);

  return res;
}

#endif /* OC_SECURITY */
