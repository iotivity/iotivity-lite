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

#include "oc_api.h"
#include "oc_ael.h"
#include "oc_core_res.h"
#include "oc_pstat.h"
#include "oc_store.h"
#include "oc_clock_util.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#include "port/oc_assert.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_DYNAMIC_ALLOCATION
static oc_sec_ael_t s_ael;
#endif /* OC_DYNAMIC_ALLOCATION */

static oc_sec_ael_t *ael = NULL;

static void oc_sec_ael_reset(void);

static bool oc_sec_ael_add_event(uint8_t category, uint8_t priority, oc_clock_time_t timestamp,
                                 const char *aeid, const char *message, const char **aux, size_t aux_len,
                                 bool write_to_storage);

#ifdef OC_DYNAMIC_ALLOCATION
static size_t oc_sec_ael_calc_event_size(const char *aeid, const char *message, const char **aux_info, size_t aux_size,
                                         size_t *aeid_sz, size_t *message_sz, size_t *aux_info_sz, size_t **aux_sz);

static oc_sec_ael_event_t *oc_sec_ael_create_event(uint8_t category, uint8_t priority, oc_clock_time_t timestamp,
                                                   const char *aeid, const char *message, const char** aux_info, size_t aux_size,
                                                   size_t event_sz, size_t aeid_sz, size_t message_sz, size_t aux_info_sz, size_t *aux_sz);
static inline void oc_sec_ael_free_event(oc_sec_ael_event_t *event)
{
  free(event);
}
#endif /* OC_DYNAMIC_ALLOCATION */

static inline size_t oc_sec_ael_max_space(void)
{
  size_t res = OC_SEC_AEL_MAX_SIZE;
  switch (ael->unit)
  {
  case OC_SEC_AEL_UNIT_BYTE:
    res = ael->maxsize;
    break;
  case OC_SEC_AEL_UNIT_KBYTE:
    res = ael->maxsize / 1024;
    break;
  }
  return res;
}
static inline size_t oc_sec_ael_used_space(void)
{
  size_t res = 0;
  switch (ael->unit)
  {
  case OC_SEC_AEL_UNIT_BYTE:
    res = ael->events.size;
    break;
  case OC_SEC_AEL_UNIT_KBYTE:
    res = ael->events.size / 1024;
    break;
  }
  return res;
}

static const char* oc_sec_ael_unit_string(void)
{
  static const char* ael_unit_string[] = {"Byte", "Kbyte"};
  switch (ael->unit)
  {
  case OC_SEC_AEL_UNIT_BYTE:
  case OC_SEC_AEL_UNIT_KBYTE:
    return ael_unit_string[ael->unit];
  }
  return "";
}

void
oc_sec_ael_init(void)
{
  oc_sec_ael_reset();
}
void
oc_sec_ael_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (ael) {
      for (oc_sec_ael_event_t* e = ael->events.tail; e; e = e->next) {
        oc_sec_ael_free_event(e);
      }
    free(ael);
    ael = NULL;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_ael_default(size_t device)
{
  oc_sec_ael_reset();
  oc_sec_dump_ael(device);
}

bool
oc_sec_ael_add(uint8_t category, uint8_t priority, const char *aeid,
               const char *message, const char **aux, size_t aux_len)
{
  return oc_sec_ael_add_event(category, priority, oc_clock_time(),
                                aeid, message, aux, aux_len, true);
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
post_ael(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data)
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
      if (oc_sec_ael_decode(request->request_payload, false)) {
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
oc_sec_ael_encode(size_t device, oc_interface_mask_t iface_mask, bool to_storage)
{
  char tmpstr[64];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_AEL, device));
  }
  /* categoryfilter */
  oc_rep_set_int(root, categoryfilter, ael->categoryfilter);
  /* priorityfilter */
  oc_rep_set_int(root, priorityfilter, ael->priorityfilter);
  /* maxspace */
  if (!to_storage) {
    oc_rep_set_int(root, maxspace, oc_sec_ael_max_space());
  } else {
    oc_rep_set_int(root, maxspace, ael->maxsize);
  }
  /* usedspace */
  if (!to_storage) {
    oc_rep_set_int(root, usedspace, oc_sec_ael_used_space());
  }
  /* unit */
  if (!to_storage) {
    oc_rep_set_text_string(root, unit, oc_sec_ael_unit_string());
  } else {
    oc_rep_set_int(root, unit, ael->unit);
  }
  /* events */
  oc_rep_set_array(root, events);
  for (oc_sec_ael_event_t *e = ael->events.tail; e; e = e->next) {
    oc_rep_object_array_start_item(events);
    /* devicetype & di */
    if (!to_storage) {
      oc_device_info_t *devinfo = oc_core_get_device_info(device);
      if (devinfo) {
        oc_resource_t *r = oc_core_get_resource_by_index(OCF_D, device);
        oc_rep_set_string_array(events, devicetype, r->types);
        oc_uuid_to_str(&devinfo->di, tmpstr, OC_UUID_LEN);
        oc_rep_set_text_string(events, di, tmpstr);
      }
    }
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
    if (e->aeid) {
      oc_rep_set_text_string(events, aeid, e->aeid);
    }
    /* message */
    if (e->message) {
      oc_rep_set_text_string(events, message, e->message);
    }
    /* auxiliaryinfo */
    if (e->aux_info && e->aux_size != 0) {
      oc_string_array_t auxiliaryinfo;
      oc_new_string_array(&auxiliaryinfo, e->aux_size);
      for (size_t i = 0; i < e->aux_size; i++) {
        oc_string_array_add_item(auxiliaryinfo, e->aux_info[i]);
      }
      oc_rep_set_string_array(events, auxiliaryinfo, auxiliaryinfo);
      oc_free_string_array(&auxiliaryinfo);
    }
    oc_rep_object_array_end_item(events);
  }
  oc_rep_close_array(root, events);
  oc_rep_end_root_object();
  return true;
}
bool
oc_sec_ael_decode(oc_rep_t *rep, bool from_storage)
{
  for (; rep; rep = rep->next) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    /* categoryfilter, priorityfilter, maxspace, unit */
    case OC_REP_INT:
      if (len == 14 && memcmp(oc_string(rep->name), "categoryfilter", 14) == 0) {
        ael->categoryfilter = (uint8_t)rep->value.integer;
      } else if (len == 14 && memcmp(oc_string(rep->name), "priorityfilter", 14) == 0) {
        ael->priorityfilter = (uint8_t)rep->value.integer;
      } else if (from_storage && len == 8 && memcmp(oc_string(rep->name), "maxspace", 8) == 0) {
        ael->maxsize = (size_t)rep->value.integer;
      } else if (from_storage && len == 4 && memcmp(oc_string(rep->name), "unit", 4) == 0) {
        ael->unit = (oc_sec_ael_unit_t)rep->value.integer;
      }
      break;
    /* events */
    case OC_REP_OBJECT_ARRAY:
      if (from_storage && len == 6 && memcmp(oc_string(rep->name), "events", 6) == 0) {
        for (oc_rep_t *event = rep->value.object_array; event; event = event->next) {
          uint8_t category = 0;
          uint8_t priority = 0;
          oc_clock_time_t timestamp = 0;
          char *aeid = NULL;
          char *message = NULL;
          size_t aux_sz = 0;
          char **aux = NULL;
          for (oc_rep_t *r = event->value.object; r; r = r->next) {
            size_t l = oc_string_len(r->name);
            switch (r->type) {
            /* category, priority, timestamp */
            case OC_REP_INT:
              if (l == 8 && memcmp(oc_string(r->name), "category", 8) == 0) {
                category = (uint8_t)r->value.integer;
              } else if (l == 8 && memcmp(oc_string(r->name), "priority", 8) == 0) {
                priority = (uint8_t)r->value.integer;
              } else if (l == 9 && memcmp(oc_string(r->name), "timestamp", 9) == 0) {
                timestamp = (oc_clock_time_t)r->value.integer;
              }
              break;
            /* aeid, message */
            case OC_REP_STRING:
              if (l == 4 && memcmp(oc_string(r->name), "aeid", 4) == 0) {
                aeid = oc_string(r->value.string);
              } else if (l == 7 && memcmp(oc_string(r->name), "message", 7) == 0) {
                message = oc_string(r->value.string);
              }
              break;
            /* auxiliaryinfo */
            case OC_REP_STRING_ARRAY:
#ifdef OC_DYNAMIC_ALLOCATION
              if (l == 13 && memcmp(oc_string(r->name), "auxiliaryinfo", 13) == 0) {
                aux_sz = oc_string_array_get_allocated_size(r->value.array);
                if ((aux_sz != 0) && ((aux = (char**)malloc(aux_sz * sizeof(char*))) != NULL)) {
                  for (size_t i = 0; i < aux_sz; i++) {
                    aux[i] = oc_string_array_get_item(r->value.array, i);
                  }
                }
              }
#else /* OC_DYNAMIC_ALLOCATION */
              #pragma message ("Not implemented!")
              OC_ERR("Not implemented!");
#endif /* OC_DYNAMIC_ALLOCATION */
              break;
            default:
              break;
            }
          }
          oc_sec_ael_add_event(category, priority, timestamp, aeid, message,
                               (const char **)aux, aux_sz, false);
#ifdef OC_DYNAMIC_ALLOCATION
          if (aux) {
            free(aux);
          }
#endif /* OC_DYNAMIC_ALLOCATION */
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
oc_sec_ael_reset(void)
{
  oc_sec_ael_free();
#ifdef OC_DYNAMIC_ALLOCATION
  if (!(ael = (oc_sec_ael_t *)calloc(1, sizeof(oc_sec_ael_t)))) {
    oc_abort("oc_ael: Out of memory");
  }
#else /* OC_DYNAMIC_ALLOCATION */
  ael = &s_ael;
#endif /* OC_DYNAMIC_ALLOCATION */
  ael->categoryfilter = OC_SEC_AEL_CATEGORYFILTER_DEFAULT;
  ael->priorityfilter = OC_SEC_AEL_PRIORITYFILTER_DEFAULT;
  ael->maxsize = OC_SEC_AEL_MAX_SIZE;
  ael->unit = OC_SEC_AEL_UNIT_DEFAULT;
  ael->events.size = 0;
  ael->events.head = ael->events.tail = NULL;
}

static bool
oc_sec_ael_add_event(uint8_t category, uint8_t priority, oc_clock_time_t timestamp,
                     const char *aeid, const char *message, const char **aux, size_t aux_len,
                     bool write_to_storage)
{
  bool res = false;

  if (!(ael->categoryfilter & category) || (ael->priorityfilter < priority)) {
    OC_DBG("Event category or priority not matching");
    return false;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  // calculate total event size
  size_t aeid_sz = 0;
  size_t message_sz = 0;
  size_t aux_info_sz = 0;
  size_t *aux_sz = NULL;
  size_t event_sz = oc_sec_ael_calc_event_size(aeid, message, aux, aux_len,
                                               &aeid_sz, &message_sz, &aux_info_sz, &aux_sz);
  // check size
  if (event_sz > ael->maxsize) {
    OC_ERR("event size exceeds available size!");
  } else {
    // delete old events if needed
    while (((event_sz + ael->events.size) > ael->maxsize) && ael->events.tail) {
      oc_sec_ael_event_t *t = ael->events.tail;
      ael->events.size -= t->size;
      ael->events.tail = t->next;
      oc_sec_ael_free_event(t);
    }
    // if all events deleted
    if (!ael->events.tail) {
      ael->events.head = NULL;
    }
    // create/add event
    oc_sec_ael_event_t *e = oc_sec_ael_create_event(category, priority, timestamp, aeid, message, aux, aux_len,
                                                    event_sz, aeid_sz, message_sz, aux_info_sz, aux_sz);
    if (!e) {
      OC_ERR("Can't create event!");
    } else {
      ael->events.size += e->size;
      if (!ael->events.head) {
        ael->events.head = ael->events.tail = e;
      } else {
        ael->events.head->next = e;
        ael->events.head = e;
      }
      // write to storage
      if (write_to_storage) {
        oc_sec_dump_ael(0);
      }
      res = true;
    }
  }
  if (aux_sz) {
    free(aux_sz);
  }
#else /* OC_DYNAMIC_ALLOCATION */
  #pragma message ("Not implemented!")
  (void)category;
  (void)priority;
  (void)timestamp;
  (void)aeid;
  (void)message;
  (void)aux;
  (void)aux_len;
  (void)write_to_storage;
  OC_ERR("Not implemented!");
#endif /* OC_DYNAMIC_ALLOCATION */

  return res;
}

#ifdef OC_DYNAMIC_ALLOCATION
static size_t
oc_sec_ael_calc_event_size(const char *aeid, const char *message, const char **aux_info, size_t aux_size,
                           size_t *aeid_sz, size_t *message_sz, size_t *aux_info_sz, size_t **aux_sz)
{
  size_t res = sizeof(oc_sec_ael_event_t);

  if (aeid) {
    *aeid_sz = (strlen(aeid) + 1);
    res += *aeid_sz;
  } else {
    *aeid_sz = 0;
  }
  if (message) {
    *message_sz = (strlen(message) + 1);
    res += *message_sz;
  } else {
    *message_sz = 0;
  }
  size_t *tmp_arr = NULL;
  if (aux_info && aux_size != 0 &&
          ((tmp_arr = malloc(aux_size * sizeof(char*))) != NULL)) {
    *aux_info_sz = (aux_size * sizeof(char*));
    res += *aux_info_sz;
    for (size_t i = 0; i < aux_size; i++) {
      tmp_arr[i] = (strlen(aux_info[i]) + 1);
      res += tmp_arr[i];
    }
    *aux_sz = tmp_arr;
  } else {
    *aux_info_sz = 0;
    *aux_sz = NULL;
  }

  return res;
}

static oc_sec_ael_event_t *
oc_sec_ael_create_event(uint8_t category, uint8_t priority, oc_clock_time_t timestamp,
                        const char *aeid, const char *message, const char** aux_info, size_t aux_size,
                        size_t event_sz, size_t aeid_sz, size_t message_sz, size_t aux_info_sz, size_t *aux_sz)
{
  // allocate memory
  oc_sec_ael_event_t *res = (oc_sec_ael_event_t *)malloc(event_sz);
  if (!res) {
    OC_ERR("Out of memory!");
    return NULL;
  }

  // copying values
  uint8_t* p = ((uint8_t*)res + sizeof(oc_sec_ael_event_t));

  res->size = event_sz;
  res->category = category;
  res->priority = priority;
  res->timestamp = timestamp;
  if (aeid_sz != 0) {
    res->aeid = (char*)p;
    strncpy(res->aeid, aeid, aeid_sz - 1);
    res->aeid[aeid_sz-1] = '\0';
    p+=aeid_sz;
  } else {
    res->aeid= NULL;
  }
  if (message_sz != 0) {
    res->message = (char*)p;
    strncpy(res->message, message, message_sz - 1);
    res->message[message_sz-1] = '\0';
    p+=message_sz;
  } else {
    res->message = NULL;
  }
  if (aux_info_sz != 0 && aux_sz) {
    res->aux_info = (char**)p;
    p+=aux_info_sz;
    for (size_t i = 0; i < aux_size; i++) {
      res->aux_info[i] = (char*)p;
      strncpy(res->aux_info[i], aux_info[i], aux_sz[i] - 1);
      res->aux_info[i][aux_sz[i]-1] = '\0';
      p+=aux_sz[i];
    }
    res->aux_size = aux_size;
  } else {
    res->aux_info = NULL;
    res->aux_size = 0;
  }
  res->next = NULL;

  return res;
}
#endif /* OC_DYNAMIC_ALLOCATION */

#endif /* OC_SECURITY */
