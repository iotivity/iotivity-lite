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
#include "oc_core_res.h"
#include "oc_store.h"
#include "oc_ael.h"
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#include "port/oc_assert.h"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_DYNAMIC_ALLOCATION
static oc_sec_ael_t s_ael;
#endif /* OC_DYNAMIC_ALLOCATION */

static oc_sec_ael_t *ael = NULL;

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_ael_event_t* oc_sec_ael_create_event(const char *dev_type, const oc_uuid_t *di,
                                                   uint8_t category, uint8_t priority, uint32_t timestamp,
                                                   const char *message, const char** aux_info, size_t aux_size);
static void oc_sec_ael_free_event(oc_sec_ael_event_t *event);
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
  oc_sec_ael_free();
#ifdef OC_DYNAMIC_ALLOCATION
  if (!(ael = (oc_sec_ael_t *)calloc(1, sizeof(oc_sec_ael_t)))) {
    oc_abort("oc_ael: Out of memory");
  }
#else /* OC_DYNAMIC_ALLOCATION */
  ael = &s_ael;
#endif /* OC_DYNAMIC_ALLOCATION */
  ael->events.size = 0;
  ael->events.head = ael->events.tail = NULL;
  oc_sec_ael_default();
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
oc_sec_ael_default(void)
{
  ael->logcategory = OC_SEC_AEL_LOGCATEGORY_DEFAULT;
  ael->loglevel = OC_SEC_AEL_LOGLEVEL_DEFAULT;
  memset(&ael->rowneruuid, 0, sizeof(oc_uuid_t));
  ael->maxsize = OC_SEC_AEL_MAX_SIZE;
  ael->unit = OC_SEC_AEL_UNIT_DEFAULT;
  //ael->events
}

bool
oc_sec_ael_add(const char *dev_type, const oc_uuid_t *di,
               uint8_t category, uint8_t priority, uint32_t timestamp,
               const char *message, const char **aux, size_t aux_len)
{
  if (!(ael->logcategory & category) || (ael->loglevel < priority)) {
    OC_DBG("Event category or priority not matching");
    return false;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  oc_sec_ael_event_t *e = oc_sec_ael_create_event(dev_type, di,
                                                  category, priority, timestamp,
                                                  message, aux, aux_len);
#else /* OC_DYNAMIC_ALLOCATION */
#pragma message ("Not implemented!")
  (void)dev_type;
  (void)di;
  (void)category;
  (void)priority;
  (void)timestamp;
  (void)message;
  (void)aux;
  (void)aux_len;
  oc_sec_ael_event_t *e = NULL;
#endif /* OC_DYNAMIC_ALLOCATION */
  if (!e) {
    OC_ERR("Can't create event!");
    return false;
  }

  ael->events.size += e->size;
  if (!ael->events.head) {
    ael->events.head = ael->events.tail = e;
  } else {
    ael->events.head->next = e;
    ael->events.head = e;
  }

  while (ael->events.size > ael->maxsize && ael->events.tail) {
    oc_sec_ael_event_t *t = ael->events.tail;
    ael->events.size -= t->size;
    ael->events.tail = t->next;
#ifdef OC_DYNAMIC_ALLOCATION
    oc_sec_ael_free_event(t);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
  if (!ael->events.tail) {
      ael->events.head = NULL;
  }

  return true;
}

void
get_ael(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  if (request) {
    switch (iface_mask) {

    case OC_IF_BASELINE:
      if (oc_sec_ael_encode(request->resource->device, false)) {
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
    if (oc_sec_ael_decode(request->request_payload, false)) {
      oc_send_response(request, OC_STATUS_CHANGED);
      oc_sec_dump_ael(request->resource->device);
    } else {
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
    }
  }
}

bool
oc_sec_ael_encode(size_t device, bool to_storage)
{
  char uuid[37];
  oc_rep_start_root_object();
  oc_process_baseline_interface(oc_core_get_resource_by_index(OCF_SEC_AEL, device));
  /* logcategory */
  oc_rep_set_int(root, logcategory, ael->logcategory);
  /* loglevel */
  oc_rep_set_int(root, loglevel, ael->loglevel);
  /* rowneruuid */
  oc_uuid_to_str(&ael->rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  if (!to_storage) {
    /* maxspace */
    oc_rep_set_int(root, maxspace, oc_sec_ael_max_space());
    /* usedspace */
    oc_rep_set_int(root, usedspace, oc_sec_ael_used_space());
    /* unit */
    oc_rep_set_text_string(root, unit, oc_sec_ael_unit_string());
    /* events */
    oc_rep_set_array(root, events);
    for (oc_sec_ael_event_t *e = ael->events.tail; e; e = e->next) {
      oc_rep_object_array_start_item(events);
      /* devicetype */
      if (e->dev_type) {
        oc_rep_set_text_string(events, devicetype, e->dev_type);
      }
      /* di */
      oc_uuid_to_str(&e->di, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(events, di, uuid);
      /* category */
      oc_rep_set_int(events, category, e->category);
      /* priority */
      oc_rep_set_int(events, priority, e->priority);
      /* timestamp */
      oc_rep_set_int(events, timestamp, e->timestamp);
      /* message */
      if (e->message) {
        oc_rep_set_text_string(events, message, e->message);
      }
      /* auxiliaryinfo */
      if (e->aux_info && e->aux_size != 0) {
        oc_string_array_t aux;
        oc_new_string_array(&aux, e->aux_size);
        for (size_t i = 0; i < e->aux_size; i++) {
          oc_string_array_add_item(aux, e->aux_info[i]);
        }
        oc_rep_set_string_array(events, auxiliaryinfo, aux);
        oc_free_string_array(&aux);
      }
      oc_rep_object_array_end_item(events);
    }
    oc_rep_close_array(root, events);
  }
  oc_rep_end_root_object();
  return true;
}
bool
oc_sec_ael_decode(oc_rep_t *rep, bool from_storage)
{
  (void)from_storage;
  for (; rep; rep = rep->next) {
    size_t len = oc_string_len(rep->name);
    switch (rep->type) {
    /* logcategory, loglevel */
    case OC_REP_INT:
      if (len == 11 && memcmp(oc_string(rep->name), "logcategory", 11) == 0) {
        ael->logcategory = (uint8_t)rep->value.integer;
      } else if (len == 8 && memcmp(oc_string(rep->name), "loglevel", 8) == 0) {
        ael->loglevel = (uint8_t)rep->value.integer;
      }
      break;
    /* rowneruuid */
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &ael->rowneruuid);
      }
      break;
    default:
      break;
    }
  }
  return true;
}

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_ael_event_t*
oc_sec_ael_create_event(const char *dev_type, const oc_uuid_t *di,
                        uint8_t category, uint8_t priority, uint32_t timestamp,
                        const char *message, const char** aux_info, size_t aux_size)
{
  size_t dev_type_sz = 0;
  size_t message_sz = 0;
  size_t aux_info_sz = 0;
  static size_t aux_sz[64] = {0};

  // calculate event total size
  size_t size = sizeof(oc_sec_ael_event_t);

  if (dev_type) {
    dev_type_sz = (strlen(dev_type) + 1);
    size += dev_type_sz;
  }
  if (message) {
    message_sz = (strlen(message) + 1);
    size += message_sz;
  }
  if (aux_info && aux_size != 0) {
    aux_size = (aux_size < 64) ? aux_size : 64;
    aux_info_sz = (aux_size * sizeof(char*));
    size += aux_info_sz;
    for (size_t i = 0; i < aux_size; i++) {
      aux_sz[i] = (strlen(aux_info[i]) + 1);
      size += aux_sz[i];
    }
  }

  // allocate memory
  oc_sec_ael_event_t *res = (oc_sec_ael_event_t *)malloc(size);
  if (!res) {
    OC_ERR("Out of memory!");
    return NULL;
  }

  // copying values
  uint8_t* p = ((uint8_t*)res + sizeof(oc_sec_ael_event_t));

  res->size = size;
  if (dev_type_sz != 0) {
    res->dev_type = (char*)p;
    strncpy(res->dev_type, dev_type, dev_type_sz - 1);
    res->dev_type[dev_type_sz-1] = '\0';
    p+=dev_type_sz;
  } else {
    res->dev_type = NULL;
  }
  if (di) {
    memcpy(&res->di, di, sizeof(oc_uuid_t));
  } else {
    memset(&res->di, 0, sizeof(oc_uuid_t));
  }
  res->category = category;
  res->priority = priority;
  res->timestamp = timestamp;
  if (message_sz != 0) {
    res->message = (char*)p;
    strncpy(res->message, message, message_sz - 1);
    res->message[message_sz-1] = '\0';
    p+=message_sz;
  } else {
    res->message = NULL;
  }
  if (aux_info_sz != 0) {
    res->aux_info = (char**)p;
    p+=aux_info_sz;
    for (size_t i = 0; i < aux_size; i++) {
      res->aux_info[i] = (char*)p;
      strncpy(res->aux_info[i], aux_info[i], aux_sz[i] - 1);
      res->aux_info[i][aux_sz[i]-1] = '\0';
      p+=aux_sz[i];
    }
  } else {
    res->aux_info = NULL;
  }
  res->aux_size = aux_size;
  res->next = NULL;

  return res;
}
static void
oc_sec_ael_free_event(oc_sec_ael_event_t *event)
{
  free(event);
}
#endif /* OC_DYNAMIC_ALLOCATION */

#endif /* OC_SECURITY */
