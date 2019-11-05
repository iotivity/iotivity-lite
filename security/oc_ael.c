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

#define OC_SEC_AEL_SIZE 1000

static const char* ael_unit_string[] = {"Event", "Byte", "Kbyte"};

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_ael_t *ael = NULL;
#else /* OC_DYNAMIC_ALLOCATION */
#error "Not implemented"
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_DYNAMIC_ALLOCATION
static void oc_sec_ael_create_event(oc_sec_ael_event_t *event,
                                    const char *dev_type, const oc_uuid_t *di,
                                    uint8_t category, uint8_t priority, uint32_t timestamp,
                                    const char *message, const char** aux_info, size_t aux_size);
static void oc_sec_ael_free_event(oc_sec_ael_event_t *event);

static char* oc_sec_ael_duplicate_string(const char* src);
#endif /* OC_DYNAMIC_ALLOCATION */

static size_t oc_sec_ael_max_space(void);
static size_t oc_sec_ael_used_space(void);

void
oc_sec_ael_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  oc_sec_ael_free();
  if (!(ael = (oc_sec_ael_t *)malloc(sizeof(oc_sec_ael_t)))) {
    oc_abort("oc_ael: Out of memory");
  }
  if (!(ael->events = (oc_sec_ael_event_t *)calloc(OC_SEC_AEL_SIZE,
                                                   sizeof(oc_sec_ael_event_t)))) {
    oc_abort("oc_ael: Out of memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_sec_ael_default();
}
void
oc_sec_ael_free(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (ael) {
    if (ael->events) {
      for (int i = 0; i < OC_SEC_AEL_SIZE; i++) {
        oc_sec_ael_free_event(&ael->events[i]);
      }
    }
    free(ael->events);
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
  ael->event_max = OC_SEC_AEL_SIZE;
  //ael->events
  ael->head_idx = ael->tail_idx = 0;
  ael->unit = OC_SEC_AEL_UNIT_DEFAULT;
}

void
oc_sec_ael_add(const char *dev_type, const oc_uuid_t *di,
               uint8_t category, uint8_t priority, uint32_t timestamp,
               const char *message, const char **aux, size_t aux_len)
{
  if ((ael->logcategory & category) && (ael->loglevel >= priority)) {
    oc_sec_ael_create_event(&ael->events[ael->head_idx], dev_type, di,
            category, priority, timestamp,
            message, aux, aux_len);
    if (++ael->head_idx >= OC_SEC_AEL_SIZE) {
      ael->head_idx = 0;
    }
    if (ael->head_idx == ael->tail_idx) {
      if (++ael->tail_idx >= OC_SEC_AEL_SIZE) {
        ael->tail_idx = 0;
      }
    }
  }
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
    if (oc_sec_ael_decode(request->request_payload)) {
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
    /* events */
    oc_rep_set_array(root, events);
    for (uint32_t idx = ael->tail_idx; idx != ael->head_idx;) {
      oc_rep_object_array_start_item(events);
      /* devicetype */
      oc_rep_set_text_string(events, devicetype, ael->events[idx].dev_type);
      /* di */
      oc_uuid_to_str(&ael->events[idx].di, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(events, di, uuid);
      /* category */
      oc_rep_set_int(events, category, ael->events[idx].category);
      /* priority */
      oc_rep_set_int(events, priority, ael->events[idx].priority);
      /* timestamp */
      oc_rep_set_int(events, timestamp, ael->events[idx].timestamp);
      /* message */
      oc_rep_set_text_string(events, message, ael->events[idx].message);
      /* auxiliaryinfo */
      oc_string_array_t aux;
      oc_new_string_array(&aux, ael->events[idx].aux_size);
      for (size_t i = 0; i < ael->events[idx].aux_size; i++) {
        oc_string_array_add_item(aux, ael->events[idx].aux_info[i]);
      }
      oc_rep_set_string_array(events, auxiliaryinfo, aux);
      oc_free_string_array(&aux);
      oc_rep_object_array_end_item(events);
      if (++idx >= OC_SEC_AEL_SIZE) {
        idx = 0;
      }
    }
    oc_rep_close_array(root, events);
    /* unit */
    oc_rep_set_text_string(root, unit, ael_unit_string[ael->unit]);
  }
  oc_rep_end_root_object();
  return true;
}
bool
oc_sec_ael_decode(oc_rep_t *rep)
{
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
static void oc_sec_ael_create_event(oc_sec_ael_event_t *event,
                                    const char *dev_type, const oc_uuid_t *di,
                                    uint8_t category, uint8_t priority, uint32_t timestamp,
                                    const char *message, const char** aux_info, size_t aux_size)
{
  oc_sec_ael_free_event(event);

  if (dev_type) {
    if (!(event->dev_type = oc_sec_ael_duplicate_string(dev_type))) {
      oc_abort("oc_ael: Out of memory");
    }
  }
  if (di) {
    memcpy(&event->di, di, sizeof(oc_uuid_t));
  } else {
    memset(&event->di, 0, sizeof(oc_uuid_t));
  }
  event->category = category;
  event->priority = priority;
  event->timestamp = timestamp;
  if (message) {
    if (!(event->message = oc_sec_ael_duplicate_string(message))) {
      oc_abort("oc_ael: Out of memory");
    }
  }
  if (aux_info && aux_size != 0) {
    if (!(event->aux_info = (char **)calloc(aux_size, sizeof(char*)))) {
      oc_abort("oc_ael: Out of memory");
    }
    for (size_t i = 0; i < aux_size; i++) {
      if (!(event->aux_info[i] = oc_sec_ael_duplicate_string(aux_info[i]))) {
        oc_abort("oc_ael: Out of memory");
      }
    }
    event->aux_size = aux_size;
  } else {
    event->aux_size = 0;
  }
}
static void
oc_sec_ael_free_event(oc_sec_ael_event_t *event)
{
  if (event->dev_type) {
    free(event->dev_type);
    event->dev_type = NULL;
  }
  if (event->message) {
    free(event->message);
    event->message = NULL;
  }
  if (event->aux_info) {
    for (size_t i = 0; i < event->aux_size; i++) {
      free(event->aux_info[i]);
    }
    free(event->aux_info);
    event->aux_info = NULL;
  }
}

static char*
oc_sec_ael_duplicate_string(const char* src)
{
  char* res = NULL;
  size_t len = strlen(src);
  if ((res = (char *)malloc(len + 1))) {
    strncpy(res, src, len);
    res[len] = '\0';
  }
  return res;
}
#endif /* OC_DYNAMIC_ALLOCATION */

static size_t
oc_sec_ael_max_space(void)
{
  return OC_SEC_AEL_SIZE;
}
static size_t
oc_sec_ael_used_space(void)
{
  size_t res = 0;
  if (ael->head_idx > ael->tail_idx) {
    res = ael->head_idx - ael->tail_idx;
  } else if (ael->head_idx < ael->tail_idx) {
    res = OC_SEC_AEL_SIZE - 1;
  }
  return res;
}

#endif /* OC_SECURITY */
