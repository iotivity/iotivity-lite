/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 * @file plgd_wot.h
 *
 * @brief Web of Things
 *
 * @author Jozef Kralik
 */
#ifndef PLGD_WOT_H
#define PLGD_WOT_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_WOT

#define PLGD_DEV_WOT_THING_DESCRIPTION_RT "wot.thing"

#include "oc_ri.h"

OC_API
void plgd_wot_resource_set_thing_description(
  oc_resource_t *resource, plgd_wot_extend_thing_description_cb_t cb,
  void *data);

typedef enum plgd_wot_property_type_e {
  PLGD_DEV_WOT_PROPERTY_TYPE_BOOLEAN,
  PLGD_DEV_WOT_PROPERTY_TYPE_INTEGER,
  PLGD_DEV_WOT_PROPERTY_TYPE_NUMBER,
  PLGD_DEV_WOT_PROPERTY_TYPE_STRING,
  PLGD_DEV_WOT_PROPERTY_TYPE_OBJECT,
  PLGD_DEV_WOT_PROPERTY_TYPE_ARRAY,
  PLGD_DEV_WOT_PROPERTY_TYPE_NULL,
} plgd_wot_property_type_t;

OC_API
const char *plgd_wot_property_str(plgd_wot_property_type_t p);

typedef struct plgd_wot_property_s
{
  const char *name;
  plgd_wot_property_type_t type;
  const char *description;
  bool read_only;
  bool write_only;
  bool observable;
  union {
    struct plgd_wot_property_s *properties; // for object
    struct plgd_wot_property_s *items;      // for array
  };
} plgd_wot_property_t;

/**
 * @brief Fill the cbor with the properties of the thing description,
 *
 * @param parent_map parent cbor encoder
 * @param request incoming request to the resource
 * @param properties array of properties
 * @param properties_count number of properties in the array
 */
OC_API
void plgd_wot_resource_set_td_properties_num(
  CborEncoder *parent_map, const oc_request_t *request,
  const plgd_wot_property_t *properties, size_t properties_count);

/**
 * @brief Fill the cbor with the properties of the thing description,
 *
 * @param parent_map parent cbor encoder
 * @param request incoming request to the resource
 * @param properties array of properties, must be terminated with a property
 * with name == NULL.
 */
OC_API
void plgd_wot_resource_set_td_properties(CborEncoder *parent_map,
                                         const oc_request_t *request,
                                         const plgd_wot_property_t *properties);

#endif /* OC_HAS_FEATURE_PLGD_WOT */

#endif /* PLGD_WOT_H */
