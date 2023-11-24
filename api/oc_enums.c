/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#include "api/oc_enums_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_enums.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>

static const char *oc_pos_desc[] = {
  "unknown",     "top",      "bottom",     "left",         "right",
  "centre",      "topleft",  "bottomleft", "centreleft",   "centreright",
  "bottomright", "topright", "topcentre",  "bottomcentre",
};
// longtest value = bottomcentre = 13 chars with null terminator
#define OC_POS_DESC_MAX_LEN (13)

static const char *oc_enums[] = {
  "aborted",
  "active",
  "airDry",
  "armedAway",
  "armedInstant",
  "armedMaximum",
  "armedNightStay",
  "armedStay",
  "aroma",
  "artificalintelligence",
  "auto",
  "boiling",
  "brewing",
  "cancelled",
  "circulating",
  "cleaning",
  "clothes",
  "completed",
  "cool",
  "delicate",
  "disabled",
  "down",
  "dual",
  "dry",
  "enabled",
  "extended",
  "fan",
  "fast",
  "filterMaterial",
  "focused",
  "grinding",
  "heating",
  "heavy",
  "idle",
  "ink",
  "inkBlack",
  "inkCyan",
  "inkMagenta",
  "inkTricolour",
  "inkYellow",
  "keepwarm",
  "normal",
  "notsupported",
  "pause",
  "pending",
  "pendingHeld",
  "permapress",
  "preWash",
  "processing",
  "pure",
  "quick",
  "quiet",
  "rinse",
  "sectored",
  "silent",
  "sleep",
  "smart",
  "spot",
  "steam",
  "stopped",
  "spin",
  "testing",
  "toner",
  "tonerBlack",
  "tonerCyan",
  "tonerMagenta",
  "tonerYellow",
  "warm",
  "wash",
  "wet",
  "wind",
  "wrinklePrevent",
  "zigzag",
};
// longtest value = artificalintelligence = 22 chars with null terminator
#define OC_ENUMS_MAX_LEN (22)

static const char *oc_locns[] = {
  "unknown",       "attic",        "balcony",
  "ballroom",      "bathroom",     "bedroom",
  "border",        "boxroom",      "cellar",
  "cloakroom",     "conservatory", "corridor",
  "deck",          "den",          "diningroom",
  "drawingroom",   "driveway",     "dungeon",
  "ensuite",       "entrance",     "familyroom",
  "garage",        "garden",       "guestroom",
  "hall",          "indoor",       "kitchen",
  "larder",        "lawn",         "library",
  "livingroom",    "lounge",       "mancave",
  "masterbedroom", "musicroom",    "office",
  "outdoor",       "pantry",       "parkinglot",
  "parlour",       "patio",        "receiptionroom",
  "restroom",      "roof",         "roofterrace",
  "sauna",         "scullery",     "shed",
  "sittingroom",   "snug",         "spa",
  "studio",        "suite",        "swimmingpool",
  "terrace",       "toilet",       "utilityroom",
  "vegetableplot", "ward",         "yard",
};
// longtest value = receiptionroom = 15 chars
#define OC_LOCNS_MAX_LEN (15)

static bool
enum_is_valid_array_index(int index, size_t array_size)
{
  return index >= 0 && (size_t)index < array_size;
}

oc_string_view_t
oc_enum_to_string_view(oc_enum_t val)
{
  int index = val - 1;
  if (enum_is_valid_array_index(index, OC_ARRAY_SIZE(oc_enums))) {
    const char *str = oc_enums[index];
    size_t len = oc_strnlen(str, OC_ENUMS_MAX_LEN);
    assert(len < OC_ENUMS_MAX_LEN);
    return oc_string_view(str, len);
  }
  return OC_STRING_VIEW_NULL;
}

const char *
oc_enum_to_str(oc_enum_t val)
{
  return oc_enum_to_string_view(val).data;
}

bool
oc_enum_from_str(const char *enum_str, size_t enum_strlen, oc_enum_t *val)
{
  for (size_t i = 0; i < OC_ARRAY_SIZE(oc_enums); i++) {
    const char *str = oc_enums[i];
    size_t len = oc_strnlen(str, OC_ENUMS_MAX_LEN);
    if (len == enum_strlen && memcmp(str, enum_str, len) == 0) {
      *val = (oc_enum_t)i + 1;
      return true;
    }
  }
  return false;
}

oc_string_view_t
oc_enum_pos_desc_to_string_view(oc_pos_description_t pos)
{
  int index = pos - 1;
  if (enum_is_valid_array_index(index, OC_ARRAY_SIZE(oc_pos_desc))) {
    const char *str = oc_pos_desc[index];
    size_t len = oc_strnlen(str, OC_POS_DESC_MAX_LEN);
    assert(len < OC_POS_DESC_MAX_LEN);
    return oc_string_view(str, len);
  }
  return OC_STRING_VIEW_NULL;
}

const char *
oc_enum_pos_desc_to_str(oc_pos_description_t pos)
{
  return oc_enum_pos_desc_to_string_view(pos).data;
}

bool
oc_enum_pos_desc_from_str(const char *pos_str, size_t pos_strlen,
                          oc_pos_description_t *pos)
{
  for (size_t i = 0; i < OC_ARRAY_SIZE(oc_pos_desc); i++) {
    const char *str = oc_pos_desc[i];
    size_t len = oc_strnlen(str, OC_POS_DESC_MAX_LEN);
    if (len == pos_strlen && memcmp(str, pos_str, len) == 0) {
      *pos = (oc_pos_description_t)i + 1;
      return true;
    }
  }
  return false;
}

oc_string_view_t
oc_enum_locn_to_string_view(oc_locn_t locn)
{
  int index = locn - 1;
  if (enum_is_valid_array_index(index, OC_ARRAY_SIZE(oc_locns))) {
    const char *str = oc_locns[index];
    size_t len = oc_strnlen(str, OC_LOCNS_MAX_LEN);
    assert(len < OC_LOCNS_MAX_LEN);
    return oc_string_view(str, len);
  }
  return OC_STRING_VIEW_NULL;
}

const char *
oc_enum_locn_to_str(oc_locn_t locn)
{
  return oc_enum_locn_to_string_view(locn).data;
}

bool
oc_enum_locn_from_str(const char *locn_str, size_t locn_strlen, oc_locn_t *locn)
{
  for (size_t i = 0; i < OC_ARRAY_SIZE(oc_locns); i++) {
    const char *str = oc_locns[i];
    size_t len = oc_strnlen(str, OC_LOCNS_MAX_LEN);
    if (len == locn_strlen && memcmp(str, locn_str, len) == 0) {
      *locn = (oc_locn_t)i + 1;
      return true;
    }
  }
  return false;
}

oc_locn_t
oc_str_to_enum_locn(oc_string_t locn_str, bool *oc_defined)
{
  oc_locn_t locn;
  if (oc_enum_locn_from_str(oc_string(locn_str), oc_string_len(locn_str),
                            &locn)) {
    *oc_defined = true;
    return locn;
  }
  return OCF_LOCN_UNKNOWN;
}
