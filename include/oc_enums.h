/*
// Copyright (c) 2019 Intel Corporation
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
#ifndef OC_ENUMS_H
#define OC_ENUMS_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum oc_enum_t {
  OC_ENUM_ABORTED = 1,
  OC_ENUM_ACTIVE,
  OC_ENUM_AIRDRY,
  OC_ENUM_ARMEDAWAY,
  OC_ENUM_ARMEDINSTANT,
  OC_ENUM_ARMEDMAXIMUM,
  OC_ENUM_ARMEDNIGHTSTAY,
  OC_ENUM_ARMEDSTAY,
  OC_ENUM_AROMA,
  OC_ENUM_AI,
  OC_ENUM_AUTO,
  OC_ENUM_BOILING,
  OC_ENUM_BREWING,
  OC_ENUM_CANCELLED,
  OC_ENUM_CIRCULATING,
  OC_ENUM_CLEANING,
  OC_ENUM_CLOTHES,
  OC_ENUM_COMPLETED,
  OC_ENUM_COOL,
  OC_ENUM_DELICATE,
  OC_ENUM_DISABLED,
  OC_ENUM_DOWN,
  OC_ENUM_DUAL,
  OC_ENUM_DRY,
  OC_ENUM_ENABLED,
  OC_ENUM_EXTENDED,
  OC_ENUM_FAN,
  OC_ENUM_FAST,
  OC_ENUM_FILTERMATERIAL,
  OC_ENUM_FOCUSED,
  OC_ENUM_GRINDING,
  OC_ENUM_HEATING,
  OC_ENUM_HEAVY,
  OC_ENUM_IDLE,
  OC_ENUM_INK,
  OC_ENUM_INKBLACK,
  OC_ENUM_INKCYAN,
  OC_ENUM_INKMAGENTA,
  OC_ENUM_INKTRICOLOUR,
  OC_ENUM_INKYELLOW,
  OC_ENUM_KEEPWARM,
  OC_ENUM_NORMAL,
  OC_ENUM_NOTSUPPORTED,
  OC_ENUM_PAUSE,
  OC_ENUM_PENDING,
  OC_ENUM_PENDINGHELD,
  OC_ENUM_PERMAPRESS,
  OC_ENUM_PREWASH,
  OC_ENUM_PROCESSING,
  OC_ENUM_PURE,
  OC_ENUM_QUICK,
  OC_ENUM_QUIET,
  OC_ENUM_RINSE,
  OC_ENUM_SECTORED,
  OC_ENUM_SILENT,
  OC_ENUM_SLEEP,
  OC_ENUM_SMART,
  OC_ENUM_SPOT,
  OC_ENUM_STEAM,
  OC_ENUM_STOPPED,
  OC_ENUM_SPIN,
  OC_ENUM_TESTING,
  OC_ENUM_TONER,
  OC_ENUM_TONERBLACK,
  OC_ENUM_TONERCYAN,
  OC_ENUM_TONERMAGENTA,
  OC_ENUM_TONERYELLOW,
  OC_ENUM_WARM,
  OC_ENUM_WASH,
  OC_ENUM_WET,
  OC_ENUM_WIND,
  OC_ENUM_WRINKLEPREVENT,
  OC_ENUM_ZIGZAG
} oc_enum_t;

typedef enum oc_pos_description_t {
  OC_POS_UNKNOWN = 1,
  OC_POS_TOP,
  OC_POS_BOTTOM,
  OC_POS_LEFT,
  OC_POS_RIGHT,
  OC_POS_CENTRE,
  OC_POS_TOPLEFT,
  OC_POS_BOTTOMLEFT,
  OC_POS_CENTRELEFT,
  OC_POS_CENTRERIGHT,
  OC_POS_BOTTOMRIGHT,
  OC_POS_TOPRIGHT,
  OC_POS_TOPCENTRE,
  OC_POS_BOTTOMCENTRE
} oc_pos_description_t;

const char *oc_enum_to_str(oc_enum_t val);

const char *oc_enum_pos_desc_to_str(oc_pos_description_t pos);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENUMS_H */
