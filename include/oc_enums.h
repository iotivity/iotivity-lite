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

/**
 * @file
 */

#ifndef OC_ENUMS_H
#define OC_ENUMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "oc_helpers.h"
#include "util/oc_compiler.h"

/**
 * @brief generic enum values for resources that convey string enums
 *
 */
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

/**
 * @brief enum of position tags
 *
 */
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

/**
 * @brief enum of location tags
 *
 */
typedef enum oc_locn_t {
  OCF_LOCN_UNKNOWN = 1,
  OCF_LOCN_ATTIC,
  OCF_LOCN_BALCONY,
  OCF_LOCN_BALLROOM,
  OCF_LOCN_BATHROOM,
  OCF_LOCN_BEDROOM,
  OCF_LOCN_BORDER,
  OCF_LOCN_BOXROOM,
  OCF_LOCN_CELLAR,
  OCF_LOCN_CLOAKROOM,
  OCF_LOCN_CONSERVATORY,
  OCF_LOCN_CORRIDOR,
  OCF_LOCN_DECK,
  OCF_LOCN_DEN,
  OCF_LOCN_DININGROOM,
  OCF_LOCN_DRAWINGROOM,
  OCF_LOCN_DRIVEWAY,
  OCF_LOCN_DUNGEON,
  OCF_LOCN_ENSUITE,
  OCF_LOCN_ENTRANCE,
  OCF_LOCN_FAMILYROOM,
  OCF_LOCN_GARAGE,
  OCF_LOCN_GARDEN,
  OCF_LOCN_GUESTROOM,
  OCF_LOCN_HALL,
  OCF_LOCN_INDOOR,
  OCF_LOCN_KITCHEN,
  OCF_LOCN_LARDER,
  OCF_LOCN_LAWN,
  OCF_LOCN_LIBRARY,
  OCF_LOCN_LIVINGROOM,
  OCF_LOCN_LOUNGE,
  OCF_LOCN_MANCAVE,
  OCF_LOCN_MASTERBEDROOM,
  OCF_LOCN_MUSICROOM,
  OCF_LOCN_OFFICE,
  OCF_LOCN_OUTDOOR,
  OCF_LOCN_PANTRY,
  OCF_LOCN_PARKINGLOT,
  OCF_LOCN_PARLOUR,
  OCF_LOCN_PATIO,
  OCF_LOCN_RECEIPTIONROOM,
  OCF_LOCN_RESTROOM,
  OCF_LOCN_ROOF,
  OCF_LOCN_ROOFTERRACE,
  OCF_LOCN_SAUNA,
  OCF_LOCN_SCULLERY,
  OCF_LOCN_SHED,
  OCF_LOCN_SITTINGROOM,
  OCF_LOCN_SNUG,
  OCF_LOCN_SPA,
  OCF_LOCN_STUDIO,
  OCF_LOCN_SUITE,
  OCF_LOCN_SWIMMINGPOOL,
  OCF_LOCN_TERRACE,
  OCF_LOCN_TOILET,
  OCF_LOCN_UTILITYROOM,
  OCF_LOCN_VEGETABLEPLOT,
  OCF_LOCN_WARD,
  OCF_LOCN_YARD
} oc_locn_t;

/**
 * @brief convert enum value to string
 *
 * @param val the enum value
 * @return const char* the string
 */
const char *oc_enum_to_str(oc_enum_t val);

/**
 * @brief convert the position description enum value to string
 *
 * @param pos the enum value of the position description
 * @return const char* the string
 */
const char *oc_enum_pos_desc_to_str(oc_pos_description_t pos);

/**
 * @brief convert the location enum value to string
 *
 * @param locn the location enum value
 * @return const char* the string
 */
const char *oc_enum_locn_to_str(oc_locn_t locn);

/**
 * @brief convert a string to the location enum value
 *
 * @param locn_str the input string
 * @param oc_defined value to check if the conversion is successfull (cannot be
 * NULL)
 * @return oc_locn_t the location value
 */
oc_locn_t oc_str_to_enum_locn(oc_string_t locn_str, bool *oc_defined)
  OC_NONNULL(2);

/**
 * @brief ACE permissions, as bitmap
 *
 */
typedef enum {
  OC_PERM_NONE = 0,          ///< no permissions
  OC_PERM_CREATE = (1 << 0), ///< Create permission is granted
  OC_PERM_RETRIEVE =
    (1 << 1),                ///< Read, observe, discover permission is granted
  OC_PERM_UPDATE = (1 << 2), ///< Write, update permission is granted
  OC_PERM_DELETE = (1 << 3), ///< Delete permission is granted
  OC_PERM_NOTIFY = (1 << 4)  ///< Notify permission is granted
} oc_ace_permissions_t;

#ifdef __cplusplus
}
#endif

#endif /* OC_ENUMS_H */
