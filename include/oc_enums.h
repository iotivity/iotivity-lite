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
 * @param oc_defined value to check if the conversion is successfull
 * @return oc_locn_t the location value
 */
oc_locn_t oc_str_to_enum_locn(oc_string_t locn_str, bool *oc_defined);

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

/**
 * @brief payload content formats
 *
 * https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#rd-parameters
 *
 */
typedef enum {
  TEXT_PLAIN = 0,                    ///< text/plain
  TEXT_XML = 1,                      ///< text/xml
  TEXT_CSV = 2,                      ///< text/csv
  TEXT_HTML = 3,                     ///< text/html
  IMAGE_GIF = 21,                    ///< image/gif - not used
  IMAGE_JPEG = 22,                   ///< image/jpeg - not used
  IMAGE_PNG = 23,                    ///< image/png - not used
  IMAGE_TIFF = 24,                   ///< image/tiff - not used
  AUDIO_RAW = 25,                    ///< audio/raw - not used
  VIDEO_RAW = 26,                    ///< video/raw - not used
  APPLICATION_LINK_FORMAT = 40,      ///< application/link-format
  APPLICATION_XML = 41,              ///< application/xml
  APPLICATION_OCTET_STREAM = 42,     ///< application/octet-stream
  APPLICATION_RDF_XML = 43,          ///< application - not used
  APPLICATION_SOAP_XML = 44,         ///< application/soap - not used
  APPLICATION_ATOM_XML = 45,         ///< application - not used
  APPLICATION_XMPP_XML = 46,         ///< application - not used
  APPLICATION_EXI = 47,              ///< application/exi
  APPLICATION_FASTINFOSET = 48,      ///< application
  APPLICATION_SOAP_FASTINFOSET = 49, ///< application
  APPLICATION_JSON = 50,             ///< application/json
  APPLICATION_X_OBIX_BINARY = 51,    ///< application - not used
  APPLICATION_CBOR = 60,             ///< application/cbor
  APPLICATION_SENML_JSON = 110,      ///< application/senml+json
  APPLICATION_SENSML_JSON = 111,     ///< application/sensml+json
  APPLICATION_SENML_CBOR = 112,      ///< application/senml+cbor
  APPLICATION_SENSML_CBOR = 113,     ///< application/sensml+cbor
  APPLICATION_SENML_EXI = 114,       ///< application/senml-exi
  APPLICATION_SENSML_EXI = 115,      ///< application/sensml-exi
  APPLICATION_PKCS7_SGK =
    280, ///< application/pkcs7-mime; smime-type=server-generated-key
  APPLICATION_PKCS7_CO = 281, ///< application/pkcs7-mime; smime-type=certs-only
  APPLICATION_PKCS7_CMC_REQUEST =
    282, ///< application/pkcs7-mime; smime-type=CMC-Request
  APPLICATION_PKCS7_CMC_RESPONSE =
    283,                   ///< application/pkcs7-mime; smime-type=CMC-Response
  APPLICATION_PKCS8 = 284, ///< application/pkcs8
  APPLICATION_CRATTRS = 285,              ///< application/csrattrs
  APPLICATION_PKCS10 = 286,               ///< application/pkcs10
  APPLICATION_PKIX_CERT = 287,            ///< application/pkix-cert
  APPLICATION_TD_JSON = 432,              ///< application/td+json
  APPLICATION_VND_OCF_CBOR = 10000,       ///< application/vnd.ocf+cbor
  APPLICATION_OSCORE = 10001,             ///< application/oscore
  APPLICATION_VND_OMA_LWM2M_TLV = 11542,  ///< application/vnd.oma.lwm2m+tlv
  APPLICATION_VND_OMA_LWM2M_JSON = 11543, ///< application/vnd.oma.lwm2m+json
  APPLICATION_VND_OMA_LWM2M_CBOR = 11544, ///< application/vnd.oma.lwm2m+cbor

  APPLICATION_NOT_DEFINED = 0xFFFF, ///< not defined
} oc_content_format_t;

#ifdef __cplusplus
}
#endif

#endif /* OC_ENUMS_H */
