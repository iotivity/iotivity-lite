/*
 // Copyright (c) 2016 Intel Corporation
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

#ifndef OC_CONSTANTS_H
#define OC_CONSTANTS_H

#define OC_RSRVD_OC "oic"
#define OC_RSRVD_PAYLOAD "payload"

#define OC_RSRVD_HREF "href"
#define OC_RSRVD_PROPERTY "prop"
#define OC_RSRVD_CONTENT_TYPE "ct"
#define OC_RSRVD_RESOURCE_TYPE "rt"
#define OC_RSRVD_INTERFACE "if"
#define OC_RSRVD_REPRESENTATION "rep"

#define OC_RSRVD_SERVER_INSTANCE_ID "sid"
#define OC_RSRVD_POLICY "p"
#define OC_RSRVD_BITMAP "bm"
#define OC_RSRVD_SECURE "sec"
#define OC_RSRVD_HOSTING_PORT "port"

#define OC_RSRVD_DEVICE_ID "di"
#define UUID_SIZE (16)
#define OC_RSRVD_DEVICE_NAME "n"
#define OC_RSRVD_SPEC_VERSION "icv"
#define OC_RSRVD_DATA_MODEL_VERSION "dmv"

#define OC_RSRVD_PLATFORM_ID "pi"
#define OC_RSRVD_MFG_NAME "mnmn"
#define OC_RSRVD_MFG_URL "mnml"
#define OC_RSRVD_MODEL_NUM "mnmo"
#define OC_RSRVD_MFG_DATE "mndt"
#define OC_RSRVD_PLATFORM_VERSION "mnpv"
#define OC_RSRVD_OS_VERSION "mnos"
#define OC_RSRVD_HARDWARE_VERSION "mnhw"
#define OC_RSRVD_FIRMWARE_VERSION "mnfv"
#define OC_RSRVD_SUPPORT_URL "mnsl"
#define OC_RSRVD_SYSTEM_TIME "st"

#define OC_RSRVD_TTL "ttl"
#define OC_RSRVD_NONCE "non"
#define OC_RSRVD_TRIGGER "trg"

#define OC_RSRVD_TRIGGER_CREATE "create"
#define OC_RSRVD_TRIGGER_CHANGE "change"
#define OC_RSRVD_TRIGGER_DELETE "delete"

#define OC_RSRVD_LINKS "links"

#define OC_RSRVD_RESOURCE_TYPE_PRESENCE "oic.wk.ad"

/* OCF standard resource interfaces */
#define OC_NUM_STD_INTERFACES (7)
#define OC_RSRVD_IF_BASELINE "oic.if.baseline"
#define OC_BASELINE_IF_LEN (15)
#define OC_RSRVD_IF_LL "oic.if.ll"
#define OC_LL_IF_LEN (9)
#define OC_RSRVD_IF_B "oic.if.b"
#define OC_B_IF_LEN (8)
#define OC_RSRVD_IF_R "oic.if.r"
#define OC_R_IF_LEN (8)
#define OC_RSRVD_IF_RW "oic.if.rw"
#define OC_RW_IF_LEN (9)
#define OC_RSRVD_IF_A "oic.if.a"
#define OC_A_IF_LEN (8)
#define OC_RSRVD_IF_S "oic.if.s"
#define OC_S_IF_LEN (8)

/* OCF Core resource URIs */
#define OC_RSRVD_WELL_KNOWN_URI "/oic/res"
#define OC_MULTICAST_DISCOVERY_URI "/oic/res"
#define OC_RSRVD_DEVICE_URI "/oic/d"
#define OC_RSRVD_PLATFORM_URI "/oic/p"
#define OC_RSRVD_RESOURCE_TYPES_URI "oic/res/types/d"
#define OC_RSRVD_PRESENCE_URI "oic/ad"

#define OC_DEFAULT_PRESENCE_TTL_SECONDS (60)
#define OC_DEFAULT_PRESENCE_TTL_SECONDS (60)
#define OC_MAX_PRESENCE_TTL_SECONDS (60 * 60 * 24)

#define OC_QUERY_SEPARATOR "&;"

#endif /* OC_CONSTANTS_H */
