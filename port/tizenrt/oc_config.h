/*
 // Copyright (c) 2018 Samsung Electronics France SAS
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

#ifndef OC_CONFIG_H
#define OC_CONFIG_H

/* Time resolution */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t oc_clock_time_t;
#define OC_CLOCK_CONF_TICKS_PER_SECOND 1

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (600)

/* Maximum wait time for select function */
#define SELECT_TIMEOUT_SEC (1)

/* Add support for dns lookup to the endpoint */
#define OC_DNS_LOOKUP

/* If we selected support for dynamic memory allocation */
#ifdef OC_DYNAMIC_ALLOCATION
#define OC_COLLECTIONS
#define OC_BLOCK_WISE

#else /* OC_DYNAMIC_ALLOCATION */
/* List of constraints below for a build that does not employ dynamic
   memory allocation
*/
/* Memory pool sizes */
#define OC_BYTES_POOL_SIZE (1800)
#define OC_INTS_POOL_SIZE (100)
#define OC_DOUBLES_POOL_SIZE (4)

/* Server-side parameters */
/* Maximum number of server resources */
#define OC_MAX_APP_RESOURCES (4)

#define OC_MAX_NUM_COLLECTIONS (1)

/* Common paramters */
/* Prescriptive lower layers MTU size, enable block-wise transfers */
#define OC_BLOCK_WISE_SET_MTU (700)

/* Maximum size of request/response payloads */
#define OC_MAX_APP_DATA_SIZE (2048)

/* Maximum number of concurrent requests */
#define OC_MAX_NUM_CONCURRENT_REQUESTS (3)

/* Maximum number of nodes in a payload tree structure */
#define OC_MAX_NUM_REP_OBJECTS (150)

/* Number of devices on the OCF platform */
#define OC_MAX_NUM_DEVICES (2)

/* Maximum number of endpoints */
#define OC_MAX_NUM_ENDPOINTS (20)

/* Security layer */
/* Maximum number of authorized clients */
#define OC_MAX_NUM_SUBJECTS (2)

/* Maximum number of concurrent DTLS sessions */
#define OC_MAX_DTLS_PEERS (1)

/* Maximum number of peer for TCP channel */
#define OC_MAX_TCP_PEERS (2)

/* Maximum number of callbacks for connection of session */
#define OC_MAX_SESSION_EVENT_CBS (2)

#endif /* !OC_DYNAMIC_ALLOCATION */

/* library features that require persistent storage */
#ifdef OC_SECURITY
#define OC_STORAGE
#endif
#ifdef OC_IDD_API
#define OC_STORAGE
#endif
#ifdef OC_CLOUD
#define OC_STORAGE
#endif
#ifdef OC_SOFTWARE_UPDATE
#define OC_STORAGE
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OC_CONFIG_H */
