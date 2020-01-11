/******************************************************************
*
* Copyright 2018 iThemba LABS All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

*    http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************/

#ifndef CONFIG_H
#define CONFIG_H

/* Time resolution */
#include <stdint.h>
#include <TimeLib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_MCAST_PORT_UNSECURED (5683)
#define OCF_PORT_UNSECURED (56789)
#define OCF_PORT_SECURED (42536)
/** Multicast IP address.*/
#define OCF_IPv4_MULTICAST      "224.0.1.187"

typedef uint32_t oc_clock_time_t;

#define OC_CLOCK_CONF_TICKS_PER_SECOND (1)
#define MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256 0xFF00

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (5000)


/* If we selected support for dynamic memory allocation */
#ifdef OC_DYNAMIC_ALLOCATION
#define OC_BLOCK_WISE
#define OC_COLLECTIONS // why? i got this error: api/oc_ri.c:1064:10: error: 'resource_is_collection' undeclared (first use in this function)
#else /* OC_DYNAMIC_ALLOCATION */

#define OC_BYTES_POOL_SIZE (2000)
#define OC_INTS_POOL_SIZE (100)
#define OC_DOUBLES_POOL_SIZE (2)

/* Server-side parameters */
/* Maximum number of server resources */
#define OC_MAX_APP_RESOURCES (4)

/* Common paramters */
/* Prescriptive lower layers MTU size, enable block-wise transfers */
#define OC_BLOCK_WISE_SET_MTU (700)

/* Maximum size of request/response payloads */
#ifndef OC_DYNAMIC_ALLOCATION
#define OC_MAX_APP_DATA_SIZE (800)
#endif
/* Maximum number of concurrent requests */
#define OC_MAX_NUM_CONCURRENT_REQUESTS (3)

/* Maximum number of nodes in a payload tree structure */
#define OC_MAX_NUM_REP_OBJECTS (15)

/* Number of devices on the OCF platform */
#define OC_MAX_NUM_DEVICES (1)

/* Maximum number of endpoints */
#define OC_MAX_NUM_ENDPOINTS (4)

/* Security layer */
/* Maximum number of authorized clients */
#define OC_MAX_NUM_SUBJECTS (2)

/* Maximum number of concurrent (D)TLS sessions */
#define OC_MAX_TLS_PEERS (1)


#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef __cplusplus
}
#endif
#endif /* CONFIG_H */
