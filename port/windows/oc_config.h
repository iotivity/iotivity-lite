#ifndef OC_CONFIG_H
#define OC_CONFIG_H

/* Time resolution */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t oc_clock_time_t;
#define strncasecmp _strnicmp
/* Sets one clock tick to 1 ms */
#define OC_CLOCK_CONF_TICKS_PER_SECOND (1000)

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (300)

/* IoTivity-lite stack features*/
/* Add support for client APIs */
#define OC_CLIENT
/* Add support for server APIs */
#define OC_SERVER
/* Add support for IPv4 endpoints */
#define OC_IPV4
/* Add support for encryption and access control Without security support the
 * IoT device can not be certified. */
#define OC_SECURITY
/* Add support for public key infrastructure */
#define OC_PKI
/* Alow dynamic allocation of resources on the heap (required for windows
 * build)*/
#define OC_DYNAMIC_ALLOCATION
/* Use oc_set_introspection_data function to set introspection data */
#define OC_IDD_API
/* Platform provides an entropy source good enough for security */
/* used by the mbedtls library oc_config must be included before including
 * mbedtls/endtopy.h. */
#define __OC_RANDOM
/* Add cloud support */
// define OC_CLOUD
/* Add support for software update */
//#define OC_SOFTWARE_UPDATE
/* Add support for the oic.if.create interface in Collections */
//#define OC_COLLECTIONS_IF_CREATE
/* Add support for the maintenance resource */
//#define OC_MNT
/* Enable debug logs if NDEBUG is not defined. */
#if !defined(NDEBUG)
#define OC_DEBUG
#endif
#if !defined(OC_DYNAMIC_ALLOCATION)
#error "Set preprocessor definition OC_DYNAMIC_ALLOCATION in your build"
#endif /* OC_DYNAMIC_ALLOCATION */
#if !defined(OC_COLLECTIONS)
#define OC_COLLECTIONS
#endif /* OC_COLLECTIONS */
#if !defined(OC_BLOCK_WISE)
#define OC_BLOCK_WISE
#endif /* OC_BLOCK_WISE */

#ifdef __cplusplus
}
#endif

#endif /* OC_CONFIG_H */
