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

/* Add support for software update */
//#define OC_SOFTWARE_UPDATE
/* Add support for the oic.if.create interface in Collections */
//#define OC_COLLECTIONS_IF_CREATE
/* Add support for the maintenance resource */
//#define OC_MNT

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
