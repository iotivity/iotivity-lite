#ifndef CONFIG_H
#define CONFIG_H

/* Time resolution */
#include <stdint.h>
typedef uint64_t oc_clock_time_t;
#define strncasecmp _strnicmp
/* Sets one clock tick to 1 ms */
#define OC_CLOCK_CONF_TICKS_PER_SECOND (1000)

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (300)

#if !defined(OC_DYNAMIC_ALLOCATION)
#error "Set preprocessor definition OC_DYNAMIC_ALLOCATION in your build"
#endif /* OC_DYNAMIC_ALLOCATION */
#if !defined(OC_COLLECTIONS)
#define OC_COLLECTIONS
#endif /* OC_COLLECTIONS */
#if !defined(OC_BLOCK_WISE)
#define OC_BLOCK_WISE
#endif /* OC_BLOCK_WISE */

#endif /* CONFIG_H */
