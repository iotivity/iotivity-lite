#ifndef OC_CONFIG_H
#define OC_CONFIG_H

/* Time resolution */
#include <stdint.h>
#ifdef __GNUC__
#include <string.h> // redefine strncasecmp for MinGW and Cygwin
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** time.h is available on platform */
#define OC_HAVE_TIME_H

typedef uint64_t oc_clock_time_t;
#define strncasecmp _strnicmp
/* Sets one clock tick to 1 ms */
#define OC_CLOCK_CONF_TICKS_PER_SECOND (1000)

/* jitter added to response to some multicast requests */
#define OC_MULTICAST_RESPONSE_JITTER_MS (2000)

/* Time-to-live value of outgoing multicast packets */
#define OC_IPV4_MULTICAST_TTL (1)

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (300)

/* Add support for passing network up/down events to the app */
#define OC_NETWORK_MONITOR
/* Add support for passing TCP/TLS/DTLS session connection events to the app */
#define OC_SESSION_EVENTS

/* Add support for dns lookup to the endpoint */
#define OC_DNS_LOOKUP
// #define OC_DNS_LOOKUP_IPV6

/* Add request history for deduplicate UDP/DTLS messages */
#define OC_REQUEST_HISTORY

// The maximum size of a response to an OBSERVE request, in bytes.
// #define OC_MAX_OBSERVE_SIZE 512

/* Add support observable for oic/res */
// #define OC_DISCOVERY_RESOURCE_OBSERVABLE

/* Enable reallocation during encoding the representation to cbor */
// #define OC_REP_ENCODING_REALLOC

/* Maximum size of uri for a collection resource */
// #define OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE (64)

#if !defined(OC_DYNAMIC_ALLOCATION)
#error "Set preprocessor definition OC_DYNAMIC_ALLOCATION in your build"
#endif /* OC_DYNAMIC_ALLOCATION */
#if !defined(OC_COLLECTIONS)
#define OC_COLLECTIONS
#endif /* OC_COLLECTIONS */
#if !defined(OC_BLOCK_WISE)
#define OC_BLOCK_WISE
#endif /* OC_BLOCK_WISE */

/* Maximum number of callbacks for Network interface event monitoring */
#define OC_MAX_NETWORK_INTERFACE_CBS (2)

/* Maximum number of callbacks for connection of session */
#define OC_MAX_SESSION_EVENT_CBS (2)

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

/* /.well-known/core discovery on ALL COAP nodes */
// #define OC_WKCORE

/* Wipe device name during reset, when oic/con is enabled */
/* Default: Wipe name */
#define OC_WIPE_NAME (1)

#ifdef __cplusplus
}
#endif

#endif /* OC_CONFIG_H */
