#ifndef OC_CONFIG_H
#define OC_CONFIG_H

/* Time resolution */
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** time.h is available on platform */
#define OC_HAVE_TIME_H
/** clockid_t is available on platform  */
#define OC_HAVE_CLOCKID_T

typedef uint64_t oc_clock_time_t;
#define OC_CLOCK_CONF_TICKS_PER_SECOND CLOCKS_PER_SEC

/* jitter added to response to some multicast requests */
#define OC_MULTICAST_RESPONSE_JITTER_MS (2000)

// #define OC_SPEC_VER_OIC
/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (600)

/* Maximum wait time for select function */
#define SELECT_TIMEOUT_SEC (1)

/* The current implementation in Android port relies on notifications from a
 * NETLINK socket to retrieve interface change notifications, but this is
 * restricted from ANDROID_API >= 30  */
#if __ANDROID_API__ < 30
/* Add support for passing network up/down events to the app */
#define OC_NETWORK_MONITOR
#endif /* __ANDROID_API__ < 30 */
/* Add support for passing TCP/TLS/DTLS session connection events to the app */
#define OC_SESSION_EVENTS

/* Add support for dns lookup to the endpoint */
#define OC_DNS_LOOKUP
// #define OC_DNS_LOOKUP_IPV6

/* Add request history for deduplicate UDP/DTLS messages */
#define OC_REQUEST_HISTORY

/* Maximum size of uri for a collection resource */
// #define OC_MAX_COLLECTIONS_INSTANCE_URI_SIZE (64)

/* If we selected support for dynamic memory allocation */
#ifdef OC_DYNAMIC_ALLOCATION
#define OC_COLLECTIONS
#define OC_BLOCK_WISE

// The maximum size of a response to an OBSERVE request, in bytes.
// #define OC_MAX_OBSERVE_SIZE 512

/* Add support observable for oic/res */
// #define OC_DISCOVERY_RESOURCE_OBSERVABLE

/* Enable reallocation during encoding the representation to cbor */
// #define OC_REP_ENCODING_REALLOC

/* Maximum number of messages in the network event queue for a device */
#ifndef OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS
#define OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS (32)
#endif /* OC_DEVICE_MAX_NUM_CONCURRENT_REQUESTS */

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

/* Common parameters */
/* Prescriptive lower layers MTU size, enable block-wise transfers */
#define OC_BLOCK_WISE_SET_MTU (700)
#define OC_BLOCK_WISE

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

/* Maximum number of concurrent (D)TLS sessions */
#define OC_MAX_TLS_PEERS (1)

/* Maximum number of peer for TCP channel */
#define OC_MAX_TCP_PEERS (2)

/* Maximum number of interfaces for IP adapter */
/* Warning: Android has often over 10 interfaces. */
#define OC_MAX_IP_INTERFACES (20)

/* Maximum number of callbacks for Network interface event monitoring */
#define OC_MAX_NETWORK_INTERFACE_CBS (2)

/* Maximum number of callbacks for connection of session */
#define OC_MAX_SESSION_EVENT_CBS (2)

/* Maximal number of callbacks for ownership status changes */
#define OC_MAX_DOXM_OWNED_CBS (2)

/* Maximal number of callbacks invoked before a dynamic resource is deleted */
#define OC_MAX_ON_DELETE_RESOURCE_CBS (2)

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

/* Wipe device name during reset, when oic/con is enabled */
/* Default: Wipe name */
#define OC_WIPE_NAME (1)

#ifdef __cplusplus
}
#endif

#endif /* OC_CONFIG_H */
