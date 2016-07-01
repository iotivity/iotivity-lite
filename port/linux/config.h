#ifndef CONFIG_H
#define CONFIG_H

/* Time resolution */
#include <stdint.h>
typedef uint64_t oc_clock_time_t;
#define OC_CLOCK_CONF_SECOND (1000)

#define OC_BYTES_POOL_SIZE (2048)
#define OC_INTS_POOL_SIZE (16)
#define OC_DOUBLES_POOL_SIZE (16)

/* Server-side parameters */
/* Maximum number of server resources */
#define MAX_APP_RESOURCES (2)

/* Client-side parameters */

/* Common paramters */
/* Maximum number of concurrent requests */
#define MAX_NUM_CONCURRENT_REQUESTS (3)

#define EST_NUM_REP_OBJECTS (100)

/* Maximum size of request/response PDUs */
#define MAX_PAYLOAD_SIZE (612)

/* Number of send/receive buffers */
#define NUM_TX_RX_BUFFERS (MAX_NUM_CONCURRENT_REQUESTS + 1)

/* Number of devices on the OCF platform */
#define MAX_NUM_DEVICES (1)

/* Platform payload size */
#define MAX_PLATFORM_PAYLOAD_SIZE (256)

/* Device payload size */
#define MAX_DEVICE_PAYLOAD_SIZE (256)

/* Security layer */
#define MAX_NUM_SUBJECTS (2)

#define MAX_DTLS_PEERS (1)

#define DTLS_INACTIVITY_TIMEOUT (10)

#endif /* CONFIG_H */
