#ifndef CONFIG_H
#define CONFIG_H

/* Server-side parameters */
/* Maximum number of server resources */
#define MAX_APP_RESOURCES (2)

/* Client-side parameters */

/* Common paramters */
/* Maximum number of concurrent requests */
#define MAX_NUM_CONCURRENT_REQUESTS (2)

#define EST_NUM_REP_OBJECTS (100)

/* Time resolution */
#define OC_CLOCK_CONF_SECOND (10)

/* Connectivity */
#define POLL_NETWORK 1

/* Maximum size of request/response PDUs */
#define MAX_PAYLOAD_SIZE (512)

/* Number of send/receive buffers */
#define NUM_TX_RX_BUFFERS (MAX_NUM_CONCURRENT_REQUESTS * 2)

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
