#ifndef __WIZ5500_H__
#define __WIZ5500_H__


#ifdef __cplusplus
extern "C" {
#endif
// remove warning: ISO C++11 requires at least one argument for the "..." in a variadic macro
//#pragma GCC system_header
#include <Arduino.h>

#define SnMR_CLOSE  ((const uint8_t )0x00)
#define SnMR_TCP    ((const uint8_t )0x01)
#define SnMR_UDP    ((const uint8_t )0x02)
#define SnMR_IPRAW  ((const uint8_t )0x03)
#define SnMR_MACRAW ((const uint8_t )0x04)
#define SnMR_PPPOE  ((const uint8_t )0x05)
#define SnMR_ND     ((const uint8_t )0x20)
#define SnMR_MULTI  ((const uint8_t )0x80)

#define SnSR_CLOSED      ((const uint8_t )0x00)
#define SnSR_INIT        ((const uint8_t )0x13)
#define SnSR_LISTEN      ((const uint8_t )0x14)
#define SnSR_SYNSENT     ((const uint8_t )0x15)
#define SnSR_SYNRECV     ((const uint8_t )0x16)
#define SnSR_ESTABLISHED ((const uint8_t )0x17)
#define SnSR_FIN_WAIT    ((const uint8_t )0x18)
#define SnSR_CLOSING     ((const uint8_t )0x1A)
#define SnSR_TIME_WAIT   ((const uint8_t )0x1B)
#define SnSR_CLOSE_WAIT  ((const uint8_t )0x1C)
#define SnSR_LAST_ACK    ((const uint8_t )0x1D)
#define SnSR_UDP         ((const uint8_t )0x22)
#define SnSR_IPRAW       ((const uint8_t )0x32)
#define SnSR_MACRAW      ((const uint8_t )0x42)
#define SnSR_PPPOE       ((const uint8_t )0x5F)




struct wiz5500;
typedef struct wiz5500 wiz5500_t;

extern wiz5500_t *wiznet5500;// = NULL;

wiz5500_t *wiz5500_create();
void wiz5500_destroy(wiz5500_t *wiznet_holder);

// Maybe use a boolean to optimize RAM usage
void wiz5500_getIPAddress(wiz5500_t *wiznet_holder, uint8_t *addr);

uint8_t wiz5500_readSnSR(wiz5500_t *wiznet_holder, uint8_t *socketID) ;

uint16_t wiz5500_writeSnDIPR(wiz5500_t *wiznet_holder, uint8_t *socketID, uint8_t *_mcast_ipaddr);

uint16_t wiz5500_writeSnDHAR(wiz5500_t *wiznet_holder, uint8_t *socketID, uint8_t *_buff);

void wiz5500_writeSnDPORT(wiz5500_t *wiznet_holder, uint8_t *socketID, uint16_t *mport);

uint16_t wiz5500_getRXReceivedSize(wiz5500_t *wiznet_holder, uint8_t *socketID);

#ifdef __cplusplus
}
#endif

#endif /* __WIZ5500_H__ */
