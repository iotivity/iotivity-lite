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
/**
 * @file
 * This file provides APIs ethernet client/server/network monitor modules.
 */

#ifndef ETH_ADAPTER_UTILS_
#define ETH_ADAPTER_UTILS_

#include <stdint.h>
#include <socket.h>

#ifdef __cplusplus
extern "C"
{
#endif
typedef enum
{
	/** Success status code - START HERE.*/
	STATUS_OK = 0,
	STATUS_FAILED = -1,
	SOCKET_OPERATION_FAILED = -2,
	STATUS_INVALID_PARAM = 1,
	SERVER_STARTED_ALREADY = 2,
} OCResult_t;

typedef struct  sdset_t {
  uint8_t sdsset;
  uint8_t sds[MAX_SOCK_NUM];
  uint8_t ready_sds;
  uint16_t rcv_size;
} sdset_t;

#define SETSIZE (8)
#define SD_ZERO(_setsds) (((sdset_t*)_setsds)->sdsset = 0 )
#define SD_SET(sd,_setsds)                                  \
do {                                                        \
	((sdset_t*)_setsds)->sds[sd] = sd;                      \
	((sdset_t*)_setsds)->sdsset |= (1 << (sd % SETSIZE));	\
} while(0)
#define SD_CLR(sd, _setsds)   (((sdset_t*)_setsds)->sdsset &= ~(1 << (sd % SETSIZE)))
#define SD_ISSET(sd, _setsds) (((sdset_t*)_setsds)->sdsset & (1 << (sd % SETSIZE)))

uint8_t select(uint8_t nsds, sdset_t *setsds);
int16_t recv_msg(uint8_t *socketID, uint8_t *sender_addr,
				uint16_t *sender_port, uint8_t *data, uint16_t packets_size);

uint8_t start_udp_server(uint16_t *local_port);

uint8_t start_udp_mcast_server(const char *mcast_addr, uint16_t *mcast_port, uint16_t *local_port);

/**
 * Get available UDP socket.
 * @param[out]   sockID         Available UDP socket ID.
 * @return  ::OC_STATUS_OK or Appropriate error code.
 */
extern OCResult_t arduino_get_free_socket(uint8_t *sockID);

/**
 * Initialize Unicast UDP socket.
 * @param[in/out]   port        Port to start the unicast server.
 * @param[out]      socketID    Unicast socket ID.
 * @return  ::OC_STATUS_OK or Appropriate error code.
 */
extern OCResult_t arduino_init_udp_socket(uint16_t *local_port, uint8_t *socketID);

/**
 * Initialize Multicast UDP socket.
 * @param[in]   mcastAddress     Port to start the unicast server.
 * @param[in]   mport            Multicast port.
 * @param[in]   lport            Local port on which the server is started.
 * @param[out]  socketID         Multicast socket ID.
 * @return  ::OC_STATUS_OK or Appropriate error code.
 */

extern OCResult_t arduino_init_mcast_udp_socket(const char *mcast_addr, uint16_t *mcast_port,
												     uint16_t *local_port, uint8_t *socketID);
/**
 * To parse the IP address and port from "ipaddress:port".
 * @param[in]   ipAddrStr       IP address to be parsed.
 * @param[out]  ipAddr          Parsed IP address.
 * @param[in]   ipAddr          Buffer length for parsed IP address.
 * @param[out]  port            Parsed Port number.
 * @return ::CA_STATUS_OK or Appropriate error code.
 */
extern OCResult_t arduino_parse_IPv4_addr(const char *ipAddrStr, uint8_t *ipAddr,
                                      uint8_t ipAddrLen, uint16_t *port);
/**
* Get the Interface Info(Allocated IP address)
* @param[in] address  endpoint ipv4 address
*/
OCResult_t oc_ard_get_iface_addr(uint8_t *address);



extern OCResult_t ard_send_data(uint8_t socketID, uint8_t *dest_addr,
								uint16_t *dest_port, uint8_t *data, const uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* OC_ARDUINO_ETHERNET_ADAPTER_UTILS_ */
