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
#include <ctype.h>
#include "oc_config.h"
#include "port/oc_log.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "Wiz5500.h"
#include "ethadapter_utils.h"


OCResult_t arduino_get_free_socket(uint8_t *sockID){

	uint8_t state;
	if(!wiznet5500) {
		wiznet5500 = wiz5500_create();
		if(!wiznet5500)
			return STATUS_FAILED;
	}
	*sockID = 0;
	for (uint8_t i = 1; i < MAX_SOCK_NUM; i++)
	{
		state = wiz5500_readSnSR(wiznet5500, &i) ;
		if (state == SnSR_CLOSED || state == SnSR_FIN_WAIT)
		{
			*sockID = i;
			break;
		}
	}
	if (*sockID == 0)
	{
		OC_ERR("No socket sockID 0");
		return SOCKET_OPERATION_FAILED;
	}
	return STATUS_OK;
}

OCResult_t arduino_init_udp_socket(uint16_t *local_port, uint8_t *socketID){

	if(!socketID) {
		OC_ERR("Socket ID not provided!");
		return SOCKET_OPERATION_FAILED;
	}
	/*Get an availlable socket(closing or closed)*/
	OCResult_t ret = arduino_get_free_socket(socketID);
	if (ret != STATUS_OK)
	{
		OC_ERR("Get sock failed!");
		return ret;
	}
	//Create a datagram socket on which to recv/send.
	if (!socket(*socketID, SnMR_UDP, *local_port, 0))
	{
		OC_ERR("socket create failed!");
		return STATUS_FAILED;
	}
	return STATUS_OK;
}
OCResult_t
arduino_init_mcast_udp_socket(const char *mcast_addr, uint16_t *mcast_port,
									uint16_t *local_port, uint8_t *socketID)
{

	if(!socketID || !mcast_addr) {
		OC_ERR("Socket ID or mcast addr null!");
		return SOCKET_OPERATION_FAILED;
	}
	uint8_t mcast_mac_addr[] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00};
	uint8_t ip_addr[4] = { 0 };
	uint16_t parsed_port = 0;
	if (arduino_parse_IPv4_addr(mcast_addr, ip_addr, sizeof(ip_addr), &parsed_port) != STATUS_OK)
	{
		OC_ERR("mcast ip parse fail!");
		return STATUS_FAILED;
	}
	*socketID = 0;
	OCResult_t ret = arduino_get_free_socket(socketID);
	if (ret != STATUS_OK)
	{
		OC_ERR("Get sock fail!");
		return ret;
	}
	//Calculate Multicast MAC address
	mcast_mac_addr[3] = ip_addr[1] & 0x7F;
	mcast_mac_addr[4] = ip_addr[2];
	mcast_mac_addr[5] = ip_addr[3];
	wiz5500_writeSnDIPR(wiznet5500, socketID, (uint8_t *)ip_addr);
	wiz5500_writeSnDHAR(wiznet5500, socketID, (uint8_t *)mcast_mac_addr);
	wiz5500_writeSnDPORT(wiznet5500, socketID, mcast_port);
	if (!socket(*socketID, SnMR_UDP, *local_port, SnMR_MULTI))
	{
		OC_ERR("sock create fail!");
		return SOCKET_OPERATION_FAILED;
	}
	return STATUS_OK;
}
/// Retrieves the IP address assigned to Arduino Ethernet shield
OCResult_t oc_ard_get_iface_addr(uint8_t *address)
{
	//TODO : Fix this for scenarios when this API is invoked when device is not connected
	if(!wiznet5500) {
		wiznet5500 = wiz5500_create();
		if(!wiznet5500)
			return STATUS_FAILED;
	}
	wiz5500_getIPAddress(wiznet5500, (uint8_t *)address);
	return STATUS_OK;
}

OCResult_t arduino_parse_IPv4_addr(const char *ip_addrStr, uint8_t *ip_addr,
                                      uint8_t ip_addrLen, uint16_t *port)
{
	if (!ip_addr || !isdigit(ip_addrStr[0]) || !port)
	{
		OC_ERR("invalid param!");
		return STATUS_INVALID_PARAM;
	}
	uint8_t index = 0;
	uint8_t dotCount = 0;
	ip_addr[index] = 0;
	*port = 0;
	while (*ip_addrStr)
	{
		if (isdigit(*ip_addrStr))
		{
			if(index >= ip_addrLen)
			{
				OC_ERR(("invalid mcast addr!"));
				return STATUS_INVALID_PARAM;
			}
			ip_addr[index] *= 10; //20+2=22 --> 220+7
			ip_addr[index] += *ip_addrStr - '0';
		}
		else if (*ip_addrStr == '.')
		{
			index++;
			dotCount++;
			ip_addr[index] = 0;
		}
		else
		{
			break;
		}
		ip_addrStr++;
	}
  // incase user supply ip:port fetch the port number as below
	if (*ip_addrStr == ':')
	{
		ip_addrStr++;
		while (*ip_addrStr)
		{
			if (isdigit(*ip_addrStr))
			{
				*port *= 10;
				*port += *ip_addrStr - '0';
			}
			else
			{
				break;
			}
			ip_addrStr++;
		}
	}
	if (dotCount == 3)
	{
		return STATUS_OK;
	}
	return STATUS_FAILED;
}
/**
 * Flag to check if multicast server is started
 */
bool arduino_mcast_serv_started = false;

uint8_t start_udp_server(uint16_t *local_port)
{
	if(!local_port) {
	  OC_DBG("server port null!");
		return STATUS_FAILED;
	}
	uint8_t raw_ip_addr[4];
	if(!wiznet5500) {
		wiznet5500 = wiz5500_create();
		if(!wiznet5500)
			return STATUS_FAILED;
	}
	wiz5500_getIPAddress(wiznet5500, raw_ip_addr);
	uint8_t serverFD = 1; // try this socket
	if (arduino_init_udp_socket(local_port, &serverFD) != STATUS_OK)
	{
		return STATUS_FAILED;
	}
	return serverFD;
}
uint8_t start_udp_mcast_server(const char *mcast_addr,
                              uint16_t *mcast_port,
                              uint16_t *local_port)
{
	if (arduino_mcast_serv_started == true)
	{
	  return SERVER_STARTED_ALREADY;
	}
	uint8_t serverFD = 1;
	if (arduino_init_mcast_udp_socket(mcast_addr, mcast_port, local_port, &serverFD)!= STATUS_OK)
		return STATUS_FAILED;
  return serverFD;
}

/*Utility method to monitor ready socket*/
static uint16_t socket_ready(uint8_t *socketID){

  if(!wiznet5500) {
    wiznet5500 = wiz5500_create();
    if(!wiznet5500)
      return STATUS_FAILED;
  }
  uint16_t recvLen = wiz5500_getRXReceivedSize(wiznet5500, socketID);
  if(recvLen == 0) {
    return 0;
  } else {
    return recvLen;
  }
}

uint8_t select(uint8_t nsds, sdset_t *setsds){
  uint8_t n = 0;
  for(int i = 1; i < nsds; i++){
      uint16_t ret = socket_ready(&setsds->sds[i]);
      // Good: data has been receive on this socket: clear it and increase socket ready count
      if(ret != 0) {
		SD_CLR(setsds->sds[i], setsds);
        n++;
		setsds->rcv_size = ret;
      }
  }
  return n;
}

int16_t recv_msg(uint8_t *socketID, uint8_t *sender_addr, uint16_t *sender_port,
                 uint8_t *data, uint16_t packets_size)
{
  packets_size = packets_size > OC_MAX_APP_DATA_SIZE ? OC_MAX_APP_DATA_SIZE : packets_size;
  return recvfrom(*socketID, (uint8_t *)data, packets_size + 1, sender_addr, sender_port);
}

OCResult_t ard_send_data(uint8_t socketID, uint8_t *dest_addr,
                          uint16_t *dest_port, uint8_t *data,
                          const uint16_t len)
{
	uint8_t _socketID = socketID; // default client socket
	uint32_t ret = sendto(_socketID, data, len, dest_addr, *dest_port);
	if (ret <= 0){
		OC_ERR("SendData failed: %u", ret);
	}
	return STATUS_OK;
}


