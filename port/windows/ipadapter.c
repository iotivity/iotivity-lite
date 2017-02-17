/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <malloc.h>
#include <windows.h>
#include <winsock2.h>
#include <iptypes.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>

#undef NO_ERROR

#include "oc_buffer.h"
#include "port/oc_connectivity.h"

#define OCF_PORT_UNSECURED (5683)
#define ALL_OCF_NODES "FF02::158"

static CRITICAL_SECTION cs;
static CONDITION_VARIABLE cv;

condition_wait(int us) {
	SleepConditionVariableCS(&cv, &cs, us/1000);
}

static DWORD event_thread;
static HANDLE mutex;
static SOCKADDR_STORAGE mcast, server, client;

static int server_sock = -1, mcast_sock = -1, terminate;

#ifdef OC_SECURITY
static struct sockaddr_storage secure;
static int secure_sock = -1;
static uint16_t dtls_port = 0;

uint16_t
oc_connectivity_get_dtls_port(void)
{
  return dtls_port;
}
#endif /* OC_SECURITY */

void signal_event_loop_intern() 
{
	WaitForSingleObject(&cs, 0);
	WakeConditionVariable(&cv);
	ReleaseMutex(&cs);
}

void
oc_network_event_handler_mutex_init(void)
{
	mutex = CreateMutex(NULL, FALSE, NULL);
	if (mutex == NULL) {
		LOG("ERROR initializing network event handler mutex\n");
	}
	InitializeCriticalSection(&cs);
	InitializeConditionVariable(&cv);
}

void
oc_network_event_handler_mutex_lock(void)
{
	WaitForSingleObject(mutex, 0);
}

void
oc_network_event_handler_mutex_unlock(void)
{
	ReleaseMutex(mutex);
}

#define HEXWIDTH  (1 << 4)
static int32_t hexdump(const void* const buf, const size_t len) {
	FILE* const fp = stderr;
	const uint32_t indent = 5;
	const unsigned char*  p = (unsigned char*)buf;
	size_t  i, j;

	if (NULL == buf || 0 == len || NULL == fp)
		return -1;

	for (j = 0; j < indent; ++j)
		fputc(' ', fp);
	for (i = 0; i < len; ++i) {
		fprintf(fp, "%02X", p[i]);
		if (0 == ((i + 1) & (HEXWIDTH - 1)) && i + 1 < len) {
			fputc('\n', fp);
			for (j = 0; j < indent; ++j)
				fputc(' ', fp);
		}
		else
			fputc(' ', fp);
	}
	fputc('\n', fp);

	fflush(fp);

	return 0;
}

static void *
network_event_thread(void *data)
{
	(void)data;
	struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
	socklen_t len = sizeof(client);

	fd_set rfds = { 0 }, setfds = { 0 };

	FD_ZERO(&rfds);
	FD_SET(server_sock, &rfds);
	FD_SET(mcast_sock, &rfds);

#ifdef OC_SECURITY
	FD_SET(secure_sock, &rfds);
#endif

	int i, n;

	while (!terminate) {
		setfds = rfds;
		n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

		for (i = 0; i < n; i++) {
			oc_message_t *message = oc_allocate_message();

			if (!message) {
				break;
			}

			if (FD_ISSET(server_sock, &setfds)) {
				message->length = recvfrom(server_sock, message->data, OC_PDU_SIZE, 0, (struct sockaddr *)&client, &len);
				message->endpoint.flags = IPV6;
				FD_CLR(server_sock, &setfds);
				goto common;
			}

			if (FD_ISSET(mcast_sock, &setfds)) {
				message->length = recvfrom(mcast_sock, message->data, OC_PDU_SIZE, 0, (struct sockaddr *)&client, &len);
				message->endpoint.flags = IPV6;
				FD_CLR(mcast_sock, &setfds);
				goto common;
			}

#ifdef OC_SECURITY
			if (FD_ISSET(secure_sock, &setfds)) {
				message->length = recvfrom(secure_sock, message->data, OC_PDU_SIZE, 0, (struct sockaddr *)&client, &len);
				message->endpoint.flags = IPV6 | SECURED;
			}
#endif /* OC_SECURITY */

		common:
			memcpy(message->endpoint.addr.ipv6.address, c->sin6_addr.s6_addr, sizeof(c->sin6_addr.s6_addr));
			message->endpoint.addr.ipv6.scope = c->sin6_scope_id;
			message->endpoint.addr.ipv6.port = ntohs(c->sin6_port);

			PRINT("Incoming message (len=%d) from ", message->length);
			PRINTipaddr(message->endpoint);
			PRINT("\n");
			hexdump(message->data, message->length);


			oc_network_event(message);
		}
	}

	CloseHandle(mutex);
	return NULL;
}

void
oc_send_buffer(oc_message_t *message)
{
	PRINT("Outgoing message to ");
	PRINTipaddr(message->endpoint);
	PRINT("\n");

	struct sockaddr_storage receiver;
	struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
	memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address, sizeof(r->sin6_addr.s6_addr));
	r->sin6_family = AF_INET6;
	r->sin6_port = htons(message->endpoint.addr.ipv6.port);
	r->sin6_scope_id = message->endpoint.addr.ipv6.scope;
	int send_sock = -1;

#ifdef OC_SECURITY
	if (message->endpoint.flags & SECURED)
		send_sock = secure_sock;
	else
#endif /* OC_SECURITY */
		send_sock = server_sock;

	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(send_sock, &wfds);

	int n = select(FD_SETSIZE, NULL, &wfds, NULL, NULL);
	if (n > 0) {
		int bytes_sent = 0, x;
		while (bytes_sent < (int)message->length) {
			x = sendto(send_sock, message->data + bytes_sent,
				message->length - bytes_sent, 0, (struct sockaddr *)&receiver,
				sizeof(receiver));
			bytes_sent += x;
		}
		PRINT("Sent %d bytes\n", bytes_sent);
	}
}

#define MAX_IP_SIZE  INET6_ADDRSTRLEN
#define MAX_LEN_NIC_LONG_NAME 50

typedef struct {
	struct sockaddr addr;
	char longname[MAX_LEN_NIC_LONG_NAME];	/**< network interface long name */
	char dotname[MAX_IP_SIZE];
} network_interface_t;

#define MAX_NICS 10
static network_interface_t g_nics[MAX_NICS];

static int get_network_interfaces(network_interface_t nic_array[], int nic_size) {
	IP_ADAPTER_ADDRESSES *info = NULL;
	ULONG info_size = 0;

	int nCount = 0;

	if (nic_array == NULL || nic_size == 0)
		return 0;

	memset(nic_array, 0, nic_size * sizeof(*nic_array));

	// Gets the number of bytes needed to store all currently active adapter-info.
	GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &info_size);

	if (info_size == 0 || (info = calloc(1, info_size)) == NULL)
		goto cleanup;

	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, info, &info_size) != NO_ERROR)
		goto cleanup;

	IP_ADAPTER_ADDRESSES *adapter = NULL;
	for (adapter = info; nCount < nic_size && adapter != NULL; adapter = adapter->Next) {
		IP_ADAPTER_UNICAST_ADDRESS* address = NULL;

		if (IfOperStatusUp != adapter->OperStatus)
			continue;

		for (address = adapter->FirstUnicastAddress; nCount < nic_size && address; address = address->Next) {
			if (address->Address.lpSockaddr->sa_family == AF_INET) {
				memcpy(&nic_array[nCount].addr, address->Address.lpSockaddr, sizeof(struct sockaddr_in));
				getnameinfo(&nic_array[nCount].addr, sizeof(struct sockaddr_in), nic_array[nCount].dotname, sizeof(nic_array[nCount].dotname), NULL, 0, NI_NUMERICHOST);
				if (adapter->FriendlyName) {
					WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, wcslen(adapter->FriendlyName), nic_array[nCount].longname, sizeof(nic_array[nCount].longname), NULL, NULL);
				}
			} else if (address->Address.lpSockaddr->sa_family == AF_INET6) {
				memcpy(&nic_array[nCount].addr, address->Address.lpSockaddr, sizeof(struct sockaddr_in6));
				getnameinfo(&nic_array[nCount].addr, sizeof(struct sockaddr_in6), nic_array[nCount].dotname, sizeof(nic_array[nCount].dotname), NULL, 0, NI_NUMERICHOST);
				if (adapter->FriendlyName) {
					WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, wcslen(adapter->FriendlyName), nic_array[nCount].longname, sizeof(nic_array[nCount].longname), NULL, NULL);
				}
			}
			else {
				continue; // only AF_INET and AF_INET6
			}
			nCount++;
		}
	}

cleanup:
	free(info);

	return nCount;
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
	int cnt = get_network_interfaces(g_nics, MAX_NICS);

	int i;
	for (i = 0; i < cnt; i++) {
		if (g_nics[i].addr.sa_family == AF_INET6) {
			// currently only IPv6
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&g_nics[i].addr;
			if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
				int mif = addr->sin6_scope_id;
				if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&mif, sizeof(mif)) == -1) {
					LOG("ERROR setting socket option for default IPV6_MULTICAST_IF: %d\n", errno);
				}
				oc_send_buffer(message);
			}
		}
	}
}
#endif /* OC_CLIENT */

int
oc_connectivity_init(void)
{
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2, 2), &wsadata);

	memset(&mcast, 0, sizeof(struct sockaddr_storage));
	memset(&server, 0, sizeof(struct sockaddr_storage));

	struct sockaddr_in6 *m = (struct sockaddr_in6 *)&mcast;
	m->sin6_family = AF_INET6;
	m->sin6_port = htons(OCF_PORT_UNSECURED);
	m->sin6_addr = in6addr_any;

	struct sockaddr_in6 *l = (struct sockaddr_in6 *)&server;
	l->sin6_family = AF_INET6;
	l->sin6_addr = in6addr_any;
	l->sin6_port = 0;

#ifdef OC_SECURITY
	memset(&secure, 0, sizeof(struct sockaddr_storage));
	struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&secure;
	sm->sin6_family = AF_INET6;
	sm->sin6_port = 0;
	sm->sin6_addr = in6addr_any;
#endif /* OC_SECURITY */

	server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (server_sock < 0 || mcast_sock < 0) {
		LOG("ERROR creating server sockets\n");
		return -1;
	}

#ifdef OC_SECURITY
	secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (secure_sock < 0) {
		LOG("ERROR creating secure socket\n");
		return -1;
	}
#endif /* OC_SECURITY */

	if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
		LOG("ERROR binding server socket %d\n", errno);
		return -1;
	}

	struct ipv6_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	if (inet_pton(AF_INET6, ALL_OCF_NODES, (void *)&mreq.ipv6mr_multiaddr) != 1) {
		LOG("ERROR setting mcast addr\n");
		return -1;
	}
	mreq.ipv6mr_interface = 0;
	if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == -1) {
		LOG("ERROR setting mcast join option %d\n", errno);
		return -1;
	}
	int reuse = 1;
	if (setsockopt(mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		LOG("ERROR setting reuseaddr option %d\n", errno);
		return -1;
	}
	if (bind(mcast_sock, (struct sockaddr *)&mcast, sizeof(mcast)) == -1) {
		LOG("ERROR binding mcast socket %d\n", errno);
		return -1;
	}

#ifdef OC_SECURITY
	if (setsockopt(secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		LOG("ERROR setting reuseaddr option %d\n", errno);
		return -1;
	}
	if (bind(secure_sock, (struct sockaddr *)&secure, sizeof(secure)) == -1) {
		LOG("ERROR binding smcast socket %d\n", errno);
		return -1;
	}

	socklen_t socklen = sizeof(secure);
	if (getsockname(secure_sock, (struct sockaddr *)&secure, &socklen) == -1) {
		LOG("ERROR obtaining secure socket information %d\n", errno);
		return -1;
	}

	dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */

	if (CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, NULL, 0, &event_thread) == NULL) {
		LOG("ERROR creating network polling thread\n");
		return -1;
	}
	LOG("Successfully initialized connectivity\n");
	return 0;
}

void
oc_connectivity_shutdown(void)
{
	terminate = 1;

	closesocket(server_sock);
	closesocket(mcast_sock);

#ifdef OC_SECURITY
	closesocket(secure_sock);
#endif /* OC_SECURITY */

	//TerminateThread(event_thread,0);
	WSACleanup();
	LOG("oc_connectivity_shutdown\n");
}


