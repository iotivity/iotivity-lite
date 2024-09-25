/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ip.h"
#include "port/oc_log_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

ssize_t
oc_ip_send_msg(int sock, struct sockaddr_storage *receiver,
               const oc_message_t *message)
{
  if (sock == -1) {
    OC_ERR("socket is disabled");
    return -1;
  }
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];
  struct iovec iovec[1];
  struct msghdr msg;

  memset(&msg, 0, sizeof(struct msghdr));
  msg.msg_name = (void *)receiver;
  msg.msg_namelen = sizeof(struct sockaddr_storage);

  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;

  if (message->endpoint.flags & IPV6) {
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;

    msg.msg_control = msg_control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

    CLANG_IGNORE_WARNING_START
    CLANG_IGNORE_WARNING("-Wcast-align")
    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    CLANG_IGNORE_WARNING_END
    memset(pktinfo, 0, sizeof(struct in6_pktinfo));

    /* Get the outgoing interface index from message->endpoint */
    pktinfo->ipi6_ifindex = message->endpoint.interface_index;
    /* Set the source address of this message using the address
     * from the endpoint's addr_local attribute.
     */
    memcpy(&pktinfo->ipi6_addr, message->endpoint.addr_local.ipv6.address, 16);
  }
#ifdef OC_IPV4
  else if (message->endpoint.flags & IPV4) {
    struct cmsghdr *cmsg;
    struct in_pktinfo *pktinfo;

    msg.msg_control = msg_control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

    CLANG_IGNORE_WARNING_START
    CLANG_IGNORE_WARNING("-Wcast-align")
    pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
    CLANG_IGNORE_WARNING_END
    memset(pktinfo, 0, sizeof(struct in_pktinfo));

    pktinfo->ipi_ifindex = (int)message->endpoint.interface_index;
    memcpy(&pktinfo->ipi_spec_dst, message->endpoint.addr_local.ipv4.address,
           4);
  }
#else  /* !OC_IPV4 */
  else {
    OC_ERR("invalid endpoint");
    return -1;
  }
#endif /* OC_IPV4 */

  size_t bytes_sent = 0;
  while (bytes_sent < message->length) {
    iovec[0].iov_base = (void *)(message->data + bytes_sent);
    iovec[0].iov_len = message->length - bytes_sent;
    ssize_t ret;
    do {
      ret = sendmsg(sock, &msg, 0);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
      OC_ERR("sendmsg failed (error %d)", (int)errno);
      break;
    }
    // overflow check for coverity scan
    assert(bytes_sent <= SIZE_MAX - (size_t)ret && "Integer overflow detected");
    bytes_sent += ret;
  }
  OC_TRACE("Sent %zu bytes", bytes_sent);
  if (bytes_sent == 0) {
    return -1;
  }
  if (bytes_sent < message->length) {
    OC_WRN("Message truncated(%zu bytes out of %zu sent)", bytes_sent,
           message->length);
  }
  return (ssize_t)bytes_sent;
}

int
oc_ip_recv_msg(int sock, uint8_t *recv_buf, long recv_buf_size,
               oc_endpoint_t *endpoint, bool multicast)
{
  struct sockaddr_storage client;
  memset(&client, 0, sizeof(client));
  struct iovec iovec[1];
  struct msghdr msg;
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];

  iovec[0].iov_base = recv_buf;
  iovec[0].iov_len = (size_t)recv_buf_size;

  msg.msg_name = &client;
  msg.msg_namelen = sizeof(client);

  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;

  msg.msg_control = msg_control;
  msg.msg_controllen = sizeof(msg_control);

  msg.msg_flags = 0;

  ssize_t ret;
  do {
    ret = recvmsg(sock, &msg, 0);
  } while (ret < 0 && errno == EINTR);

  if (ret < 0 || (msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
    OC_ERR("recvmsg failed (error %d)", (int)errno);
    return -1;
  }

  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
      if (msg.msg_namelen != sizeof(struct sockaddr_in6)) {
        OC_ERR("anciliary data contains invalid source address");
        return -1;
      }
      /* Set source address of packet in endpoint structure */
      const struct sockaddr_in6 *c6 = (struct sockaddr_in6 *)&client;
      memcpy(endpoint->addr.ipv6.address, c6->sin6_addr.s6_addr,
             sizeof(c6->sin6_addr.s6_addr));
      endpoint->addr.ipv6.scope = c6->sin6_scope_id;
      endpoint->addr.ipv6.port = ntohs(c6->sin6_port);

      /* Set receiving network interface index */
      CLANG_IGNORE_WARNING_START
      CLANG_IGNORE_WARNING("-Wcast-align")
      const struct in6_pktinfo *pktinfo =
        (const struct in6_pktinfo *)CMSG_DATA(cmsg);
      CLANG_IGNORE_WARNING_END
      endpoint->interface_index = pktinfo->ipi6_ifindex;

      /* For a unicast receiving socket, extract the destination address
       * of the UDP packet into the endpoint's addr_local attribute.
       * This would be used to set the source address of a response that
       * results from this message.
       */
      if (!multicast) {
        memcpy(endpoint->addr_local.ipv6.address, pktinfo->ipi6_addr.s6_addr,
               16);
      } else {
        memset(endpoint->addr_local.ipv6.address, 0, 16);
      }
      break;
    }
#ifdef OC_IPV4
    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
      if (msg.msg_namelen != sizeof(struct sockaddr_in)) {
        OC_ERR("anciliary data contains invalid source address");
        return -1;
      }
      CLANG_IGNORE_WARNING_START
      CLANG_IGNORE_WARNING("-Wcast-align")
      const struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
      CLANG_IGNORE_WARNING_END
      const struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
      memcpy(endpoint->addr.ipv4.address, &c4->sin_addr.s_addr,
             sizeof(c4->sin_addr.s_addr));
      endpoint->addr.ipv4.port = ntohs(c4->sin_port);
      endpoint->interface_index = (unsigned)pktinfo->ipi_ifindex;
      if (!multicast) {
        memcpy(endpoint->addr_local.ipv4.address, &pktinfo->ipi_addr.s_addr, 4);
      } else {
        memset(endpoint->addr_local.ipv4.address, 0, 4);
      }
      break;
    }
#endif /* OC_IPV4 */
  }

  assert(ret <= INT_MAX);
  return (int)ret;
}
