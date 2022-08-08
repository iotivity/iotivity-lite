/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <tcpcontext.h>
#include <pthread.h>
#include <sys/select.h>
#include <string.h>

#ifdef OC_TCP

void
tcp_context_cfds_fd_set(tcp_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->cfds_mutex);
  FD_SET(sockfd, &dev->cfds);
  pthread_mutex_unlock(&dev->cfds_mutex);
}

void
tcp_context_cfds_fd_clr(tcp_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->cfds_mutex);
  FD_CLR(sockfd, &dev->cfds);
  pthread_mutex_unlock(&dev->cfds_mutex);
}

fd_set
tcp_context_cfds_fd_copy(tcp_context_t *dev)
{
  fd_set setfds;
  FD_ZERO(&setfds);
  pthread_mutex_lock(&dev->cfds_mutex);
  memcpy(&setfds, &dev->cfds, sizeof(dev->cfds));
  pthread_mutex_unlock(&dev->cfds_mutex);
  return setfds;
}

#endif /* OC_TCP */
