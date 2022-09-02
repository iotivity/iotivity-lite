/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#include "ipcontext.h"

void
ip_context_rfds_fd_set(ip_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_SET(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

void
ip_context_rfds_fd_clr(ip_context_t *dev, int sockfd)
{
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_CLR(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

fd_set
ip_context_rfds_fd_copy(ip_context_t *dev)
{
  fd_set setfds;
  FD_ZERO(&setfds);
  pthread_mutex_lock(&dev->rfds_mutex);
  memcpy(&setfds, &dev->rfds, sizeof(dev->rfds));
  pthread_mutex_unlock(&dev->rfds_mutex);
  return setfds;
}
