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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef PORT_OC_FCNTL_INTERNAL_H
#define PORT_OC_FCNTL_INTERNAL_H

#include <stdbool.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32

/**
 * @brief Set socket descriptor to blocking mode.
 *
 * @param fd file descriptor
 * @return true on success
 * @return false on failure
 */
bool oc_fcntl_set_blocking(SOCKET sock);

/**
 * @brief Set socket descriptor to non-blocking mode.
 *
 * @param fd file descriptor
 * @return true on success
 * @return false on failure
 */
bool oc_fcntl_set_nonblocking(SOCKET sock);

#else /* !_WIN32 */

/**
 * @brief Add or remove file descriptor flags.
 *
 * Functions gets the current file descriptor flags, removes the to_remove
 * flags, then adds the to_add flags and updates the file descriptor flags with
 * this new value.
 *
 * @param fd file descriptor
 * @param to_add flags to be added
 * @param to_remove flags to be removed
 * @return >=0 on success, the current file descriptor flags
 * @return -1 on failure
 */
int oc_fcntl_set_flags(int fd, unsigned to_add, unsigned to_remove);

/**
 * @brief Set file descriptor to blocking mode.
 *
 * @param fd file descriptor
 * @return true on success
 * @return false on failure
 */
bool oc_fcntl_set_blocking(int fd);

/**
 * @brief Set file descriptor to non-blocking mode.
 *
 * @param fd file descriptor
 * @return true on success
 * @return false on failure
 */
bool oc_fcntl_set_nonblocking(int fd);

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif

#endif /* PORT_OC_FCNTL_INTERNAL_H */
