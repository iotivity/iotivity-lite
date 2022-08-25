/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef HAWKBIT_H
#define HAWKBIT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate hawkbit helper data structures.
 *
 * @return 0 on success
 * @return -1 on failure
 */
int hawkbit_init(void);

/**
 * @brief Deallocate hawkbit helper data structures.
 */
void hawkbit_free(void);

typedef struct hawkbit_context_t hawkbit_context_t;

/**
 * @brief Create the hawkbit resource
 *
 * @param device device index
 */
void hawkbit_resource_register(size_t device);

/**
 * @brief Validate value of the package url
 *
 * @param purl package url
 * @return 0 on success
 * @return -1 on failure
 */
int validate_purl(const char *purl);

/**
 * @brief Check hawkbit server for updates
 *
 * @param device device index
 * @param url url of the hawkbit server
 * @param version
 * @return 0 on success
 * @return -1 on failure
 */
int check_new_version(size_t device, const char *url, const char *version);

/**
 * @brief Donwload update to second partition, but keep the original boot
 * partition.
 *
 * @param device device index
 * @param url url of the hawkbit server
 * @return 0 on success
 * @return -1 on failure
 */
int download_update(size_t device, const char *url);

/**
 * @brief Verify the second partition, if it contains a valid update then switch
 * to this partition and reboot the device. If it doesn't contain a valid update
 * then try to execute a full update.
 *
 * @param device device index
 * @param url url of the hawkbit server
 * @return 0 on success
 * @return -1 on failure
 */
int perform_upgrade(size_t device, const char *url);

#ifdef __cplusplus
}
#endif

#endif
