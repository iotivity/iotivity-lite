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

#ifndef HAWKBIT_HTTP_H
#define HAWKBIT_HTTP_H

#include "esp_http_client.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAWKBIT_HTTP_CODE_OK 200
#define HAWKBIT_HTTP_MAX_OUTPUT_BUFFER 2048

/**
 * @brief Perform GET request and store response to buffer.
 *
 * @param[in] url request url
 * @param[out] buffer output buffer (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return -1 on error
 * @return >=0 on success, status code
 */
int hawkbit_http_perform_get(const char *url, char *buffer, size_t buffer_size);

/**
 * @brief Perform POST request and store response to buffer.
 *
 * @param[in] url request url
 * @param[in] body request body
 * @param[out] buffer output buffer (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return -1 on error
 * @return >=0 on success, status code
 */
int hawkbit_http_perform_post(const char *url, const char *body, char *buffer,
                              size_t buffer_size);

/**
 * @brief Perform PUT request and store response to buffer.
 *
 * @param[in] url request url
 * @param[in] body request body
 * @param[out] buffer output buffer (cannot be NULL)
 * @param[in] buffer_size size of the output buffer
 * @return -1 on error
 * @return >=0 on success, status code
 */
int hawkbit_http_perform_put(const char *url, const char *body, char *buffer,
                             size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_HTTP_H */
