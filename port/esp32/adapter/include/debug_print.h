/*
   This code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H

#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "port/oc_connectivity.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  print current all macro information
 *
 * for easily debug, print all macro configuration
 *
 * @param[in]  no param input
 *
 */
void print_macro_info();

/**
 * @brief  print detailed struct message content
 *
 * for easily debug, print more parameter in struct message
 *
 * @param[in]  message: the struct oc_message_t to print
 *
 */
void print_message_info(const oc_message_t *message);

/**
 * @brief  print the fatal error information and cycle it
 *
 * usage: same as printf
 * */
#define print_error(fmt, args...)                                              \
  do {                                                                         \
    printf("[error]:");                                                        \
    printf(fmt, ##args);                                                       \
    printf(",heap size:%" PRIu32 "%s", esp_get_free_heap_size(), "\r\n");      \
    vTaskDelay(2000 / portTICK_PERIOD_MS);                                     \
  } while (1)

#ifdef APP_DEBUG

#define APP_LOG(level, ...)                                                    \
  do {                                                                         \
    printf("%s: %s <%s:%d>: ", level, __FILE__, __FUNCTION__, __LINE__);       \
    printf(__VA_ARGS__);                                                       \
    printf("\n");                                                              \
  } while (0)
#define APP_DBG(...) APP_LOG("DEBUG", __VA_ARGS__)
#define APP_WRN(...) APP_LOG("WARNING", __VA_ARGS__)
#define APP_ERR(...) APP_LOG("ERROR", __VA_ARGS__)

#else

#define APP_LOG(...)
#define APP_DBG(...)
#define APP_WRN(...)
#define APP_ERR(...)

#endif // APP_DEBUG

#ifdef __cplusplus
}
#endif

#endif // DEBUG_PRINT_H
