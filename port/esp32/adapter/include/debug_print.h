/*
   This code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef _DEBUG_PRINT_H_
#define _DEBUG_PRINT_H_

#include "oc_network_events.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define APP_PRINT(...) printf(__VA_ARGS__)

/**
 * @brief  print current all macro information
 *
 * for easily debug, print all macro configuration
 *
 * @param[in]  no param input
 *
 * @return noreturn
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
 * @return  noreturn
 * */
void print_message_info(oc_message_t *message);

/**
 * @brief  print the data detail information
 *
 * print input data, print from data[0] to data[len-1], addtionally add notes string
 *
 * @param[in]  data: input data pointer to print
 * @param[in]  len: data length
 * @param[in]  note: notes for read easily
 * @param[in]  mode: 0x00, 0x01, 0x10, 0x11 to decide the BINARY_SHOW && BYTES_SHOW
 *
 * @return noreturn
 *
 */
void print_debug(const char *data, const unsigned int len, const char *note, int mode);

/**
 * @brief  print the fatal error information and cycle it
 *
 *  usage: same to printf
 *
 * @return noreturn
 * */
#define print_error(fmt, args...)                                \
  do                                                             \
  {                                                              \
    printf("[error]:");                                          \
    printf(fmt, ##args);                                         \
    printf(",heap size:%d%s", esp_get_free_heap_size(), "\r\n"); \
    vTaskDelay(2000 / portTICK_RATE_MS);                         \
  } while (1)

#if APP_DEBUG

#define APP_LOG(level, ...)                                                 \
  do                                                                        \
  {                                                                         \
    APP_PRINT("%s: %s <%s:%d>: ", level, __FILE__, __FUNCTION__, __LINE__); \
    APP_PRINT(__VA_ARGS__);                                                 \
    printf("\n");                                                           \
  } while (0)
#define APP_DBG(...) APP_LOG("DEBUG", __VA_ARGS__)
#define APP_WRN(...) APP_LOG("WARNING", __VA_ARGS__)
#define APP_ERR(...) APP_LOG("ERROR", __VA_ARGS__)

#else

#define APP_LOG(...)
#define APP_DBG(...)
#define APP_WRN(...)
#define APP_ERR(...)

#endif // endif APP_DEBUG

#endif // endif _DEBUG_PRINT_H_
