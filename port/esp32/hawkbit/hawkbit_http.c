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

#include "hawkbit_context.h"
#include "hawkbit_http.h"
#include "debug_print.h"
#include "esp_err.h"
#include "esp_tls.h"
#include <stddef.h>

typedef struct
{
  char *data;
  size_t size;
} hawkbit_http_buffer_t;

static esp_err_t
http_event_handler(esp_http_client_event_t *evt)
{
  static int output_len = 0;
  switch (evt->event_id) {
  case HTTP_EVENT_ERROR:
    APP_DBG("HTTP_EVENT_ERROR");
    break;
  case HTTP_EVENT_ON_CONNECTED:
    APP_DBG("HTTP_EVENT_ON_CONNECTED");
    output_len = 0;
    break;
  case HTTP_EVENT_HEADER_SENT:
    APP_DBG("HTTP_EVENT_HEADER_SENT");
    break;
  case HTTP_EVENT_ON_HEADER:
    APP_DBG("HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key,
            evt->header_value);
    break;
  case HTTP_EVENT_ON_DATA: {
    APP_DBG("HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
    if (evt->user_data == NULL) {
      APP_ERR("invalid output buffer");
      return ESP_ERR_NO_MEM;
    }

    hawkbit_http_buffer_t *buffer = (hawkbit_http_buffer_t *)evt->user_data;
    if (output_len + evt->data_len >= buffer->size) {
      APP_ERR("data larger than output buffer");
      return ESP_ERR_NO_MEM;
    }

    if (esp_http_client_is_chunked_response(evt->client)) {
      APP_ERR("chunked data not supported");
      return ESP_ERR_NOT_SUPPORTED;
    }

    // copy the response into the buffer
    memcpy(buffer->data + output_len, evt->data, evt->data_len);
    output_len += evt->data_len;
    buffer->data[output_len] = '\0';
    break;
  }
  case HTTP_EVENT_ON_FINISH:
    APP_DBG("HTTP_EVENT_ON_FINISH");
    output_len = 0;
    break;
  case HTTP_EVENT_DISCONNECTED: {
    APP_DBG("HTTP_EVENT_DISCONNECTED");
    int mbedtls_err = 0;
    esp_err_t err = esp_tls_get_and_clear_last_error(
      (esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
    if (err != 0) {
      APP_ERR("Last esp error code: 0x%x", err);
      APP_ERR("Last mbedtls failure: 0x%x", mbedtls_err);
    }
    output_len = 0;
    break;
  }
  case HTTP_EVENT_REDIRECT:
    APP_DBG("HTTP_EVENT_REDIRECT");
    return ESP_ERR_NOT_SUPPORTED;
  }
  return ESP_OK;
}

static esp_http_client_config_t
hawkbit_get_client_config(const char *url, hawkbit_http_buffer_t *buffer)
{
  esp_http_client_config_t config = {};
  config.url = url;
  config.user_data = buffer;
  config.event_handler = http_event_handler;
  return config;
}

static esp_http_client_handle_t
hawkbit_prepare_client(esp_http_client_config_t config,
                       esp_http_client_method_t method, const char *accept,
                       const char *content_type)
{
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == NULL) {
    APP_ERR("Failed to set init http client");
    return NULL;
  }
  esp_err_t err = esp_http_client_set_method(client, method);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    APP_ERR("Failed to set HTTP method: %s", esp_err_to_name(err));
    return NULL;
  }
  if (accept != NULL) {
    err = esp_http_client_set_header(client, "Accept", accept);
    if (err != ESP_OK) {
      esp_http_client_cleanup(client);
      APP_ERR("Failed to set header \"Accept\": %s", esp_err_to_name(err));
      return NULL;
    }
  }
  if (content_type != NULL) {
    err = esp_http_client_set_header(client, "Content-Type", content_type);
    if (err != ESP_OK) {
      esp_http_client_cleanup(client);
      APP_ERR("Failed to set header \"Content-Type\": %s",
              esp_err_to_name(err));
      return NULL;
    }
  }
  return client;
}

int
hawkbit_http_perform_get(const char *url, char *buffer, size_t buffer_size)
{
  hawkbit_http_buffer_t data = {
    .data = buffer,
    .size = buffer_size,
  };
  esp_http_client_handle_t client =
    hawkbit_prepare_client(hawkbit_get_client_config(url, &data),
                           HTTP_METHOD_GET, "application/hal+json", NULL);
  if (client == NULL) {
    APP_ERR("perform HTTP GET failed: %s", "failed to get http client");
    return -1;
  }
  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    APP_ERR("perform HTTP GET failed: %s", esp_err_to_name(err));
    return -1;
  }
  int code = esp_http_client_get_status_code(client);
  APP_DBG("HTTP GET response code: %d", code);
  esp_http_client_cleanup(client);
  return code;
}

static int
hawkbit_http_perform_update(esp_http_client_method_t method, const char *url,
                            const char *body, char *buffer, size_t buffer_size)
{
  assert(url != NULL);
  if (method != HTTP_METHOD_POST && method != HTTP_METHOD_PUT) {
    APP_ERR("invalid method(%d)", (int)method);
    return -1;
  }
  hawkbit_http_buffer_t data = {
    .data = buffer,
    .size = buffer_size,
  };
  esp_http_client_handle_t client =
    hawkbit_prepare_client(hawkbit_get_client_config(url, &data), method,
                           "application/hal+json", "application/json");
  if (client == NULL) {
    APP_ERR("perform HTTP %s failed: failed to get http client",
            method == HTTP_METHOD_POST ? "POST" : "GET");
    return -1;
  }
  if (body != NULL) {
    esp_err_t err = esp_http_client_set_post_field(client, body, strlen(body));
    if (err != ESP_OK) {
      esp_http_client_cleanup(client);
      APP_ERR("set HTTP %s field failed: %s",
              method == HTTP_METHOD_POST ? "POST" : "GET",
              esp_err_to_name(err));
      return -1;
    }
  }
  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    esp_http_client_cleanup(client);
    APP_ERR("perform HTTP %s failed: %s",
            method == HTTP_METHOD_POST ? "POST" : "GET", esp_err_to_name(err));
    return -1;
  }
  int code = esp_http_client_get_status_code(client);
  APP_DBG("HTTP %s response code: %d",
          method == HTTP_METHOD_POST ? "POST" : "GET", code);
  esp_http_client_cleanup(client);
  return code;
}

int
hawkbit_http_perform_post(const char *url, const char *body, char *buffer,
                          size_t buffer_size)
{
  return hawkbit_http_perform_update(HTTP_METHOD_POST, url, body, buffer,
                                     buffer_size);
}

int
hawkbit_http_perform_put(const char *url, const char *body, char *buffer,
                         size_t buffer_size)
{
  return hawkbit_http_perform_update(HTTP_METHOD_PUT, url, body, buffer,
                                     buffer_size);
}
