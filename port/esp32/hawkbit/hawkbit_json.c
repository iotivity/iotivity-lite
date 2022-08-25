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

#include "hawkbit_json.h"
#include "debug_print.h"
#include <assert.h>
#include <cJSON.h>
#include <string.h>

static const cJSON *
hawkbit_json_get_node(const cJSON *node, const char *path)
{
  if (node == NULL || path == NULL) {
    return NULL;
  }

  const cJSON *o = node;
  char key[128] = { 0 };
  const char *start = path;
  const char *end;
  do {
    end = strchr(start, '.');
    size_t len = 0;
    if (end != NULL) {
      len = (end - start);
    } else {
      len = strlen(start);
    }
    assert(len <= sizeof(key));
    memcpy(key, start, len);
    key[len] = '\0';
    o = cJSON_GetObjectItem(o, key);
    if (o == NULL) {
      return NULL;
    }

    start = (end + 1);
  } while (end != NULL);

  return o;
}

const cJSON *
hawkbit_json_get_array(const cJSON *node, const char *path)
{
  const cJSON *o = hawkbit_json_get_node(node, path);
  if (o != NULL && cJSON_IsArray(o)) {
    return o;
  }
  return NULL;
}

double
hawkbit_json_get_number(const cJSON *node, const char *path,
                        double defaultValue)
{
  const cJSON *o = hawkbit_json_get_node(node, path);
  if (o != NULL && cJSON_IsNumber(o)) {
    return cJSON_GetNumberValue(o);
  }
  return defaultValue;
}

const cJSON *
hawkbit_json_get_object(const cJSON *node, const char *path)
{
  const cJSON *o = hawkbit_json_get_node(node, path);
  if (o != NULL && cJSON_IsObject(o)) {
    return o;
  }
  return NULL;
}

const char *
hawkbit_json_get_string(const cJSON *node, const char *path)
{
  return cJSON_GetStringValue(hawkbit_json_get_node(node, path));
}
