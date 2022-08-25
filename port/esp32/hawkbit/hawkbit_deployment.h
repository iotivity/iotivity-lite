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

#ifndef HAWKBIT_DEPLOYMENT_H
#define HAWKBIT_DEPLOYMENT_H

#include "hawkbit_download.h"
#include "hawkbit_util.h"
#include "oc_helpers.h"

#include <cJSON.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_SKIP,
  HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT,
  HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_FORCED,
} hawkbit_deployment_download_type_t;

typedef enum {
  HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_AVAILABLE,
  HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_UNAVAILABLE,
} hawkbit_deployment_maintenance_window_t;

typedef struct
{
  oc_string_t md5;
  oc_string_t sha1;
  oc_string_t sha256;
} hawkbit_deployment_hashes_t;

typedef struct
{
  oc_string_t filename;
  size_t size;
  hawkbit_deployment_hashes_t hashes;
  hawkbit_download_links_t links;
} hawkbit_deployment_artifact_t;

typedef struct
{
  oc_string_t version;
  oc_string_t name;
  hawkbit_deployment_artifact_t artifact;
} hawkbit_deployment_chunk_t;

#define HAWKBIT_DEPLOYMENT_CHUNK_PART_TYPE_APP "bApp"
#define HAWKBIT_DEPLOYMENT_CHUNK_PART_TYPE_OS "os"

/**
 * @brief Representation of deployment resource data received from Hawkbit
 * server
 */
typedef struct hawkbit_deployment_t
{
  oc_string_t id;
  hawkbit_deployment_download_type_t download;
  hawkbit_deployment_download_type_t update;
  int maintenanceWindow; // hawkbit_deployment_maintenance_window_t or -1 if not
                         // set
  hawkbit_deployment_chunk_t chunk;
} hawkbit_deployment_t;

/**
 * @brief Parse deployment from json.
 *
 * @param[in] json json to parse
 * @param[out] deployment parsed deployment
 * @return true on success
 * @return false on failure
 */
bool hawkbit_parse_deployment(const cJSON *json,
                              hawkbit_deployment_t *deployment);

/** Deallocate deployment instance */
void hawkbit_deployment_free(hawkbit_deployment_t *deployment);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_DEPLOYMENT_H */
