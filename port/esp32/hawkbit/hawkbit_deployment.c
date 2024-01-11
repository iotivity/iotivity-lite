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

#include "debug_print.h"
#include "hawkbit_deployment.h"
#include "hawkbit_json.h"
#include "oc_helpers.h"

static int
hawkbit_deployment_download_type_from_string(const char *text)
{
#define HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_SKIP_STR "skip"
#define HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT_STR "attempt"
#define HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_FORCED_STR "forced"

  size_t len = strlen(text);
  if ((len == sizeof(HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_SKIP_STR) - 1) &&
      (strcmp(text, HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_SKIP_STR)) == 0) {
    return HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_SKIP;
  }
  if ((len == sizeof(HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT_STR) - 1) &&
      (strcmp(text, HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT_STR)) == 0) {
    return HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT;
  }
  if ((len == sizeof(HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_FORCED_STR) - 1) &&
      (strcmp(text, HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_FORCED_STR)) == 0) {
    return HAWKBIT_DEPLOYMENT_DOWNLOAD_TYPE_ATTEMPT;
  }
  return -1;
}

static int
hawkbit_deployment_maintenance_window_from_string(const char *text)
{
#define HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_AVAILABLE_STR "available"
#define HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_UNAVAILABLE_STR "unavailable"

  size_t len = strlen(text);
  if ((len ==
       sizeof(HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_AVAILABLE_STR) - 1) &&
      (strcmp(text, HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_AVAILABLE_STR)) ==
        0) {
    return HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_AVAILABLE;
  }
  if ((len ==
       sizeof(HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_UNAVAILABLE_STR) - 1) &&
      (strcmp(text, HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_UNAVAILABLE_STR)) ==
        0) {
    return HAWKBIT_DEPLOYMENT_MAINTENANCE_WINDOW_UNAVAILABLE;
  }
  return -1;
}

static void
hawkbit_deployment_artifact_free(hawkbit_deployment_artifact_t *artifact)
{
  oc_free_string(&artifact->filename);

  oc_free_string(&artifact->hashes.md5);
  oc_free_string(&artifact->hashes.sha1);
  oc_free_string(&artifact->hashes.sha256);

  oc_free_string(&artifact->links.download);
  oc_free_string(&artifact->links.downloadHttp);
}

static bool
hawkbit_deployment_get_artifact(const cJSON *node,
                                hawkbit_deployment_artifact_t *artifact)
{
  const char *filename = hawkbit_json_get_string(node, "filename");
  if (filename == NULL) {
    APP_ERR("get deployment artifact failed: filename property not found");
    return false;
  }
  APP_DBG("artifact filename: %s", filename);

  long size = (long)hawkbit_json_get_number(node, "size", -1);
  if (size == -1) {
    APP_ERR("get deployment artifact failed: size property not found");
    return false;
  }
  APP_DBG("artifact size: %ld", size);

  // hashes
  const cJSON *hashes_node = hawkbit_json_get_object(node, "hashes");
  if (hashes_node == NULL) {
    APP_ERR("get deployment artifact failed: hashes property not found");
    return false;
  }
  const char *md5_hash = hawkbit_json_get_string(hashes_node, "md5");
  if (md5_hash == NULL) {
    APP_ERR("get deployment artifact failed: hashes.md5 property not found");
    return false;
  }
  APP_DBG("artifact md5 hash: %s", md5_hash);

  const char *sha1_hash = hawkbit_json_get_string(hashes_node, "sha1");
  if (sha1_hash == NULL) {
    APP_ERR("get deployment artifact failed: hashes.sha1 property not found");
    return false;
  }
  APP_DBG("artifact sha1 hash: %s", sha1_hash);

  const char *sha256_hash = hawkbit_json_get_string(hashes_node, "sha256");
  if (sha256_hash == NULL) {
    APP_ERR("get deployment artifact failed: hashes.sha256 property not found");
    return false;
  }
  APP_DBG("artifact sha256 hash: %s", sha256_hash);

  size_t sha256_hash_len = strlen(sha256_hash);
  if (sha256_hash_len != (HAWKBIT_SHA256_HASH_SIZE - 1)) {
    APP_ERR("get deployment artifact failed: invalid sha256 hash");
    return false;
  }

  // _links
  const cJSON *links_node = hawkbit_json_get_object(node, "_links");
  if (links_node == NULL) {
    APP_ERR("get deployment artifact failed: _links property not found");
    return false;
  }

  const char *download = hawkbit_json_get_string(
    hawkbit_json_get_object(links_node, "download"), "href");
  if (download != NULL) {
    APP_DBG("artifact download: %s", download);
  }
  const char *download_http = hawkbit_json_get_string(
    hawkbit_json_get_object(links_node, "download-http"), "href");

  if (download_http != NULL) {
    APP_DBG("artifact download-http: %s", download_http);
  }
  if (download == NULL && download_http == NULL) {
    APP_ERR("get deployment artifact failed: no download property found");
    return false;
  }

  oc_new_string(&artifact->filename, filename, strlen(filename));
  artifact->size = size;
  oc_new_string(&artifact->hashes.md5, md5_hash, strlen(md5_hash));
  oc_new_string(&artifact->hashes.sha1, sha1_hash, strlen(sha1_hash));
  oc_new_string(&artifact->hashes.sha256, sha256_hash, sha256_hash_len);
  if (download != NULL) {
    oc_new_string(&artifact->links.download, download, strlen(download));
  }
  if (download_http != NULL) {
    oc_new_string(&artifact->links.downloadHttp, download_http,
                  strlen(download_http));
  }
  return true;
}

static void
hawkbit_deployment_chunk_free(hawkbit_deployment_chunk_t *chunk)
{
  hawkbit_deployment_artifact_free(&chunk->artifact);
  oc_free_string(&chunk->version);
  oc_free_string(&chunk->name);
}

static bool
hawkbit_deployment_get_chunk(const cJSON *json,
                             hawkbit_deployment_chunk_t *chunk)
{
  const cJSON *chunks_array = hawkbit_json_get_array(json, "deployment.chunks");
  if (chunks_array == NULL) {
    APP_ERR("get deployment chunk failed: chunks property not found");
    return false;
  }

  size_t chunks_array_size = (size_t)cJSON_GetArraySize(chunks_array);
  if (chunks_array_size != 1) {
    APP_ERR("get deployment chunk failed: unexpected number(%d) of chunks",
            chunks_array_size);
    return false;
  }

  cJSON *chunk_node = cJSON_GetArrayItem(chunks_array, 0);
  const char *part = hawkbit_json_get_string(chunk_node, "part");
  if (part == NULL) {
    APP_ERR("get deployment chunk failed: part not set");
    return false;
  }
  const char *version = hawkbit_json_get_string(chunk_node, "version");
  if (version == NULL) {
    APP_ERR("get deployment chunk failed: version not set");
    return false;
  }
  APP_DBG("deployment chunk version: %s", version);
  const char *name = hawkbit_json_get_string(chunk_node, "name");
  if (name == NULL) {
    APP_ERR("get deployment chunk failed: name not set");
    return false;
  }
  APP_DBG("deployment chunk name: %s", name);

  const cJSON *artifacts = hawkbit_json_get_array(chunk_node, "artifacts");
  if (artifacts == NULL) {
    APP_ERR("get deployment chunk failed: artifacts not set");
    return false;
  }
  size_t artifacts_size = (size_t)cJSON_GetArraySize(artifacts);
  if (artifacts_size != 1) {
    APP_ERR("get deployment chunk failed: unexpected number(%zu) of artifacts",
            artifacts_size);
    return false;
  }

  const cJSON *artifact_node = cJSON_GetArrayItem(artifacts, 0);
  hawkbit_deployment_artifact_t artifact = {};
  if (!hawkbit_deployment_get_artifact(artifact_node, &artifact)) {
    APP_ERR("get deployment chunk failed: invalid deployment artifact");
    return false;
  }

  if (chunk != NULL) {
    oc_new_string(&chunk->version, version, strlen(version));
    oc_new_string(&chunk->name, name, strlen(name));
    chunk->artifact = artifact;
  }
  return true;
}

void
hawkbit_deployment_free(hawkbit_deployment_t *deployment)
{
  if (deployment == NULL) {
    return;
  }
  hawkbit_deployment_chunk_free(&deployment->chunk);
  oc_free_string(&deployment->id);
}

bool
hawkbit_parse_deployment(const cJSON *json, hawkbit_deployment_t *deployment)
{
  const char *id = hawkbit_json_get_string(json, "id");
  if (id == NULL) {
    APP_ERR("fetch deployment failed: id not set");
    return false;
  }
  APP_DBG("deployment id=%s", id);

  // ['skip', 'attempt', 'forced']
  const char *download_str =
    hawkbit_json_get_string(json, "deployment.download");
  if (download_str == NULL) {
    APP_ERR("fetch deployment failed: download not set");
    return false;
  }
  int download = hawkbit_deployment_download_type_from_string(download_str);
  if (download < 0) {
    APP_ERR("fetch deployment failed: invalid download value(%s)",
            download_str);
    return false;
  }
  APP_DBG("deployment download=%s", download_str);

  // [ 'skip', 'attempt', 'forced' ]
  const char *update_str = hawkbit_json_get_string(json, "deployment.update");
  if (update_str == NULL) {
    APP_ERR("fetch deployment failed: update not set");
    return false;
  }
  int update = hawkbit_deployment_download_type_from_string(update_str);
  if (update < 0) {
    APP_ERR("fetch deployment failed: invalid update value(%s)", update_str);
    return false;
  }
  APP_DBG("deployment update=%s", update_str);

  // optional
  // ['available', 'unavailable']
  const char *mw_str =
    hawkbit_json_get_string(json, "deployment.maintenanceWindow");
  int mw = -1;
  if (mw_str != NULL) {
    mw = hawkbit_deployment_maintenance_window_from_string(mw_str);
    if (mw < 0) {
      APP_ERR("fetch deployment failed: invalid maintenanceWindow value(%s)",
              mw_str);
      return false;
    }
    APP_DBG("deployment maintenanceWindow=%s", mw_str);
  }

  hawkbit_deployment_chunk_t chunk;
  if (!hawkbit_deployment_get_chunk(json, &chunk)) {
    APP_ERR("fetch deployment failed: invalid deployment chunk");
    return false;
  }
  if (deployment != NULL) {
    oc_new_string(&deployment->id, id, strlen(id));
    deployment->download = download;
    deployment->update = update;
    deployment->maintenanceWindow = mw;
    deployment->chunk = chunk;
  }
  return true;
}
