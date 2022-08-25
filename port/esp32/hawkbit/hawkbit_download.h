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

#ifndef HAWKBIT_DOWNLOAD_H
#define HAWKBIT_DOWNLOAD_H

#include "hawkbit_util.h"
#include "oc_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_string_t download;
  oc_string_t downloadHttp;
} hawkbit_download_links_t;

typedef struct hawkbit_download_t hawkbit_download_t;

/** Allocate download instance */
hawkbit_download_t *hawkbit_download_alloc();

/** Free download instance */
void hawkbit_download_free(hawkbit_download_t *download);

typedef struct hawkbit_deployment_t hawkbit_deployment_t;

/** Copy data to download from deployment */
void hawkbit_download_set_from_deployment(
  hawkbit_download_t *download, const hawkbit_deployment_t *deployment);

/** Get deployment id */
const char *hawkbit_download_get_deployment_id(
  const hawkbit_download_t *download);

/** Get version */
const char *hawkbit_download_get_version(const hawkbit_download_t *download);

/** Get deployment name */
const char *hawkbit_download_get_name(const hawkbit_download_t *download);

/** Get filename */
const char *hawkbit_download_get_filename(const hawkbit_download_t *download);

/** Get download size */
size_t hawkbit_download_get_size(const hawkbit_download_t *download);

/** Get sha256 */
hawkbit_sha256_digest_t hawkbit_download_get_hash(
  const hawkbit_download_t *download);

/** Get download links */
hawkbit_download_links_t hawkbit_download_get_links(
  const hawkbit_download_t *download);

#ifdef __cplusplus
}
#endif

#endif /* HAWKBIT_DOWNLOAD_H */
