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

#include "hawkbit_download.h"
#include "hawkbit_deployment.h"

#include "oc_helpers.h"
#include "port/oc_assert.h"
#include "util/oc_memb.h"

#include <assert.h>
#include <stddef.h>

typedef struct hawkbit_download_t
{
  oc_string_t deployment_id;
  oc_string_t version;
  oc_string_t name;
  oc_string_t filename;
  size_t size;
  hawkbit_sha256_digest_t hash;
  hawkbit_download_links_t links;
} hawkbit_download_t;

OC_MEMB(g_hawkbit_download_s, hawkbit_download_t, OC_MAX_NUM_DEVICES);

hawkbit_download_t *
hawkbit_download_alloc()
{
  hawkbit_download_t *download = oc_memb_alloc(&g_hawkbit_download_s);
  if (download == NULL) {
    oc_abort("Insufficient memory");
  }
  return download;
}

void
hawkbit_download_set_from_deployment(hawkbit_download_t *download,
                                     const hawkbit_deployment_t *deployment)
{
  oc_set_string(&download->deployment_id, oc_string(deployment->id),
                oc_string_len(deployment->id));
  oc_set_string(&download->version, oc_string(deployment->chunk.version),
                oc_string_len(deployment->chunk.version));
  oc_set_string(&download->name, oc_string(deployment->chunk.name),
                oc_string_len(deployment->chunk.name));
  oc_set_string(&download->filename,
                oc_string(deployment->chunk.artifact.filename),
                oc_string_len(deployment->chunk.artifact.filename));
  download->size = deployment->chunk.artifact.size;
  hawkbit_sha256_hash_t hash;
  assert(deployment->chunk.artifact.hashes.sha256.size == sizeof(hash.data));
  memcpy(hash.data, oc_string(deployment->chunk.artifact.hashes.sha256),
         deployment->chunk.artifact.hashes.sha256.size);
  download->hash = hawkbit_sha256_hash_to_digest(hash);

  oc_set_string(&download->links.download,
                oc_string(deployment->chunk.artifact.links.download),
                oc_string_len(deployment->chunk.artifact.links.download));
  oc_set_string(&download->links.downloadHttp,
                oc_string(deployment->chunk.artifact.links.downloadHttp),
                oc_string_len(deployment->chunk.artifact.links.downloadHttp));
}

void
hawkbit_download_free(hawkbit_download_t *download)
{
  if (download == NULL) {
    return;
  }
  oc_free_string(&download->deployment_id);
  oc_free_string(&download->version);
  oc_free_string(&download->name);
  oc_free_string(&download->filename);
  oc_free_string(&download->links.download);
  oc_free_string(&download->links.downloadHttp);
  oc_memb_free(&g_hawkbit_download_s, download);
}

oc_string_view_t
hawkbit_download_get_deployment_id(const hawkbit_download_t *download)
{
  return oc_string_view2(&download->deployment_id);
}

oc_string_view_t
hawkbit_download_get_version(const hawkbit_download_t *download)
{
  return oc_string_view2(&download->version);
}

oc_string_view_t
hawkbit_download_get_name(const hawkbit_download_t *download)
{
  return oc_string_view2(&download->name);
}

oc_string_view_t
hawkbit_download_get_filename(const hawkbit_download_t *download)
{
  return oc_string_view2(&download->filename);
}

size_t
hawkbit_download_get_size(const hawkbit_download_t *download)
{
  return download->size;
}

hawkbit_sha256_digest_t
hawkbit_download_get_hash(const hawkbit_download_t *download)
{
  return download->hash;
}

hawkbit_download_links_t
hawkbit_download_get_links(const hawkbit_download_t *download)
{
  return download->links;
}
