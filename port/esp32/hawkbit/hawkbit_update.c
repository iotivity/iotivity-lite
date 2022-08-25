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

#include "hawkbit_update.h"

hawkbit_async_update_t
hawkbit_update_create(const char *deployment_id, const char *version,
                      const uint8_t *sha256, size_t sha256_size,
                      const uint8_t *partition_sha256,
                      size_t partition_sha256_size)
{
  assert(deployment_id != NULL);
  assert(version != NULL);

  hawkbit_async_update_t update;
  memset(&update, 0, sizeof(hawkbit_async_update_t));
  oc_new_string(&update.deployment_id, deployment_id, strlen(deployment_id));
  oc_new_string(&update.version, version, strlen(version));
  assert(sha256_size == sizeof(update.sha256));
  memcpy(update.sha256, sha256, sha256_size);
  assert(partition_sha256_size == sizeof(update.partition_sha256));
  memcpy(update.partition_sha256, partition_sha256, partition_sha256_size);
  return update;
}

void
hawkbit_update_free(hawkbit_async_update_t *update)
{
  oc_free_string(&update->deployment_id);
  oc_free_string(&update->version);
  memset(update, 0, sizeof(hawkbit_async_update_t));
}
