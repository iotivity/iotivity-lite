/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_CLOUD_RD_INTERNAL_H
#define OC_CLOUD_RD_INTERNAL_H

#include "api/cloud/oc_cloud_context_internal.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Update resource links after manager status change.
 *
 * If cloud is in logged in state the function executes several resource links
 * updates: deletes links scheduled to be deleted, publishes links scheduled
 * to be published and republishes links that were already published.
 * Additionally, if Time to Live property is not equal to
 * RD_PUBLISH_TTL_UNLIMITED then published links are scheduled to be republished
 * each hour. (If cloud_rd_manager_status_changed function is triggered again
 * before the scheduled time passes the republishing is rescheduled with updated
 * time.)
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_manager_status_changed(oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Deallocate all resource directory context member variables.
 *
 * Deallocate the list of to be published resources, the list of published
 * resources and the list of to be deleted resources. Remove delayed callback
 * that republishes resources (if it's active).
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_deinit(oc_cloud_context_t *ctx) OC_NONNULL();

/**
 * @brief Reset resource directory context member variables.
 *
 * Items in the list of published resources are moved to the list of to be
 * published resources. The list of to be deleted resources is cleared.
 *
 * @param ctx Cloud context, must not be NULL
 */
void cloud_rd_reset_context(oc_cloud_context_t *ctx) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */
