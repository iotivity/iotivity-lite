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
#ifdef OC_CLOUD

#include "api/oc_link_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_log_internal.h"
#include "oc_collection.h"
#include "rd_client_internal.h"

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#define ONE_HOUR 3600
#define OC_RSRVD_LINKS "links"
#define OC_RSRVD_HREF "href"
#define OC_RSRVD_INSTANCEID "ins"

static oc_link_t *
rd_link_find(oc_link_t *head, const oc_resource_t *res)
{
  oc_link_t *iter = head;
  while (iter != NULL && iter->resource != res) {
    iter = iter->next;
  }
  return iter;
}

static void
rd_link_add(oc_link_t **head, oc_link_t *link)
{
  if (!head) {
    return;
  }
  if (!*head) {
    *head = link;
    return;
  }
  oc_list_add((oc_list_t)*head, link);
}

static oc_link_t *
rd_link_pop(oc_link_t **head)
{
  if (!head || !*head) {
    return NULL;
  }
  oc_link_t *link = *head;
  *head = link->next;
  link->next = NULL;
  return link;
}

static void
rd_link_free(oc_link_t **head)
{
  for (oc_link_t *link = rd_link_pop(head); link != NULL;
       link = rd_link_pop(head)) {
    oc_delete_link(link);
  }
}

static oc_link_t *
rd_link_find_by_href(oc_link_t *head, const char *href, size_t href_size)
{
  oc_link_t *iter = head;
  while (iter != NULL &&
         (oc_string_len(iter->resource->uri) != href_size ||
          strncmp(oc_string(iter->resource->uri), href, href_size) != 0)) {
    iter = iter->next;
  }
  return iter;
}

static oc_link_t *
rd_link_remove(oc_link_t **head, const oc_link_t *l)
{
  if (*head == NULL || l == NULL) {
    return NULL;
  }

  if (l == *head) {
    return rd_link_pop(head);
  }
  return oc_list_remove2((oc_list_t)*head, l);
}

static oc_link_t *
rd_link_remove_by_resource(oc_link_t **head, const oc_resource_t *res)
{
  return rd_link_remove(head, rd_link_find(*head, res));
}

static void
cloud_publish_resources_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  OC_CLOUD_DBG("publish resources handler(%d)", data->code);

  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    return;
  }
  if (data->code != OC_STATUS_CHANGED) {
    return;
  }

  oc_rep_t *link = NULL;
  if (!oc_rep_get_object_array(data->payload, OC_RSRVD_LINKS, &link)) {
    return;
  }
  for (; link != NULL; link = link->next) {
    char *href = NULL;
    size_t href_size = 0;
    if (!oc_rep_get_string(link->value.object, OC_RSRVD_HREF, &href,
                           &href_size)) {
      OC_CLOUD_DBG("link skipped: no href");
      continue;
    }
    int64_t instance_id = -1;
    if (!oc_rep_get_int(link->value.object, OC_RSRVD_INSTANCEID,
                        &instance_id)) {
      OC_CLOUD_DBG("link skipped: no instanceID");
      continue;
    }
    oc_link_t *l =
      rd_link_find_by_href(ctx->rd_publish_resources, href, href_size);
    if (l == NULL) {
      OC_CLOUD_DBG("link(%s) skipped: not found", href);
      continue;
    }
    l->ins = instance_id;
    rd_link_remove(&ctx->rd_publish_resources, l);
    OC_CLOUD_DBG("link(href=%s,ins=%" PRId64 ") published", href, instance_id);
    rd_link_add(&ctx->rd_published_resources, l);
  }
}

static void
cloud_publish_resources(oc_cloud_context_t *ctx)
{
#ifdef OC_SECURITY
  if (!oc_sec_pstat_is_in_dos_state(ctx->device,
                                    OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    OC_CLOUD_DBG("cannot publish resource links when not in RFNOP");
    return;
  }
#endif /* OC_SECURITY */
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_CLOUD_DBG("cannot publish resource links when not logged in");
    return;
  }

  if (!rd_publish(ctx->rd_publish_resources, ctx->cloud_ep, ctx->device,
                  ctx->time_to_live, cloud_publish_resources_handler, LOW_QOS,
                  ctx)) {
    OC_CLOUD_ERR("cannot send publish resource links request");
  }
}

int
oc_cloud_add_resource(oc_resource_t *res)
{
  if (res == NULL) {
    return -1;
  }
  oc_cloud_context_t *ctx = oc_cloud_get_context(res->device);
  if (ctx == NULL) {
    return -1;
  }
  const oc_link_t *publish = rd_link_find(ctx->rd_publish_resources, res);
  if (publish != NULL) {
    return 0;
  }
  const oc_link_t *published = rd_link_find(ctx->rd_published_resources, res);
  if (published != NULL) {
    return 0;
  }
  oc_link_t *delete =
    rd_link_remove_by_resource(&ctx->rd_delete_resources, res);
  if (delete) {
    oc_delete_link(delete);
  }

  oc_link_t *link = oc_new_link(res);
  if (link == NULL) {
    return -1;
  }
  rd_link_add(&ctx->rd_publish_resources, link);
  cloud_publish_resources(ctx);
  return 0;
}

static void
move_published_to_publish_resources(oc_cloud_context_t *ctx)
{
  while (ctx->rd_published_resources) {
    oc_link_t *link = rd_link_pop(&ctx->rd_published_resources);
    rd_link_add(&ctx->rd_publish_resources, link);
  }
}

static oc_event_callback_retval_t
publish_published_resources(void *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data;
  move_published_to_publish_resources(ctx);
  cloud_publish_resources(ctx);
  return OC_EVENT_CONTINUE;
}

static void cloud_delete_resources(oc_cloud_context_t *ctx);

static void
delete_resources_handler(oc_client_response_t *data)
{
  OC_CLOUD_DBG("delete resources handler(%d)", data->code);
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  if (ctx->rd_delete_resources == NULL) {
    return;
  }
  if (oc_status_is_internal_code(data->code)) {
    OC_CLOUD_ERR("unpublishing of remaining resource links skipped for "
                 "internal response code(%d)",
                 (int)data->code);
    return;
  }
  cloud_delete_resources(ctx);
}

static void
cloud_delete_resources(oc_cloud_context_t *ctx)
{
  assert(ctx->rd_delete_resources != NULL);
#ifdef OC_SECURITY
  if (!oc_sec_pstat_is_in_dos_state(ctx->device,
                                    OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    OC_CLOUD_DBG("cannot unpublish resource links when not in RFNOP");
    return;
  }
#endif /* OC_SECURITY */
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    OC_CLOUD_DBG("cannot unpublish resource links when not logged in");
    return;
  }

  rd_links_partition_t partition;
  memset(&partition, 0, sizeof(rd_links_partition_t));
  if (rd_delete(ctx->rd_delete_resources, ctx->cloud_ep, ctx->device,
                delete_resources_handler, LOW_QOS, ctx,
                &partition) == RD_DELETE_ERROR) {
    OC_CLOUD_ERR("unpublishing of resource links failed");
    return;
  }

#if OC_DBG_IS_ENABLED
  for (const oc_link_t *link = partition.not_deleted; link != NULL;
       link = link->next) {
    OC_CLOUD_DBG("link(href=%s, ins=%" PRId64 ") not unpublished",
                 oc_string(link->resource->uri), link->ins);
  }
#endif /* OC_DBG_IS_ENABLED */
  ctx->rd_delete_resources = partition.not_deleted;
  rd_link_free(&partition.deleted);
}

void
cloud_rd_manager_status_changed(oc_cloud_context_t *ctx)
{
  if ((ctx->store.status & OC_CLOUD_LOGGED_IN) == 0) {
    oc_remove_delayed_callback(ctx, publish_published_resources);
    return;
  }
  if ((ctx->store.status & OC_CLOUD_REFRESHED_TOKEN) != 0) {
    // when refresh occurs we don't want to publish resources.
    return;
  }
  if (ctx->rd_publish_resources != NULL) {
    cloud_publish_resources(ctx);
  }
  if (ctx->rd_delete_resources != NULL) {
    cloud_delete_resources(ctx);
  }

  oc_remove_delayed_callback(ctx, publish_published_resources);
  if (ctx->time_to_live != RD_PUBLISH_TTL_UNLIMITED) {
    oc_set_delayed_callback(ctx, publish_published_resources, ONE_HOUR);
  }
}

void
cloud_rd_deinit(oc_cloud_context_t *ctx)
{
  oc_remove_delayed_callback(ctx, publish_published_resources);

  rd_link_free(&ctx->rd_delete_resources);
  rd_link_free(&ctx->rd_published_resources);
  rd_link_free(&ctx->rd_publish_resources);
}

void
cloud_rd_reset_context(oc_cloud_context_t *ctx)
{
  oc_remove_delayed_callback(ctx, publish_published_resources);

  rd_link_free(&ctx->rd_delete_resources);
  move_published_to_publish_resources(ctx);
}

void
oc_cloud_delete_resource(oc_resource_t *res)
{
  if (res == NULL) {
    return;
  }
  oc_cloud_context_t *ctx = oc_cloud_get_context(res->device);
  if (ctx == NULL) {
    return;
  }
  oc_link_t *publish =
    rd_link_remove_by_resource(&ctx->rd_publish_resources, res);
  oc_delete_link(publish);

  oc_link_t *published =
    rd_link_remove_by_resource(&ctx->rd_published_resources, res);

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(res->device);
  if (pstat->s == OC_DOS_RESET || pstat->s == OC_DOS_RFOTM) {
    oc_delete_link(published);

    oc_link_t *delete =
      rd_link_remove_by_resource(&ctx->rd_delete_resources, res);
    oc_delete_link(delete);
    return;
  }
#endif /* OC_SECURITY */

  if (published != NULL) {
    if (published->resource) {
      published->resource = NULL;
    }
    rd_link_add(&ctx->rd_delete_resources, published);
    cloud_delete_resources(ctx);
  }
}

int
oc_cloud_publish_resources(size_t device)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(device);
  if (ctx == NULL) {
    OC_ERR("cannot publish resource: invalid device(%zu)", device);
    return -1;
  }
  publish_published_resources(ctx);
  if (ctx->rd_delete_resources != NULL) {
    cloud_delete_resources(ctx);
  }
  return 0;
}

#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
