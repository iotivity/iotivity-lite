/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#ifdef OC_CLOUD

#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_collection.h"
#include "rd_client.h"
#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#endif /* OC_SECURITY */
#define ONE_HOUR 3600
#define OC_RSRVD_LINKS "links"
#define OC_RSRVD_HREF "href"
#define OC_RSRVD_INSTANCEID "ins"

static oc_link_t *
rd_link_find(oc_link_t *head, oc_resource_t *res)
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
  while (iter != NULL && oc_string_len(iter->resource->uri) != href_size &&
         !strncmp(oc_string(iter->resource->uri), href, href_size)) {
    iter = iter->next;
  }
  return iter;
}

static oc_link_t *
rd_link_remove(oc_link_t **head, oc_link_t *l)
{
  if (l) {
    if (l == *head) {
      return rd_link_pop(head);
    }
    oc_list_remove((oc_list_t)*head, l);
    l->next = NULL;
  }
  return l;
}

static oc_link_t *
rd_link_remove_by_resource(oc_link_t **head, oc_resource_t *res)
{
  return rd_link_remove(head, rd_link_find(*head, res));
}

static void
publish_resources_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  OC_DBG("[CRD] publish resources handler(%d)\n", data->code);

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN))
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;

  oc_rep_t *link = NULL;
  if (oc_rep_get_object_array(data->payload, OC_RSRVD_LINKS, &link)) {
    while (link) {
      char *href = NULL;
      size_t href_size = 0;
      int64_t instance_id = -1;
      if (oc_rep_get_string(link->value.object, OC_RSRVD_HREF, &href,
                            &href_size) &&
          oc_rep_get_int(link->value.object, OC_RSRVD_INSTANCEID,
                         &instance_id)) {
        oc_link_t *l =
          rd_link_find_by_href(ctx->rd_publish_resources, href, href_size);
        if (l) {
          l->ins = instance_id;
          rd_link_remove(&ctx->rd_publish_resources, l);
          rd_link_add(&ctx->rd_published_resources, l);
        }
      }
      link = link->next;
    }
  }

  return;

error : {
}
}

static void
publish_resources(oc_cloud_context_t *ctx)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (pstat->s != OC_DOS_RFNOP) {
    return;
  }
#endif /* OC_SECURITY */
  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return;
  }

  rd_publish(ctx->cloud_ep, ctx->rd_publish_resources, ctx->device,
             publish_resources_handler, LOW_QOS, ctx);
}

int
oc_cloud_add_resource(oc_resource_t *res)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(res->device);
  if (ctx == NULL) {
    return -1;
  }
  oc_link_t *publish = rd_link_find(ctx->rd_publish_resources, res);
  if (publish) {
    return 0;
  }
  oc_link_t *published = rd_link_find(ctx->rd_published_resources, res);
  if (published) {
    return 0;
  }
  oc_link_t *delete =
    rd_link_remove_by_resource(&ctx->rd_delete_resources, res);
  if (delete) {
    oc_delete_link(delete);
  }

  oc_link_t *link = oc_new_link(res);
  rd_link_add(&ctx->rd_publish_resources, link);
  publish_resources(ctx);
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
  publish_resources(ctx);
  return OC_EVENT_CONTINUE;
}

static void
delete_resources_handler(oc_client_response_t *data)
{
  oc_cloud_context_t *ctx = (oc_cloud_context_t *)data->user_data;
  OC_DBG("[CRD] delete resources handler(%d)\n", data->code);

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN))
    return;
  if (data->code != OC_STATUS_DELETED)
    goto error;
  while (ctx->rd_delete_resources) {
    oc_link_t *link = rd_link_pop(&ctx->rd_delete_resources);
    oc_delete_link(link);
  }

error : {
}
}

static void
delete_resources(oc_cloud_context_t *ctx, bool all)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (pstat->s != OC_DOS_RFNOP) {
    return;
  }
#endif /* OC_SECURITY */
  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return;
  }

  if (all) {
    rd_delete(ctx->cloud_ep, NULL, ctx->device, delete_resources_handler,
              LOW_QOS, ctx);
    return;
  }
  if (ctx->rd_delete_resources) {
    rd_delete(ctx->cloud_ep, ctx->rd_delete_resources, ctx->device,
              delete_resources_handler, LOW_QOS, ctx);
  }
}

void
cloud_rd_manager_status_changed(oc_cloud_context_t *ctx)
{
  if (ctx->store.status & OC_CLOUD_LOGGED_IN) {
    publish_published_resources(ctx);
    delete_resources(ctx, false);
    oc_remove_delayed_callback(ctx, publish_published_resources);
    oc_set_delayed_callback(ctx, publish_published_resources, ONE_HOUR);
  } else {
    oc_remove_delayed_callback(ctx, publish_published_resources);
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
oc_cloud_delete_resource(oc_resource_t *res)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(res->device);
  if (ctx == NULL) {
    return;
  }
  oc_link_t *publish =
    rd_link_remove_by_resource(&ctx->rd_publish_resources, res);
  if (publish != NULL) {
    oc_delete_link(publish);
  }
  oc_link_t *published =
    rd_link_remove_by_resource(&ctx->rd_published_resources, res);
  if (published != NULL) {
    if (published->resource) {
      published->resource = NULL;
    }
    rd_link_add(&ctx->rd_delete_resources, published);
    delete_resources(ctx, false);
  }
}

int
oc_cloud_publish_resources(size_t device)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(device);
  if (ctx) {
    publish_published_resources(ctx);
    delete_resources(ctx, false);
    return 0;
  }
  return -1;
}
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */
