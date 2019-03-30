/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik  All Rights Reserved.
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

#include "cloud.h"
#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "rd_client.h"

#define ONE_HOUR 3600
#define OC_RSRVD_LINKS "links"
#define OC_RSRVD_HREF "href"
#define OC_RSRVD_INSTANCEID "ins"

static oc_link_t *rd_link_find(oc_link_t *head, oc_resource_t *res) {
  oc_link_t *iter = head;
  while (iter != NULL && iter->resource != res) {
    iter = iter->next;
  }
  return iter;
}

static void rd_link_add(oc_link_t **head, oc_link_t *link) {
  if (!head) {
    return;
  }
  if (!*head) {
    *head = link;
    return;
  }
  oc_list_add((oc_list_t)*head, link);
}

static oc_link_t *rd_link_pop(oc_link_t **head) {
  if (!head || !*head) {
    return NULL;
  }
  oc_link_t *link = *head;
  *head = link->next;
  link->next = NULL;
  return link;
}

static void rd_link_free(oc_link_t **head) {
  for (oc_link_t *link = rd_link_pop(head); link != NULL;
       link = rd_link_pop(head)) {
    oc_delete_link(link);
  }
}

static oc_link_t *rd_link_find_by_href(oc_link_t *head, const char *href,
                                       size_t href_size) {
  oc_link_t *iter = head;
  while (iter != NULL && oc_string_len(iter->resource->uri) != href_size &&
         !strncmp(oc_string(iter->resource->uri), href, href_size)) {
    iter = iter->next;
  }
  return iter;
}

static oc_link_t *rd_link_remove(oc_link_t **head, oc_link_t *l) {
  if (l) {
    if (l == *head) {
      return rd_link_pop(head);
    }
    oc_list_remove((oc_list_t)*head, l);
    l->next = NULL;
  }
  return l;
}

static oc_link_t *rd_link_remove_by_resource(oc_link_t **head,
                                             oc_resource_t *res) {
  return rd_link_remove(head, rd_link_find(*head, res));
}

static void publish_resources_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;
  OC_DBG("[CRD] publish resources handler(%d)\n", data->code);

  if (ctx->store.status != CLOUD_SIGNED_IN)
    return;
  if (data->code != OC_STATUS_CHANGED)
    goto error;

  oc_rep_t *link = NULL;
  if (oc_rep_get_object_array(data->payload, OC_RSRVD_LINKS, &link)) {
    while (link) {
      char *href = NULL;
      size_t href_size = 0;
      int64_t instace_id = -1;
      if (oc_rep_get_string(link->value.object, OC_RSRVD_HREF, &href,
                            &href_size) &&
          oc_rep_get_int(link->value.object, OC_RSRVD_INSTANCEID,
                         &instace_id)) {
        oc_link_t *l =
            rd_link_find_by_href(ctx->rd_publish_resources, href, href_size);
        if (l) {
          char buf[16];
          int n = snprintf(buf, sizeof(buf) - 1, "%lld", (long long) instace_id);
          if (n < 1) {
            continue;
          }
          if (oc_string(l->ins)) {
            oc_free_string(&l->ins);
          }
          if (n > 0) {
            oc_new_string(&l->ins, buf, n);
          } else {
            memset(&l->ins, 0, sizeof(l->ins));
          }
          rd_link_remove(&ctx->rd_publish_resources, l);
          rd_link_add(&ctx->rd_publish_resources, l);
        }
      }
      link = link->next;
    }
  }

  return;

error : {}
}

static void publish_resources(cloud_context_t *ctx) {
  if (ctx->store.status != CLOUD_SIGNED_IN) {
    return;
  }

  rd_publish(ctx->cloud_ep, ctx->rd_publish_resources, ctx->device_index,
             publish_resources_handler, LOW_QOS, ctx);
}

int cloud_rd_publish(oc_resource_t *res) {
  cloud_context_t *ctx = cloud_find_context(res->device);
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

static void move_published_to_publish_resources(cloud_context_t *ctx) {
  while (ctx->rd_published_resources) {
    oc_link_t *link = rd_link_pop(&ctx->rd_published_resources);
    rd_link_add(&ctx->rd_publish_resources, link);
  }
}

static oc_event_callback_retval_t publish_published_resources(void *data) {
  cloud_context_t *ctx = (cloud_context_t *)data;
  move_published_to_publish_resources(ctx);
  publish_resources(ctx);
  return OC_EVENT_CONTINUE;
}

static void delete_resources_handler(oc_client_response_t *data) {
  cloud_context_t *ctx = (cloud_context_t *)data->user_data;
  OC_DBG("[CRD] delete resources handler(%d)\n", data->code);

  if (ctx->store.status != CLOUD_SIGNED_IN)
    return;
  if (data->code != OC_STATUS_DELETED)
    goto error;
  while (ctx->rd_delete_resources) {
    oc_link_t *link = rd_link_pop(&ctx->rd_delete_resources);
    oc_delete_link(link);
  }

error : {}
}

static void delete_resources(cloud_context_t *ctx, bool all) {
  if (ctx->store.status != CLOUD_SIGNED_IN) {
    return;
  }

  if (all) {
    rd_delete(ctx->cloud_ep, NULL, ctx->device_index, delete_resources_handler,
              LOW_QOS, ctx);
    return;
  }
  if (ctx->rd_delete_resources) {
    rd_delete(ctx->cloud_ep, ctx->rd_delete_resources, ctx->device_index,
              delete_resources_handler, LOW_QOS, ctx);
  }
}

void cloud_rd_manager_status_changed(cloud_context_t *ctx) {
  if (ctx->store.status == CLOUD_SIGNED_IN) {
    publish_published_resources(ctx);
    delete_resources(ctx, false);
    oc_remove_delayed_callback(ctx, publish_published_resources);
    oc_set_delayed_callback(ctx, publish_published_resources, ONE_HOUR);
  } else {
    oc_remove_delayed_callback(ctx, publish_published_resources);
  }
}

void cloud_rd_deinit(cloud_context_t *ctx) {
  oc_remove_delayed_callback(ctx, publish_published_resources);

  rd_link_free(&ctx->rd_delete_resources);
  rd_link_free(&ctx->rd_published_resources);
  rd_link_free(&ctx->rd_publish_resources);
}

void cloud_rd_delete(oc_resource_t *res) {
  cloud_context_t *ctx = cloud_find_context(res->device);
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
      // dont hold link on resource, because it can points to deleted resource.
      published->resource->num_links--;
      published->resource = NULL;
    }
    rd_link_add(&ctx->rd_delete_resources, published);
    delete_resources(ctx, false);
  }
}