/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "gtest/gtest.h"
#include <cstdlib>

extern "C"
{
#include "oc_doxm.c"
#include "oc_doxm.h"
#include "oc_ri.h"
#include "util/oc_mem.h"
}

static int dev = 0;

bool
change_owner_cb(void)
{
  return true;
}

TEST(Security, DoxmInit)
{
  oc_sec_set_owner_cb(change_owner_cb);
  oc_sec_doxm_free();
  oc_sec_doxm_init();
  oc_sec_doxm_free();
}
TEST(Security, DoxmDefault)
{
  oc_sec_doxm_init();
  oc_sec_doxm_default(dev);
  oc_sec_doxm_mfg(dev);
  oc_sec_doxm_default(dev);
  oc_sec_dump_doxm(dev);
}
TEST(Security, DoxmEncode)
{
  oc_sec_encode_doxm(dev);
}
TEST(Security, DoxmSecGet)
{
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(dev);
  EXPECT_TRUE(doxm != NULL);
}
TEST(Security, DoxmGet)
{
  get_doxm(NULL, OC_IF_BASELINE, NULL);
  oc_request_t *request = (oc_request_t *)oc_mem_malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)oc_mem_malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  request->response = (oc_response_t *)oc_mem_malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)oc_mem_malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)oc_mem_malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)oc_mem_malloc(request->query_len);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm?owned=false&owned=true");
  get_doxm(request, OC_IF_BASELINE, NULL);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm?owned=true&owned=false");
  get_doxm(request, OC_IF_BASELINE, NULL);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm?owned=ff&owner=me");
  get_doxm(request, OC_IF_BASELINE, NULL);
  get_doxm(request, OC_IF_S, NULL);
  oc_mem_free(request->response->response_buffer->buffer);
  oc_mem_free(request->response->response_buffer);
  oc_mem_free(request->response);
  oc_mem_free((void *)request->query);
  oc_mem_free(request);
}
TEST(Security, DoxmDecode)
{

  EXPECT_TRUE(oc_sec_decode_doxm(NULL, 0, -1));
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)oc_mem_malloc(OC_MAX_APP_DATA_SIZE);
  char svr_tag[32];
  snprintf(svr_tag, sizeof(svr_tag), "doxm_%d", dev);
  ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
    char rep_objects_alloc[150];
    oc_rep_t rep_objects_pool[150];
    memset(rep_objects_alloc, 0, 150 * sizeof(char));
    memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                   (void *)rep_objects_pool, 0 };
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)ret, &rep);
    EXPECT_FALSE(oc_sec_decode_doxm(rep, false, -1));
    EXPECT_FALSE(oc_sec_decode_doxm(rep, false, 0));
    EXPECT_TRUE(oc_sec_decode_doxm(rep, true, 0));
    oc_free_rep(rep);
  }
  oc_mem_free(buf);
}
TEST(Security, DoxmPost)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)oc_mem_malloc(OC_MAX_APP_DATA_SIZE);
  char svr_tag[32];
  snprintf(svr_tag, sizeof(svr_tag), "doxm_%d", dev);
  ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
    char rep_objects_alloc[150];
    oc_rep_t rep_objects_pool[150];
    memset(rep_objects_alloc, 0, 150 * sizeof(char));
    memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                   (void *)rep_objects_pool, 0 };
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)ret, &rep);
  }
  oc_mem_free(buf);

  oc_request_t *request = (oc_request_t *)oc_mem_malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)oc_mem_malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  request->response = (oc_response_t *)oc_mem_malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)oc_mem_malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)oc_mem_malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)oc_mem_malloc(request->query_len);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm");
  request->request_payload = rep;
  post_doxm(request, OC_IF_BASELINE, NULL);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm");
  post_doxm(request, OC_IF_BASELINE, NULL);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/doxm");
  post_doxm(request, OC_IF_BASELINE, NULL);
  post_doxm(request, OC_IF_S, NULL);
  oc_free_rep(request->request_payload);
  oc_mem_free(request->response->response_buffer->buffer);
  oc_mem_free(request->response->response_buffer);
  oc_mem_free(request->response);
  oc_mem_free((void *)request->query);
  oc_mem_free(request);
}
TEST(Security, DoxmDeInit)
{
  oc_sec_doxm_free();
}
