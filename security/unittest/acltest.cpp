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
#include "oc_acl.c"
#include "oc_acl.h"
#include "oc_tls.c"
#include "util/oc_mem.h"
}

static int dev = 0;

static oc_sec_ace_t *
get_aces()
{
  oc_sec_acl_t *a = &aclist[dev];
  return (oc_sec_ace_t *)oc_list_head(a->subjects);
}

TEST(Security, AclInit)
{
  oc_sec_acl_init();
  oc_sec_acl_default(dev);
  oc_ace_subject_t subject;
  oc_str_to_uuid("11111111-1111-1111-1111-111111111111", &subject.uuid);
  int aceid = get_new_aceid(dev);
  EXPECT_TRUE(aceid != 0);
  int permission = OC_PERM_CREATE | OC_PERM_RETRIEVE | OC_PERM_UPDATE |
                   OC_PERM_DELETE | OC_PERM_NOTIFY;
  oc_ace_wildcard_t wc = OC_ACE_WC_ALL;
  oc_string_array_t rt;
  oc_new_string_array(&rt, 3);
  oc_string_array_add_item(rt, "/oic/d/");
  oc_string_array_add_item(rt, "/oic/sec/acl");
  oc_string_array_add_item(rt, "/oic/sec/doxm");
  oc_sec_ace_update_res(OC_SUBJECT_UUID, &subject, aceid, permission, "*", wc,
                        &rt, OC_IF_BASELINE, 0);
  oc_ace_subject_t subject1;
  oc_new_string(&subject1.role.role, "god", 4);
  oc_new_string(&subject1.role.authority, "god", 4);
  oc_sec_ace_update_res(OC_SUBJECT_ROLE, &subject1, aceid, permission, "*", wc,
                        &rt, OC_IF_BASELINE, 0);
#ifdef OC_DEBUG
  dump_acl(dev);
#endif
}
TEST(Security, AclGet)
{
  oc_sec_acl_t *acl = oc_sec_get_acl(dev);
  EXPECT_TRUE(acl != NULL);
}
TEST(Security, AclUniq)
{
  EXPECT_TRUE(unique_aceid(0, dev));
}
TEST(Security, AclNewAceId)
{
  EXPECT_TRUE(get_new_aceid(dev) != 0);
}
TEST(Security, AclFindResource)
{
  oc_string_array_t rt;
  oc_new_string_array(&rt, 3);
  oc_string_array_add_item(rt, "/oic/d/");
  oc_string_array_add_item(rt, "/oic/sec/acl");
  oc_string_array_add_item(rt, "/oic/sec/doxm");
  oc_sec_ace_t *ace = get_aces();
  oc_ace_res_t *res = oc_sec_ace_find_resource(NULL, ace, "/oic/d", &rt,
                                               OC_IF_BASELINE, OC_ACE_NO_WC);
  EXPECT_FALSE(res != NULL);
}
TEST(Security, AclFindSubject)
{
  oc_ace_subject_t subject;
  oc_new_string(&subject.role.role, "god", 4);
  oc_new_string(&subject.role.authority, "god", 4);
  uint16_t permission = OC_PERM_CREATE | OC_PERM_RETRIEVE | OC_PERM_UPDATE |
                        OC_PERM_DELETE | OC_PERM_NOTIFY;
  oc_sec_ace_t *ace = oc_sec_acl_find_subject(NULL, OC_SUBJECT_ROLE, &subject,
                                              -1, permission, dev);
  EXPECT_TRUE(ace != NULL);
}
TEST(Security, AclgetPermission)
{
  oc_sec_ace_t *ace = get_aces();
  EXPECT_TRUE(ace != NULL);
  EXPECT_FALSE(oc_ace_get_permission(ace, oc_ri_get_app_resources()) != 0);
}
TEST(Security, AclCheck)
{
  oc_endpoint_t *endpoint = oc_connectivity_get_endpoints(dev);
  oc_tls_add_peer(endpoint, MBEDTLS_SSL_IS_SERVER);
  oc_resource_t *resource = oc_ri_get_app_resources();
  EXPECT_FALSE(oc_sec_check_acl(OC_GET, resource, endpoint));
  EXPECT_FALSE(oc_sec_check_acl(OC_POST, resource, endpoint));
  EXPECT_FALSE(oc_sec_check_acl(OC_PUT, resource, endpoint));
}
TEST(Security, AclSetPostOtm)
{
  oc_sec_set_post_otm_acl(dev);
}
TEST(Security, AclPost)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)oc_mem_malloc(OC_MAX_APP_DATA_SIZE);
  char svr_tag[32];
  snprintf(svr_tag, sizeof(svr_tag), "acl_%d", dev);
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
           "coaps://127.0.0.1:2048/oic/sec/acl");
  request->request_payload = rep;
  post_acl(request, OC_IF_BASELINE, NULL);
  get_acl(request, OC_IF_BASELINE, NULL);
  request->query_len =
    snprintf((char *)request->query, 2048,
             "coaps://127.0.0.1:2048/oic/sec/acl?aceid=0&aceid=1");
  delete_acl(request, OC_IF_BASELINE, NULL);
  request->query_len = snprintf((char *)request->query, 2048,
                                "coaps://127.0.0.1:2048/oic/sec/acl");
  post_acl(request, OC_IF_BASELINE, NULL);
  request->query_len = snprintf((char *)request->query, 2048,
                                "coaps://127.0.0.1:2048/oic/sec/acl");
  post_acl(request, OC_IF_BASELINE, NULL);
  post_acl(request, OC_IF_S, NULL);
  delete_acl(request, OC_IF_BASELINE, NULL);
  oc_free_rep(request->request_payload);
  oc_mem_free(request->response->response_buffer->buffer);
  oc_mem_free(request->response->response_buffer);
  oc_mem_free(request->response);
  oc_mem_free((void *)request->query);
  oc_mem_free(request);
}
TEST(Security, AclFreeResources)
{
  oc_sec_acl_default(dev);
  oc_sec_ace_t *ace = get_aces();
  oc_ace_free_resources(dev, &ace, "/oic/p");
}
TEST(Security, AclRemoveAce)
{
  oc_acl_remove_ace(dev, 0);
}
TEST(Security, AclClear)
{
  oc_sec_clear_acl(dev);
}
TEST(Security, AclFree)
{
  oc_sec_acl_free();
}
