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

#include <cstdlib>
#include <gtest/gtest.h>

extern "C"
{
#include <sys/stat.h>
#include <sys/types.h>

#include "oc_acl.c"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.c"
#include "oc_cred.h"
#include "oc_doxm.c"
#include "oc_doxm.h"
#include "oc_pstat.c"
#include "oc_pstat.h"
#include "oc_ri.h"
#include "oc_store.c"
#include "oc_svr.c"
#include "oc_tls.c"
}

static int dev = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("UnitTest", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource(NULL, "/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_type(res, "core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
  PRINT("%s\n", __func__);
}

void
requests_entry(void)
{
  PRINT("%s\n", __func__);
}

TEST(Security, Init)
{
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources,
                                        .requests_entry = NULL };

  mkdir("unittest_creds", 0770);
  oc_storage_config("unittest_creds");
  oc_main_init(&handler);
  oc_core_regen_unique_ids(0);

  oc_endpoint_t *endpoint = oc_connectivity_get_endpoints(0);
  oc_tls_add_peer(endpoint, MBEDTLS_SSL_IS_SERVER);
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  snprintf((char *)peer->master_secret, 48, "secret");
  snprintf((char *)peer->client_server_random, 48, "random");
}

void
sec_free()
{
  oc_sec_acl_free();
  oc_sec_doxm_free();
  oc_sec_pstat_free();
  oc_sec_cred_free();
}

void
sec_init()
{
  oc_sec_acl_init();
  oc_sec_doxm_init();
  oc_sec_pstat_init();
  oc_sec_cred_init();

  oc_sec_pstat_default(dev);
  oc_core_regen_unique_ids(0);
}

//-------------------------------------------------ACL---------------------------------------------
static oc_sec_ace_t *
get_aces()
{
  oc_sec_acl_t *a = &aclist[dev];
  return (oc_sec_ace_t *)oc_list_head(a->subjects);
}

TEST(Security, AclInit)
{
  sec_init();
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
TEST(Security, AclGetPermission)
{
  oc_sec_ace_t *ace = get_aces();
  EXPECT_TRUE(ace);
  oc_resource_t *r = oc_ri_get_app_resources();
  EXPECT_TRUE(r);
  EXPECT_FALSE(oc_ace_get_permission(ace, r) != 0);

  oc_resource_t *res = oc_new_resource("cooler", "/coller/1", 1, dev);
  EXPECT_TRUE(res);
  EXPECT_TRUE(oc_ace_get_permission(ace, res) == 0);
  
  oc_resource_t *res1 = oc_new_resource("p", "/oic/p", 1, dev);
  oc_ace_wildcard_t wc = (r->properties & OC_DISCOVERABLE)
                           ? OC_ACE_WC_ALL_DISCOVERABLE
                           : OC_ACE_WC_ALL_NON_DISCOVERABLE;
  oc_ace_res_t *rs = oc_sec_ace_find_resource(NULL, ace, oc_string(res1->uri), 
        &res1->types, res1->interfaces, wc);
  EXPECT_FALSE(rs);
}
TEST(Security, AclCheck)
{
  oc_endpoint_t *endpoint = oc_connectivity_get_endpoints(dev);
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

  uint8_t *buf = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
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
  free(buf);

  oc_request_t *request = (oc_request_t *)malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  request->response = (oc_response_t *)malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)malloc(request->query_len);
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
  free(request->response->response_buffer->buffer);
  free(request->response->response_buffer);
  free(request->response);
  free((void *)request->query);
  free(request);
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
  sec_free();
}
//-----------------------------------------DOXM-----------------------------------------
bool
change_owner_cb(void)
{
  return true;
}

TEST(Security, DoxmInit)
{
  sec_init();
}
TEST(Security, DoxmDefault)
{
  oc_sec_doxm_free();
  oc_sec_doxm_init();
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
  oc_request_t *request = (oc_request_t *)malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  request->response = (oc_response_t *)malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)malloc(request->query_len);
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
  free(request->response->response_buffer->buffer);
  free(request->response->response_buffer);
  free(request->response);
  free((void *)request->query);
  free(request);
}
TEST(Security, DoxmDecode)
{

  EXPECT_TRUE(oc_sec_decode_doxm(NULL, 0, -1));
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
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
  free(buf);
}
TEST(Security, DoxmPost)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
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
  free(buf);

  oc_request_t *request = (oc_request_t *)malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  request->response = (oc_response_t *)malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)malloc(request->query_len);
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
  free(request->response->response_buffer->buffer);
  free(request->response->response_buffer);
  free(request->response);
  free((void *)request->query);
  free(request);
}
TEST(Security, DoxmDeInit)
{
  sec_free();
}
//---------------------------------------CRED--------------------------------------------
static bool
add_cred(const char *suuid)
{
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);
  oc_rep_set_int(creds, credid, get_new_credid(dev));
  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string(creds, subjectuuid, suuid);
  oc_rep_set_object(creds, privatedata);
  oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
  oc_rep_close_object(creds, privatedata);
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_set_text_string(root, rowneruuid, suuid);
  oc_rep_end_root_object();
  return true;
}

static bool
add_cred1(const char *suuid)
{
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);
  oc_rep_set_int(creds, credid, get_new_credid(dev));
  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string(creds, credusage, "oic.sec.cred.mfgcert");
  oc_rep_set_object(creds, privatedata);
  oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.base64");
  oc_rep_close_object(creds, privatedata);
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_set_text_string(root, rowneruuid, suuid);
  oc_rep_end_root_object();
  return true;
}

static bool
add_cred2(const char *suuid)
{
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);
  oc_rep_set_int(creds, credid, get_new_credid(dev));
  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string(creds, credusage, "oic.sec.cred.mfgtrustca");
  oc_rep_set_object(creds, privatedata);
  oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.base64");
  oc_rep_close_object(creds, privatedata);
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_set_text_string(root, rowneruuid, suuid);
  oc_rep_end_root_object();
  return true;
}
static bool
add_cred3(const char *suuid)
{
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);
  oc_rep_set_int(creds, credid, get_new_credid(dev));
  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string(creds, subjectuuid, suuid);
  oc_rep_set_object(creds, publicdata);
  oc_rep_set_text_string(publicdata, data, "key");
  oc_rep_close_object(creds, publicdata);
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_set_text_string(root, rowneruuid, suuid);
  oc_rep_end_root_object();
  return true;
}

TEST(Security, CredInit)
{
  sec_init();

  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_add_peer(ep, MBEDTLS_SSL_IS_SERVER);
  oc_tls_peer_t *peer = oc_tls_get_peer(ep);
  peer->ssl_ctx.session =
    (mbedtls_ssl_session *)malloc(sizeof(mbedtls_ssl_session));
  ;
  mbedtls_ssl_session_init(peer->ssl_ctx.session);
  peer->ssl_ctx.session->ciphersuite =
    MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256;
}
TEST(Security, CredDecode3)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)malloc(sz);
  EXPECT_TRUE(buf);
  oc_rep_new(buf, sz);

  add_cred3(suuid);

  int size = oc_rep_finalize();
  EXPECT_GT(size, 0);
  oc_rep_t *rep;

  char rep_objects_alloc[150];
  oc_rep_t rep_objects_pool[150];
  memset(rep_objects_alloc, 0, 150 * sizeof(char));
  memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                 (void *)rep_objects_pool, 0 };
  oc_rep_set_pool(&rep_objects);
  oc_parse_rep(buf, size, &rep);
  oc_sec_cred_t *owner = NULL;
  EXPECT_TRUE(oc_sec_decode_cred(rep, &owner, false, dev));
  EXPECT_TRUE(owner != NULL);

  oc_free_rep(rep);
  free(buf);
}
TEST(Security, CredDecode2)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)malloc(sz);
  EXPECT_TRUE(buf);
  oc_rep_new(buf, sz);

  add_cred2(suuid);

  int size = oc_rep_finalize();
  EXPECT_GT(size, 0);
  oc_rep_t *rep;

  char rep_objects_alloc[150];
  oc_rep_t rep_objects_pool[150];
  memset(rep_objects_alloc, 0, 150 * sizeof(char));
  memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                 (void *)rep_objects_pool, 0 };
  oc_rep_set_pool(&rep_objects);
  oc_parse_rep(buf, size, &rep);
  oc_sec_cred_t *owner = NULL;
  EXPECT_FALSE(oc_sec_decode_cred(rep, &owner, false, dev));
  EXPECT_FALSE(owner != NULL);

  oc_free_rep(rep);
  free(buf);
}
TEST(Security, CredDecode1)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)malloc(sz);
  EXPECT_TRUE(buf);
  oc_rep_new(buf, sz);

  add_cred1(suuid);

  int size = oc_rep_finalize();
  EXPECT_GT(size, 0);
  oc_rep_t *rep;

  char rep_objects_alloc[150];
  oc_rep_t rep_objects_pool[150];
  memset(rep_objects_alloc, 0, 150 * sizeof(char));
  memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                 (void *)rep_objects_pool, 0 };
  oc_rep_set_pool(&rep_objects);
  oc_parse_rep(buf, size, &rep);
  oc_sec_cred_t *owner = NULL;
  EXPECT_FALSE(oc_sec_decode_cred(rep, &owner, false, dev));
  EXPECT_FALSE(owner != NULL);

  oc_free_rep(rep);
  free(buf);
}
TEST(Security, CredDecode)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)malloc(sz);
  EXPECT_TRUE(buf);
  oc_rep_new(buf, sz);

  add_cred(suuid);

  int size = oc_rep_finalize();
  EXPECT_GT(size, 0);
  oc_rep_t *rep;

  char rep_objects_alloc[150];
  oc_rep_t rep_objects_pool[150];
  memset(rep_objects_alloc, 0, 150 * sizeof(char));
  memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                 (void *)rep_objects_pool, 0 };
  oc_rep_set_pool(&rep_objects);
  oc_parse_rep(buf, size, &rep);
  oc_sec_cred_t *owner = NULL;
  EXPECT_TRUE(oc_sec_decode_cred(rep, &owner, false, dev));
  EXPECT_TRUE(owner != NULL);

  oc_free_rep(rep);
  free(buf);
}

oc_sec_cred_t *
add_cred(bool mfg)
{
  oc_sec_cred_t *c = (oc_sec_cred_t *)malloc(sizeof(oc_sec_cred_t));
  ;

  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  memcpy(&c->subjectuuid, uuid, 16);

  c->next = NULL;
  for (int i = 0; i < 16; i++)
    c->key[i] = rand();
  oc_new_string(&c->role.role, "god", 4);
  oc_new_string(&c->role.authority, "god", 4);
  return c;
}
TEST(Security, CredDefault)
{
  EXPECT_EQ(oc_list_length(devices[dev].creds), 1);
  oc_list_add(devices[dev].creds, add_cred(false));
  oc_list_add(devices[dev].creds, add_cred(true));
  oc_list_add(devices[dev].creds, add_cred(false));
  oc_list_add(devices[dev].creds, add_cred(true));
  EXPECT_EQ(oc_list_length(devices[dev].creds), 5);
  oc_sec_cred_default(dev);
  EXPECT_GE(oc_list_length(devices[dev].creds), 0);
}
TEST(Security, CredFind)
{
  oc_uuid_t *uuid = (oc_uuid_t *)malloc(sizeof(oc_uuid_t));
  oc_gen_uuid(uuid);
  oc_sec_cred_t *c = oc_sec_find_cred(uuid, dev);
  EXPECT_TRUE(c == NULL);
  free((void *)uuid);
  oc_list_add(devices[dev].creds, add_cred(false));
  oc_list_add(devices[dev].creds, add_cred(true));
  uuid = oc_core_get_device_id(dev);
  c = NULL;
  c = oc_sec_find_cred(uuid, dev);
  EXPECT_TRUE(c != NULL);
}
TEST(Security, CredRemove)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);
  EXPECT_TRUE(oc_cred_remove_subject(suuid, dev));
}
TEST(Security, CredGet)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
  char svr_tag[32];
  snprintf(svr_tag, sizeof(svr_tag), "cred_%d", dev);
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
  free(buf);

  oc_request_t *request = (oc_request_t *)malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  oc_new_string(&request->resource->name, "cred", 5);
  request->response = (oc_response_t *)malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)malloc(request->query_len);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/cred");
  request->request_payload = rep;
  get_cred(request, OC_IF_BASELINE, 0);
  request->query_len =
    snprintf((char *)request->query, 2048,
             "coaps://127.0.0.1:2048/oic/sec/cred?credid=0&credid=1");
  delete_cred(request, OC_IF_BASELINE, NULL);
  request->query_len = snprintf((char *)request->query, 2048,
                                "coaps://127.0.0.1:2048/oic/sec/cred");
  post_cred(request, OC_IF_BASELINE, NULL);
  request->query_len = snprintf((char *)request->query, 2048,
                                "coaps://127.0.0.1:2048/oic/sec/cred");
  post_cred(request, OC_IF_BASELINE, NULL);
  post_cred(request, OC_IF_S, NULL);
  delete_cred(request, OC_IF_BASELINE, NULL);
  oc_free_rep(request->request_payload);
  free(request->response->response_buffer->buffer);
  free(request->response->response_buffer);
  free(request->response);
  free((void *)request->query);
  free(request);
}
TEST(Security, CredSecGetCred)
{
  oc_uuid_t uuid = { 0 };
  oc_str_to_uuid("00000001-0001-0001-0001-000000000001", &uuid);
  oc_sec_cred_t *c = oc_sec_get_cred(&uuid, dev);
  EXPECT_TRUE(c != NULL);
}
TEST(Security, CredFree)
{
  oc_list_add(devices[dev].creds, add_cred(false));
  oc_list_add(devices[dev].creds, add_cred(true));
  int num = oc_list_length(devices[dev].creds);
  EXPECT_GT(num, 0);
  oc_sec_remove_cred_by_credid(100, dev);
  EXPECT_EQ(oc_list_length(devices[dev].creds), num);
  oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(devices[dev].creds);
  EXPECT_TRUE(oc_sec_remove_cred_by_credid(c->credid, dev));
  sec_free();
}
//------------------------------------------PSTAT------------------------------------
TEST(Security, PstatInit)
{
  sec_init();
}
TEST(Security, PstatNullUuid)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_FALSE(nil_uuid(uuid));
  oc_str_to_uuid("00000000-0000-0000-0000-000000000000", uuid);
  EXPECT_TRUE(nil_uuid(uuid));
}
TEST(Security, PstatValidTransition)
{
  pstat[dev].s = OC_DOS_RESET;
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RESET));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFOTM));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFPRO));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFNOP));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_SRESET));
  pstat[dev].s = OC_DOS_RFOTM;
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RESET));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFOTM));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFPRO));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFNOP));
  EXPECT_FALSE(valid_transition(dev, OC_DOS_SRESET));
  pstat[dev].s = OC_DOS_RFPRO;
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RESET));
  EXPECT_FALSE(valid_transition(dev, OC_DOS_RFOTM));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFPRO));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFNOP));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_SRESET));
  pstat[dev].s = OC_DOS_RFNOP;
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RESET));
  EXPECT_FALSE(valid_transition(dev, OC_DOS_RFOTM));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFPRO));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFNOP));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_SRESET));
  pstat[dev].s = OC_DOS_SRESET;
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RESET));
  EXPECT_FALSE(valid_transition(dev, OC_DOS_RFOTM));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_RFPRO));
  EXPECT_FALSE(valid_transition(dev, OC_DOS_RFNOP));
  EXPECT_TRUE(valid_transition(dev, OC_DOS_SRESET));
  pstat[dev].s = OC_DOS_RFNOP;
}
TEST(Security, Pstat)
{
  oc_sec_pstat_t *ps = (oc_sec_pstat_t *)malloc(sizeof(oc_sec_pstat_t));
  ps->s = OC_DOS_RESET;
  EXPECT_TRUE(oc_pstat_handle_state(ps, dev));
  ps->s = OC_DOS_RFOTM;
  EXPECT_TRUE(oc_pstat_handle_state(ps, dev));
  ps->s = OC_DOS_RFPRO;
  EXPECT_FALSE(oc_pstat_handle_state(ps, dev));
  ps->s = OC_DOS_RFNOP;
  EXPECT_FALSE(oc_pstat_handle_state(ps, dev));
  ps->s = OC_DOS_SRESET;
  EXPECT_FALSE(oc_pstat_handle_state(ps, dev));
  ps->s = (oc_dostype_t)10;
  EXPECT_FALSE(oc_pstat_handle_state(ps, dev));
}
TEST(Security, PstatIsOp)
{
  EXPECT_FALSE(oc_sec_is_operational(dev));
}
TEST(Security, PstatDumpAclPostOtm)
{
  EXPECT_TRUE(dump_acl_post_otm(0) == OC_EVENT_DONE);
}
TEST(Security, PstatDecode)
{
  char suuid[37];
  oc_rep_t *rep;

  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)malloc(sz);
  EXPECT_TRUE(buf);
  oc_rep_new(buf, sz);

  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_PSTAT, dev));
  oc_rep_set_object(root, dos);
  oc_rep_set_boolean(dos, p, 1);
  oc_rep_set_int(dos, s, 1);
  oc_rep_close_object(root, dos);
  oc_rep_set_int(root, cm, 1);
  oc_rep_set_int(root, tm, 1);
  oc_rep_set_int(root, om, 1);
  oc_rep_set_int(root, sm, 1);
  oc_rep_set_boolean(root, isop, pstat[dev].isop);
  oc_rep_set_text_string(root, rowneruuid, suuid);
  oc_rep_end_root_object();

  int size = oc_rep_finalize();
  EXPECT_GT(size, 0);
  char rep_objects_alloc[150];
  oc_rep_t rep_objects_pool[150];
  memset(rep_objects_alloc, 0, 150 * sizeof(char));
  memset(rep_objects_pool, 0, 150 * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 150, rep_objects_alloc,
                                 (void *)rep_objects_pool, 0 };
  oc_rep_set_pool(&rep_objects);
  oc_parse_rep(buf, size, &rep);
  EXPECT_FALSE(oc_sec_decode_pstat(rep, false, dev));
  EXPECT_TRUE(oc_sec_decode_pstat(rep, true, dev));
//  oc_sec_load_certs(dev);
  oc_free_rep(rep);
  free(buf);
}

TEST(Security, PstatSecReset)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
  char svr_tag[32];
  snprintf(svr_tag, sizeof(svr_tag), "pstat_%d", dev);
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
  free(buf);

  oc_request_t *request = (oc_request_t *)malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  oc_new_string(&request->resource->name, "patst", 5);
  request->response = (oc_response_t *)malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)malloc(request->query_len);
  snprintf((char *)request->query, request->query_len,
           "coaps://127.0.0.1:2048/oic/sec/pstat");
  request->request_payload = rep;
  get_pstat(request, OC_IF_BASELINE, 0);
  request->query_len =
    snprintf((char *)request->query, 2048,
             "coaps://127.0.0.1:2048/oic/sec/pstat?id=0&id=1");
  post_pstat(request, OC_IF_BASELINE, NULL);
  request->query_len = snprintf((char *)request->query, 2048,
                                "coaps://127.0.0.1:2048/oic/sec/pstat");
  post_pstat(request, OC_IF_BASELINE, NULL);
  post_pstat(request, OC_IF_S, NULL);
//  oc_free_rep(request->request_payload);
  free(request->response->response_buffer->buffer);
  free(request->response->response_buffer);
  free(request->response);
  free((void *)request->query);
  free(request);
}
TEST(Security, PstatFree)
{
  sec_free();
}
//------------------------------------------STORE------------------------------------
TEST(Security, StoreInit)
{
  sec_init();
}
TEST(Security, StoreGenSvrTag)
{
  char *svr_tag = (char *)malloc(SVR_TAG_MAX);
  gen_svr_tag("doxm", dev, svr_tag);
  EXPECT_STREQ("doxm_0", svr_tag);
  free(svr_tag);
}
TEST(Security, StoreLoadDoxm)
{
  oc_sec_load_doxm(dev);
}
TEST(Security, StoreLoadUniqueIds)
{
  oc_sec_load_unique_ids(dev);
}
TEST(Security, StoreLoadPstat)
{
  oc_sec_load_pstat(dev);
}
//------------------------------------------OTHER------------------------------------
TEST(Security, SvrCreate)
{
  oc_sec_create_svr();
}

