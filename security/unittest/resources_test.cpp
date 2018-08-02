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
#if defined(OC_SECURITY)

#include <cstdlib>
#include <gtest/gtest.h>

extern "C"
{
#include <sys/stat.h>
#include <sys/types.h>

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_doxm.h"
#include "oc_endpoint.h"
#include "oc_pstat.h"
#include "oc_ri.h"
#include "util/oc_mem.h"

#define SECURED 1 << 1
#define TCP 1 << 4

#include "oc_acl.c"
#include "oc_cred.c"
#include "oc_doxm.c"
#include "oc_otm_state.c"
#include "oc_pstat.c"
#include "oc_store.c"
#include "oc_svr.c"
#include "oc_tls.c"
}

#define FUNC_NAME                                                              \
  do {                                                                         \
    PRINT("[          ] %s\n", __func__);                                      \
  } while (0)

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
  FUNC_NAME;
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  FUNC_NAME;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  FUNC_NAME;
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
  FUNC_NAME;
}

void
requests_entry(void)
{
  FUNC_NAME;
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
otm_err_cb(oc_sec_otm_err_code_t c)
{
  PRINT("[          ] %s %d\n", __func__, c);
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
  oc_sec_otm_set_err_cb(otm_err_cb);
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
  oc_ace_res_t *rs = oc_sec_ace_find_resource(
    NULL, ace, oc_string(res1->uri), &res1->types, res1->interfaces, wc);
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
TEST(Security, AclSetAceConnAnonClear)
{
  EXPECT_TRUE(oc_sec_ace_update_conn_anon_clear("/a/light", 2, 14, dev));
  EXPECT_FALSE(
    oc_sec_ace_update_conn_anon_clear("/oic/provisioninginfo", 200, 14, dev));
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
TEST(Security, AclEncodeV1)
{
  EXPECT_TRUE(oc_sec_encode_acl(dev));
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
  oc_sec_doxm(dev, OC_DOXM_JW);
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
  // removed by Kishen request(26013), use white box testing
  //  get_doxm(NULL, OC_IF_BASELINE, NULL);
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
    (mbedtls_ssl_session *)oc_mem_malloc(sizeof(mbedtls_ssl_session));
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
  uint8_t *buf = (uint8_t *)oc_mem_malloc(sz);
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
  oc_mem_free(buf);
}
TEST(Security, CredDecode2)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)oc_mem_malloc(sz);
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
  oc_mem_free(buf);
}
TEST(Security, CredDecode1)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)oc_mem_malloc(sz);
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
  oc_mem_free(buf);
}
TEST(Security, CredDecode)
{
  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  EXPECT_TRUE(uuid);
  char suuid[37];
  oc_uuid_to_str(uuid, suuid, 37);

  size_t sz = 32 * OC_MAX_APP_DATA_SIZE;
  uint8_t *buf = (uint8_t *)oc_mem_malloc(sz);
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
  oc_mem_free(buf);
}

oc_sec_cred_t *
add_cred(bool mfg)
{
  oc_sec_cred_t *c = (oc_sec_cred_t *)oc_mem_malloc(sizeof(oc_sec_cred_t));
  ;

  oc_uuid_t *uuid = oc_core_get_device_id(dev);
  memcpy(&c->subjectuuid, uuid, 16);

  c->next = NULL;
  c->mfgkey = NULL;
  c->mfgtrustca = NULL;
  c->mfgowncertlen = NULL;
  c->credid = get_new_credid(dev);
  c->credtype = 1;
  c->mfgkeylen = 0;
  c->mfgowncert = NULL;
  c->mfgkey = NULL;
  c->mfgkeylen = 0;
  c->mfgowncertlen = NULL;
  c->ownchainlen = 0;
  c->mfgtrustca = NULL;
  c->mfgtrustcalen = 0;
  if (mfg) {
    c->mfgkeylen = 512;
    c->mfgkey = (uint8_t *)oc_mem_malloc(c->mfgkeylen);
    for (int i = 0; i < c->mfgkeylen; i++)
      c->mfgkey[i] = rand();
    c->mfgtrustcalen = 512;
    c->mfgtrustca = (uint8_t *)oc_mem_malloc(512);
  } else {
    for (int i = 0; i < 16; i++)
      c->key[i] = rand();
  }
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
  oc_uuid_t *uuid = (oc_uuid_t *)oc_mem_malloc(sizeof(oc_uuid_t));
  oc_gen_uuid(uuid);
  oc_sec_cred_t *c = oc_sec_find_cred(uuid, dev);
  EXPECT_TRUE(c == NULL);
  oc_mem_free((void *)uuid);
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
#if !defined(OC_SPEC_VER_OIC)
TEST(Security, CredGet)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)oc_mem_malloc(OC_MAX_APP_DATA_SIZE);
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
  oc_mem_free(buf);

  oc_request_t *request = (oc_request_t *)oc_mem_malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)oc_mem_malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  oc_new_string(&request->resource->name, "cred", 5);
  request->response = (oc_response_t *)oc_mem_malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)oc_mem_malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)oc_mem_malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)oc_mem_malloc(request->query_len);
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
  oc_mem_free(request->response->response_buffer->buffer);
  oc_mem_free(request->response->response_buffer);
  oc_mem_free(request->response);
  oc_mem_free((void *)request->query);
  oc_mem_free(request);
}
#endif // OC_SPEC_VER_OIC
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
void
oc_sec_otm_err_cb(oc_sec_otm_err_code_t c)
{
  EXPECT_EQ(OC_SEC_ERR_ACL, c);
}
TEST(Security, OtmErr)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(dev);
  pstat->s = OC_DOS_RFNOP;
  oc_sec_otm_set_err_cb(oc_sec_otm_err_cb);
  oc_sec_otm_err(dev, OC_SEC_ERR_CRED);
  pstat->s = OC_DOS_RFOTM;
  oc_sec_otm_err(dev, OC_SEC_ERR_ACL);
  oc_sec_otm_set_err_cb(oc_sec_otm_err_cb);
  oc_sec_otm_set_err_cb(otm_err_cb);
}
TEST(Security, Pstat)
{
  oc_sec_pstat_t *ps = (oc_sec_pstat_t *)oc_mem_malloc(sizeof(oc_sec_pstat_t));
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
  uint8_t *buf = (uint8_t *)oc_mem_malloc(sz);
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
#ifdef OC_MFG
  oc_sec_load_mfg_certs(dev);
#endif /* OC_MFG */
  oc_free_rep(rep);
  oc_mem_free(buf);
}

#if !defined(OC_SPEC_VER_OIC)
TEST(Security, PstatSecReset)
{
  long ret = 0;
  oc_rep_t *rep;

  uint8_t *buf = (uint8_t *)oc_mem_malloc(OC_MAX_APP_DATA_SIZE);
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

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_request_t *request = (oc_request_t *)oc_mem_malloc(sizeof(oc_request_t));
  request->resource = (oc_resource_t *)oc_mem_malloc(sizeof(oc_resource_t));
  request->resource->device = dev;
  oc_new_string(&request->resource->name, "pstat", 5);
  request->response = (oc_response_t *)oc_mem_malloc(sizeof(oc_response_t));
  request->response->response_buffer =
    (oc_response_buffer_t *)oc_mem_malloc(sizeof(oc_response_buffer_t));
  request->response->response_buffer->response_length = 2048;
  request->response->response_buffer->buffer = (uint8_t *)oc_mem_malloc(
    request->response->response_buffer->response_length);
  request->query_len = 2048;
  request->query = (char *)oc_mem_malloc(request->query_len);
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
  oc_mem_free(buf);
  oc_free_rep(request->request_payload);
  oc_mem_free(request->response->response_buffer->buffer);
  oc_mem_free(request->response->response_buffer);
  oc_mem_free(request->response);
  oc_mem_free((void *)request->query);
  oc_mem_free(request);
}
#endif // !defined(OC_SPEC_VER_OIC)
TEST(Security, PstatOcSecReset)
{
  oc_sec_reset();
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
  char *svr_tag = (char *)oc_mem_malloc(SVR_TAG_MAX);
  gen_svr_tag("doxm", dev, svr_tag);
  EXPECT_STREQ("doxm_0", svr_tag);
  oc_mem_free(svr_tag);
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
//------------------------------------------TLS------------------------------------
#if defined(OC_TCP)
#endif // defined(OC_TLS)
TEST(Security, TlsIsPeerActive)
{
  EXPECT_FALSE(is_peer_active(NULL));
  oc_tls_peer_t *p = (oc_tls_peer_t *)oc_list_head(tls_peers);
  EXPECT_TRUE(is_peer_active(p));
}
TEST(Security, TlsFreePeer)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  OC_LIST_STRUCT_INIT(peer, send_q);
  oc_message_t *message = oc_allocate_message();
  EXPECT_TRUE(message);
  oc_list_push(peer->send_q, message);
  OC_LIST_STRUCT_INIT(peer, recv_q);
  oc_message_t *message1 = oc_allocate_message();
  EXPECT_TRUE(message1);
  oc_list_push(peer->recv_q, message1);
  oc_tls_free_peer(peer, true);
  EXPECT_TRUE(peer);
  peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  OC_LIST_STRUCT_INIT(peer, send_q);
  message = oc_allocate_message();
  EXPECT_TRUE(message);
  oc_list_push(peer->send_q, message);
  OC_LIST_STRUCT_INIT(peer, recv_q);
  EXPECT_TRUE(message);
  message1 = oc_allocate_message();
  EXPECT_TRUE(message1);
  oc_list_push(peer->recv_q, message1);
  oc_tls_free_peer(peer, false);
  EXPECT_TRUE(peer);
}
TEST(Security, TlsRemovePeer)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep);
  oc_tls_remove_peer(ep);
}
TEST(Security, TlsHandleSchdReadWrite)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  oc_tls_handler_schedule_read(peer);
  oc_tls_handler_schedule_write(peer);
}
TEST(Security, TlsInactive)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  oc_tls_inactive(peer);
  oc_mem_free(peer);
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_add_peer(ep, MBEDTLS_SSL_IS_SERVER);
  peer = oc_tls_get_peer(ep);
  EXPECT_TRUE(peer);
  peer->ssl_ctx.session =
    (mbedtls_ssl_session *)oc_mem_malloc(sizeof(mbedtls_ssl_session));
  ;
  mbedtls_ssl_session_init(peer->ssl_ctx.session);
  peer->ssl_ctx.session->ciphersuite =
    MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256;
  oc_tls_inactive(peer);
}
TEST(Security, TlsCloseConnection)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_close_connection(ep);
}
TEST(Security, TlsSslRecv)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  OC_LIST_STRUCT_INIT(peer, send_q);
  OC_LIST_STRUCT_INIT(peer, recv_q);
  oc_message_t *message = oc_allocate_message();
  EXPECT_TRUE(message);
  oc_list_push(peer->recv_q, message);
  size_t len = 512;
  unsigned char *buf = (unsigned char *)oc_mem_malloc(len);
  EXPECT_EQ(ssl_recv(peer, buf, len), 0);
  oc_mem_free(buf);
}
TEST(Security, TlsSslSend)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_mem_malloc(sizeof(oc_tls_peer_t));
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  memcpy(&peer->endpoint, oc_connectivity_get_endpoints(dev),
         sizeof(oc_endpoint_t));
  size_t len = 512;
  unsigned char *buf = (unsigned char *)oc_mem_malloc(len);
  EXPECT_EQ(ssl_send(peer, buf, len), len);
  oc_mem_free(buf);
}
TEST(Security, TlsCheckRetsTimers)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_add_peer(ep, MBEDTLS_SSL_IS_SERVER);

  check_retr_timers();
}
TEST(Security, TlsSetTimers)
{
  oc_tls_retr_timer_t *timer =
    (oc_tls_retr_timer_t *)oc_mem_malloc(sizeof(oc_tls_retr_timer_t));
  ssl_set_timer(timer, 100, 102);
  timer->fin_timer.timer.interval = 1;
  ssl_set_timer(timer, 100, 102);
}
TEST(Security, TlsGetPskCb)
{
  oc_uuid_t uuid;
  oc_str_to_uuid("11111111-1111-1111-1111-111111111111", &uuid);
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_list_head(tls_peers);
  EXPECT_EQ(get_psk_cb(0, &peer->ssl_ctx, (const unsigned char *)&uuid, 16),
            -1);
}
TEST(Security, TlsPrf)
{
  uint8_t secret[48];
  uint8_t output[48];
  EXPECT_EQ(oc_tls_prf(secret, sizeof(secret), output, sizeof(output), 0), 48);
}
TEST(Security, TlsSecDeriveOwnerPsk)
{
  uint8_t key[16];
  uint8_t oxm[16];
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_add_peer(ep, MBEDTLS_SSL_IS_SERVER);
  oc_tls_peer_t *peer = oc_tls_get_peer(ep);
  for (int i = 0; i < 48; i++) {
    peer->master_secret[i] = rand();
    peer->client_server_random[i] = rand();
  }
  peer->ssl_ctx.session =
    (mbedtls_ssl_session *)oc_mem_malloc(sizeof(mbedtls_ssl_session));
  mbedtls_ssl_session_init(peer->ssl_ctx.session);
  peer->ssl_ctx.session->ciphersuite =
    MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256;
  oc_uuid_t server_uuid, obt_uuid;
  oc_str_to_uuid("11111111-1111-1111-1111-111111111111", &server_uuid);
  oc_str_to_uuid("11111111-1111-1111-1111-111111111110", &obt_uuid);
  EXPECT_TRUE(oc_sec_derive_owner_psk(
    ep, oxm, sizeof(oxm), (const uint8_t *)&server_uuid, 16,
    (const uint8_t *)&obt_uuid, 16, key, sizeof(key)));
}
TEST(Security, TlsSendMessage)
{
  oc_message_t *message = oc_allocate_message();
  EXPECT_TRUE(message);
  memcpy(&message->endpoint, oc_connectivity_get_endpoints(dev),
         sizeof(oc_endpoint_t));
  EXPECT_EQ(oc_tls_send_message(message), 0);
}
TEST(Security, TlsWriteAppData)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_list_head(tls_peers);
  EXPECT_TRUE(peer);
  mbedtls_ssl_init(&peer->ssl_ctx);
  OC_LIST_STRUCT_INIT(peer, send_q);
  oc_message_t *message = oc_allocate_message();
  EXPECT_TRUE(message);
  oc_list_push(peer->send_q, message);

  write_application_data(peer);
}
TEST(Security, TlsElevateAnon)
{
  oc_tls_elevate_anon_ciphersuite();
  oc_tls_demote_anon_ciphersuite();
}
TEST(Security, TlsInitConnection)
{
  oc_message_t *message = oc_allocate_message();
  EXPECT_TRUE(message);
  memcpy(&message->endpoint, oc_connectivity_get_endpoints(dev),
         sizeof(oc_endpoint_t));
  oc_tls_init_connection(message);
}
TEST(Security, TlsConnected)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep);
  EXPECT_FALSE(oc_tls_connected(ep));
}
TEST(Security, TlsReadApplicationData)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(dev);
  EXPECT_TRUE(ep != NULL);
  oc_tls_add_peer(ep, MBEDTLS_SSL_IS_SERVER);
  oc_tls_peer_t *peer = oc_tls_get_peer(ep);
  peer->ssl_ctx.session =
    (mbedtls_ssl_session *)oc_mem_malloc(sizeof(mbedtls_ssl_session));
  ;
  mbedtls_ssl_session_init(peer->ssl_ctx.session);
  peer->ssl_ctx.session->ciphersuite =
    MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256;
  peer->ssl_ctx.state = MBEDTLS_SSL_HANDSHAKE_OVER;
  read_application_data(peer);
}
#if defined(OC_RPK)
void
get_cpubkey_and_token(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token,
                      int *token_len)
{
  if (!cpubkey || !cpubkey_len || !token || !token_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t key[32] = { 0x41, 0x97, 0x77, 0x33, 0x6e, 0xea, 0x62, 0x6c,
                      0x5d, 0x89, 0x2e, 0x50, 0x21, 0x94, 0x74, 0xcc,
                      0x50, 0x24, 0x00, 0x84, 0x42, 0x24, 0x13, 0xeb,
                      0x64, 0xab, 0x2e, 0xe7, 0x53, 0x28, 0x71, 0x40 };
  uint8_t tkn[8] = "12345678";
  memcpy(cpubkey, key, 32);
  memcpy(token, tkn, 8);
  *cpubkey_len = 32;
  *token_len = 8;
  return;
}

void
get_own_key(uint8_t *priv_key, int *priv_key_len, uint8_t *pub_key,
            int *pub_key_len)
{
  if (!priv_key || !priv_key_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
  uint8_t prv[32] = { 0x46, 0x70, 0x85, 0x56, 0xf4, 0x54, 0xdc, 0x63,
                      0xaa, 0xb9, 0x20, 0xfc, 0x8a, 0xc7, 0x59, 0xf4,
                      0xf4, 0x6e, 0x37, 0x64, 0xcc, 0x8e, 0xa2, 0xb5,
                      0x39, 0xe9, 0xe9, 0xb2, 0x69, 0xcd, 0x91, 0x28 };
  uint8_t pub[32] = { 0x67, 0x32, 0x94, 0x85, 0xcf, 0x46, 0x0f, 0x92,
                      0x4c, 0x77, 0x18, 0x05, 0xbb, 0xda, 0x7a, 0x50,
                      0x17, 0xfe, 0xfa, 0x72, 0xc4, 0x51, 0x42, 0x89,
                      0xa7, 0x3c, 0xc1, 0xcd, 0x23, 0x43, 0x54, 0xed };
  memcpy(priv_key, prv, 32);
  memcpy(pub_key, pub, 32);
  *priv_key_len = 32;
  *pub_key_len = 32;
  return;
}
TEST(Security, TlsGenMasterKey)
{
  uint8_t master[32];
  int len = 0;
  EXPECT_FALSE(gen_master_key(master, &len));
  EXPECT_EQ(0, len);
  oc_sec_set_cpubkey_and_token_load(get_cpubkey_and_token);
  oc_sec_set_own_key_load(get_own_key);
  EXPECT_TRUE(gen_master_key(master, &len));
  EXPECT_EQ(32, len);
}
TEST(Security, TlsGetRptPsk)
{
  unsigned char psk[16] = { 0x0 };
  int psk_len = 0;
  EXPECT_TRUE(oc_sec_get_rpk_psk(dev, psk, &psk_len));
  EXPECT_EQ(16, psk_len);
  for (int i = 0; i < psk_len; i++) {
    EXPECT_NE(0, psk[i]);
  }
}
#endif // OC_RPK
TEST(Security, TlsShutdown)
{
  oc_tls_shutdown();
}
TEST(Security, Clear)
{
  unlink("unittest_creds/acl_0");
  unlink("unittest_creds/cred_0");
  unlink("unittest_creds/doxm_0");
  unlink("unittest_creds/pstat_0");
  unlink("unittest_creds/u_ids_0");
  rmdir("unittest_creds/");
}
#endif // defined(OC_SECURITY)
