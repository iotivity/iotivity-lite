/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifdef OC_SECURITY
#include "st_security.h"
#endif
#include "oc_rep.h"
#include "port/oc_storage.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "st_store.h"
#include "util/oc_mem.h"

#define ST_MAX_DATA_SIZE (1024)
#define ST_STORE_NAME "st_info"

#define st_rep_set_string_with_chk(object, key, value)                         \
  if (value)                                                                   \
    oc_rep_set_text_string(object, key, value);

static st_store_t g_store_info;

static void st_encode_store_data_info(unsigned char *encrypted_data,
                                      int encrypted_data_len);
static int st_decode_store_data_info(oc_rep_t *rep);

#ifdef STORE_ENCRYPT
#define ST_STORE_SECURE_NAME "st_info_secure"
#define ST_SALT_LEN (32)
#define ST_IV_LEN (16)

static void st_encode_security_info(uint8_t *buf);
static void st_encode_cloud_accesspoint_info(void);
static int st_decode_security_info(oc_rep_t *rep);
#endif /* STORE_ENCRYPT */

typedef int (*st_store_load_handler_t)(oc_rep_t *rep);
typedef void (*st_store_dump_handler_t)(uint8_t *buf);

static int
st_store_load_internal(char *store_name, st_store_load_handler_t decode_handler)
{
  if (!store_name || !decode_handler) {
    return -1;
  }

  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf) {
    st_print_log("[ST_STORE] alloc failed!\n");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
#ifdef OC_SECURITY
  size = oc_storage_read(store_name, buf, ST_MAX_DATA_SIZE);
#else
  (void)store_name;
#endif /* OC_SECURITY */
  if (size > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
    oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                   rep_objects_alloc, (void *)rep_objects_pool,
                                   0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)size, &rep);
    ret = decode_handler(rep);
    oc_rep_set_pool(&rep_objects); // Reset representation pool
    oc_free_rep(rep);
  } else {
    st_store_info_initialize();
    ret = -2;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

int
st_store_load(void)
{
  int ret = 0;
#ifdef STORE_ENCRYPT
  ret = st_store_load_internal(ST_STORE_SECURE_NAME, st_decode_security_info);
  if (ret == -2) {
    st_print_log("[ST_Store] we don't need to load %s\n", ST_STORE_NAME);
    return 0;
  }
#endif /* STORE_ENCRYPT */

  ret = st_store_load_internal(ST_STORE_NAME, st_decode_store_data_info);
  if (ret == -2) {
    st_print_log("[ST_Store] we don't need to load %s\n", ST_STORE_NAME);
    return 0;
  }

  return ret;
}

static int
st_store_dump_internal(char *store_name, st_store_dump_handler_t encode_handler)
{
  if (!store_name || !encode_handler) {
    return -1;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return -1;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  encode_handler(buf);
  int size = oc_rep_finalize();
#ifdef OC_SECURITY
  if (size > 0) {
    oc_storage_write(store_name, buf, size);
  }
#else  /* OC_SECURITY */
  (void)store_name;
#endif /* !OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_reset();

  return size;
}

static void
st_encode_data_info(uint8_t *buf)
{
  oc_rep_new(buf, ST_MAX_DATA_SIZE);

#ifdef OC_DYNAMIC_ALLOCATION
  unsigned char *encrypted_data = NULL;
#else /* OC_DYNAMIC_ALLOCATION */
  unsigned char encrypted_data[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  unsigned int encrypted_data_len = 0;

#ifdef STORE_ENCRYPT
  // Dumping cloud and accesspoint information.
  st_encode_cloud_accesspoint_info();
  int size = oc_rep_finalize();
  if (size <= 0 || size == 2)
    return;

  encrypted_data_len = size + 16;
#ifdef OC_DYNAMIC_ALLOCATION
  encrypted_data = oc_mem_malloc(encrypted_data_len);
#endif /* OC_DYNAMIC_ALLOCATION */

  g_store_info.securityinfo.data_len = size;

#ifdef OC_SECURITY
  // Encrypting cloud info and accesspoint info.
  st_security_encrypt(buf, size, encrypted_data, &encrypted_data_len);
  st_print_log("[ST_Store] encrypted data len %d\n", encrypted_data_len);
  g_store_info.securityinfo.encrypted_len = encrypted_data_len;
#else  /* OC_SECURITY */
  st_print_log("[ST_Store] non-secure build can't encrypt data\n");
  goto exit;
#endif /* !OC_SECURITY */

  oc_rep_reset();
#endif /* STORE_ENCRYPT */

  // Encoding encrypted data along with status and cloud status.
  st_encode_store_data_info(encrypted_data, encrypted_data_len);

#ifndef OC_SECURITY
exit:
#endif /* !OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  if (encrypted_data)
    oc_mem_free(encrypted_data);
#endif /* OC_DYNAMIC_ALLOCATION */
}

int
st_store_dump(void)
{
  int ret = 0;
  // Calling dump for cloud and access point info
  ret = st_store_dump_internal(ST_STORE_NAME, st_encode_data_info);
  if (ret < 0)
    return ret;

#ifdef STORE_ENCRYPT
  // Calling dump for salt and iv
  ret = st_store_dump_internal(ST_STORE_SECURE_NAME, st_encode_security_info);
#endif /* STORE_ENCRYPT */

  return ret;
}

static oc_event_callback_retval_t
st_store_dump_handler(void *data)
{
  (void)data;
  st_store_dump();
  return OC_EVENT_DONE;
}

void
st_store_dump_async(void)
{
  oc_set_delayed_callback(NULL, st_store_dump_handler, 0);
  _oc_signal_event_loop();
}

void
st_store_info_initialize(void)
{
  g_store_info.status = false;
  if (oc_string(g_store_info.accesspoint.ssid)) {
    oc_free_string(&g_store_info.accesspoint.ssid);
  }
  if (oc_string(g_store_info.accesspoint.pwd)) {
    oc_free_string(&g_store_info.accesspoint.pwd);
  }
  if (oc_string(g_store_info.cloudinfo.ci_server)) {
    oc_free_string(&g_store_info.cloudinfo.ci_server);
  }
  if (oc_string(g_store_info.cloudinfo.auth_provider)) {
    oc_free_string(&g_store_info.cloudinfo.auth_provider);
  }
  if (oc_string(g_store_info.cloudinfo.uid)) {
    oc_free_string(&g_store_info.cloudinfo.uid);
  }
  if (oc_string(g_store_info.cloudinfo.access_token)) {
    oc_free_string(&g_store_info.cloudinfo.access_token);
  }
  if (oc_string(g_store_info.cloudinfo.refresh_token)) {
    oc_free_string(&g_store_info.cloudinfo.refresh_token);
  }
#ifdef STORE_ENCRYPT
  if (oc_string(g_store_info.securityinfo.salt)) {
    oc_free_string(&g_store_info.securityinfo.salt);
  }
  if (oc_string(g_store_info.securityinfo.iv)) {
    oc_free_string(&g_store_info.securityinfo.iv);
  }
  g_store_info.securityinfo.data_len =0;
  g_store_info.securityinfo.encrypted_len = 0;
#endif /* STORE_ENCRYPT */
  g_store_info.cloudinfo.status = 0;
}

st_store_t *
st_store_get_info(void)
{
  return &g_store_info;
}

#ifdef STORE_ENCRYPT
static int
st_decode_security_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_BYTE_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "salt", 4) == 0) {
        oc_new_string(&g_store_info.securityinfo.salt,
                      oc_string(t->value.string),
                      ST_SALT_LEN);
      } else if (len == 2 && memcmp(oc_string(t->name), "iv", 2) == 0) {
        oc_new_string(&g_store_info.securityinfo.iv,
                      oc_string(t->value.string),
                      ST_IV_LEN);
      } else {
        st_print_log("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_INT:
      if (len == 8 && memcmp(oc_string(t->name), "data_len", 8) == 0) {
        g_store_info.securityinfo.data_len= t->value.integer;
      } else if (len == 13 && memcmp(oc_string(t->name), "encrypted_len", 13) == 0) {
        g_store_info.securityinfo.encrypted_len= t->value.integer;
      } else {
        st_print_log("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      st_print_log("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }
  return 0;
}
#endif /* STORE_ENCRYPT */

static int
st_decode_cloud_accesspoint_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
      case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "ssid", 4) == 0) {
        oc_new_string(&g_store_info.accesspoint.ssid,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "pwd", 3) == 0) {
        oc_new_string(&g_store_info.accesspoint.pwd, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 9 && memcmp(oc_string(t->name), "ci_server", 9) == 0) {
        oc_new_string(&g_store_info.cloudinfo.ci_server,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "auth_provider", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.auth_provider,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 3 && memcmp(oc_string(t->name), "uid", 3) == 0) {
        oc_new_string(&g_store_info.cloudinfo.uid, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 12 &&
                 memcmp(oc_string(t->name), "access_token", 12) == 0) {
        oc_new_string(&g_store_info.cloudinfo.access_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 13 &&
                 memcmp(oc_string(t->name), "refresh_token", 13) == 0) {
        oc_new_string(&g_store_info.cloudinfo.refresh_token,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    default:
      OC_ERR("[ST_Store] Unknown property %s", oc_string(t->name));
      return -1;
    }
    t = t->next;
  }
  return 0;
}

#ifdef STORE_ENCRYPT
static void
decode_encrypted_data_info(oc_rep_t *rep)
{
  oc_rep_t *rep_internal;
  st_security_store_t securityinfo = g_store_info.securityinfo;
  unsigned int decrypted_buff_len = ST_MAX_DATA_SIZE;
#ifdef OC_DYNAMIC_ALLOCATION
  unsigned char *decrypted_buff = (unsigned char *)malloc(decrypted_buff_len);
#else /* OC_DYNAMIC_ALLOCATION */
  unsigned char decrypted_buff[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_SECURITY
  // Decrypting data.
  st_security_decrypt(oc_cast(securityinfo.salt, unsigned char),
                      oc_cast(securityinfo.iv, unsigned char),
                      oc_cast(rep->value.string, unsigned char),
                      securityinfo.encrypted_len, decrypted_buff,
                      &decrypted_buff_len);
#else  /* OC_SECURITY */
  st_print_log("[ST_Store] non-secure build can't decrypt data\n");
  goto exit;
#endif /* !OC_SECURITY */
#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc2[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool2[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc2, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool2, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects2 = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                  rep_objects_alloc2, (void *)rep_objects_pool2,
                                  0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
  struct oc_memb rep_objects2 = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_set_pool(&rep_objects2);
  oc_parse_rep(decrypted_buff, (uint16_t)decrypted_buff_len, &rep_internal);
  // Decoding decrypted data and fetching cloud and accesspoint info.
  st_decode_cloud_accesspoint_info(rep_internal);
  oc_free_rep(rep_internal);

#ifndef OC_SECURITY
exit:
#endif /* !OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(decrypted_buff);
#endif /* OC_DYNAMIC_ALLOCATION */
}
#endif /* STORE_ENCRYPT */

static int
st_decode_store_data_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_BOOL:
      if (len == 6 && memcmp(oc_string(t->name), "status", 6) == 0) {
        g_store_info.status = t->value.boolean;
      }
    case OC_REP_INT:
      if (len == 11 && memcmp(oc_string(t->name), "cloudstatus", 11) == 0) {
        g_store_info.cloudinfo.status = t->value.integer;
      }
      break;
#ifdef STORE_ENCRYPT
    case OC_REP_BYTE_STRING:
#else  /* STORE_ENCRYPT */
    case OC_REP_OBJECT:
#endif /* !STORE_ENCRYPT */
      if (len == 4 && memcmp(oc_string(t->name), "data", 4) == 0) {
#ifdef STORE_ENCRYPT
        decode_encrypted_data_info(t);
#else /* STORE_ENCRYPT */
        st_decode_cloud_accesspoint_info(t->value.object);
#endif /* !STORE_ENCRYPT */
      }
      break;
    default:
      st_print_log("[ST_Store] Unknown property %s, %d", oc_string(t->name), t->type);
      return -1;
    }
    t = t->next;
  }

  return 0;
}

#ifdef STORE_ENCRYPT
static void
st_encode_security_info(uint8_t *buf)
{
  oc_rep_new(buf, ST_MAX_DATA_SIZE);
  oc_rep_start_root_object();
  if (oc_string_len(g_store_info.securityinfo.salt) > 0) {
    oc_rep_set_byte_string(root, salt,
                           oc_cast(g_store_info.securityinfo.salt, uint8_t),
                           ST_SALT_LEN);
  }
  if (oc_string_len(g_store_info.securityinfo.iv) > 0) {
    oc_rep_set_byte_string(
      root, iv, oc_cast(g_store_info.securityinfo.iv, uint8_t), ST_IV_LEN);
  }
  oc_rep_set_int(root, data_len, g_store_info.securityinfo.data_len);
  oc_rep_set_int(root, encrypted_len, g_store_info.securityinfo.encrypted_len);
  oc_rep_end_root_object();
}
#endif /* STORE_ENCRYPT */

static void
encode_cloud_accesspoint_with_map(CborEncoder *object_map)
{
  st_rep_set_string_with_chk(*object, ssid,
                             oc_string(g_store_info.accesspoint.ssid));
  st_rep_set_string_with_chk(*object, pwd,
                             oc_string(g_store_info.accesspoint.pwd));
  st_rep_set_string_with_chk(*object, ci_server,
                             oc_string(g_store_info.cloudinfo.ci_server));
  st_rep_set_string_with_chk(*object, auth_provider,
                             oc_string(g_store_info.cloudinfo.auth_provider));
  st_rep_set_string_with_chk(*object, uid,
                             oc_string(g_store_info.cloudinfo.uid));
  st_rep_set_string_with_chk(*object, access_token,
                             oc_string(g_store_info.cloudinfo.access_token));
  st_rep_set_string_with_chk(*object, refresh_token,
                             oc_string(g_store_info.cloudinfo.refresh_token));
}

#ifdef STORE_ENCRYPT
static void
st_encode_cloud_accesspoint_info(void)
{
  oc_rep_start_root_object();
  encode_cloud_accesspoint_with_map(&root_map);
  oc_rep_end_root_object();
}
#endif /* STORE_ENCRYPT */

static void
st_encode_store_data_info(unsigned char *encrypted_data, int encrypted_data_len)
{
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, status, g_store_info.status);
  oc_rep_set_int(root, cloudstatus, g_store_info.cloudinfo.status);
#ifdef STORE_ENCRYPT
  if (encrypted_data)
    oc_rep_set_byte_string(root, data, encrypted_data, encrypted_data_len);
#else  /* STORE_ENCRYPT */
  (void)encrypted_data;
  (void)encrypted_data_len;
  oc_rep_set_object(root, data);
  encode_cloud_accesspoint_with_map(&data_map);
  oc_rep_close_object(root, data);
#endif /* !STORE_ENCRYPT */
  oc_rep_end_root_object();
}
