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

#include "st_store.h"
#include "oc_rep.h"
#include "port/oc_storage.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "util/oc_mem.h"

#define ST_MAX_DATA_SIZE (1024)
#define ST_MAX_SECURE_DATA_SIZE (100)
#define ST_STORE_NAME "st_info"
#define ST_STORE_SECURE_NAME "st_info_secure"

#define st_rep_set_string_with_chk(object, key, value)                         \
  if (value)                                                                   \
    oc_rep_set_text_string(object, key, value);

static st_store_t g_store_info;

static int st_decode_store_info(oc_rep_t *rep, unsigned char *decrypted_buff, unsigned int *decrypted_buff_len);
static void st_encode_store_info(unsigned char *encrypted_data);
static void st_encode_security_info(void);
static int st_decode_security_info(oc_rep_t *rep);
static int st_decode_encrypted_store_info(oc_rep_t *rep);

int
st_store_load_internal(int secure , char *store_name,int data_size)
{
  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(data_size);
  if (!buf) {
    st_print_log("[ST_STORE] alloc failed!\n");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[data_size];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
#ifdef OC_SECURITY
  size = oc_storage_read(store_name, buf, data_size);
#endif
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
    if(secure == 1){
      ret = st_decode_security_info(rep);
      oc_free_rep(rep);
    }else{
      unsigned char *decrypted_buff;
      unsigned int decrypted_buff_len;
      st_security_store_t securityinfo = g_store_info.securityinfo;
      decrypted_buff_len = securityinfo.data_len;
      oc_rep_t *rep_internal;
      decrypted_buff = (unsigned char *)malloc(decrypted_buff_len);
      ret = st_decode_store_info(rep,decrypted_buff,&decrypted_buff_len);
      oc_free_rep(rep);

#ifndef OC_DYNAMIC_ALLOCATION
      char rep_objects_alloc2[OC_MAX_NUM_REP_OBJECTS];
      oc_rep_t rep_objects_poo2l[OC_MAX_NUM_REP_OBJECTS];
      memset(rep_objects_alloc2, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
      memset(rep_objects_poo2l, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
      struct oc_memb rep_objects2 = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                         rep_objects_alloc, (void *)rep_objects_pool,
                         0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
      struct oc_memb rep_objects2 = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_rep_set_pool(&rep_objects2);
      oc_parse_rep(decrypted_buff, (uint16_t)decrypted_buff_len, &rep_internal);
      st_decode_encrypted_store_info(rep_internal);
      oc_free_rep(rep_internal);
      oc_mem_free(decrypted_buff);
    }
  } else {
    st_store_info_initialize();
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}
int
st_store_load(void)
{
int ret =0;
ret= st_store_load_internal(1,ST_STORE_SECURE_NAME,ST_MAX_DATA_SIZE);
ret = st_store_load_internal(0,ST_STORE_NAME,ST_MAX_DATA_SIZE);

  return ret;
}
int
st_store_secure_dump()
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return -1;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, ST_MAX_DATA_SIZE);
 st_encode_security_info();

  int size = -1;
#ifdef OC_SECURITY
  size = oc_rep_finalize();
  if (size > 0) {
    oc_storage_write(ST_STORE_SECURE_NAME, buf, size);
  }

#endif /* OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_reset();

  return size;
}

st_store_dump_internal()
{
  unsigned char *encrypted_data= NULL;
  unsigned int encrypted_data_len;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return -1;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, ST_MAX_DATA_SIZE);
  oc_rep_start_root_object();
  st_rep_set_string_with_chk(root, ssid,
                             oc_string(g_store_info.accesspoint.ssid));
  st_rep_set_string_with_chk(root, pwd,
                             oc_string(g_store_info.accesspoint.pwd));
  st_rep_set_string_with_chk(root, ci_server,
                             oc_string(g_store_info.cloudinfo.ci_server));
  st_rep_set_string_with_chk(root, auth_provider,
                             oc_string(g_store_info.cloudinfo.auth_provider));
  st_rep_set_string_with_chk(root, uid,
                             oc_string(g_store_info.cloudinfo.uid));
  st_rep_set_string_with_chk(root, access_token,
                             oc_string(g_store_info.cloudinfo.access_token));
  st_rep_set_string_with_chk(root, refresh_token,
                             oc_string(g_store_info.cloudinfo.refresh_token));
  oc_rep_end_root_object();

  int size =-1;
#ifdef OC_SECURITY
 size = oc_rep_finalize();
  if (size > 0 && size !=2) {

    encrypted_data_len = size + 16;
    encrypted_data= (unsigned char *)malloc(encrypted_data_len);
    g_store_info.securityinfo.data_len = size;

    st_security_encrypt(buf,size, encrypted_data, &encrypted_data_len);
    st_print_log("[ST_Store] encrypted token len%d\n", encrypted_data_len);
    g_store_info.securityinfo.encrypted_len= encrypted_data_len;
  }

  oc_rep_reset();
#endif /* OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  st_encode_store_info(encrypted_data);
  if(encrypted_data)
    oc_mem_free(encrypted_data);

  return size;
}

int
st_store_dump(void)
{
int ret =0;
  ret = st_store_dump_internal();
  if(ret < 0 )
    return -1;

  ret = st_store_secure_dump();
    if(ret < 0 )
    return -1;

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
  if (oc_string(g_store_info.securityinfo.salt)) {
    oc_free_string(&g_store_info.securityinfo.salt);
  }
  if (oc_string(g_store_info.securityinfo.iv)) {
    oc_free_string(&g_store_info.securityinfo.iv);
  }
  g_store_info.cloudinfo.status = 0;
}

st_store_t *
st_store_get_info(void)
{
  return &g_store_info;
}

static int
st_decode_security_info(oc_rep_t *rep)
{
  oc_rep_t *t = rep;
  int len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "salt", 4) == 0) {
        oc_new_string(&g_store_info.securityinfo.salt,
                      oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else if (len == 2 && memcmp(oc_string(t->name), "iv", 2) == 0) {
        oc_new_string(&g_store_info.securityinfo.iv, oc_string(t->value.string),
                      oc_string_len(t->value.string));
      } else {
        st_print_log("[ST_Store] Unknown property %s", oc_string(t->name));
        return -1;
      }
      break;
    case OC_REP_INT:
      if (len == 8 && memcmp(oc_string(t->name), "data_len", 8) == 0) {
        g_store_info.securityinfo.data_len= t->value.integer;
      }else if (len == 13 && memcmp(oc_string(t->name), "encrypted_len", 13) == 0) {
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

static int st_decode_encrypted_store_info(oc_rep_t *rep)
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
      }else {
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
  }

static int
st_decode_store_info(oc_rep_t *rep, unsigned char *decrypted_buff, unsigned int *decrypted_buff_len)
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
    case OC_REP_STRING:
      if (len == 4 && memcmp(oc_string(t->name), "data", 4) == 0) {

        unsigned char *buff;
        st_security_store_t securityinfo = g_store_info.securityinfo;
        unsigned int buff_len =ST_MAX_DATA_SIZE;
        buff = (unsigned char *)malloc(buff_len);

        st_security_decrypt(oc_string(securityinfo.salt),oc_string(securityinfo.iv),
                      oc_string(t->value.string),
                      securityinfo.encrypted_len,
                      buff,
                      &buff_len);
        memcpy(decrypted_buff,buff,buff_len);
        *decrypted_buff_len= buff_len;
        oc_mem_free(buff);
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

static void
st_encode_security_info(void)
{
  oc_rep_start_root_object();
  st_rep_set_string_with_chk(root, salt,
                             oc_string(g_store_info.securityinfo.salt));
  st_rep_set_string_with_chk(root, iv,
                             oc_string(g_store_info.securityinfo.iv));
  oc_rep_set_int(root, data_len, g_store_info.securityinfo.data_len);
  oc_rep_set_int(root, encrypted_len, g_store_info.securityinfo.encrypted_len);
    oc_rep_end_root_object();
}

static void
st_encode_store_info(unsigned char *encrypted_data)
{
  #ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return ;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, ST_MAX_DATA_SIZE);
  oc_rep_start_root_object();
  oc_rep_set_boolean(root, status, g_store_info.status);
  oc_rep_set_int(root, cloudstatus, g_store_info.cloudinfo.status);
  st_rep_set_string_with_chk(root, data,encrypted_data);
  oc_rep_end_root_object();

    int size = -1;
#ifdef OC_SECURITY
  size = oc_rep_finalize();
  if (size > 0) {
    oc_storage_write(ST_STORE_NAME, buf, size);
  }

#endif /* OC_SECURITY */
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_reset();

}
