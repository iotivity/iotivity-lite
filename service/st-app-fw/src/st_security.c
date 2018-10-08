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

#define ST_SECURITY_DEBUG
#ifdef ST_SECURITY_DEBUG
static void _print_binary_to_hex(const char* name, const unsigned char* buffer, int buffer_len)
{
  char buffer_hex[81] = {0};
  int i;
  int j;

  st_print_log("%s(%d) = \n", name, buffer_len);
  for(i=1, j=0; i<=buffer_len; i++, j++){

    sprintf(buffer_hex + 2*j, "%02x", buffer[i-1]);

    if(i % 40 == 0){
      st_print_log(" - %s\n", buffer_hex);
      memset(buffer_hex, 0, sizeof(buffer_hex));
      j = -1;
    }
  }
  st_print_log(" - %s\n", buffer_hex);
}
#endif

// Generate random number
int gen_random(unsigned char* random, unsigned int random_len)
{
  int ret = 0;
   unsigned char mac[6] = { 0 };

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init( &entropy );

   if (!oc_get_mac_addr(mac)) {
    st_print_log("[ST_SEC] oc_get_mac_addr failed!\n");
    goto cleanup;
  }

  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)mac, 6);
  if(ret != 0)
  {
    st_print_log("[ST_SEC]failed in mbedtls_ctr_drbg_seed: %d\n", ret );
    goto cleanup;
  }

  mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );

  ret = mbedtls_ctr_drbg_random(&ctr_drbg, random, random_len);
  if(ret != 0)
  {
    st_print_log("[ST_SEC]failed in mbedtls_ctr_drbg_random: %d\n", ret);
    goto cleanup;
  }

  _print_binary_to_hex("random on initial(encrypt)", random, random_len);

 cleanup:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}

int pbkdf2(const unsigned char *password, unsigned char* key,unsigned char * salt)
{
  int ret = 0;

  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info;
  mbedtls_md_init(&ctx);

  info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(info == NULL)
  {
    st_print_log("[ST_SEC]failed in mbedtls_md_info_from_type\n");
    goto cleanup;
  }

  ret = mbedtls_md_setup(&ctx, info, 1);
  if(ret != 0)
  {
    st_print_log("[ST_SEC]failed in mbedtls_md_setup: %d", ret);
    goto cleanup;
  }

  ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, password, strlen(password), salt, 32, 1000, 32, key);
  if(ret != 0)
  {
    st_print_log("[ST_SEC]failed in mbedtls_pkcs5_pbkdf2_hmac: %d", ret);
    goto cleanup;
  }

 cleanup:
  mbedtls_md_free(&ctx);

  return ret;
}

int aes_encrypt(const unsigned char* key, unsigned char* iv, const unsigned char* data, const unsigned int data_len, unsigned char* encrypted_data, unsigned int* encrypted_data_len)
{
  int ret = 0;

  unsigned char temp_iv[16] = {0};
  unsigned char* padded_data = NULL;
  unsigned int padded_data_len;
  unsigned int padding_len;

  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init(&aes_ctx);

  // Use temp_iv because mbedtls_aes_crypt_cbc change iv param
  memcpy(temp_iv, iv, 16);

  padding_len = 16 - (data_len % 16);

  padded_data_len = data_len + padding_len;

  padded_data = (unsigned char*)malloc(padded_data_len);
  // Set PKCS7 padding
  memset(padded_data, padding_len, padded_data_len);
  memcpy(padded_data, data, data_len);

  // Set 256 bit (32 byte) key
  mbedtls_aes_setkey_enc(&aes_ctx, key, 256);
  ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_data_len, temp_iv, padded_data, encrypted_data);
  if(ret != 0)
  {
    st_print_log("[ST_SEC] failed in mbedtls_aes_crypt_cbc during aes_encrypt(): %d\n", ret);
    goto cleanup;
  }

  *encrypted_data_len = padded_data_len;

  st_print_log("[ST_SEC] encrypted_data_len %d \n",*encrypted_data_len);

 cleanup:
  mbedtls_aes_free(&aes_ctx);

  return ret;
}


int aes_decrypt(const unsigned char* key, const unsigned char* iv, unsigned char* encrypted_data, unsigned int encrypted_data_len, unsigned char* decrypted_data, unsigned int* decrypted_data_len)
{
  int ret = 0;
  unsigned char i = 0;
  unsigned char padding_len = 0;
    unsigned char temp_iv[16] = {0};

  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init(&aes_ctx);
  memcpy(temp_iv, iv, 16);

  // Set 256 bit (32 byte) key
  mbedtls_aes_setkey_dec(&aes_ctx, key, 256);
  ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_data_len, temp_iv, encrypted_data, decrypted_data);
  if(ret != 0)
  {
    st_print_log("[ST_SEC]failed in mbedtls_aes_crypt_cbc during aes_decrypt(): %d\n", ret);
    goto cleanup;
  }

  padding_len = decrypted_data[encrypted_data_len - 1];
  st_print_log("[ST_SEC]padding len = 0x%02x\n", padding_len);

  // Checking PKCS7 padding
  for(i = 1; i<= padding_len; i++){
    if(padding_len != decrypted_data[encrypted_data_len - i]){
      st_print_log("Invalid padding\n");
      ret = -1;
      goto cleanup;
      break;
    }
  }

  st_print_log("Remove padding\n");
  *decrypted_data_len = encrypted_data_len - padding_len;

 cleanup:
  mbedtls_aes_free(&aes_ctx);

  return ret;
}
int st_security_encrypt(const unsigned char* data, const unsigned int data_len, unsigned char* encrypted_data, unsigned int* encrypted_data_len)
{
  unsigned char key[32] = {0};
  unsigned char mac[6+1] = { 0 };
  char iv_internal[16] = {0};
  char salt_internal[32] = {0};
  int ret = 0;

  st_store_t *store_info = st_store_get_info();
  //Check if already exists
  if(oc_string_len(store_info->securityinfo.iv) == 0 && oc_string_len(store_info->securityinfo.salt)==0){

    ret = gen_random(salt_internal, 32);
    if(ret != 0)
    {
     st_print_log("[ST_SEC]failed in gen_random: %d\n", ret);
     return -1;
    }

    // Use random 16 byte for iv
    ret = gen_random(iv_internal, 16);
    if(ret != 0)
    {
      st_print_log("[ST_SEC]failed in gen_random: %d\n", ret);
      return -1;
    }
      //Dumping security info
    oc_new_string(&store_info->securityinfo.salt, salt_internal, 32);
    oc_new_string(&store_info->securityinfo.iv, iv_internal, 16);
    st_store_dump_async();

  }else {
    st_print_log("[ST_SEC] Encryption details already exist!\n");
    memcpy(iv_internal, oc_string(store_info->securityinfo.iv), 16);
    memcpy(salt_internal, oc_string(store_info->securityinfo.salt), 32);
  }

  if (!oc_get_mac_addr(mac)) {
  st_print_log("[ST_ES] oc_get_mac_addr failed!\n");
  return -1;
  }

  // Generate 32 byte key
  pbkdf2(mac, key, salt_internal);

#ifdef ST_SECURITY_DEBUG
    _print_binary_to_hex("iv on initial(encrypt)", iv_internal, 16);
    _print_binary_to_hex("salt on initial(encrypt)", salt_internal, 32);
    _print_binary_to_hex("key on initial(encrypt)", key, 32);
#endif

  ret = aes_encrypt(key, iv_internal, data, data_len, encrypted_data, encrypted_data_len);

  return ret;
}

int st_security_decrypt(unsigned char *salt,unsigned char *iv, unsigned char* encrypted_data, unsigned int encrypted_data_len, unsigned char* decrypted_data, unsigned int* decrypted_data_len)
{
  unsigned char key[32] = {0};
  unsigned char mac[6+1] = { 0 };
  int ret = 0;

  if (!oc_get_mac_addr(mac)) {
    st_print_log("[ST_ES] oc_get_mac_addr failed!\n");
    return -1;
  }

  // Generate 32 byte key
  pbkdf2(mac, key,salt);

#ifdef ST_SECURITY_DEBUG
  _print_binary_to_hex("iv on decrypt", iv, 16);
  _print_binary_to_hex("salt on decrypt", salt, 32);
  _print_binary_to_hex("key on decrypt", key, 32);
  st_print_log("[ST_ES] decrypted data length %d \n",*decrypted_data_len);
#endif

  ret = aes_decrypt(key, iv, encrypted_data, encrypted_data_len,decrypted_data, decrypted_data_len);
  return ret;
}
#endif /* OC_SECURITY*/