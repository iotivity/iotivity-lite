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

#include "oc_api.h"
#include "port/oc_clock.h"
#include "security/oc_doxm.h"
#include "security/oc_tls.h"

// server private key
uint8_t prv[32] = { 0x46, 0x70, 0x85, 0x56, 0xf4, 0x54, 0xdc, 0x63,
                    0xaa, 0xb9, 0x20, 0xfc, 0x8a, 0xc7, 0x59, 0xf4,
                    0xf4, 0x6e, 0x37, 0x64, 0xcc, 0x8e, 0xa2, 0xb5,
                    0x39, 0xe9, 0xe9, 0xb2, 0x69, 0xcd, 0x91, 0x28 };

// server public key
uint8_t pub[32] = { 0x67, 0x32, 0x94, 0x85, 0xcf, 0x46, 0x0f, 0x92,
                    0x4c, 0x77, 0x18, 0x05, 0xbb, 0xda, 0x7a, 0x50,
                    0x17, 0xfe, 0xfa, 0x72, 0xc4, 0x51, 0x42, 0x89,
                    0xa7, 0x3c, 0xc1, 0xcd, 0x23, 0x43, 0x54, 0xed };

// client public key
uint8_t key[32] = { 0x41, 0x97, 0x77, 0x33, 0x6e, 0xea, 0x62, 0x6c,
                    0x5d, 0x89, 0x2e, 0x50, 0x21, 0x94, 0x74, 0xcc,
                    0x50, 0x24, 0x00, 0x84, 0x42, 0x24, 0x13, 0xeb,
                    0x64, 0xab, 0x2e, 0xe7, 0x53, 0x28, 0x71, 0x40 };

// token
uint8_t tkn[8] = "12345678";

void
get_cpubkey_and_token(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token,
                      int *token_len)
{
  if (!cpubkey || !cpubkey_len || !token || !token_len) {
    PRINT("get_rpk: NULL param");
    return;
  }
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
  memcpy(priv_key, prv, 32);
  memcpy(pub_key, pub, 32);
  *priv_key_len = 32;
  *pub_key_len = 32;
  return;
}

static void print_binary_to_hex(const char* name, const unsigned char* buffer, int buffer_len)
{
    char buffer_hex[81] = {0};
    int i;
    int j;

    printf("%s(%d) = \n", name, buffer_len);
    for(i=1, j=0; i<=buffer_len; i++, j++){

        sprintf(buffer_hex + 2*j, "%02x", buffer[i-1]);

        if(i % 40 == 0){
            printf(" - %s\n", buffer_hex);
            memset(buffer_hex, 0, sizeof(buffer_hex));
            j = -1;
        }
    }
    printf(" - %s\n", buffer_hex);
}

int
main_init()
{
  int ret = 0;

  oc_random_init();//oc_ri_init();
  oc_core_init();

  ret = oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                      "ocf.res.1.0.0", NULL, NULL);

  if (ret < 0)
    goto err;

  ret = oc_tls_init_context();
  if (ret < 0)
    goto err;

  oc_sec_create_svr();

  return 0;

err:
  OC_ERR("oc_main: error in stack initialization");
  return ret;
}

int
main(void)
{
  int init = main_init();
  if (init < 0)
    return init;

  oc_sec_set_cpubkey_and_token_load(get_cpubkey_and_token);
  oc_sec_set_own_key_load(get_own_key);

  char master[32] = {0};
  int master_len = 0;
  gen_master_key(master, &master_len);
  print_binary_to_hex("master key: ", master, master_len);

  oc_main_shutdown();
  return 0;
}
