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

#ifndef ST_SECURITY_H
#define ST_SECURITY_H

#include <stdio.h>
#include <stdlib.h>
#ifdef OC_SECURITY
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pkcs5.h"
#endif /* OC_SECURITY*/
#include "st_store.h"

#ifdef __cplusplus
extern "C" {
#endif

int st_security_encrypt(const unsigned char *data, const unsigned int data_len,
                        unsigned char *encrypted_data,
                        unsigned int *encrypted_data_len);
int st_security_decrypt(unsigned char *salt, unsigned char *iv,
                        unsigned char *encrypted_data,
                        unsigned int encrypted_data_len,
                        unsigned char *decrypted_data,
                        unsigned int *decrypted_data_len);

#ifdef __cplusplus
}
#endif

#endif /* ST_SECURITY_H */
