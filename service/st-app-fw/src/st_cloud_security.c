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

/*
--jwt structure--
Header
{
"alg":"EdDSA",
"kty":"OKP",
"crv":"Ed25519", // https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06
"typ": "JWT",
"ver": "1.0.0",
"kid": "sn" // KeyId, serial number
}
Payload
{
"iat": "$unixepoch", // Issued At
"jti": "$random_string_uuid_format" // JWT ID, nonce
}
*/

#ifdef OC_RPK

#include <string.h>
#include "st_jwt.h"
#include "st_cloud_security.h"

int st_sign_jwt_getter(char **outbuf, const char *pub_key, const char *priv_key, const char *sn)
{
  if ((outbut == NULL)||(pub_key == NULL)||(priv_key == NULL)||(sn == NULL))
    goto fail;
 
  char jwt_header_data[JSON_HEADER_SIZE];
  char jwt_payload_data[JSON_PAYLOAD_SIZE];
  char signature[64] = {0, };
  char signature2[64] = {0, };

  char *tmpbuf;
  int olen = 0;
  int ret;

  tmpbuf = *outbuf = NULL;

  *outbuf = oc_mem_malloc(JWT_BUFFER_SIZE);
  tmpbuf = oc_mem_malloc(JSON_PAYLOAD_SIZE);

  // error checking
  if (!*outbuf || !tmpbuf) {
    goto fail;
  }

  st_jwt_json_signup_get(jwt_header_data, jwt_payload_data, sn);
  st_print_log("json object information.\n<header> \n%s\n<payload>\n%s\n", jwt_header_data, jwt_payload_data);

  /* encoding base64 */
  ret = mbedtls_base64_encode((unsigned char *)*outbuf, (size_t)JWT_BUFFER_SIZE, (size_t *)&olen,
                              (const unsigned char *)jwt_header_data, (size_t)strlen(jwt_header_data));
  if(ret != 0) {
    goto fail;
  }

  ret = mbedtls_base64_encode((unsigned char *)tmpbuf, (size_t)JSON_PAYLOAD_SIZE, (size_t *)&olen,
                              (const unsigned char *)jwt_payload_data, (size_t)strlen(jwt_payload_data));
  if(ret != 0) {
    goto fail;
  }

  /*make jwt style xxx.yyy */
  strcat(*outbuf, ".");
  strcat(*outbuf, tmpbuf);

  //tmpbuf should be larger for signature
  oc_mem_free(tmpbuf);
  tmpbuf = NULL;

  if (!st_jwt_signature_get(signature, pub_key, priv_key, *outbuf, strlen(*outbuf))) {
    goto fail;
  }
 
  hex_dump_data(signature, sizeof(signature));

  tmpbuf = oc_mem_malloc(JSON_SIGNATURE_SIZE);
  // error checking
  if (!tmpbuf) {
    goto fail;
  }

  memset(tmpbuf, 0, JSON_SIGNATURE_SIZE);
  ret = mbedtls_base64_encode((unsigned char *)tmpbuf, (size_t)JSON_SIGNATURE_SIZE, (size_t *)&olen,
                              (const unsigned char *)signature, (size_t)64);
  st_print_log("signature is\n %s, ret = %d\n", tmpbuf, ret);

  if(ret != 0) {
    goto fail;
  }

  /*complete jwt with signature xxx.yyy.zzz */
  strcat(*outbuf, ".");
  strcat(*outbuf, tmpbuf);

  st_print_log("final jwt data\n%s\n", *outbuf);

  if (tmpbuf != NULL) {
    oc_mem_free(tmpbuf);
    tmpbuf = NULL;
  }
  return 0;

fail:
  if (*outbuf != NULL) {
    oc_mem_free(*outbuf);
    *outbuf = NULL;
  }
  if (tmpbuf != NULL) {
    oc_mem_free(tmpbuf);
    tmpbuf = NULL;
  }
  return -1;
}

#endif
