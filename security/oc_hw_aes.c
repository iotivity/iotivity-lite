#include "mbedtls/ctr_drbg.h"

#ifdef ST_MBEDTLS_HW_AES
#define MBEDTLS_AES_SETKEY_ENC_ALT
#define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_ENCRYPT_ALT
#define MBEDTLS_AES_DECRYPT_ALT
#endif ST_MBEDTLS_HW_AES

#ifdef MBEDTLS_AES_SETKEY_ENC_ALT
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    ctx->rk = ctx->buf;
    memcpy (ctx->rk, key, 16);
    return 0;
}
#endif /* MBEDTLS_AES_SETKEY_ENC_ALT */

#ifdef MBEDTLS_AES_SETKEY_DEC_ALT
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    ctx->rk = ctx->buf;
    memcpy (ctx->rk, key, 16);
    return 0;
}
#endif /* MBEDTLS_AES_SETKEY_DEC_ALT */

#ifdef MBEDTLS_AES_ENCRYPT_ALT
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    oc_abort("mbedtls_internal_aes_encrypt is not implented!");
    return 0;
}
#endif /* MBEDTLS_AES_ENCRYPT_ALT */

#ifdef MBEDTLS_AES_DECRYPT_ALT
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    oc_abort("mbedtls_internal_aes_decrypt is not implented!");
    return 0;
}
#endif /* MBEDTLS_AES_DECRYPT_ALT */
