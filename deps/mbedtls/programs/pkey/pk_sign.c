/*
 *  Public key-based signature creation program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char filename[512];
    const char *pers = "mbedtls_pk_sign";
    size_t olen = 0;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pk );

    if( argc != 3 )
    {
        mbedtls_printf( "usage: mbedtls_pk_sign <key_file> <filename>\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from '%s'", argv[1] );
    fflush( stdout );

    if( ( ret = mbedtls_pk_parse_keyfile( &pk, argv[1], "" ) ) != 0 )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not open '%s'\n", argv[1] );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */
    mbedtls_printf( "\n  . Generating the SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    argv[2], hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", argv[2] );
        goto exit;
    }

    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>.sig
     */
    mbedtls_snprintf( filename, sizeof(filename), "%s.sig", argv[2] );

    if( ( f = fopen( filename, "wb+" ) ) == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", filename );
        goto exit;
    }

    if( fwrite( buf, 1, olen, f ) != olen )
    {
        mbedtls_printf( "failed\n  ! fwrite failed\n\n" );
        fclose( f );
        goto exit;
    }

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", filename );

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_ERROR_C)
    if( ret != 0 )
    {
        mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
        mbedtls_printf( "  !  Last error was: %s\n", buf );
    }
#endif

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
