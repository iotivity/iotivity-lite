#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

// mbedTLS cannot decode the compressed points in the specification, so we have to do it ourselves.
// generated using the Python `cryptography` module:
// M = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x02886...).to_bytes(33, 'big'))
// N = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x03d8b...).to_bytes(33, 'big'))
// M.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
// N.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()

uint8_t bytes_M[] = {
  0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
  0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf,
  0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43,
  0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0,
  0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20
};
uint8_t bytes_N[] = {
  0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
  0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b,
  0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad,
  0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3,
  0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7
};

static int
init_context(void)
{
  int ret;
  // initialize entropy and drbg contexts
  mbedtls_entropy_init(&entropy_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
  if (ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func,
                                  &entropy_ctx, NULL, 0))
    ;
  return ret;

  return 0;
}

static int
free_context(void)
{
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return 0;
}

  //mbedtls_ecp_gen_keypair(&grp, a, &pubA, mbedtls_ctr_drbg_random,
  //                        &ctr_drbg_ctx);

static int
calculate_pA(mbedtls_ecp_point *pA, const mbedtls_mpi *a, const mbedtls_ecp_point *pubA, const mbedtls_mpi *w0)
{
  mbedtls_mpi one;
  mbedtls_ecp_point M;
  mbedtls_ecp_group grp;

  mbedtls_mpi_init(&one);

  mbedtls_ecp_point_init(&M);

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  mbedtls_ecp_point_read_binary(&grp, &M, bytes_M, sizeof(bytes_M));

	mbedtls_mpi_read_string(&one, 10, "1");

	// pA = 1 * pubA + w0 * M
  mbedtls_ecp_muladd(&grp, pA, &one, pubA, w0, &M);

	mbedtls_mpi_free(&one);
	mbedtls_ecp_point_free(&M);
	mbedtls_ecp_group_free(&grp);
}