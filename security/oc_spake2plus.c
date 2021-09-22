#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <assert.h>

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

// clang-format off
// mbedTLS cannot decode the compressed points in the specification, so we have to do it ourselves.
// generated using the Python `cryptography` module:
// M = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x02886...).to_bytes(33, 'big'))
// N = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x03d8b...).to_bytes(33, 'big'))
// M.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
// N.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
// clang-format on

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

// mbedtls_ecp_gen_keypair(&grp, a, &pubA, mbedtls_ctr_drbg_random,
//                        &ctr_drbg_ctx);

// generic formula for
// pX = pubX + wX * L
static int
calculate_pX(mbedtls_ecp_point *pX, const mbedtls_ecp_point *pubX,
             const mbedtls_mpi *wX, const uint8_t bytes_L[], size_t len_L)
{
  mbedtls_mpi one;
  mbedtls_ecp_point L;
  mbedtls_ecp_group grp;
  int ret;

  mbedtls_mpi_init(&one);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&L);

  // MBEDTLS_MPI_CHK sets ret to the return value of f and goes to cleanup if
  // ret is nonzero
  MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
  MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &L, bytes_L, len_L));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&one, 10, "1"));

  // pA = 1 * pubA + w0 * M
  MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, pX, &one, pubX, wX, &L));

cleanup:
  mbedtls_mpi_free(&one);
  mbedtls_ecp_point_free(&L);
  mbedtls_ecp_group_free(&grp);
  return ret;
}

// pA = pubA + w0 * M
static int
calculate_pA(mbedtls_ecp_point *pA, const mbedtls_ecp_point *pubA,
             const mbedtls_mpi *w0)
{
  return calculate_pX(pA, pubA, w0, bytes_M, sizeof(bytes_M));
}

// pB = pubB + w0 * N
static int
calculate_pB(mbedtls_ecp_point *pB, const mbedtls_ecp_point *pubB,
             const mbedtls_mpi *w0)
{
  return calculate_pX(pB, pubB, w0, bytes_N, sizeof(bytes_N));
}

// generic formula for
// J = f * (K - g * L)
static int
calculate_JfKgL(mbedtls_ecp_point *J, const mbedtls_mpi *f,
                const mbedtls_ecp_point *K, const mbedtls_mpi *g,
                const mbedtls_ecp_point *L)
{
  int ret;
  mbedtls_mpi negative_g, zero, one;
  mbedtls_mpi_init(&negative_g);
  mbedtls_mpi_init(&zero);
  mbedtls_mpi_init(&one);

  mbedtls_ecp_point K_minus_g_L;
  mbedtls_ecp_point_init(&K_minus_g_L);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));

  // negative_g = -g
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&zero, 10, "0"));
  MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&negative_g, &zero, g));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&negative_g, &negative_g, &grp.N));

  // K_minus_g_L = K - g * L
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&one, 10, "1"));
  MBEDTLS_MPI_CHK(
    mbedtls_ecp_muladd(&grp, &K_minus_g_L, &one, K, &negative_g, L));

  // J = f * (K_minus_g_L)
  MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, J, f, &K_minus_g_L,
                                  // TODO this segfaults, find out why
                                  // mbedtls_ctr_drbg_random, &ctr_drbg_ctx));
                                  NULL, NULL));

cleanup:
  mbedtls_mpi_free(&negative_g);
  mbedtls_mpi_free(&zero);
  mbedtls_mpi_free(&one);
  mbedtls_ecp_point_free(&K_minus_g_L);
  mbedtls_ecp_group_free(&grp);
  return ret;
}

// Z = h*x*(Y - w0*N)
// also works for:
// V = h*w1*(Y - w0*N)
// Z = h*y*(X - w0*M)
static int
calculate_ZV_N(mbedtls_ecp_point *Z, const mbedtls_mpi *x,
             const mbedtls_ecp_point *Y, const mbedtls_mpi *w0)
{
  int ret;

  mbedtls_ecp_point N;
  mbedtls_ecp_point_init(&N);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);

  MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
  MBEDTLS_MPI_CHK(
    mbedtls_ecp_point_read_binary(&grp, &N, bytes_N, sizeof(bytes_N)));

  // For the secp256r1 curve, h is 1, so we don't need to do anything
  MBEDTLS_MPI_CHK(calculate_JfKgL(Z, x, Y, w0, &N));

cleanup:
  mbedtls_ecp_point_free(&N);
  return ret;
}

int
validate_against_test_vector()
{
  // Test Vector values from Spake2+ draft.
  // Using third set, as we only have easy access to the server (e.g. device)
  // identity.
  char Context[] = "SPAKE2+-P256-SHA256-HKDF draft-01";
  char A[] = "";
  char B[] = "server";

  uint8_t bytes_w0[] = { 0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79,
                         0xc6, 0x9b, 0xf4, 0x79, 0x28, 0xa8, 0x45, 0x14,
                         0xb5, 0xe3, 0x55, 0xac, 0x03, 0x48, 0x63, 0xf7,
                         0xff, 0xaf, 0x43, 0x90, 0xe6, 0x7d, 0x79, 0x8c };
  uint8_t bytes_w1[] = { 0x24, 0xb5, 0xae, 0x4a, 0xbd, 0xa8, 0x68, 0xec,
                         0x93, 0x36, 0xff, 0xc3, 0xb7, 0x8e, 0xe3, 0x1c,
                         0x57, 0x55, 0xbe, 0xf1, 0x75, 0x92, 0x27, 0xef,
                         0x53, 0x72, 0xca, 0x13, 0x9b, 0x94, 0xe5, 0x12 };

  uint8_t bytes_L[] = { 0x04, 0x95, 0x64, 0x5c, 0xfb, 0x74, 0xdf, 0x6e, 0x58,
                        0xf9, 0x74, 0x8b, 0xb8, 0x3a, 0x86, 0x62, 0x0b, 0xab,
                        0x7c, 0x82, 0xe1, 0x07, 0xf5, 0x7d, 0x68, 0x70, 0xda,
                        0x8c, 0xbc, 0xb2, 0xff, 0x9f, 0x70, 0x63, 0xa1, 0x4b,
                        0x64, 0x02, 0xc6, 0x2f, 0x99, 0xaf, 0xcb, 0x97, 0x06,
                        0xa4, 0xd1, 0xa1, 0x43, 0x27, 0x32, 0x59, 0xfe, 0x76,
                        0xf1, 0xc6, 0x05, 0xa3, 0x63, 0x97, 0x45, 0xa9, 0x21,
                        0x54, 0xb9 };

  uint8_t bytes_x[] = { 0xba, 0x0f, 0x0f, 0x5b, 0x78, 0xef, 0x23, 0xfd,
                        0x07, 0x86, 0x8e, 0x46, 0xae, 0xca, 0x63, 0xb5,
                        0x1f, 0xda, 0x51, 0x9a, 0x34, 0x20, 0x50, 0x1a,
                        0xcb, 0xe2, 0x3d, 0x53, 0xc2, 0x91, 0x87, 0x48 };
  uint8_t bytes_X[] = { 0x04, 0xc1, 0x4d, 0x28, 0xf4, 0x37, 0x0f, 0xea, 0x20,
                        0x74, 0x51, 0x06, 0xce, 0xa5, 0x8b, 0xcf, 0xb6, 0x0f,
                        0x29, 0x49, 0xfa, 0x4e, 0x13, 0x1b, 0x9a, 0xff, 0x5e,
                        0xa1, 0x3f, 0xd5, 0xaa, 0x79, 0xd5, 0x07, 0xae, 0x1d,
                        0x22, 0x9e, 0x44, 0x7e, 0x00, 0x0f, 0x15, 0xeb, 0x78,
                        0xa9, 0xa3, 0x2c, 0x2b, 0x88, 0x65, 0x2e, 0x34, 0x11,
                        0x64, 0x20, 0x43, 0xc1, 0xb2, 0xb7, 0x99, 0x2c, 0xf2,
                        0xd4, 0xde };

  uint8_t bytes_y[] = { 0x39, 0x39, 0x7f, 0xbe, 0x6d, 0xb4, 0x7e, 0x9f,
                        0xbd, 0x1a, 0x26, 0x3d, 0x79, 0xf5, 0xd0, 0xaa,
                        0xa4, 0x4d, 0xf2, 0x6c, 0xe7, 0x55, 0xf7, 0x8e,
                        0x09, 0x26, 0x44, 0xb4, 0x34, 0x53, 0x3a, 0x42 };
  uint8_t bytes_Y[] = { 0x04, 0xd1, 0xbe, 0xe3, 0x12, 0x0f, 0xd8, 0x7e, 0x86,
                        0xfe, 0x18, 0x9c, 0xb9, 0x52, 0xdc, 0x68, 0x88, 0x23,
                        0x08, 0x0e, 0x62, 0x52, 0x4d, 0xd2, 0xc0, 0x8d, 0xff,
                        0xe3, 0xd2, 0x2a, 0x0a, 0x89, 0x86, 0xaa, 0x64, 0xc9,
                        0xfe, 0x01, 0x91, 0x03, 0x3c, 0xaf, 0xbc, 0x9b, 0xca,
                        0xef, 0xc8, 0xe2, 0xba, 0x8b, 0xa8, 0x60, 0xcd, 0x12,
                        0x7a, 0xf9, 0xef, 0xdd, 0x7f, 0x1c, 0x3a, 0x41, 0x92,
                        0x0f, 0xe8 };

  uint8_t bytes_Z[] = { 0x04, 0xaa, 0xc7, 0x1c, 0xf4, 0xc8, 0xdf, 0x81, 0x81,
                        0xb8, 0x67, 0xc9, 0xec, 0xbe, 0xe9, 0xd0, 0x96, 0x3c,
                        0xaf, 0x51, 0xf1, 0x53, 0x4a, 0x82, 0x34, 0x29, 0xc2,
                        0x6f, 0xe5, 0x24, 0x83, 0x13, 0xff, 0xc5, 0xc5, 0xe4,
                        0x4e, 0xa8, 0x16, 0x21, 0x61, 0xab, 0x6b, 0x3d, 0x73,
                        0xb8, 0x77, 0x04, 0xa4, 0x58, 0x89, 0xbf, 0x63, 0x43,
                        0xd9, 0x6f, 0xa9, 0x6c, 0xd1, 0x64, 0x1e, 0xfa, 0x71,
                        0x60, 0x7c };

  uint8_t bytes_V[] = { 0x04, 0xc7, 0xc9, 0x50, 0x53, 0x65, 0xf7, 0xce, 0x57,
                        0x29, 0x3c, 0x92, 0xa3, 0x7f, 0x1b, 0xbd, 0xc6, 0x8e,
                        0x03, 0x22, 0x90, 0x1e, 0x61, 0xed, 0xef, 0x59, 0xfe,
                        0xe7, 0x87, 0x6b, 0x17, 0xb0, 0x63, 0xe0, 0xfa, 0x4a,
                        0x12, 0x6e, 0xae, 0x0a, 0x67, 0x1b, 0x37, 0xf1, 0x46,
                        0x4c, 0xf1, 0xcc, 0xad, 0x59, 0x1c, 0x33, 0xae, 0x94,
                        0x4e, 0x3b, 0x1f, 0x31, 0x8d, 0x76, 0xe3, 0x6f, 0xea,
                        0x99, 0x66 };

  uint8_t cmpbuf[128];
  size_t cmplen;
  int ret;

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));

  // =========================
  // Check that X = x*P + w0*M
  // =========================
  mbedtls_mpi x, w0;
  mbedtls_mpi_init(&x);
  mbedtls_mpi_init(&w0);

  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, bytes_x, sizeof(bytes_x)));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&w0, bytes_w0, sizeof(bytes_w0)));

  mbedtls_ecp_point X, pubA;
  mbedtls_ecp_point_init(&X);
  mbedtls_ecp_point_init(&pubA);
  // pubA = x*P (P is the generator group element, mbedtls uses G)
  MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &pubA, &x, &grp.G, NULL, NULL));

  // X = pubA + w0*M
  MBEDTLS_MPI_CHK(calculate_pA(&X, &pubA, &w0));
  MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
    &grp, &X, MBEDTLS_ECP_PF_UNCOMPRESSED, &cmplen, cmpbuf, sizeof(cmpbuf)));

  // check the value of X is correct
  assert(memcmp(bytes_X, cmpbuf, cmplen) == 0);

  // =========================
  // Check that Y = y*P + w0*N
  // =========================
  mbedtls_mpi y;
  mbedtls_mpi_init(&y);

  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&y, bytes_y, sizeof(bytes_y)));

  mbedtls_ecp_point Y, pubB;
  mbedtls_ecp_point_init(&Y);
  mbedtls_ecp_point_init(&pubB);
  // pubB = y*P
  MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &pubB, &y, &grp.G, NULL, NULL));

  // Y = pubB + w0*N
  MBEDTLS_MPI_CHK(calculate_pB(&Y, &pubB, &w0));
  MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
    &grp, &Y, MBEDTLS_ECP_PF_UNCOMPRESSED, &cmplen, cmpbuf, sizeof(cmpbuf)));
  // check the value of Y is correct
  assert(memcmp(bytes_Y, cmpbuf, cmplen) == 0);

  // ==============================
  // Check that altering the inputs
  // does indeed change the result
  // ==============================
  mbedtls_mpi bad_y;
  mbedtls_ecp_point bad_pubB, bad_Y;
  mbedtls_mpi_init(&bad_y);
  mbedtls_ecp_point_init(&bad_pubB);
  mbedtls_ecp_point_init(&bad_Y);

  bytes_y[5]++;
  mbedtls_mpi_read_binary(&bad_y, bytes_y, sizeof(bytes_y));
  bytes_y[5]--;

  // pubB = y*P
  MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &bad_pubB, &bad_y, &grp.G, NULL, NULL));

  // Y = pubB + w0*N
  MBEDTLS_MPI_CHK(calculate_pB(&bad_Y, &bad_pubB, &w0));
  MBEDTLS_MPI_CHK(
    mbedtls_ecp_point_write_binary(&grp, &bad_Y, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &cmplen, cmpbuf, sizeof(cmpbuf)));
  // check the value of Y is NOT correct
  assert(memcmp(bytes_Y, cmpbuf, cmplen) != 0);

  // ================================
  // Check that party A can calculate
  // the shared secret key material
  // ================================

  mbedtls_ecp_point Z;
  mbedtls_ecp_point_init(&Z);

  // Z = h*x*(Y - w0*N)
  printf("Calculating Z...\n");
  MBEDTLS_MPI_CHK(calculate_ZV_N(&Z, &x, &Y, &w0));

  printf("Comparing Z...\n");
  MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(&grp, &Z, MBEDTLS_ECP_PF_UNCOMPRESSED, &cmplen, cmpbuf, sizeof(cmpbuf)));
  assert(memcmp(bytes_Z, cmpbuf, cmplen) == 0);

  // V = h*w1*(Y - w0*N)

cleanup:
  return ret;
}