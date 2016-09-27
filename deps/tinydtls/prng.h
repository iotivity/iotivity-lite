/* prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010--2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the library tinydtls. Please see
 * README for terms of use. 
 */

/** 
 * @file prng.h
 * @brief Pseudo Random Numbers
 */

#ifndef _DTLS_PRNG_H_
#define _DTLS_PRNG_H_

#include "tinydtls.h"

/** 
 * @defgroup prng Pseudo Random Numbers
 * @{
 */

#if !defined(WITH_CONTIKI) && !defined(WITH_OCF)
#include <stdlib.h>

/**
 * Fills \p buf with \p len random bytes. This is the default
 * implementation for prng().  You might want to change prng() to use
 * a better PRNG on your specific platform.
 */
static inline int
dtls_prng(unsigned char *buf, size_t len) {
  while (len--)
    *buf++ = rand() & 0xFF;
  return 1;
}

static inline void
dtls_prng_init(unsigned short seed) {
	srand(seed);
}
#else /* !WITH_CONTIKI && !WITH_OCF */
#include <string.h>
#ifdef WITH_CONTIKI
#include "random.h"
#else /* WITH_CONTIKI */
#include "port/oc_random.h"
#endif /* WITH_OCF */

#if defined(WITH_CONTIKI) && defined(HAVE_PRNG)
static inline int
dtls_prng(unsigned char *buf, size_t len)
{
	return contiki_prng_impl(buf, len);
}
#else /* WITH_CONTIKI && HAVE_PRNG */
/**
 * Fills \p buf with \p len random bytes. This is the default
 * implementation for prng().  You might want to change prng() to use
 * a better PRNG on your specific platform.
 */
static inline int
dtls_prng(unsigned char *buf, size_t len) {
#ifdef WITH_CONTIKI
  unsigned short v = random_rand();
#else  /* WITH_CONTIKI */
  unsigned int v = oc_random_value();
#endif /* WITH_OCF */
  while (len > sizeof(v)) {
    memcpy(buf, &v, sizeof(v));
    len -= sizeof(v);
    buf += sizeof(v);
#ifdef WITH_CONTIKI
    v = random_rand();
#else  /* WITH_CONTIKI */
    v = oc_random_value();
#endif /* WITH_OCF */
  }

  memcpy(buf, &v, len);
  return 1;
}
#endif /* !HAVE_PRNG */

static inline void
dtls_prng_init(unsigned short seed) {
#ifdef WITH_CONTIKI
	random_init(seed);
#endif /* WITH_CONTIKI */
}
#endif /* WITH_CONTIKI || WITH_OCF */

/** @} */

#endif /* _DTLS_PRNG_H_ */
