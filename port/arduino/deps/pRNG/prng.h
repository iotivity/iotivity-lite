#ifndef __PRNG_H__
#define __PRNG_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdlib.h>
struct prng;
typedef struct prng prng_t;

extern prng_t *_prng_holder;

prng_t *prng_create();
void prng_destroy(prng_t *m);

uint8_t prng_getRndByte(prng_t *m);
uint16_t prng_getRndInt(prng_t *m);
uint32_t prng_getRndLong(prng_t *m);

#ifdef __cplusplus
}
#endif

#endif /* __PRNG_H__ */
