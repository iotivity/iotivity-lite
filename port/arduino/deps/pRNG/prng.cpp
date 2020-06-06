#include <Arduino.h>
#include <stdio.h>
#include "prng.h"
#include "pRNG.h"

struct prng {
    void *prng_ref;
};
prng_t *_prng_holder = NULL;

prng_t *prng_create()
{
    prng_t *prng_holder;
    pRNG *prng_ref;

    prng_holder     = (typeof(prng_holder))malloc(sizeof(*prng_holder));
    prng_ref    = new pRNG();
    prng_holder->prng_ref = prng_ref;
    return prng_holder;
}

void prng_destroy(prng_t *prng_holder)
{
    if (prng_holder== NULL)
        return;
    delete static_cast<pRNG *>(prng_holder->prng_ref);
    free(prng_holder);
}
uint8_t prng_getRndByte(prng_t *prng_holder){

    pRNG *prng_ref;

    if (prng_holder== NULL)
        return 1;

    prng_ref = static_cast<pRNG *>(prng_holder->prng_ref);
    return prng_ref->getRndByte();
}

uint16_t prng_getRndInt(prng_t *prng_holder){

    pRNG *prng_ref;

    if (prng_holder== NULL)
        return 1;
    prng_ref = static_cast<pRNG *>(prng_holder->prng_ref);
    return prng_ref->getRndInt();
}

uint32_t prng_getRndLong(prng_t *prng_holder){

    pRNG *prng_ref;

    if (prng_holder== NULL)
        return 1;
    prng_ref = static_cast<pRNG *>(prng_holder->prng_ref);
    return prng_ref->getRndLong();
}