/******************************************************************
*
* Copyright 2018 iThemba LABS All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

*    http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************/
#include "port/oc_random.h"
#include "port/oc_log.h"
#include "oc_helpers.h"

#if defined(__AVR__)
#include "prng.h"
#elif defined(__SAMD21G18A__)
#include <WMath.h>
#include "stdlib.h"
#include "stdint.h"
// This temporary: one need to implment the prng for samd ARCH
void random32Seed( uint32_t dwSeed )
{
  if ( dwSeed != 0 )
    srand( dwSeed );
}
long random32(long max) {
  if ( max == 0 )
    return 0 ;
  return rand() % max;
}
extern long _random32( long howsmall, long howbig )
{
  if (howsmall >= howbig)
  {
    return howsmall;
  }

  long diff = howbig - howsmall;

  return random32(diff) + howsmall;
}
#elif defined(__SAM3X8E__)
#include <sam.h>
#include <trng.h>
#endif

void
oc_random_init(void)
{
#if defined(__AVR__)
  _prng_holder = prng_create();
#elif defined(__SAM3X8E__ )
  pmc_enable_periph_clk(ID_TRNG);
  TRNG->TRNG_IDR = 0xFFFFFFFF;
  TRNG->TRNG_CR = TRNG_CR_KEY(0x524e47) | TRNG_CR_ENABLE;
#elif defined(__SAMD21G18A__)
  random32Seed(analogRead(0));
#endif
}

unsigned int
oc_random_value(void)
{
unsigned int rand_val = 0;
#if defined(__AVR__)
  if(_prng_holder == NULL) {
    _prng_holder = prng_create();
  }
  if (_prng_holder == NULL)
      return 0;
  rand_val =  (unsigned int)prng_getRndInt(_prng_holder);
#elif defined(__SAM3X8E__ )
  while (! (TRNG->TRNG_ISR & TRNG_ISR_DATRDY));
  rand_val = TRNG->TRNG_ODATA;
#elif defined(__SAMD21G18A__)
  rand_val = random32( 1 << 16 );
#endif
  return rand_val;
}

void
oc_random_destroy(void)
{
#ifdef __AVR__
  prng_destroy(_prng_holder);
#endif
}
