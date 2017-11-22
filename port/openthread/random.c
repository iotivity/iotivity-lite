#include "oc_random.h"
#include "oc_log.h"

#include <openthread/platform/random.h>

void
oc_random_init(void)
{
}

unsigned int
oc_random_value(void)
{
  return otPlatRandomGet();;
}

void
oc_random_destroy(void)
{
}
