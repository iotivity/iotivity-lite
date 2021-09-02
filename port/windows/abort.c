#include "port/oc_assert.h"
#include <stdlib.h>

void
abort_impl(void)
{
  exit(1);
}

void
exit_impl(int status)
{
  exit(status);
}
