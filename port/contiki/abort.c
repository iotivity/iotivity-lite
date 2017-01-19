#include "port/oc_assert.h"

// TODO:
#ifndef __linux__
void
abort_impl()
{
}
#endif /* __linux__ */
