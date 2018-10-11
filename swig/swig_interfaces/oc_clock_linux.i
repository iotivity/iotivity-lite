/* File oc_clock.i */
%module OCClock
#define OC_DYNAMIC_ALLOCATION
#define CLOCKS_PER_SEC (1000000)
%include "../../port/linux/config.h"
%{
#include "../../port/oc_clock.h"
%}
%include "../../port/oc_clock.h"