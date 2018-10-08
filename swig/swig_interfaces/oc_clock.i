/* File oc_clock.i */
%module OCClock
#define OC_DYNAMIC_ALLOCATION
%include "../../port/windows/config.h"
%{
#include "../../port/oc_clock.h"
%}
%include "../../port/oc_clock.h"