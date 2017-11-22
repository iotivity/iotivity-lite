#ifndef OC_INSTANCE_H_
#define OC_INSTANCE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "oc_api.h"

void ocInstanceInit(const oc_handler_t *handler);

void ocInstanceSignal();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
