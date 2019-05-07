#ifndef LUNA_ADAPTER_UTIL_H
#define LUNA_ADAPTER_UTIL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "oc_network_events.h"

bool CAInitializeLS(void);
void CATerminateLS();
void CANetworkMonitorHandler();

#endif /* LUNA_ADAPTER_UTIL_H */
