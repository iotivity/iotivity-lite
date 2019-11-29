#ifndef UPLUS_AIRPURIFIER
#define UPLUS_AIRPURIFIER

#ifdef __cplusplus
extern "C" {
#endif


#include "oc_core_res.h"

#define OC_AIRPURIFIER_DEVICE_TYPE          "oic.d.airpurifier"
#define MAX_AIRPURIFIER_MODES               3
#define MAX_AIRPURIFIER_LEVELS              5
#define DERIVED_BINARY_SWITCH               "OnOffStatus"
#define DERIVED_LEVEL                       "WindSpeed"
#define DERIVED_MODE                        "operationMode"


typedef struct uplus_airpurifier
{
    bool binary_switch;
    int64_t level;
    char mode[16];
}uplus_airpurifier;

/**
 * This method init the virtual uplus airpurifier .
 *
 * @param[in]  uri        device uri.
 * @param[in]  name       device name.
 *
 */
oc_device_info_t*
uplus_airpurifier_init(const char* uri, const char* name);

/**
 * This method register the resources of the virtual airpurifier.
 */
void
register_airpurifier_resources(void);

/**
 * This method synchronize attributes to the virtual airpurifier
 *
 * @param[in]  airpurfier        the latest value of the airpuifier's attribute.
 *
 */
int
uplus_post_airpurifier(uplus_airpurifier airpurifier);

#ifdef __cplusplus
}
#endif

#endif