#ifndef UPLUS_airconditioner
#define UPLUS_airconditioner

#ifdef __cplusplus
extern "C" {
#endif


#include "oc_core_res.h"

#define OC_airconditioner_DEVICE_TYPE          "oic.d.airconditioner"
#define MAX_airconditioner_MODES               3
#define MAX_airconditioner_LEVELS              5
#define DERIVED_BINARY_SWITCH               "OnOffStatus"
#define DERIVED_TEMPERATURE                 "currentTemperature"
#define DERIVED_MODE                        "operationMode"
#define AirConditionerID                    "11111112-1112-1112-1112-111111111112"


typedef struct uplus_airconditioner
{
    bool binary_switch;
    double temperature;
    char mode[16];
    char units[3];
}uplus_airconditioner;

/**
 * This method init the virtual uplus airconditioner .
 *
 * @param[in]  uri        device uri.
 * @param[in]  name       device name.
 *
 */
oc_device_info_t*
uplus_airconditioner_init(const char* uri, const char* name);

/**
 * This method register the resources of the virtual airconditioner.
 */
void
register_airconditioner_resources(void);

/**
 * This method synchronize attributes to the virtual airconditioner
 *
 * @param[in]  airpurfier        the latest value of the airpuifier's attribute.
 *
 */
int
uplus_post_airconditioner(uplus_airconditioner airconditioner);

#ifdef __cplusplus
}
#endif

#endif