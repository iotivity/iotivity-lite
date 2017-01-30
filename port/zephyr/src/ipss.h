/** @file
 *  @brief IPSP Service sample
 */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __cplusplus
extern "C" {
#endif

void ipss_set_attributes(char *device, char *manufacturer, char *model);
void ipss_init();
int ipss_advertise(void);

#ifdef __cplusplus
}
#endif
