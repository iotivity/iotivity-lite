#ifndef HAWKBIT_H
#define HAWKBIT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int validate_purl(const char *purl);
int check_new_version(size_t device, const char *url, const char *version);
int download_update(size_t device, const char *url);
int perform_upgrade(size_t device, const char *url);

#ifdef __cplusplus
}
#endif

#endif