#include <stdint.h>
#include <stdlib.h>
#include "oc_audit.h"
#include "oc_ael.h"

void oc_audit_log(const char* aeid, const char *message, uint8_t category, uint8_t priority, char **aux, size_t aux_len) {
  bool ret = oc_sec_ael_add(category, priority, aeid, message, (const char**) aux, aux_len);
  (void)ret;
  OC_ERR("audit_log: %s %s %u %u; status = %d", aeid, message, category, priority, ret);
  if (aux) {
    size_t i;
    for (i = 0; i < aux_len; ++i) {
      if (aux[i]) {
        OC_ERR("audit_log: %s", aux[i]);
        free(aux[i]);
      }
    }
    free(aux);
  }
}
